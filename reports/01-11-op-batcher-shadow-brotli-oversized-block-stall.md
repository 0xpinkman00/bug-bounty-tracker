# op-batcher — shadow compressor with Brotli mistakes the version byte for data — an oversized L2 block is never batched and the batcher spams empty channels

| Field | Value |
|---|---|
| **Target** | `op-batcher/compressor/shadow_compressor.go`, `op-node/rollup/derive/channel_compressor.go` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Medium (config-dependent) |
| **Impact category** | Temporary freezing of funds (withdrawals stall because the safe head stops advancing); a later reorg of unsafe L2 blocks is possible; wasted L1 fees for the batcher |
| **Fix commit(s)** | `542fa53d848ba7a60a3ca3fa05a428c07ab34c41` (PR #18485) — 2026-01-08 |
| **Vulnerable since** | `4b8f6f4ffc` "Fjord: Add Brotli channel compression support" (PR #10358), 2024-05-13 |

## Brief / Intro

The batcher is the service that takes L2 blocks from the sequencer, compresses them into "channels", and posts them to Ethereum L1. Only after a block is posted to L1 does it become "safe", and only safe blocks can back output roots and therefore withdrawals. With the default shadow compressor and the optional Brotli algorithm, the batcher had a bug: if one L2 block was larger after compression than a channel's target size, the block was never put into any channel. The batcher then opened and posted an empty channel, again and again, paying L1 fees each time, while the safe head stayed where it was. Any L2 user who can fill a block with incompressible data can trigger this on a chain that uses this configuration.

## Vulnerability Details

The shadow compressor keeps a second "shadow" compressor so it can estimate when the real output is about to exceed `TargetOutputSize`. There is a deliberate exception. If the channel is still empty, a block is accepted even when it goes over the target, because a single oversized block would otherwise never fit anywhere. The "is the channel still empty" test was `t.Len() > 0`.

Parent `op-batcher/compressor/shadow_compressor.go:55-83`:

```go
func (t *ShadowCompressor) Write(p []byte) (int, error) {
    ...
        newBound = uint64(t.shadowCompressor.Len()) + CloseOverheadZlib
        if newBound > t.config.TargetOutputSize {
            t.fullErr = derive.ErrCompressorFull
            if t.Len() > 0 {                       // line 74
                // only return an error if we've already written data to this compressor before
                // (otherwise single blocks over the target would never be written)
                return 0, t.fullErr
            }
        }
    ...
}
```

The Brotli channel compressor writes a one-byte channel-version prefix into its output buffer when it is created or reset. Parent `op-node/rollup/derive/channel_compressor.go:65` and `:83`:

```go
compressed.WriteByte(ChannelVersionBrotli)
```

So for Brotli, `t.Len()` is already 1 on an empty channel, and the exception never applies:

1. The oversized block is offered to a fresh channel. The shadow estimate is over the target and `t.Len() == 1 > 0`, so `Write` returns `ErrCompressorFull` with 0 bytes written.
2. `ChannelBuilder.AddBlock` (`op-batcher/batcher/channel_builder.go:170-178`) marks the channel full. `channelManager.processBlocks` (`channel_manager.go:423-433`) breaks out, and the block stays pending (`blockCursor` does not move).
3. The full channel, which holds zero blocks, is closed, framed and submitted to L1.
4. A new channel is opened for the same pending block, and step 1 repeats indefinitely.

Zlib writes no prefix, so `t.Len()` is 0 on an empty channel and the exception works. That is why the bug was specific to Brotli.

Fix (`542fa53d84`): each compressor now reports its static header length, and the empty-channel test ignores it:

```diff
-			if t.Len() > 0 {
+			if t.Len() > t.compressor.StaticBytesLen() {
```

```go
func (bc *ZlibCompressor) StaticBytesLen() int   { return 0 }
func (bc *BrotliCompressor) StaticBytesLen() int { return 1 }
```

### Attack scenario

1. The target chain runs op-batcher with `--compressor=shadow` (the default) and `--compression-algo=brotli|brotli-9|brotli-10|brotli-11`. Its channel target (`MaxL1TxSize × TargetNumFrames`) is smaller than the largest block users can get the sequencer to build. The most likely example is calldata DA, with a 120 KB target, or blobs with `TargetNumFrames=1`.
2. The attacker sends one or more transactions carrying random (incompressible) calldata, so that the L2 block they land in compresses to more than the target. With the batcher's default DA throttling, the per-block DA limit is 130 KB (`DefaultThrottleBlockSizeUpperLimit`, `op-batcher/flags/throttle_flags.go:15`). That is still above a 120 KB calldata target.
3. The batcher stops making progress. It posts an empty channel in every publishing cycle and never includes the attacker's block, or any later block.

## Impact Details

- **Safe head stalls.** No L2 block from the oversized one onwards becomes safe. Proposers cannot post new output roots, so withdrawals cannot be proven or finalized for as long as the stall lasts (temporary freezing of funds).
- **Unsafe reorg risk.** If the stall outlasts the sequencing window (3600 L1 blocks, about 12 h, on standard chains), derivation forces deposit-only blocks for the stalled range. Every unsafe L2 transaction since the oversized block is then reorged out.
- **Batcher fund drain.** Each empty channel is a real L1 transaction. The PoC below shows 50 of 50 submissions carrying empty channels.
- **Cost to attacker.** One L2 block's worth of random calldata, roughly 120-130 KB. At typical L2 fees that costs little.

**Mitigating factors:**
- Brotli is opt-in; the default algorithm is zlib.
- On chains that use blobs with the usual 5-6 frames per channel, the default 130 KB per-block DA throttle keeps blocks well under the target, so the bug is hard to reach there.
- The stall is loud: the safe head stops and alerts fire. An operator can recover by switching the batcher to zlib or raising the target.

For these reasons we rate it **Medium** rather than High. On an affected configuration it is a cheap, permissionless way to halt the safe chain.

## Proof of Concept

**Executed: yes.** I ran this on a `git archive` snapshot of the parent commit, then applied the fix diff and ran it again.

1. The regression test added by the fix, `TestChannelManager_SingleBlockBiggerThanMaxFrameSize` (`op-batcher/batcher/channel_manager_test.go`), on the parent commit:

```
--- FAIL: TestChannelManager_SingleBlockBiggerThanMaxFrameSize
    --- PASS: .../zlib
    --- FAIL: .../brotli      (pendingBlocks expected 0, got 1; channel blocks expected 1, got 0)
    --- FAIL: .../brotli-9
    --- FAIL: .../brotli-10
    --- FAIL: .../brotli-11
```

2. An end-to-end channel-manager PoC that drives the real publish loop (`TxData` / `TxConfirmed`) and counts empty channels. Save it as `op-batcher/batcher/poc_brotli_loop_test.go`:

```go
package batcher

import (
	"math/rand"
	"testing"

	"github.com/ethereum-optimism/optimism/op-batcher/metrics"
	"github.com/ethereum-optimism/optimism/op-node/rollup/derive"
	derivetest "github.com/ethereum-optimism/optimism/op-node/rollup/derive/test"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
	"github.com/ethereum/go-ethereum/log"
	"github.com/stretchr/testify/require"
)

func TestPoC_ShadowBrotliOversizedBlockNeverBatched(t *testing.T) {
	rng := rand.New(rand.NewSource(1234))
	a := derivetest.RandomL2BlockWithChainId(rng, 4, defaultTestRollupConfig.L2ChainID)
	l1Head := eth.BlockID{Hash: a.Hash(), Number: a.NumberU64()}

	for _, algo := range []derive.CompressionAlgo{derive.Zlib, derive.Brotli} {
		t.Run(string(algo), func(t *testing.T) {
			cfg := channelManagerTestConfig(1_000, derive.SingularBatchType) // target << block size
			cfg.InitShadowCompressor(algo)
			cfg.ChannelTimeout = 1_000
			m := NewChannelManager(testlog.Logger(t, log.LevelCrit), metrics.NoopMetrics, cfg, defaultTestRollupConfig)
			require.NoError(t, m.AddL2Block(a))

			emptyChannels, txs := 0, 0
			for i := 0; i < 50; i++ {
				txd, err := m.TxData(l1Head, false, pubInfo{})
				if err != nil {
					break
				}
				if len(m.channelQueue) > 0 && m.channelQueue[len(m.channelQueue)-1].blocks.Len() == 0 {
					emptyChannels++
				}
				m.TxConfirmed(txd.ID(), l1Head)
				txs++
			}
			t.Logf("algo=%s txsSubmitted=%d emptyChannels=%d pendingBlocks=%d", algo, txs, emptyChannels, m.pendingBlocks())
			require.Equal(t, 0, m.pendingBlocks(), "oversized block was never batched")
		})
	}
}
```

Run it against a checkout of the parent (`542fa53d84^`) and then the fix:

```sh
cd op-batcher/batcher
go test -count=1 -run 'TestPoC_ShadowBrotli|TestChannelManager_SingleBlockBiggerThanMaxFrameSize' -v .
```

Observed output on the parent:

```
algo=zlib   txsSubmitted=4  emptyChannels=0  pendingBlocks=0
algo=brotli txsSubmitted=50 emptyChannels=50 pendingBlocks=1
--- FAIL: TestPoC_ShadowBrotliOversizedBlockNeverBatched/brotli
```

Observed output with the fix applied:

```
algo=zlib   txsSubmitted=4 emptyChannels=0 pendingBlocks=0
algo=brotli txsSubmitted=4 emptyChannels=0 pendingBlocks=0
--- PASS: TestPoC_ShadowBrotliOversizedBlockNeverBatched
--- PASS: TestChannelManager_SingleBlockBiggerThanMaxFrameSize
```

## Recommendation

The fix is correct: the "channel already has data" test now subtracts the compressor's static header. Two defence-in-depth suggestions:

- The channel manager should never submit a channel that contains zero blocks. If a full channel is empty, log an error and force the pending block in, or refuse to publish, rather than posting an empty frame.
- Add a metric or alert for "channel closed full with 0 blocks" so any future variant of this loop is seen straight away.

## References

- Fix commit: `542fa53d848ba7a60a3ca3fa05a428c07ab34c41`
- Pull request: https://github.com/ethereum-optimism/optimism/pull/18485
- Introduced by: `4b8f6f4ffc` (PR #10358, Fjord Brotli support)
- Relevant files: `op-batcher/compressor/shadow_compressor.go`, `op-node/rollup/derive/channel_compressor.go`, `op-batcher/batcher/channel_manager.go`, `op-batcher/batcher/channel_builder.go`, `op-batcher/flags/throttle_flags.go`
