# op-batcher SpanChannelOut: over-limit channel is still submitted, and derivation discards all of it (safe-head stall)

| Field | Value |
|---|---|
| **Target** | `op-node/rollup/derive/span_channel_out.go` (the channel encoder used by `op-batcher`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Medium |
| **Impact category** | "Temporary freezing of network transactions by delaying one block by 500% or more of the average block time of the preceding 24 hours beyond standard difficulty adjustments" (applies to the safe/finalized chain; the unsafe chain keeps going) |
| **Fix commit(s)** | dcce927ab82ca3977ca1ecc5ad03ea7dd851a57e (PR #14310), 2025-02-14 |
| **Vulnerable since** | a3cc8f275d "op-batcher: Embed Zlib Compressor into Span Channel Out; Compression Avoidance Strategy" (PR #10002), 2024-04-08. Live for about 10 months in op-batcher releases. From Fjord (mainnet July 2024) onwards the limit is 100,000,000 bytes. |

## Brief / Intro

The batcher packs L2 blocks into *channels*: it RLP-encodes a list of blocks (a *span batch*), compresses the result, and posts it to L1. The protocol caps how many uncompressed RLP bytes a channel may hold (`MaxRLPBytesPerChannel`: 10 MB before Fjord, 100 MB after). Every verifier stops reading a channel at that cap. When adding a block pushed a span channel over the cap, the batcher returned "channel full" but left the too-large encoding in place. It then closed and posted that encoding anyway. Derivation cannot decode an RLP item larger than the cap, so it throws away the whole channel, including every block the batcher believed it had posted. The safe head stops advancing. When the batcher retries, it rebuilds the same over-limit channel. Highly compressible L2 transactions, such as large all-zero calldata, bring a channel to the cap long before it reaches its compressed-size target. So ordinary L2 users can steer a channel into this state, not only the operator.

## Vulnerability Details

`addSingularBatch` keeps two RLP buffers. The *inactive* buffer holds the encoding before the new block, and the *active* buffer holds the encoding after it. If the new encoding is over the limit, the function returns an error. It does not swap back to the previous buffer or recompress:

`op-node/rollup/derive/span_channel_out.go:165-183` (parent of fix)
```go
co.swapRLP()
active := co.activeRLP()
active.Truncate(co.sealedRLPBytes)
if err = rlp.Encode(active, NewBatchData(rawSpanBatch)); err != nil { ... }

maxRLPBytesPerChannel := co.chainSpec.MaxRLPBytesPerChannel(batch.Timestamp)
if active.Len() > int(maxRLPBytesPerChannel) {
    return fmt.Errorf("could not take %d bytes as replacement of channel of %d bytes, max is %d. err: %w",
        active.Len(), co.inactiveRLP().Len(), maxRLPBytesPerChannel, ErrTooManyRLPBytes)
}
```

Compare the `ErrCompressorFull` path in the same function (lines 209-216). It does revert: `co.swapRLP(); co.compress()`.

The batcher's `ChannelBuilder.AddBlock` (`op-batcher/batcher/channel_builder.go:179-182`) treats `ErrTooManyRLPBytes` as "channel full". It does not add the block to the channel's block list and will put it in the next channel. It then closes the channel. `SpanChannelOut.Close()` calls `compress()`, which compresses the **active** buffer. That buffer is the over-limit encoding, and it also contains the block that was supposedly rejected.

On the verifier side, `ChannelInReader` builds a reader with `rlp.NewStream(zr, MaxRLPBytesPerChannel)` (`channel.go:210`). A span channel normally holds one RLP item: the whole span batch. When that item is larger than the stream limit, `Decode` fails with `rlp: value size exceeds available input length`. `ChannelInReader.NextBatch` (`channel_in_reader.go:95-98`) logs "failed to read batch ... skipping to next channel" and drops the channel. So every block in the channel is lost to derivation, not just the last one.

The fix reverts the buffer on this path too:

```diff
 	if active.Len() > int(maxRLPBytesPerChannel) {
+		// if active size exceeds MaxRLPBytesPerChannel we revert the last batch
+		// by switching the RLP buffer and doing a fresh compression
+		co.swapRLP()
+		if err = co.compress(); err != nil {
+			return err
+		}
 		return fmt.Errorf("could not take %d bytes ...", ..., ErrTooManyRLPBytes)
 	}
```

Before PR #10002 the RLP was encoded into a temporary buffer and only committed after the check, so the regression came from that refactor.

### Attack scenario

1. Channels are closed mainly by a *compressed*-size target, usually a few blobs (hundreds of KB). An attacker sends L2 transactions with large all-zero calldata. The per-transaction limit is 128 KB and zero bytes cost 4 gas each. About 100 MB of this compresses to roughly 100 KB, mostly signatures, so the channel stays under its compressed target while its RLP size passes 100 MB. With a 60M gas limit this takes about 7 full blocks. The L1 data fee on these transactions is tiny because the Fjord FastLZ estimate of zeros is small.
2. The batcher's span channel hits `ErrTooManyRLPBytes`, and the batcher closes and posts the over-limit channel.
3. Every verifier and the fault-proof program drop the channel. The safe head stops at the block before the channel.
4. The batcher's sync logic (`sync_actions.go`, "sequencer did not make expected progress") clears its state and reloads the same unsafe blocks. It rebuilds the same channel, which hits the same limit and is dropped again. This repeats while L1 fees are spent on every attempt.
5. If nobody steps in, the safe head stays stuck until the sequencing window runs out (3600 L1 blocks, about 12 h on OP Mainnet). Derivation then fills the gap with deposit-only blocks, and every unsafe block since the stall is reorged out.

## Impact Details

- **Safe/finalized chain halts.** Output proposals cannot move past the stuck block, so withdrawals that need newer outputs are delayed. Anything that waits for safe or finalized data (bridges, exchanges) stalls. The unsafe chain keeps being produced.
- **Possible large unsafe reorg** if the stall outlasts the sequencing window.
- **Wasted L1 fees** on the repeated submissions.

Mitigating factors:
- Operators can recover without a code change. Switching the batcher to singular batches (`--batch-type=0`) works because `SingularChannelOut` checks the limit before committing. Any batcher patch also works. Recovery needs someone to diagnose the stall first, so the halt lasts for hours rather than days, assuming the team responds.
- No funds are stolen or permanently frozen, and the unsafe chain keeps working.
- An attacker must pay for about 100 MB of L2 calldata gas (hundreds of millions of gas) inside one channel window, compete with normal traffic, and repeat this per halt. On low-fee OP chains that costs only a few dollars to tens of dollars. I did not verify the end-to-end attack against a live devnet. The PoC shows the encoder/decoder mismatch deterministically.

The triage entry rated this Low on the view that only the batcher's own output was involved. The batcher's output is shaped by user transactions, however, and the result is a network-wide safe-head halt, so I rate it **Medium**. It stops short of High because the unsafe chain keeps going and operators have a simple configuration workaround.

## Proof of Concept

Executed: **yes**. The test fails on the parent `443e931f24` and passes on the fix `dcce927ab8`.

It fills a span channel with 1 MB zero-calldata transactions until `ErrTooManyRLPBytes`. It then closes the channel as op-batcher does and decodes it with the same RLP limit that derivation uses. The test config has no Fjord, so the limit is 10 MB.

`op-node/rollup/derive/poc_oversize_channel_test.go`:
```go
package derive

import (
	"errors"
	"math/big"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/ethereum-optimism/optimism/op-node/rollup"
)

func TestPoC_SpanChannelOut_OversizedChannelUnreadable(t *testing.T) {
	spec := rollup.NewChainSpec(&rollupCfg) // no Fjord -> 10,000,000 byte RLP limit
	maxRLP := spec.MaxRLPBytesPerChannel(0)

	cout, err := NewSpanChannelOut(1_000_000, Zlib, spec) // compressed target never reached
	require.NoError(t, err)

	rng := rand.New(rand.NewSource(1))
	key, _ := crypto.GenerateKey()
	signer := types.LatestSignerForChainID(rollupCfg.L2ChainID)

	added := 0
	for i := 0; ; i++ {
		tx := types.MustSignNewTx(key, signer, &types.DynamicFeeTx{
			ChainID: rollupCfg.L2ChainID, Nonce: uint64(i), Gas: 5_000_000,
			GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), Data: make([]byte, 1<<20),
		})
		raw, err := tx.MarshalBinary()
		require.NoError(t, err)
		b := RandomSingularBatch(rng, 0, rollupCfg.L2ChainID)
		b.Transactions = append(b.Transactions, raw)
		b.Timestamp = rollupCfg.Genesis.L2Time + 420_000 + rollupCfg.BlockTime*uint64(i)

		err = cout.addSingularBatch(b, uint64(i))
		if errors.Is(err, ErrTooManyRLPBytes) {
			break // op-batcher marks the channel full; this block goes to the next channel
		}
		require.NoError(t, err)
		added++
	}

	require.NoError(t, cout.Close()) // op-batcher closes and submits the channel

	next, err := BatchReader(cout.compressor.GetCompressed(), maxRLP, false)
	require.NoError(t, err)
	bd, err := next()
	require.NoError(t, err, "derivation must be able to decode the span batch the batcher submitted")
	rsb, ok := bd.inner.(*RawSpanBatch)
	require.True(t, ok)
	require.Equal(t, uint64(added), rsb.blockCount)
}
```

Run it (read-only extraction, so the repo is untouched):
```bash
for rev in dcce927ab82ca3977ca1ecc5ad03ea7dd851a57e^ dcce927ab82ca3977ca1ecc5ad03ea7dd851a57e; do
  d=$(mktemp -d); git archive $rev go.mod go.sum op-node op-service op-supervisor op-alt-da op-program op-chain-ops | tar -x -C $d
  cp poc_oversize_channel_test.go $d/op-node/rollup/derive/
  (cd $d && go test ./op-node/rollup/derive/ -run TestPoC_SpanChannelOut -count=1)
done
```

Observed output:
```
# parent
--- FAIL: TestPoC_SpanChannelOut_OversizedChannelUnreadable (2.92s)
    Error: Received unexpected error: rlp: value size exceeds available input length
    Messages: derivation must be able to decode the span batch the batcher submitted
# fix
ok  	github.com/ethereum-optimism/optimism/op-node/rollup/derive	3.155s
```

The fix commit's own regression test, `TestSpanChannelOut_MaxRLPBytesPerChannel` in `channel_out_test.go`, checks the same thing at the buffer level: after the error, the active RLP buffer must be at or below the limit.

## Recommendation

The fix swaps back to the previous RLP buffer and recompresses before returning `ErrTooManyRLPBytes`. This matches the `ErrCompressorFull` path. Further hardening:
- Have the batcher check, before closing and submitting a channel, that `InputBytes()` is no more than `MaxRLPBytesPerChannel` for the inclusion-time fork. That turns the next encoder bug into a hard local error instead of a silent network stall.
- If a single block is over the limit, the batcher can never submit it. Alert on that case explicitly.
- Add a decoder round-trip test (encode with `SpanChannelOut`, decode with `BatchReader`) to the channel-out fuzz tests.

## References

- Fix commit: dcce927ab82ca3977ca1ecc5ad03ea7dd851a57e
- Pull request: https://github.com/ethereum-optimism/optimism/pull/14310
- Regression introduced: a3cc8f275d (https://github.com/ethereum-optimism/optimism/pull/10002)
- Relevant files: `op-node/rollup/derive/span_channel_out.go`, `op-node/rollup/derive/channel.go`, `op-node/rollup/derive/channel_in_reader.go`, `op-batcher/batcher/channel_builder.go`, `op-batcher/batcher/sync_actions.go`
- Spec: https://specs.optimism.io/protocol/derivation.html#channel-format (`MAX_RLP_BYTES_PER_CHANNEL`), https://specs.optimism.io/protocol/fjord/derivation.html
