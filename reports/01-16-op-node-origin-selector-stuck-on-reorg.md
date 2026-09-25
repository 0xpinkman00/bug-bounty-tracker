# op-node sequencer — L1 origin selector gets stuck on a reorged-out L1 origin — sequencer keeps building on a dead L1 fork

| Field | Value |
|---|---|
| **Target** | `op-node/rollup/sequencing/origin_selector.go` (`L1OriginSelector.maybeSetNextOrigin`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | Temporary sequencer liveness degradation: unsafe blocks are built on a non-canonical L1 origin and later reorged out. There is no exact Immunefi match; the closest is the Low class for node-level disruption that does not shut down the network |
| **Fix commit(s)** | `13162127a81f1abf5b9227f58b90c357878e6d53` (PR #18233) — 2025-12-03 |
| **Vulnerable since** | `445a3d40ec` (2024-10-01, "Origin Selector asynchronously prefetches the next origin from events", PR #12134) |

## Brief / Intro

Every L2 block the sequencer builds names an L1 block as its "L1 origin". The origin selector decides which L1 block to use next. It caches the current origin and prefetches the next one. The prefetched block was accepted only if its parent hash equalled the cached current origin's hash. If an L1 reorg replaced the current origin, no later L1 block could ever pass that check. The selector then kept handing the sequencer the dead origin, and the sequencer kept producing blocks on an L1 fork that no longer exists. Those blocks can never become safe and must be reorged out. The sequencer recovers only when something else resets it, or when the sequencer-drift limit (30 minutes after Fjord) forces a fresh lookup. A natural L1 reorg is enough to trigger this. No attacker is needed.

## Vulnerability Details

Parent `op-node/rollup/sequencing/origin_selector.go:169-177`:

```go
func (los *L1OriginSelector) maybeSetNextOrigin(nextOrigin eth.L1BlockRef) {
    los.mu.Lock()
    defer los.mu.Unlock()

    // Set the next origin if it is the immediate child of the current origin.
    if nextOrigin.ParentHash == los.currentOrigin.Hash {
        los.nextOrigin = nextOrigin
    }
}
```

What happens step by step:
1. The L2 unsafe head's origin is `b` (L1 #11). `currentOrigin = b`.
2. L1 reorgs: `b` becomes `b2`, and the canonical #12 (`c`) has `ParentHash = b2`.
3. On every forkchoice update, `tryFetchNextOrigin` fetches #12 = `c`. `maybeSetNextOrigin(c)` rejects it (`c.ParentHash != b.Hash`), so `nextOrigin` stays empty.
4. `CurrentAndNextOrigin` hits the "L2 head is still on the current origin" branch, because `l2Head.L1Origin == currentOrigin.ID()`, and never re-fetches `b`.
5. `FindL1Origin` returns `currentOrigin = b` while `l2Head.Time + BlockTime - b.Time <= MaxSequencerDrift`. `PreparePayloadAttributes` checks origin/parent consistency only when the origin number changes, so every new block on epoch `b` passes.

Nothing in the selector notices the reorg. Recovery depends on either (a) the derivation pipeline detecting the reorg and emitting `rollup.ResetEvent`, which calls `ResetOrigins()` and makes the engine reset rewind the unsafe head, or (b) the drift limit being exceeded. In case (b), `FindL1Origin` fetches #12 directly, returns `c`, and `PreparePayloadAttributes` fails the parent-hash check with a reset error.

Fix:

```diff
-	// Set the next origin if it is the immediate child of the current origin.
-	if nextOrigin.ParentHash == los.currentOrigin.Hash {
+	// Set the next origin if it is the subsequent block by number.
+	// On reorgs, this might not be the immediate child of the current origin
+	// since the hash is not checked.
+	if nextOrigin.Number == los.currentOrigin.Number+1 {
 		los.nextOrigin = nextOrigin
 	}
```

`c` is now cached as the next origin and returned as soon as the L2 time allows. The attributes builder's parent-hash check then fails, and the sequencer resets. A follow-up refactor, `f0fcc8d5f0` (#18589, 2025-12-18), makes the selector detect this directly: it returns `ErrNextL1OriginOrphaned` when `nextL1Origin.ParentHash != currentL1Origin.Hash`, and the sequencer emits a `ResetEvent` immediately.

### Attack scenario

1. No attacker is needed. An L1 reorg removes the block the sequencer is currently using as its L1 origin. With the default `sequencer.l1-confs = 4`, that means a reorg at least 4 blocks deep, or a shallower one on chains configured with lower confirmation depth.
2. The sequencer's derivation pipeline has not yet traversed past that L1 block (for example, it is catching up after a restart or stalled on L1/beacon data), so it emits no reset.
3. The sequencer keeps producing unsafe L2 blocks with L1 origin `b` for up to `MaxSequencerDrift` (1800 s after Fjord).
4. Those blocks are gossiped and served over RPC as the unsafe chain. When they are batched, derivation drops them (epoch hash mismatch), so every one of them is reorged out. Users who saw their transactions in unsafe blocks see them disappear. They may be re-included from the mempool.

## Impact Details

- **Who is affected:** the sequencer of any OP Stack chain running op-node from `445a3d40ec` (Oct 2024) up to the fix (Dec 2025). Verifier nodes do not run the origin selector.
- **What breaks:** the unsafe chain can grow by up to about 30 minutes of blocks that are guaranteed to be discarded. Apps and bridges that act on unsafe confirmations see a deep unsafe reorg. The safe and finalized chains are unaffected, and no funds are at direct risk.
- **Limiting factors:** it needs an L1 reorg deeper than the sequencer confirmation depth (rare on post-Merge Ethereum) *and* the derivation pipeline must not reset first. In the common case, the pipeline is idle at the L1 tip, sees the reorg within one L1 block, and emits a `ResetEvent` that clears the selector. In the worst case, it resolves by itself after the drift window.
- **Severity:** Low. This is a production component and the trigger is natural. But the effect is limited to the unsafe chain, it is bounded in time, and it needs an uncommon L1 event combined with lagging derivation.

## Proof of Concept

The fix added `TestOriginSelectorHandlesReorg`. The standalone test below works on both the fix commit and the current `develop` code. On `develop`, the selector returns `ErrNextL1OriginOrphaned`; on the fix commit it returns `c`. It fails when the fix is reverted, because the selector keeps returning `b`. Save it as `op-node/rollup/sequencing/origin_selector_poc_test.go`:

```go
package sequencing

import (
	"context"
	"testing"

	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-node/rollup/engine"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
	"github.com/ethereum-optimism/optimism/op-service/testutils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/stretchr/testify/require"
)

func TestPoC_OriginSelectorStuckOnReorgedOrigin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &rollup.Config{MaxSequencerDrift: 500, BlockTime: 2}
	l1 := &testutils.MockL1Source{}
	a := eth.L1BlockRef{Hash: common.Hash{'a'}, Number: 10, Time: 20}
	b := eth.L1BlockRef{Hash: common.Hash{'b'}, Number: 11, Time: 22, ParentHash: a.Hash}
	l1.ExpectL1BlockRefByNumber(b.Number, b, nil)

	s := NewL1OriginSelector(ctx, testlog.Logger(t, log.LevelDebug), cfg, l1)
	s.currentOrigin = a

	l2Head := eth.L2BlockRef{L1Origin: a.ID(), Time: 24}
	require.True(t, s.OnEvent(ctx, engine.ForkchoiceUpdateEvent{UnsafeL2Head: l2Head}))
	next, err := s.FindL1Origin(ctx, l2Head)
	require.NoError(t, err)
	require.Equal(t, b, next) // L2 head moves onto origin b

	// L1 reorg: b is replaced by b2; the canonical block 12 (c) builds on b2.
	c := eth.L1BlockRef{Hash: common.Hash{'c'}, Number: 12, Time: 24, ParentHash: common.Hash{'b', '2'}}
	l1.ExpectL1BlockRefByNumber(c.Number, c, nil)
	l2Head = eth.L2BlockRef{L1Origin: b.ID(), Time: 26}
	require.True(t, s.OnEvent(ctx, engine.ForkchoiceUpdateEvent{UnsafeL2Head: l2Head}))

	for i := 0; i < 50; i++ {
		next, err = s.FindL1Origin(ctx, l2Head)
		if err != nil || next != b {
			return // fixed: reorg surfaced (returns c, or ErrNextL1OriginOrphaned on develop)
		}
		l2Head.Time += cfg.BlockTime
	}
	t.Fatalf("selector stuck: kept returning reorged-out origin %s for 50 consecutive L2 blocks", b)
}
```

I ran it read-only with `go test -overlay`. The "vuln" overlay also replaces `origin_selector.go` with a copy whose line 149 is reverted to `if nextOrigin.ParentHash == los.currentOrigin.Hash {`:

```bash
go test -overlay overlay16_fixed.json ./op-node/rollup/sequencing/ -run TestPoC_ -count=1 -v
# --- PASS: TestPoC_OriginSelectorStuckOnReorgedOrigin

go test -overlay overlay16_vuln.json  ./op-node/rollup/sequencing/ -run TestPoC_ -count=1 -v
# origin_selector_poc_test.go:52: selector stuck: kept returning reorged-out origin 0x6200…:11 for 50 consecutive L2 blocks
# --- FAIL: TestPoC_OriginSelectorStuckOnReorgedOrigin
```

Executed: yes. I ran it on the current `develop` tree, with the fix intact and with it reverted through an overlay.

## Recommendation

The fix caches the next origin by number, so the existing parent-hash check in the attributes builder can detect the reorg. The follow-up in `f0fcc8d5f0` is the better long-term design: the selector checks `nextL1Origin.ParentHash != currentL1Origin.Hash` itself and returns a sentinel error, and the sequencer turns that into an immediate `ResetEvent`. As further defence in depth, the selector could periodically re-validate `currentOrigin` by number (canonical check) instead of relying on the derivation pipeline to notice reorgs.

## References

- Fix commit: 13162127a81f1abf5b9227f58b90c357878e6d53
- Pull request: https://github.com/ethereum-optimism/optimism/pull/18233
- Follow-up: f0fcc8d5f0 (PR #18589, "l1 origin selection improvements")
- Introduced by: 445a3d40ec (PR #12134)
- Relevant files: `op-node/rollup/sequencing/origin_selector.go`, `op-node/rollup/sequencing/origin_selector_test.go`, `op-node/rollup/sequencing/sequencer.go`, `op-node/rollup/derive/attributes.go`
