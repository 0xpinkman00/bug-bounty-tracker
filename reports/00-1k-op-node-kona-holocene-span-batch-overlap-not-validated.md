# op-node / kona Holocene batch stage: a span batch whose overlap disagreed with the safe chain was still applied, splicing a stale or replaced history onto the canonical chain

| Field | Value |
|---|---|
| **Target** | op-node `op-node/rollup/derive/{batch_stage.go,batches.go}`, kona `rust/kona/crates/protocol/derive/src/stages/batch/batch_stream.rs`, `rust/kona/crates/protocol/protocol/src/batch/span.rs`, and `rust/kona/crates/proof/proof/src/l2/chain_provider.rs` (fault-proof L2 provider) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | "A bug in layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk". Here that means derivation applies blocks from a replaced (invalidated) interop lineage. Low because interop is not live, and otherwise it needs a batcher that equivocates |
| **Fix commit(s)** | 3233dd8bde590372e5820ae9f68c5b2c25e8ba51 (PR #22215), 2026-08-19 |
| **Vulnerable since** | Holocene batch stage (`BatchStage` / kona `BatchStream`), which only ran the span-batch *prefix* checks. Fixed in `kona-client/v1.7.0-rc.1` and later. The Karst prestate `kona-client/v1.6.0` does not have it |

## Brief / Intro

A *span batch* describes a run of consecutive L2 blocks. Sometimes a span batch starts *before* the current safe head, meaning some of its blocks are already part of the agreed chain. Before Holocene, nodes checked that those overlapping blocks matched the safe chain exactly, and dropped the batch if they did not. The Holocene batch stage in both op-node and kona only checked the span's *prefix*: its parent, timestamps and L1 origins. It then quietly skipped the overlapping blocks and applied the rest. If the overlap described a *different* history, the rest of that other history was attached to the canonical chain. On today's non-interop chains, only a batcher posting conflicting data can cause this. Under interop it becomes reachable without any misbehaviour: a block containing an invalid cross-chain message is *replaced* by a deposits-only block, and the batcher's already-posted channel still carries the original lineage.

## Vulnerability Details

Before the fix, `op-node/rollup/derive/batch_stage.go:139` (`nextSingularBatchCandidate`) did this:

```go
validity, _ := checkSpanBatchPrefix(ctx, bs.config, bs.Log(), bs.l1Blocks, parent, spanBatch, bs.origin, bs.l2)
switch validity {
case BatchAccept: // continue
...
}
singularBatches, err := spanBatch.GetSingularBatches(bs.l1Blocks, parent)
```

`GetSingularBatches` returns only the elements past the safe head. The elements at or below it are treated as past batches and skipped, and their *contents* are never compared with the safe chain. The overlap content check, which compares tx counts, tx bytes and L1 origin per overlapped height, existed only in the pre-Holocene full `checkSpanBatch` (`batches.go:~409-450`, parent). kona's `BatchStream` (`batch_stream.rs:151`) mirrored this with `check_batch_prefix`.

As a result, with safe chain `… → P → X'` (where `X'` replaced `X`) and a span batch `[X, Y]` whose parent is `P`:

1. The prefix checks pass: the parent is `P`, timestamps line up, and L1 origins are valid.
2. The element at height `X` is at or below the safe head and is skipped. Its difference from `X'` is never looked at.
3. `Y` is derived as the next block on top of `X'`, even though it belongs to the invalidated `X` lineage.

### The fix

Both implementations now run the prefix checks *and* the overlap content checks in Holocene:

```go
// op-node/rollup/derive/batches.go (3233dd8bde)
func checkSpanBatchHolocene(...) BatchValidity {
    prefixValidity, parentBlock := checkSpanBatchPrefix(ctx, cfg, log, l1Blocks, l2SafeHead, batch, l1InclusionBlock, l2Fetcher)
    if prefixValidity != BatchAccept {
        return prefixValidity
    }
    return checkSpanBatchOverlap(ctx, cfg, log, batch, parentBlock, l2SafeHead, l2Fetcher)
}
```

```diff
// batch_stage.go
-		validity, _ := checkSpanBatchPrefix(ctx, bs.config, bs.Log(), bs.l1Blocks, parent, spanBatch, bs.origin, bs.l2)
+		validity := checkSpanBatchHolocene(ctx, bs.config, bs.Log(), bs.l1Blocks, parent, spanBatch, bs.origin, bs.l2)
```

`checkSpanBatchOverlap` is the old overlap loop moved out into its own function, so the pre-Holocene path uses it too. On a mismatch it returns `BatchDrop`, and the Holocene stage flushes the whole channel. kona gets a matching `SpanBatch::check_batch_holocene`. Its fault-proof `OracleL2ChainProvider` gains a by-number header cache so that looking up overlapped payloads stays linear inside the FPVM.

### Attack scenario

**Interop, the case that motivated the fix.**

1. On an interop chain, block `X` contains an executing message that later turns out to be invalid. The supernode / op-node *replaces* `X` with a deposits-only block `X'`, which becomes the safe block.
2. The batcher had already posted a channel with a span batch `[X, Y, Z]` built on the original lineage.
3. Before the fix, derivation skips `X` and applies `Y` and `Z` on top of `X'`. The remainder of the invalidated lineage is spliced onto the canonical chain, with transactions (and possibly more executing messages) that were built on a state that no longer exists. The sequencer's rebuilt unsafe chain then gets reorged away.

**Non-interop.** The kona test `rust/kona/tests/proofs/span_batch_overlap_test.go` reproduces it with batcher equivocation. Channel 2 carries `[2*, 3*]`, an alternative valid lineage, after channel 1 already derived `[1, 2]`. Without the rule, `3*` is spliced onto the canonical `2`, and the canonical block 3 posted later is dropped as a "past batch".

## Impact Details

- **Consequence:** the safe chain contains blocks from a lineage that should have been abandoned. Under interop this weakens the block-replacement guarantee, because parts of an invalidated history come back. That can cause unexpected unsafe reorgs and, in the worst case, re-apply transactions whose cross-chain assumptions no longer hold. op-node and kona behaved *the same way* before the fix, so this was not a split between clients, and the fault proof agreed with the nodes.
- **Preconditions:** interop block replacement (not active on production OP Stack chains when the fix landed), or a batcher that posts conflicting span batches (trusted role).
- **Rollout note:** the fix changes a derivation rule on an already-active fork, in both clients at once. Any mix of fixed and unfixed op-node or kona, for example a node on the new op-node while `kona-client/v1.6.0` is still the respected prestate, would split on exactly this input. The fix is not in `kona-client/v1.6.0` and is in `v1.7.0-rc.1` and later.
- **Severity: Low.** No funds are directly at risk, the scenario needs either a pre-production feature or a privileged role, and op-node and kona were consistent with each other.

## Proof of Concept

The fix added `TestBatchStage_OverlapContent` (`op-node/rollup/derive/overlap_content_test.go`). It builds a safe chain whose head is a deposits-only replacement block and feeds the `BatchStage` a span batch whose overlapping element still carries the replaced transaction:

```go
// The canonical block at height 1 is a deposits-only replacement: no sequencer txs.
replacementBatch := &SingularBatch{ParentHash: parentRef.Hash, Timestamp: 22,
    EpochNum: rollup.Epoch(l1[1].Number), EpochHash: l1[1].Hash}
...
deniedLineageSpan := func() *SpanBatch {
    return initializedSpanBatch([]*SingularBatch{
        b(cfg.L2ChainID, 22, l1[1]), // same height as the replacement, carries the replaced tx
        b(cfg.L2ChainID, 24, l1[1]), // the lineage remainder that must not splice
    }, cfg.Genesis.L2Time, chainId)
}
...
batch, _, err := stage.NextBatch(context.Background(), safeHead)
require.ErrorIs(t, err, NotEnoughData)      // parent: returns the ts=24 singular batch instead
require.Nil(t, batch)
logs.RequireMessageContainedOnce(t, "overlapped block's tx count does not match")
```

To run it against the parent commit, the test file needs no changes, but the log string it asserts ("Dropping invalid span batch, flushing channel (span batch checks)") changed in the fix. Copy the file into `op-node/rollup/derive/` of a `3233dd8bde^` tree, then:

```
go test ./op-node/rollup/derive -run TestBatchStage_OverlapContent -v
```

On `3233dd8bde^`, the subtest `conflicting overlap is dropped` fails: `NextBatch` returns the timestamp-24 singular batch from the denied lineage, not `NotEnoughData`. On `3233dd8bde` it passes. The cross-implementation action test is `rust/kona/tests/proofs/span_batch_overlap_test.go` (`TestSpanBatchOverlapContent`). It drives op-node derivation and then replays the same L1 data in kona-client, and needs the kona prestate/host build.

Executed: no.

## Recommendation

The fix is appropriate. It reinstates the pre-Holocene overlap rule in the Holocene stage for both clients, flushes the channel on a mismatch, and keeps the fault-proof provider efficient. Further suggestions:

- Record the rule change in the specs, under Holocene / interop derivation, so that other implementations adopt it.
- Coordinate the rollout so that op-node, kona-node and the respected kona-client prestate switch to the new rule together, ideally at a fork boundary, because the rule change is itself consensus-affecting.
- In the Holocene stage, `BatchUndecided` now consumes the span batch without retrying it, as the new comments say. Check that a temporary L2 fetch error during overlap validation cannot make an honest node skip a valid batch that another node accepts.

## References

- Fix commit: 3233dd8bde590372e5820ae9f68c5b2c25e8ba51
- Pull request: https://github.com/ethereum-optimism/optimism/pull/22215
- Relevant files: `op-node/rollup/derive/batch_stage.go`, `op-node/rollup/derive/batches.go`, `op-node/rollup/derive/overlap_content_test.go`, `rust/kona/crates/protocol/derive/src/stages/batch/batch_stream.rs`, `rust/kona/crates/protocol/protocol/src/batch/span.rs`, `rust/kona/crates/proof/proof/src/l2/chain_provider.rs`, `rust/kona/tests/proofs/span_batch_overlap_test.go`
- Specs: https://specs.optimism.io/protocol/holocene/derivation.html (span batch prefix checks), interop derivation / block replacement
