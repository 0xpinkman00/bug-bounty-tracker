# op-node Holocene batch stage: overlapping span batch with a too-old L1 origin raises a critical error and halts derivation

| Field | Value |
|---|---|
| **Target** | `op-node/rollup/derive` (`BatchStage`, `SpanBatch.GetSingularBatches`); shared by `op-program` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Medium (High if the batcher key were not a trusted role) |
| **Impact category** | "Network not being able to confirm new transactions (total network shutdown)", downgraded because only the chain's batcher key can trigger it |
| **Fix commit(s)** | 848a9c26215f48fcd68e56ca86b1bdd76beb5518 (PR #18283), 2025-11-21 |
| **Vulnerable since** | 580898584b "op-node/rollup/derive: Implement Holocene Batch Stage" (PR #12417), 2024-10-22. Earliest `op-node/*` release tag containing it: v1.9.5. Live on mainnet from Holocene activation (January 2025) until op-node v1.16.3, about 10 months. |

## Brief / Intro

The op-node rebuilds the L2 chain from batches that the batcher posts to L1. A *span batch* packs many L2 blocks into one compact record. Each block names its *epoch*, i.e. the L1 block it builds on (its "L1 origin"). Since the Holocene upgrade, op-node checks only a *prefix* of a span batch before it expands the batch into single blocks. A span batch that overlaps the current safe head and contains a new block whose L1 origin is *older* than the safe head's origin passes that prefix check. The expansion step then fails, and op-node treated that failure as a *critical* error. A critical error shuts op-node down. On restart it reads the same batch and shuts down again. Every op-node on the chain, including the sequencer's own node, stops advancing the safe head. The fault-proof program `op-program` runs the same code and would crash rather than derive. Only data from the chain's batcher address is read by derivation, so an attacker needs the batcher key, or an honest batcher has to resubmit stale data after an unsafe reorg.

## Vulnerability Details

Before Holocene, `BatchQueue` ran the *full* `checkSpanBatch`. That check compares every overlapped block against the existing safe chain, including its L1 origin number. Span-batch epochs never decrease, so a batch whose overlapped blocks match the safe chain cannot contain a later block with an epoch older than the safe head's. The pre-Holocene path was therefore not reachable in practice.

Holocene's `BatchStage` deliberately skips the overlapped part of a span batch. It runs only `checkSpanBatchPrefix`. That function checks the parent hash, the timestamps, the sequencing window and the *last* block's epoch. It does not check the epochs of the blocks after the safe head. The stage then expands the batch:

`op-node/rollup/derive/batch_stage.go:158-162` (parent of fix)
```go
// If next batch is SpanBatch, convert it to SingularBatches.
singularBatches, err := spanBatch.GetSingularBatches(bs.l1Blocks, parent)
if err != nil {
    return nil, NewCriticalError(err)
}
```

`GetSingularBatches` looks up each new block's epoch in `bs.l1Blocks`. That buffer starts at the safe head's L1 origin (or the one after it), so an older epoch is never found:

`op-node/rollup/derive/span_batch.go:598-609` (parent of fix)
```go
originFound := false
for i := originIdx; i < len(l1Origins); i++ {
    if l1Origins[i].Number == uint64(batch.EpochNum) {
        ...
        originFound = true
        break
    }
}
if !originFound {
    return nil, fmt.Errorf("unable to find L1 origin for the epoch number: %d", batch.EpochNum)
}
```

The critical error goes to `rollup.CriticalErrorEvent`, and `OpNode.onEvent` responds with `n.cancel(...)` (`op-node/node/node.go:759-762`), which shuts down the node. In `op-program`, `CriticalErrorEvent` sets `resultError` (`op-program/client/driver/program.go:104-106`), and the client exits with code 2 (panic).

The Holocene spec says an invalid span batch must be *dropped* and its channel flushed. It must not halt derivation.

**Fix.** `BatchStage` now treats an extraction error as an invalid batch:

```diff
 singularBatches, err := spanBatch.GetSingularBatches(bs.l1Blocks, parent)
+// Errors can happen here because the span batch prefix checks are not exhaustive (unlike the full span batch
+// checks) so an error must be handled like an invalid span batch (DROP).
 if err != nil {
-    return nil, NewCriticalError(err)
+    spanBatch.LogContext(bs.Log()).Warn("Dropping invalid span batch, flushing channel (singular batch extraction)", "error", err)
+    bs.FlushChannel()
+    return nil, NotEnoughData
 }
```

`GetSingularBatches` now returns an explicit error for `batch.EpochNum < l2SafeHead.L1Origin.Number`. The full `checkSpanBatch`, used by the pre-Holocene `BatchQueue`, also gained explicit "block epoch is too old" and "origin not found" `BatchDrop` checks as defense in depth. Previously, when an origin was missing, it went on with a zero-valued `l1Origin`.

### Attack scenario

1. After Holocene, the safe head is L2 block `S` with L1 origin `E`.
2. The batcher posts a span batch built on a canonical block at or below `S`, so the parent hash matches. The batch overlaps `S` and contains a block after `S` whose epoch is `E-1`. Epochs never decrease, so the batch's last epoch can still be `E` or later and pass the prefix check.
3. Every op-node that derives this L1 block hits `GetSingularBatches` → "unable to find L1 origin" → `CriticalErrorEvent` → node shutdown. It crash-loops on restart. The sequencer's op-node also derives, so the chain stops, and `op-program` exits with a panic for any claim that spans this L1 block.

A batcher can also produce this batch by accident. If an old channel built from an unsafe chain that was later reorged is resubmitted, its first blocks can still share the canonical parent while its later blocks carry older L1 origins than the new safe chain.

## Impact Details

- **Liveness:** all op-node instances (verifiers and the sequencer's node) halt at the L1 block that contains the bad batch. The safe head and, through the sequencer's node, the chain stop until a patched binary is deployed. This fits "Network not being able to confirm new transactions (total network shutdown)".
- **Fault proofs:** the on-chain absolute prestate contains the vulnerable `op-program`. Even after nodes are patched and the batch is dropped, any output root derived past that L1 block can only be "proven" by a program that panics. A panic counts as disputing the claim, so honest proposals could not be defended until governance upgraded the prestate. Withdrawals would be delayed until then.
- **Mitigating factors:** derivation reads batch data only from the `SystemConfig` batcher address. That key is operated by the chain operator and is treated as trusted. No funds can be stolen. The halt is recoverable with a software patch and a prestate update.
- **Severity:** a total network halt is High or Critical under Immunefi's Blockchain/DLT classification. It is rated **Medium** here because the trigger needs the privileged batcher key, or an unusual honest-batcher resubmission. The consequence is still severe (full halt plus a fault-proof prestate upgrade) and could follow from a batcher bug, so it is not downgraded to Low.

## Proof of Concept

This test is adapted from the regression test `testBatchStage_OverlappingSpanBatch` that the fix added in `op-node/rollup/derive/batch_queue_test.go`. It is self-contained and uses only helpers that exist at the parent commit. It fails on the parent with a critical error and passes on the fix.

Save it as `op-node/rollup/derive/poc_too_old_epoch_test.go`:

```go
package derive

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/log"
	"github.com/stretchr/testify/require"

	"github.com/ethereum-optimism/optimism/op-core/forks"
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
)

type pocSafeFetcher struct {
	blocks   map[uint64]eth.L2BlockRef
	payloads map[uint64]*eth.ExecutionPayloadEnvelope
}

func (f *pocSafeFetcher) L2BlockRefByNumber(_ context.Context, n uint64) (eth.L2BlockRef, error) {
	r, ok := f.blocks[n]
	if !ok {
		return eth.L2BlockRef{}, errors.New("unknown L2 block")
	}
	return r, nil
}

func (f *pocSafeFetcher) PayloadByNumber(_ context.Context, n uint64) (*eth.ExecutionPayloadEnvelope, error) {
	p, ok := f.payloads[n]
	if !ok {
		return nil, errors.New("unknown payload")
	}
	return p, nil
}

func TestPoC_TooOldSpanBatchEpoch(t *testing.T) {
	lgr := testlog.Logger(t, log.LevelWarn)
	l1 := L1Chain([]uint64{10, 16, 22, 28})
	chainID := big.NewInt(1234)
	cfg := &rollup.Config{
		Genesis:           rollup.Genesis{L2Time: 20},
		BlockTime:         2,
		MaxSequencerDrift: 600,
		SeqWindowSize:     1000,
		L2ChainID:         chainID,
	}
	cfg.ActivateAtGenesis(forks.Delta)

	parentBatch := b(chainID, 20, l1[0])
	parentRef := singularBatchToBlockRef(t, parentBatch, 0)
	parentPayload := singularBatchToPayload(t, parentBatch, 0)
	safeBatch := b(chainID, 22, l1[1])
	safeHead := singularBatchToBlockRef(t, safeBatch, 1) // safe head origin = L1 block 1
	safePayload := singularBatchToPayload(t, safeBatch, 1)
	fetcher := &pocSafeFetcher{
		blocks:   map[uint64]eth.L2BlockRef{0: parentRef, 1: safeHead},
		payloads: map[uint64]*eth.ExecutionPayloadEnvelope{0: &parentPayload, 1: &safePayload},
	}

	// Built on block 0 (parent hash matches) and overlapping the safe head.
	// The block at ts=24 claims L1 origin 0, older than the safe head's origin 1.
	span := initializedSpanBatch([]*SingularBatch{
		b(chainID, 22, l1[0]), // overlapped: Holocene skips it without checking content
		b(chainID, 24, l1[0]), // too-old epoch
		b(chainID, 26, l1[1]),
	}, cfg.Genesis.L2Time, chainID)

	input := &fakeBatchQueueInput{batches: []Batch{span}, errors: []error{nil}, origin: l1[2]}
	stage := NewBatchStage(lgr, cfg, input, fetcher) // post-Holocene batch stage
	_ = stage.Reset(context.Background(), l1[1], eth.SystemConfig{})

	batch, _, err := stage.NextBatch(context.Background(), safeHead)
	require.False(t, errors.Is(err, ErrCritical), "critical error would stop op-node: %v", err)
	require.ErrorIs(t, err, NotEnoughData)
	require.Nil(t, batch)
}
```

Run it without changing the working tree by extracting each tree to a scratch directory:

```bash
H=848a9c26215f48fcd68e56ca86b1bdd76beb5518
for rev in "$H^" "$H"; do
  d=/tmp/poc-0201/$(echo $rev | tr '^' p); mkdir -p $d
  git archive $rev go.mod go.sum op-node op-service op-core op-alt-da op-supervisor op-test-sequencer | tar -x -C $d
  cp poc_too_old_epoch_test.go $d/op-node/rollup/derive/
  (cd $d && go test ./op-node/rollup/derive -run TestPoC_TooOldSpanBatchEpoch -count=1)
done
```

On the fix commit, the upstream regression test also covers this case: `go test ./op-node/rollup/derive -run 'TestBatchStages/BatchStage/SpanBatch/OverlappingSpanBatch'`.

**Executed: yes.** Results:
- Parent (`848a9c2^`): `FAIL ... critical error would stop op-node: crit: unable to find L1 origin for the epoch number: 0`
- Fix (`848a9c2`): `PASS`, logging `Dropping invalid span batch, flushing channel (singular batch extraction) ... error="future batch (ts: 24) L1 origin 0 behind safe head (ts: 22) origin 1"`

## Recommendation

The fix is correct. It matches the Holocene rule that an invalid span batch is dropped and its channel flushed. Adding the explicit epoch checks to `checkSpanBatch` also stops that function from continuing with a zero-valued `l1Origin`. Additional suggestions:

- Audit other `NewCriticalError` sites that can be reached from batcher-supplied data. Only real invariant violations should be critical. Anything that depends on input should map to drop/flush.
- Ensure kona-derive, which implements the same Holocene batch stage, drops such batches the same way. A divergence there would be a client split.
- Add a fuzz or differential test that feeds random overlapping span batches to the Holocene batch stage and asserts it never returns a critical error.

## References

- Fix commit: 848a9c26215f48fcd68e56ca86b1bdd76beb5518
- Pull request: https://github.com/ethereum-optimism/optimism/pull/18283
- Introducing commit: 580898584b (https://github.com/ethereum-optimism/optimism/pull/12417)
- Relevant files: `op-node/rollup/derive/batch_stage.go`, `op-node/rollup/derive/span_batch.go`, `op-node/rollup/derive/batches.go`, `op-node/rollup/derive/batch_queue.go`, `op-node/node/node.go`, `op-program/client/driver/program.go`
- Specs: https://specs.optimism.io/protocol/holocene/derivation.html (span batch prefix checks / batch stage)
