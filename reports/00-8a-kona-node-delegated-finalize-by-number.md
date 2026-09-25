# kona-node (delegated derivation): upstream finalized hash dropped, so the engine irreversibly finalizes whatever block it has at that height

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/node/engine/src/task_queue/tasks/finalize/task.rs`, `rust/kona/crates/node/service/src/actors/derivation/delegated/actor.rs` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | "Shutdown of less than 10% of network processing nodes" (the affected node finalizes a non-canonical block and needs a manual resync) |
| **Fix commit(s)** | 474bde76868db67cc76665e9cce96c4732f85fb1 (PR #20877), 2026-05-22 |
| **Vulnerable since** | Introduction of delegated derivation in kona-node. The by-number `FinalizeTask` predates the monorepo import (48a7a09bfc, 2026-02-10) |

## Brief / Intro

kona-node is the Rust OP Stack consensus client. In *delegated derivation* mode, it does not derive the chain itself. It polls an upstream node, such as op-node or op-supernode, for the safe and finalized L2 heads and passes them to its local execution client (EL). "Finalized" is permanent: once the EL marks a block final, it will not reorg it away. The upstream reports the finalized head as `(number, hash)`. kona kept only the number and told the engine to finalize "whatever block you have at height N". If the local EL's block at N differs from the upstream's, for example after an upstream reorg that kona has not caught up with, kona finalizes the wrong block. The node is then stuck on a branch the rest of the network has abandoned.

## Vulnerability Details

`rust/kona/crates/node/service/src/actors/derivation/delegated/actor.rs:175-178` (parent `474bde7686^`)
```rust
self.engine_client
    .send_finalized_l2_block(sync_status.finalized_l2.block_info.number)   // hash discarded
    .await
```

`rust/kona/crates/node/engine/src/task_queue/tasks/finalize/task.rs:31-47` (parent)
```rust
async fn execute(&self, state: &mut EngineState) -> Result<(), FinalizeTaskError> {
    // Sanity check that the block that is being finalized is at least safe.
    if state.sync_state.safe_head().block_info.number < self.block_number {
        return Err(FinalizeTaskError::BlockNotSafe);
    }
    let block = self.client
        .get_l2_block(self.block_number.into())       // lookup BY NUMBER
        .full().await ...
        .ok_or(FinalizeTaskError::BlockNotFound(self.block_number))?
        .into_consensus();
    let block_info = L2BlockInfo::from_block_and_genesis(&block, ...)?;
    // ... forkchoiceUpdated(finalized = block_info.hash)
```
The only guard compares heights. When the engine's canonical block at `N` has hash `H_a` and the upstream finalized `(N, H_b)`, the task finalizes `H_a`.

Fix: a `FinalizeBlockId` enum makes each caller choose. The delegated path passes `ByHash`, and the task looks the block up by hash and checks its height:
```rust
let lookup: BlockId = match self.block_id {
    FinalizeBlockId::ByHash(id) => id.hash.into(),
    FinalizeBlockId::ByNumber(n) => n.into(),
};
let block = self.client.get_l2_block(lookup).full().await?
    .ok_or(FinalizeTaskError::BlockNotFound(block_number))?.into_consensus();
...
if let FinalizeBlockId::ByHash(id) = self.block_id && block_info.block_info.number != id.number {
    return Err(FinalizeTaskError::BlockNotFound(id.number));
}
```
The local L1-finality path (`L2Finalizer`) keeps `ByNumber`. There, the node's own derivation pipeline is the only source of truth for the block at that height.

### Attack scenario

No attacker controls this directly. It is a race or consistency fault:

1. kona-node runs in delegated mode behind upstream `U`.
2. `U` reorgs its safe chain at height `N` (an L1 reorg, or interop block replacement) and then advances finality to `(N, H_b)`. kona has already applied the old block `H_a` at `N` as safe and has not yet consolidated the replacement.
3. kona polls `U`, receives `finalized = (N, H_b)`, and enqueues `FinalizeTask(N)`. The engine's block at `N` is `H_a`, and `safe_head.number >= N`, so the task finalizes `H_a`.
4. The EL now treats `H_a` as final. When kona later tries to follow `U` onto `H_b`, it has to reorg below finality, which the EL refuses. The node stays stuck on a non-canonical chain and serves wrong data to its RPC users until an operator wipes and resyncs it.

## Impact Details

- **Affected:** individual kona-node instances in delegated-derivation mode, and anything reading them (RPC users, and a sequencer if one is built on it).
- **Consequence:** a permanent local fork below "finalized", needing manual recovery. Other nodes and the protocol are unaffected.
- **Mitigating factors:**
  - Delegated mode trusts the upstream, and the trigger needs an upstream reorg to line up with the poll timing.
  - kona-node was pre-production during this window.
  - No attacker can force it.
- **Severity:** **Low**.

## Proof of Concept

The fix added `finalize_task_by_hash_errors_when_engine_lacks_hash` (`rust/kona/crates/node/engine/src/task_queue/tasks/finalize/task_test.rs`). It registers block `H_a` at number `N` with a mock engine, sets the safe head to `(N, H_a)`, and asks the task to finalize `(N, H_b)`:

```rust
let engine_client = test_engine_client_builder()
    .with_config(cfg.clone())
    .with_l2_block(BlockId::Number(N.into()), block /* hash = hash_a */)
    .build();
...
let task = FinalizeTask::new(Arc::new(engine_client), cfg,
    FinalizeBlockId::ByHash(BlockNumHash { number: N, hash: hash_b }));
let result = task.execute(&mut state).await;
assert!(matches!(result, Err(FinalizeTaskError::BlockNotFound(n)) if n == N));
```

On the parent, the equivalent is `FinalizeTask::new(client, cfg, N)`. The block-number field is all the task receives, so it resolves `H_a` by number and goes on to the forkchoice update with `finalized = H_a` instead of returning `BlockNotFound`. The task's own doc-comment records this as the "Phase 1 baseline".

Run:
```bash
cd rust
cargo test -p kona-engine finalize_task_by_hash_errors_when_engine_lacks_hash
```
To see the bug on the parent, construct the task by number (`FinalizeTask::new(client, cfg, N)`) in a scratch clone of `474bde7686^`. The mock returns `H_a` and the task does not error.

Executed: no. The kona workspace build was not run for this review.

## Recommendation

The fix is correct. Further hardening:

- Also check `hash_b` against the engine's current safe chain before finalizing. If the block at `N` on the local safe chain is not `hash_b`, request a reset or re-consolidation from upstream rather than just failing the task, which will otherwise retry forever.
- Audit the other delegated-mode messages (safe, unsafe) for the same "number only" pattern.

## References

- Fix commit: 474bde76868db67cc76665e9cce96c4732f85fb1
- Pull request: https://github.com/ethereum-optimism/optimism/pull/20877
- Relevant files: `rust/kona/crates/node/engine/src/task_queue/tasks/finalize/{id.rs,task.rs,task_test.rs}`, `rust/kona/crates/node/service/src/actors/derivation/{actor.rs,delegated/actor.rs,engine_client.rs}`, `rust/kona/crates/node/service/src/actors/engine/{actor.rs,engine_request_processor.rs,request.rs}`
