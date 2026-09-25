# kona-node engine: an invalid derived payload panics the node, and the first fix wrongly applied the Holocene deposit-only fallback before Holocene

| Field | Value |
|---|---|
| **Target** | kona-node, `crates/node/engine/src/task_queue/tasks/build/task.rs` (now `rust/kona/crates/node/engine/src/task_queue/tasks/seal/task.rs`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | "Causing network processing nodes to crash / shut down" (a) and "Unintended chain split (network partition)" (b), both limited to kona-node and needing a misbehaving authorized batcher |
| **Fix commit(s)** | a365abd51676b3645e738e007793beb3d5daa3b1 (op-rs/kona#1675), 2025-05-08: removes the panic. 8a9723ba8df54f62ca7fdc08eacf159fe6f228f2 (op-rs/kona#1702), 2025-05-09: gates the fallback on Holocene |
| **Vulnerable since** | (a) panic: 390dbbdde5 (op-rs/kona#1258, 2025-03-17) until a365abd516. (b) pre-Holocene deposit-only fallback: 63fdcc30c1 (op-rs/kona#1676, 2025-05-08 18:19 -0400) until 8a9723ba8d (2025-05-09 11:24 -0400), about 17 hours on `main`. No kona-node release tag contains either state. |

## Brief / Intro

A rollup node builds the "safe" L2 chain by turning batches that the sequencer's batcher posted on L1 into block templates ("payload attributes"). It then asks its execution client to build and import each block. A batch can contain a transaction the execution client rejects, for example one with a bad nonce. The OP Stack protocol defines exactly what a node must do in that case, and the rule differs before and after the Holocene hard fork. kona-node, the Rust rollup node that was still in alpha at the time, (a) crashed on this case with `unimplemented!()`. The first fix then (b) applied the post-Holocene rule to every block, including pre-Holocene ones. That would make kona-node produce different pre-Holocene blocks from op-node. Both cases need the chain's authorized batcher to post such a batch, and kona-node was not in production.

## Vulnerability Details

### Protocol rule

The reference implementation is `op-node/rollup/engine/build_invalid.go:33` (`onBuildInvalid`):

- **Deposit-only block invalid**: critical error.
- **Post-Holocene, derived attributes invalid**: replace the block with a *deposit-only* copy and flush the channel.
- **Pre-Holocene, derived attributes invalid**: *drop* the attributes, reset pending-safe to safe, and try the next batch. A deposit-only block appears only if the sequencing window later expires without a valid batch.

### (a) Panic on INVALID (parent of a365abd516)

```rust
// crates/node/engine/src/task_queue/tasks/build/task.rs:238 (a365abd516^)
PayloadStatusEnum::Invalid { validation_error } => {
    if payload_attrs.is_deposits_only() {
        Err(BuildTaskError::DepositOnlyPayloadFailed)
    } else {
        warn!(target: "engine_builder", "Payload import failed: {validation_error}");
        warn!(target: "engine_builder", "Re-attempting payload import with deposits only.");
        unimplemented!("HOLOCENE: Re-attempt payload import with deposits only");
    }
}
```

Any derived attributes that the EL (execution layer, i.e. the execution client) rejected as `INVALID` reached `unimplemented!()`. The engine actor's task panicked and the node stopped advancing its safe/unsafe head. This happened on every restart as soon as derivation reached the same batch.

### (b) Deposit-only fallback applied pre-Holocene (63fdcc30c1 to 8a9723ba8d^)

a365abd516 replaced the panic with `HoloceneInvalidFlush`. 63fdcc30c1 then added the deposit-only re-import, but with no fork gate:

```rust
// build/task.rs (8a9723ba8d^)
} else {
    warn!(target: "engine_builder", "Re-attempting payload import with deposits only.");
    // HOLOCENE: Re-attempt payload import with deposits only
    match Self::new(self.engine.clone(), self.cfg.clone(),
                    self.attributes.as_deposits_only(), self.is_attributes_derived)
        .execute(state).await
    { Ok(_) => info!(...), Err(_) => return Err(BuildTaskError::DepositOnlyPayloadReattemptFailed) }
    Err(BuildTaskError::HoloceneInvalidFlush)
}
```

For a pre-Holocene block, kona-node therefore *imported a deposit-only block as safe* at that height. op-node would instead discard the attributes and use the next valid batch for that height, for example a corrected resubmission within the sequencing window. The two nodes end up with different block hashes at that height and a different chain from there on.

### Fix (8a9723ba8d)

```rust
-                } else {
+                } else if cfg
+                    .is_holocene_active(payload_attrs.attributes.payload_attributes.timestamp)
+                {
                     ... deposit-only re-attempt + HoloceneInvalidFlush ...
+                } else {
+                    error!(target: "engine_builder", "Payload import failed: {validation_error}");
+                    Err(BuildTaskError::NewPayloadFailed(RpcError::local_usage_str(&validation_error)))
                 }
```

Residual note: `NewPayloadFailed` maps to `EngineTaskError::Temporary`, and `EngineTask::execute` (`tasks/task.rs:80`) retries `Temporary` errors in an endless loop. So after the fix, a pre-Holocene invalid payload no longer diverges, but kona-node spins on it (a liveness stall) instead of dropping the attributes as op-node does. The current code (`rust/kona/crates/node/engine/src/task_queue/tasks/seal/task.rs:170-205`) keeps the Holocene gate. Also note that op-node gates on `DerivedFrom.Time` (the L1 origin time), while kona gates on the L2 payload timestamp. These agree except within one L1 block of the activation boundary.

### Attack scenario

1. On a chain where Holocene is not yet active (or while syncing pre-Holocene history), the authorized batcher posts a batch containing a transaction with an invalid nonce. This happens through a sequencer or batcher bug, or on purpose.
2. op-node verifiers drop those attributes and derive that height from the next valid batch.
3. kona-node (a) panics and halts before a365abd516, or (b) imports a deposit-only block at that height between 63fdcc30c1 and 8a9723ba8d, which splits it from op-node.

## Impact Details

- **Who can trigger it**: only the chain's batcher key. Batch data is authenticated against the `SystemConfig` batcher address. An arbitrary user cannot put an invalid transaction into derived attributes.
- **Scope**: only kona-node, which was alpha/pre-production. No kona-node release tag contains the vulnerable code. All OP Mainnet-family chains activated Holocene in January 2025, so (b) only mattered for pre-Holocene devnets/testnets or for replaying historical pre-Holocene batches that contain invalid payloads.
- **Duration**: (a) about 7 weeks on `main`. (b) about 17 hours on `main`.
- Given the trusted trigger, the pre-production component and the tiny window for (b), the rating is **Low**.

## Proof of Concept

The op-node reference behaviour is covered by `op-e2e/actions/sync/sync_test.go::TestInvalidPayloadInSpanBatch` (pre-Holocene, Delta active). That test puts an invalid transaction into A8 of a span batch. It asserts that the verifier stops at A7 with safe head 0 and then derives A8 from a later corrected batch. The same scenario reproduces the kona-node bugs:

```
# 1. Reference: op-node behaviour (drop attributes, recover via next batch)
cd /home/trevor/workspace/audits/optimism
go test ./op-e2e/actions/sync -run TestInvalidPayloadInSpanBatch -v

# 2. kona-node at 63fdcc30c1 (or earlier than a365abd516 for the panic):
#    Run kona-node as a verifier on a devnet whose rollup config has holocene_time unset
#    (pre-Holocene), paired with op-reth. Post the same span batch as the Go test
#    (A1..A12 with A8 = [L1Info deposit, RandomTx with bad nonce]).
#    Expected (vulnerable):
#      - < a365abd516 : log "Re-attempting payload import with deposits only." followed by
#                       panic "not implemented: HOLOCENE: Re-attempt payload import with deposits only"
#      - 63fdcc30c1   : log "Successfully imported deposits-only payload"; kona safe block #8
#                       hash != op-node safe block #8 hash after the corrected batch is posted.
#    Expected (fixed, 8a9723ba8d): no deposit-only import pre-Holocene; block #8 matches op-node
#    once the corrected batch arrives (though see the Temporary-retry residual note above).
```

A self-contained Rust unit test is not practical at these commits. `BuildTask` holds a concrete HTTP `EngineClient`, and the crate had no mock engine at that point.

Executed: no.

## Recommendation

The fixes remove the panic and gate the deposit-only fallback on Holocene, in line with the spec. Two follow-ups are recommended. First, in the pre-Holocene case, return a result that makes derivation *drop* the attributes (op-node's `InvalidPayloadAttributesEvent`) instead of a `Temporary` error that retries forever. Second, gate on the L1 origin (`DerivedFrom`) time as op-node does, so the two agree exactly at the activation boundary. More generally, avoid `unimplemented!()`/`panic!` on paths reachable from L1 data.

## References

- Fix commits: a365abd51676b3645e738e007793beb3d5daa3b1, 8a9723ba8df54f62ca7fdc08eacf159fe6f228f2
- Regression-introducing commit for (b): 63fdcc30c17687165eb576ba6cb93c8beabb5fee
- Pull requests: https://github.com/op-rs/kona/pull/1675, https://github.com/op-rs/kona/pull/1676, https://github.com/op-rs/kona/pull/1702
- Relevant files: `crates/node/engine/src/task_queue/tasks/build/task.rs`, `build/error.rs`, `tasks/task.rs`, `crates/node/service/src/actors/derivation.rs`, `op-node/rollup/engine/build_invalid.go`
- Spec: https://specs.optimism.io/protocol/holocene/derivation.html (invalid payload handling)
