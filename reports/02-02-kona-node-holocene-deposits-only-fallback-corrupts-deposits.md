# kona-node Holocene deposits-only fallback: every transaction became a 1-byte `0x7E` blob, so the replacement block could never be built

| Field | Value |
|---|---|
| **Target** | kona `crates/protocol/protocol/src/attributes.rs` (`OpAttributesWithParent::as_deposits_only`), called by kona-node `crates/node/engine/src/task_queue/tasks/seal/task.rs`. Now under `rust/kona/` in the monorepo |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (would be Medium for a client in production use) |
| **Impact category** | "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network". In practice this is limited to kona-node instances, and the trigger requires an invalid batch from the authorized batcher |
| **Fix commit(s)** | 1210787f39d740b753fbbfb820be10f0bd3d1b02 (op-rs/kona#3077), 2025-11-24 |
| **Vulnerable since** | 63fdcc30c1 "feat(node/service): Re-import Deposits Only Payload" (op-rs/kona#1676), 2025-05-08. About 6.5 months on kona `main` |

## Brief / Intro

A rollup node builds L2 blocks from "payload attributes" that it derives from the batches the batcher posts to L1. After the Holocene upgrade, the protocol has a rule for a derived block that turns out to be invalid, for example because a user transaction in the batch has a bad nonce. The node must throw away the user transactions, rebuild the block with only the L1 *deposit* transactions, and continue. kona-node's helper for this, `as_deposits_only`, did not filter the list. It replaced *every* transaction, deposits included, with a single byte `0x7E`, which is just the deposit type tag with no body. The execution client cannot decode such a transaction. The rebuild therefore always failed, kona-node raised a critical error, and it stopped deriving the safe chain, while op-node nodes continued. Only an invalid batch from the chain's authorized batcher can trigger this. kona-node was not yet a production client.

## Vulnerability Details

The fallback is taken in the seal task when importing the derived payload fails after Holocene:

`crates/node/engine/src/task_queue/tasks/seal/task.rs:148-173` (parent of fix)
```rust
Err(InsertTaskError::UnexpectedPayloadStatus(e))
    if self.cfg.is_holocene_active(self.attributes.inner().payload_attributes.timestamp) =>
{
    warn!(target: "engine", error = ?e, "Re-attempting payload import with deposits only.");
    let deposits_only_attrs = self.attributes.as_deposits_only();
    return match build_and_seal(state, self.engine.clone(), self.cfg.clone(),
                                deposits_only_attrs.clone(), self.is_attributes_derived).await {
        Ok(_) => { ...; Err(SealTaskError::HoloceneInvalidFlush) }
        Err(_) => Err(SealTaskError::DepositOnlyPayloadReattemptFailed),
    }
}
```

The helper it calls:

`crates/protocol/protocol/src/attributes.rs:73-87` (parent of fix)
```rust
pub fn as_deposits_only(&self) -> Self {
    Self {
        inner: OpPayloadAttributes {
            transactions: self.inner.transactions.as_ref().map(|txs| {
                txs.iter()
                    .map(|_| alloy_primitives::Bytes::from(vec![OpTxType::Deposit as u8]))
                    .collect()
            }),
            ..self.inner.clone()
        },
        ...
    }
}
```

Every element, the L1-info deposit and user deposits included, is mapped to `[0x7E]`. The block therefore (1) keeps the *number* of user transactions, (2) loses the L1 attributes deposit that every L2 block must start with, and (3) contains transactions that cannot be decoded. The execution engine rejects the forkchoice/build request. `build_and_seal` then returns an error, which becomes `SealTaskError::DepositOnlyPayloadReattemptFailed`, and that has `EngineTaskErrorSeverity::Critical` (`crates/node/engine/src/task_queue/tasks/seal/error.rs:59`). kona-node's engine stops processing the safe chain.

The reference behaviour (op-node `build_invalid.go` and the Holocene spec) keeps the deposit transactions unchanged and drops everything else.

**Fix.** The helper now clones the attributes and keeps only the transactions whose first byte is the deposit type:

```diff
 pub fn as_deposits_only(&self) -> Self {
+    let mut attributes = self.attributes.clone();
+    attributes
+        .transactions
+        .iter_mut()
+        .for_each(|txs| txs.retain(|tx| tx.first().cloned() == Some(OpTxType::Deposit as u8)));
     Self {
-        inner: OpPayloadAttributes {
-            transactions: self.inner.transactions.as_ref().map(|txs| {
-                txs.iter().map(|_| Bytes::from(vec![OpTxType::Deposit as u8])).collect()
-            }),
-            ..self.inner.clone()
-        },
+        attributes,
         ...
```

The rest of the diff renames the field `inner` to `attributes`, and it adds five unit tests covering mixed, all-deposit, no-deposit and `None` transaction lists.

### Attack scenario

1. After Holocene, the batcher posts a batch with a user transaction that fails in the execution engine, for example one with a wrong nonce or an unpayable fee. This can be malicious or the result of a batcher/sequencer bug.
2. op-node follows the spec. It replaces the block with a deposits-only block and continues.
3. kona-node calls `as_deposits_only` and sends a payload of `0x7E` stubs to its execution client. The build fails and the seal task returns a `Critical` error. kona-node stops advancing its safe head and no longer agrees with the canonical safe chain.

## Impact Details

- Every kona-node on the chain halts derivation at the bad batch, while op-node nodes carry on. Operators relying on kona-node for safe-head data (RPC, bridges, monitoring) see a stuck or divergent safe head until the node is patched.
- The kona fault-proof client (`kona-client`) does not call `as_deposits_only`. Its driver has its own deposits-only path in `crates/proof/driver`. So this bug did not affect proofs.
- **Mitigating factors:** (a) the trigger needs a batch that yields an invalid payload, and only the chain's authorized batcher key can post batch data; (b) kona-node was in alpha/beta and was not the reference or majority rollup node on any major OP Stack chain; (c) nothing is lost. After a patch, the node re-derives correctly.
- **Severity:** Low. The same halt in the production op-node would be Medium, since it needs the privileged batcher.

## Proof of Concept

This test is adapted from the unit tests the fix added (`test_op_attributes_with_parent_as_deposits_only`). On the parent commit, append it to `crates/protocol/protocol/src/attributes.rs`. On the fix commit, rename `d.inner()` to `d.attributes()`.

```rust
#[cfg(test)]
mod poc_deposits_only {
    use super::*;
    use alloc::vec;

    #[test]
    fn poc_as_deposits_only_keeps_deposits_drops_user_txs() {
        let deposit: alloy_primitives::Bytes = vec![OpTxType::Deposit as u8, 0x0, 0x10, 0x20].into();
        let user: alloy_primitives::Bytes = vec![OpTxType::Eip1559 as u8, 0x0, 0x13, 0x23].into();
        let attrs = OpPayloadAttributes {
            transactions: Some(vec![deposit.clone(), user]),
            ..OpPayloadAttributes::default()
        };
        let a = OpAttributesWithParent::new(attrs, L2BlockInfo::default(), None, true);
        let d = a.as_deposits_only();
        // parent: Some([0x7E], [0x7E])  -> fails
        // fix:    Some([deposit])       -> passes
        assert_eq!(d.inner().transactions, Some(vec![deposit]));
    }
}
```

Run it from an extracted copy of the kona tree (the commit belongs to the imported op-rs/kona history, whose root is the kona workspace):

```bash
H=1210787f39d740b753fbbfb820be10f0bd3d1b02
mkdir -p /tmp/poc-0202/parent && git archive $H^ | tar -x -C /tmp/poc-0202/parent
# append the test above to crates/protocol/protocol/src/attributes.rs
cd /tmp/poc-0202/parent && cargo test -p kona-protocol --all-features --lib poc_
```

On the fix commit, the upstream tests are: `cargo test -p kona-protocol --lib test_op_attributes_with_parent_as_deposits`.

**Executed: no.** The kona workspace build did not complete in this session. The result follows directly from the parent code, which maps every element to `[0x7E]`, and from the fix's unit tests.

Expected on the parent: `assertion left == right failed`, with left = `Some([0x7e, 0x7e])` and right = `Some([0x7e001020])`. Expected on the fix: `test result: ok`.

## Recommendation

The fix is correct and matches the Holocene spec and op-node. Further suggestions:

- Add an engine-level test in which an invalid user transaction triggers the Holocene fallback end to end against a real or mock EL. Such a test would have caught this immediately.
- Consider sharing a single deposits-only helper between kona-node and the kona proof driver, so the two paths cannot drift apart.

## References

- Fix commit: 1210787f39d740b753fbbfb820be10f0bd3d1b02 (https://github.com/op-rs/kona/pull/3077)
- Introducing commit: 63fdcc30c1 (https://github.com/op-rs/kona/pull/1676)
- Relevant files: `crates/protocol/protocol/src/attributes.rs`, `crates/node/engine/src/task_queue/tasks/seal/task.rs`, `crates/node/engine/src/task_queue/tasks/seal/error.rs`
- Related report: `03-09-kona-node-invalid-payload-panic-and-pre-holocene-deposit-fallback.md` (earlier bugs in the same fallback path)
- Spec: https://specs.optimism.io/protocol/holocene/derivation.html (deposits-only replacement of invalid payloads)
