# op-reth: the payload builder attached a withdrawals list to pre-Canyon (pre-Shanghai) blocks, making the body inconsistent with the header and giving the node an unimportable payload

| Field | Value |
|---|---|
| **Target** | op-reth: `payload/src/builder.rs` (`OpBuilder::build`). Today this lives at `rust/op-reth/crates/payload` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Informational (bordering on Low) |
| **Impact category** | Closest category: "Causing network processing nodes to ... shut down" (liveness of a single node). There is no chain split and no attacker trigger |
| **Fix commit(s)** | `0bac1cc58c7fd8f3707f6bcf88fee3a6d4ba2682` (paradigmxyz/reth#12832), 2024-11-24 |
| **Vulnerable since** | Unknown. The body always used `Some(attributes.withdrawals)` in the OP builder before this change |

## Brief / Intro

"Withdrawals" are a block-body field added in Ethereum's Shanghai upgrade (Canyon on the OP Stack). OP chains always leave the list empty. Before Canyon, a block must have *no* withdrawals field at all: `null`, not an empty list. op-reth's block builder always attached a withdrawals list to the block body, even for pre-Canyon blocks. It did correctly leave the matching header field empty. The block hash, which is computed from the header, was therefore still right. But the payload op-reth handed back to op-node described a block that op-reth's own `engine_newPayload` validation (and op-node's hash check) considers malformed. A node building pre-Canyon blocks this way cannot make progress. That case only occurs when a chain has not activated Canyon, or when an old chain is re-derived from genesis through L1 derivation.

**Triage correction:** the triage note said this produced "a withdrawals root in the header and a different block hash from op-geth". That is not what the parent-commit code does. The header's `withdrawals_root` came from `commit_withdrawals`, which returns `None` before Shanghai. Only the *body* was wrong.

## Vulnerability Details

`0bac1cc5^:payload/src/builder.rs:341-420`:
```rust
let ExecutedPayload { info, withdrawals_root } = match self.execute(&mut state, &ctx)? { ... };
// withdrawals_root == None before Shanghai (from commit_withdrawals)
...
let header = Header {
    ...
    withdrawals_root,                 // None pre-Canyon: correct
    ...
};
let block = Block {
    header,
    body: BlockBody {
        transactions: info.executed_transactions,
        ommers: vec![],
        withdrawals: Some(ctx.attributes().payload_attributes.withdrawals.clone()), // always Some
    },
};
```
`OpPayloadBuilderAttributes.payload_attributes.withdrawals` is a plain `Withdrawals` value, which defaults to empty when op-node sends `withdrawals: null`. So pre-Canyon blocks had `body.withdrawals = Some([])` and `header.withdrawals_root = None`.

Consequences for the built payload:
- The payload converted for `engine_getPayload` carries `withdrawals: []`, so it is serialized as an `ExecutionPayloadV2`.
- Anyone rebuilding the block from that payload (op-node's `CheckBlockHash`, peers validating gossip, and op-reth's own `newPayload` checks) sees withdrawals present. They compute `withdrawalsRoot = EMPTY_ROOT`, which gives a different block hash from the one op-reth sealed. Or they reject "withdrawals before Shanghai" outright.
- The node therefore cannot insert the block it just built, and derivation stalls at that height.

Fix (`0bac1cc5`):
```rust
-                withdrawals: Some(ctx.attributes().payload_attributes.withdrawals.clone()),
+                withdrawals: ctx.withdrawals().cloned(),
...
+    pub fn withdrawals(&self) -> Option<&Withdrawals> {
+        self.chain_spec
+            .is_shanghai_active_at_timestamp(self.attributes().timestamp())
+            .then(|| &self.attributes().payload_attributes.withdrawals)
+    }
```

### Attack scenario

There is no attacker-controlled trigger. The bug appears when:
1. an op-reth node is asked to *build* a block whose timestamp is before Canyon/Shanghai (an op-reth sequencer on a chain without Canyon, or an op-reth node syncing OP Mainnet/Base history from Bedrock by L1 derivation instead of EL sync); and
2. the resulting payload is re-validated, which op-node always does when inserting it.
3. The node stalls at that block.

## Impact Details

- **No consensus divergence:** the sealed header, and so the block hash and state root, matched op-geth. The inconsistency is only in the body and the payload encoding, and it is rejected rather than accepted.
- **Liveness only, rare configuration:** in late 2024 every Superchain chain had long passed Canyon, and new chains launch with Canyon at genesis. op-reth's normal sync mode is EL (staged) sync, which imports historical blocks and never builds them. Only an unusual consensus-layer re-derivation of pre-Canyon history, or a devnet without Canyon, would hit this.
- **Severity:** Informational. There is no attacker, no fund impact and no chain split, and the affected configurations were essentially unused. It is recorded because it is a consensus-rule (fork-gating) mistake in block production.

## Proof of Concept

The fix added no test. A minimal check at the builder level: in upstream `paradigmxyz/reth` at the revision before PR #12832, build an OP payload with a chain spec where Shanghai/Canyon is not active, and assert that the body carries no withdrawals.

```rust
// crates/optimism/payload/src/builder.rs, #[cfg(test)]
// Sketch: use the existing OP e2e payload-builder test harness (crates/optimism/node/tests/e2e)
// with a chain spec whose Canyon (and Shanghai) timestamp is in the future.
let payload = node.payload.new_payload(attrs_with_timestamp_before_canyon).await?;
let block = payload.block();
assert!(block.header.withdrawals_root.is_none());      // passes on parent and fix
assert!(block.body.withdrawals.is_none());            // FAILS on parent (Some([])), passes on fix
// Consistency check that op-node / newPayload effectively perform:
let rebuilt = SealedBlock::from(try_into_block(block_to_payload(block.clone()))?);
assert_eq!(rebuilt.hash(), block.hash());            // FAILS on parent
```
Run with `cargo test -p reth-optimism-node --features optimism` after adding the case to the e2e payload tests.

Executed: no (sketch only; the historical crates are not a standalone workspace in this monorepo).

## Recommendation

The fix gates the body's withdrawals on `is_shanghai_active_at_timestamp`, the same condition that governs `withdrawals_root`. More generally, derive the body's optional fork fields and the header's matching roots from a single fork check. A post-seal assertion that `body.withdrawals.is_some() == header.withdrawals_root.is_some()` would catch this whole class.

## References

- Fix commit: `0bac1cc58c7fd8f3707f6bcf88fee3a6d4ba2682`
- Pull request: https://github.com/paradigmxyz/reth/pull/12832
- Relevant files: `payload/src/builder.rs` (now `rust/op-reth/crates/payload/src/builder.rs`)
- Spec: https://github.com/ethereum-optimism/specs/blob/main/specs/protocol/exec-engine.md (Canyon: withdrawals)
