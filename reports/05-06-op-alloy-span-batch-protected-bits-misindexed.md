# op-alloy-protocol span-batch decoding: the EIP-155 "protected bits" were indexed by overall transaction position, so kona-derive rejected valid span batches or rebuilt legacy transactions incorrectly

| Field | Value |
|---|---|
| **Target** | `op-alloy-protocol`: `crates/protocol/src/batch/transactions.rs` (`SpanBatchTransactions::full_txs`), consumed by kona-derive. Today: `rust/kona/crates/protocol/protocol/src/batch/transactions.rs` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (pre-production kona; in a live fault-proof program or node this would be High) |
| **Impact category** | Class: "Unintended chain split (network partition)" / fault-proof divergence from the reference derivation (op-node / op-program). Downgraded because kona-derive did not back a production node or dispute game, and the bug was live for about 2.5 weeks |
| **Fix commit(s)** | `66d8c2f7d3880dfecd7cce36adcc250de508f912` (alloy-rs/op-alloy#235), 2024-11-06; `ed4c0563c19d56be828e68aa0eee4639aab05cbe` (alloy-rs/op-alloy#270), 2024-11-16 |
| **Vulnerable since** | `c1ef4ee4a1` "feat(protocol): Span Batch Transactions" (alloy-rs/op-alloy#196), 2024-10-29, adopted by kona the same day in `9c4d999e2a` "feat(derive): use upstream op-alloy batch types" (op-rs/kona#746). kona's earlier in-tree implementation (`crates/derive/src/batch/span_batch/transactions.rs`) used a separate `protected_bits_idx` and was correct. This was a regression introduced during the migration |

## Brief / Intro

The batcher posts L2 transactions to L1 in a compressed "span batch" format that splits each transaction into columns (nonces, gas limits, signatures, and so on). For old-style "legacy" transactions only, the format stores one extra bit that says whether the transaction is replay-protected under EIP-155, meaning its signature includes the chain ID. There is exactly one such bit per *legacy* transaction, in order. The op-alloy decoder, used by the Rust derivation pipeline kona-derive, looked up that bit using the transaction's position among **all** transactions in the batch. Initially this made kona reject almost every span batch outright. After the first patch, kona silently rebuilt legacy transactions with the wrong signature format whenever a typed transaction (e.g. EIP-1559) came before them. Either way, kona derived different L2 blocks from op-node, and ordinary user traffic triggers it without any attacker.

## Vulnerability Details

The span-batch spec, and op-node's `op-node/rollup/derive/span_batch_txs.go:259-268`, keep a separate counter for legacy transactions:
```go
protectedBitsIdx := 0
...
if txType == types.LegacyTxType {
    protectedBit := btx.protectedBits.Bit(protectedBitsIdx)
    protectedBitsIdx++
```
op-alloy's encoder did the same. It sets bit `legacy_tx_count` (`66d8c2f^:transactions.rs:286-290`), and the bitlist is decoded with length `legacy_tx_count` (`:137-143`).

The decoder did not. `66d8c2f^:crates/protocol/src/batch/transactions.rs:232-273`:
```rust
for idx in 0..self.total_block_tx_count {
    ...
    let is_protected = self
        .protected_bits
        .get_bit(idx as usize)                       // <-- overall tx index, not legacy index
        .ok_or(SpanBatchError::Decoding(SpanDecodingError::InvalidTransactionData))?
        == 1;
    let tx_envelope = tx.to_enveloped_tx(*nonce, *gas, to, chain_id, sig, is_protected)?;
```
`SpanBatchBits::get_bit` (`bits.rs:66-83`) returns `None` only when `index / 8 >= byte_len`.

**Stage 1 (before #235): hard decode failure.** A span batch with no legacy transactions has an empty protected-bits list, so `get_bit(0)` is `None` and the whole batch is rejected with `InvalidTransactionData`. The same happens whenever the overall index passes `8 * ceil(legacy_count / 8)`. In practice kona-derive dropped nearly every real span batch that op-node accepts. Batches small enough to stay in range could also suffer the stage-2 misdecoding described below.

Fix #235 (`66d8c2f`) only removed the error:
```rust
-            let is_protected = self.protected_bits.get_bit(idx as usize)
-                .ok_or(SpanBatchError::Decoding(SpanDecodingError::InvalidTransactionData))? == 1;
+            let is_protected = self.protected_bits.get_bit(idx as usize).unwrap_or_default() == 1;
```

**Stage 2 (between #235 and #270): silent misdecoding.** Batches now decoded, but a legacy transaction at overall index `idx` read the bit belonging to legacy transaction number `idx`, or 0 if that was out of range. For a batch such as `[EIP-1559 tx, EIP-155 legacy tx]`, the legacy transaction reads bit 1 (value 0) instead of bit 0 (value 1). It is rebuilt as *unprotected*: `v = 27/28` and a signing hash without the chain ID. That produces different transaction bytes and hash, and ECDSA recovery gives a *different sender*. The reverse case (a pre-EIP-155 transaction read as protected) is also possible. kona's executor then runs a different transaction list from op-node, so the block hash, state root and output root differ.

Fix #270 (`ed4c056`) uses a dedicated legacy counter, matching op-node:
```rust
+        let mut protected_bit_idx = 0;
 ...
-            let is_protected = self.protected_bits.get_bit(idx as usize).unwrap_or_default() == 1;
+            let is_protected = if tx.tx_type() == TxType::Legacy {
+                protected_bit_idx += 1;
+                self.protected_bits.get_bit(protected_bit_idx - 1).unwrap_or_default() == 1
+            } else {
+                true
+            };
```

### Attack scenario

No special attacker capability is needed. Normal traffic triggers it, and a user can force it deliberately:
1. A user sends an EIP-1559 transaction and then a legacy EIP-155 transaction (e.g. from an old wallet) in the same span-batch range. Any mix of typed transactions before a legacy one is enough.
2. The batcher posts the span batch. op-node decodes it correctly.
3. kona-derive either drops the whole batch (stage 1) or reconstructs the legacy transaction with the wrong `v` and sender (stage 2). kona's derived L2 chain, and the output root it would prove in a fault-proof game, disagree with op-node and op-program.

## Impact Details

- **If kona had been in production:** as a fault-proof program, kona would prove output roots different from the canonical chain for almost any range containing span batches. That could lose honest challengers' bonds or support invalid roots, and fault-proof unsoundness is High/Critical. As a node (kona-node), it would split from op-node on the first affected batch.
- **Actual exposure:** from 2024-10-29 (kona adopts op-alloy's batch types) to 2024-11-16 (#270), kona existed only as a pre-release library and testnet-only Asterisc program. No production game or node relied on it. Stage 1 would also have failed kona's own action tests and fixture replays almost immediately.
- **Severity:** Low as deployed. The underlying class is High.

## Proof of Concept

Add to the `tests` module of `crates/protocol/src/batch/transactions.rs` (the op-alloy tree at `66d8c2f^` / `ed4c056^`; today's equivalent is `rust/kona/crates/protocol/protocol/src/batch/transactions.rs`):

```rust
#[test]
fn poc_typed_only_batch_decodes() {
    // Stage 1: a span batch without legacy txs.
    let sig = Signature::test_signature();
    let to = address!("0123456789012345678901234567890123456789");
    let tx = TxEnvelope::Eip1559(Signed::new_unchecked(
        TxEip1559 { to: TxKind::Call(to), chain_id: 10, ..Default::default() },
        sig,
        Default::default(),
    ));
    let mut buf = vec![];
    tx.encode(&mut buf);
    let mut sbt = SpanBatchTransactions::default();
    sbt.add_txs(vec![Bytes::from(buf)], 10).unwrap();
    // 66d8c2f^: Err(Decoding(InvalidTransactionData)); fixed: Ok
    let out = sbt.full_txs(10).expect("typed-only span batch must decode");
    assert_eq!(out[0], tx.encoded_2718());
}

#[test]
fn poc_legacy_after_typed_keeps_eip155_protection() {
    // Stage 2: [EIP-1559, EIP-155 legacy]
    use alloy_consensus::TxLegacy;
    let sig = Signature::test_signature();
    let to = address!("0123456789012345678901234567890123456789");
    let typed = TxEnvelope::Eip1559(Signed::new_unchecked(
        TxEip1559 { to: TxKind::Call(to), chain_id: 10, ..Default::default() },
        sig,
        Default::default(),
    ));
    let legacy = TxEnvelope::Legacy(Signed::new_unchecked(
        TxLegacy { to: TxKind::Call(to), chain_id: Some(10), ..Default::default() },
        sig,
        Default::default(),
    ));
    let raw = [&typed, &legacy]
        .iter()
        .map(|t| { let mut b = vec![]; t.encode(&mut b); Bytes::from(b) })
        .collect::<Vec<_>>();
    let mut sbt = SpanBatchTransactions::default();
    sbt.add_txs(raw, 10).unwrap();          // sets protected bit #0 (first legacy tx) = 1
    let out = sbt.full_txs(10).unwrap();
    // 66d8c2f..ed4c056^: legacy tx reads bit #1 (=0) -> rebuilt without chain id (v = 27/28)
    //                    -> bytes differ from the original tx -> assertion fails.
    // ed4c056 (fix):     bytes identical.
    assert_eq!(out[1], legacy.encoded_2718());
}
```
Run from the op-alloy workspace root at the relevant revision:
```
cargo test -p op-alloy-protocol poc_
```
Expected: at `66d8c2f^`, both tests fail. The first fails with a decode error. The second fails with wrong bytes: bit 1 of a one-byte list is in range, so it reads 0 instead of erroring. At `66d8c2f`, the first passes and the second still fails. At `ed4c056`, both pass.

Executed: no. The historical op-alloy crate is not a standalone buildable workspace inside this monorepo. The logic was checked against `bits.rs::get_bit`, `add_txs` and `full_txs` at each parent commit.

## Recommendation

The final fix (#270) matches op-node. Further suggestions:
- Add a round-trip property test (`add_txs` then `full_txs` returns identical bytes) over random mixes of legacy (protected and unprotected) and typed transactions. Either stage would have failed it immediately.
- When porting consensus-critical code between repositories (kona to op-alloy here), run the original crate's test vectors against the new implementation. The pre-migration kona code was correct.
- Neither fix added a regression test. Add the two tests above.

## References

- Fix commits: `66d8c2f7d3880dfecd7cce36adcc250de508f912`, `ed4c0563c19d56be828e68aa0eee4639aab05cbe`
- Pull requests: https://github.com/alloy-rs/op-alloy/pull/235, https://github.com/alloy-rs/op-alloy/pull/270
- Introduced by: `c1ef4ee4a1` (https://github.com/alloy-rs/op-alloy/pull/196); adopted by kona in `9c4d999e2a` (https://github.com/op-rs/kona/pull/746)
- Relevant files: `crates/protocol/src/batch/transactions.rs`, `crates/protocol/src/batch/bits.rs`; reference `op-node/rollup/derive/span_batch_txs.go`
- Spec: https://github.com/ethereum-optimism/specs/blob/main/specs/protocol/delta/span-batches.md
