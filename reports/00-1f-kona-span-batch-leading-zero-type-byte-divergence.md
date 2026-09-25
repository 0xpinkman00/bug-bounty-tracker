# kona span-batch decoding: a leading `0x00` type byte was stripped, so kona accepted batches that op-node drops (derivation / fault-proof divergence)

| Field | Value |
|---|---|
| **Target** | kona protocol span-batch decoding, `rust/kona/crates/protocol/protocol/src/utils.rs` (`read_tx_data`, moved to `batch/transactions.rs` by the fix). Used by kona-client (fault-proof program) and kona-node |
| **Asset type** | Blockchain/DLT |
| **Severity** | Medium |
| **Impact category** | "Unintended chain split (network partition)", here between the respected fault-proof program (kona-client) and the op-node chain. Downgraded from High because only the chain's authorized batcher can trigger it |
| **Fix commit(s)** | 40191ea14e039c4748f1135a843f1de201547d8e (PR #21808), 2026-07-20 |
| **Vulnerable since** | Present when kona was imported into the monorepo (48a7a09bfc, 2026-02-10) and inherited from the standalone kona repo. It is in the Karst absolute prestate `kona-client/v1.6.0-rc.2` / `v1.6.0` and fixed from `kona-client/v1.7.0-rc.1` (2026-08-21) |

## Brief / Intro

The OP Stack derives its L2 chain from compressed "batches" that the chain's batcher posts to L1. A *span batch* packs many L2 blocks together, and each user transaction inside it is stored as one element: an optional one-byte transaction-type prefix followed by an RLP list. op-node, the reference Go node, treats a leading `0x00` byte as a type prefix and rejects it, because `0x00` is not a valid typed-transaction envelope, so the whole batch is dropped. kona, the Rust implementation, threw the `0x00` away and decoded the rest as a normal legacy transaction, so it *accepted* the batch. Since the Karst upgrade (Sepolia 2026-06-17, Mainnet 2026-07-08), kona-client running in Cannon (`CANNON_KONA`, game type 8) is the respected fault-proof program. For any batch built this way, the on-chain fault proof would have agreed with neither op-node nor the proposer. Only the batcher key can post such a batch.

## Vulnerability Details

`read_tx_data` splits one span-batch transaction element into its type and payload. Before the fix (`rust/kona/crates/protocol/protocol/src/utils.rs:153-196`, at `40191ea14e^`):

```rust
let tx_type_id = if first_byte <= EIP2718_MAX_TX_TYPE {   // 0x00..=0x7F => treat as type byte
    r.advance(1);
    first_byte
} else {
    u8::from(OpTxType::Legacy)
};
...
let tx_type = match OpTxType::try_from(tx_type_id) {
    Ok(OpTxType::Deposit) | Err(_) => return Err(...InvalidTransactionType),
    Ok(ty) => ty,                                        // 0x00 -> OpTxType::Legacy
};

let is_typed_tx = tx_type != OpTxType::Legacy;           // false for a 0x00 prefix
let mut tx_data = Vec::with_capacity(payload_length_with_header + usize::from(is_typed_tx));
if is_typed_tx {
    tx_data.push(u8::from(tx_type));                     // prefix only re-added for non-legacy
}
tx_data.extend_from_slice(&r[..payload_length_with_header]);
```

Walking through it for the element `00 c3 80 80 80`:

1. `0x00 <= 0x7F`, so kona consumes it as a type byte and maps it to `OpTxType::Legacy`.
2. Because the logical type is Legacy, `is_typed_tx` is `false` and the `0x00` is **not** written back.
3. The returned bytes are `c3 80 80 80`, a well-formed prefixless legacy span-batch tx (an RLP list of value, gas price and data). `SpanBatchTransactionData::decode` accepts it and the batch derives.

op-node (`op-node/rollup/derive/span_batch.go:658` `ReadTxData`) keeps the prefix byte. Its typed decoder (`spanBatchTx.UnmarshalBinary`) then returns `types.ErrTxTypeNotSupported` for `0x00`, so the span batch fails to decode and the batch is dropped. The fix commit adds an op-node test (`TestSpanBatchReadTxDataLeadingZero`, `op-node/rollup/derive/span_batch_test.go`) that pins this behaviour on the same vector.

### The fix

The reader now records whether a prefix byte was *physically present*, not whether the logical type is Legacy. It keeps that byte, and leaves the rejection to the typed decoder, as op-node does (`batch/transactions.rs`, `40191ea14e`):

```diff
-    let tx_type_id = if first_byte <= EIP2718_MAX_TX_TYPE {
+    let has_type_prefix = first_byte <= EIP2718_MAX_TX_TYPE;
+    let tx_type_id = if has_type_prefix {
         r.advance(1);
         first_byte
@@
-        Ok(OpTxType::Deposit) | Err(_) => { return Err(...InvalidTransactionType) }
+        Err(_) => { return Err(...InvalidTransactionType) }   // Deposit now deferred too
@@
-    let is_typed_tx = tx_type != OpTxType::Legacy;
-    let tx_data_capacity = payload_length_with_header + usize::from(is_typed_tx);
+    let tx_data_capacity = payload_length_with_header + usize::from(has_type_prefix);
     let mut tx_data = Vec::with_capacity(tx_data_capacity);
-    if is_typed_tx {
-        tx_data.push(u8::from(tx_type));
+    if has_type_prefix {
+        tx_data.push(first_byte);
     }
```

`00 c3 80 80 80` now reaches `SpanBatchTransactionData::decode` with its `0x00` intact and is rejected, so kona drops the batch just as op-node does. The Deposit (`0x7E`) case already ended in a drop, so moving its rejection to the typed decoder does not change the result.

### Attack scenario

1. The batcher (malicious, compromised, or buggy) posts a span batch in which at least one user-transaction element is a valid legacy element with a `0x00` byte in front, e.g. `00 c3 80 80 80`. The rest of the batch is valid: the legacy tx is signed, the protected bits are consistent, and so on.
2. op-node fails to decode the span batch and drops it, so the op-node / op-reth network derives a different safe chain. Either the blocks come from a later valid batch, or deposit-only blocks are produced once the sequencing window expires.
3. kona-client derives the span batch's blocks. For those L2 heights, the respected fault-proof program (Cannon + kona, game type 8) computes different output roots from what op-node reports. The honest proposer and honest challengers take their roots from op-node. In a dispute that reaches the single-step stage, the VM running kona decides the outcome, so an honest claim can lose and a claim matching kona's view can win.
4. kona-node, if deployed, follows the kona chain and splits from op-node peers.

## Impact Details

- **What breaks:** consensus between the fault-proof program and the node software that proposers, challengers, bridges and users rely on. After the divergent batch, every later output root differs, because block hashes chain forward. Proposals that match the real chain could be successfully challenged, and their bonds lost. Proposals that match kona's view, which is not the chain users see, could finalize. Withdrawals are then proven against the wrong history until the Guardian intervenes by blacklisting games or changing the respected game type.
- **When it was live:** the vulnerable reader is in `kona-client/v1.6.0-rc.2`, the absolute prestate that Upgrade 19 / Karst shipped (`docs/public-docs/notices/archive/upgrade-19.mdx:196`). The same notice and `docs/public-docs/op-stack/protocol/hardforks/karst.mdx` say Karst made `CANNON_KONA` the respected game type (Sepolia 2026-06-17, Mainnet 2026-07-08). The fix is first in `kona-client/v1.7.0-rc.1` (2026-08-21). So kona was the respected proof program for roughly six weeks on Mainnet (about nine on Sepolia) while the bug was live, and for longer if the prestate was upgraded later. Before Karst, `CANNON_KONA` games existed (Upgrade 18) but were not respected, so only bonds in type-8 games were at risk.
- **Who can trigger it:** only the batcher key that the chain's `SystemConfig` authorizes. Batch data from any other sender is ignored. The OP Stack trust model assumes a compromised batcher can censor or halt the chain, but not corrupt the proof system. This bug breaks that assumption, which is why it is a real finding. Needing a privileged key is the reason it is rated **Medium** and not High.
- **Not affected:** op-node and op-reth nodes. Execution is not affected directly, and no user can trigger the bug.

## Proof of Concept

The fix added this regression test to `rust/kona/crates/protocol/protocol/src/batch/transactions.rs`. On the parent commit, `read_tx_data` lives in `utils.rs` and is re-exported as `kona_protocol::read_tx_data`. Add the test below to the `#[cfg(test)] mod tests` block of `rust/kona/crates/protocol/protocol/src/utils.rs` at `40191ea14e^`:

```rust
#[test]
fn poc_leading_zero_type_byte_is_stripped() {
    use crate::SpanBatchTransactionData;
    use alloc::vec;
    use alloy_rlp::Decodable;
    use op_alloy_consensus::OpTxType;
    // A valid legacy span-batch element (RLP list of value, gas_price, data) with a 0x00
    // EIP-2718 type byte prepended. op-node keeps the 0x00 and rejects the element
    // (TestSpanBatchReadTxDataLeadingZero), so it drops the whole batch.
    let mut data: &[u8] = &[0x00, 0xc3, 0x80, 0x80, 0x80];
    let (tx_data, tx_type) = read_tx_data(&mut data).unwrap();
    assert_eq!(tx_type, OpTxType::Legacy);
    // Fixed behaviour: the prefix is preserved and the typed decoder rejects it.
    assert_eq!(tx_data, vec![0x00, 0xc3, 0x80, 0x80, 0x80]);   // FAILS on parent: got [c3 80 80 80]
    SpanBatchTransactionData::decode(&mut tx_data.as_slice())
        .expect_err("0x00 is not a supported typed span-batch envelope");
}
```

Run it (from `rust/`):

```
cargo test -p kona-protocol --lib poc_leading_zero_type_byte_is_stripped
```

On `40191ea14e^` the first `assert_eq!` fails, because the returned bytes are `[c3, 80, 80, 80]` and would decode as a legacy tx. On `40191ea14e`, the equivalent upstream test `test_read_tx_data_preserves_leading_zero_type_byte` passes (`cargo test -p kona-protocol --lib test_read_tx_data_preserves_leading_zero_type_byte`). To check op-node's side of the same vector:

```
go test ./op-node/rollup/derive -run TestSpanBatchReadTxDataLeadingZero
```

Executed: no. The Rust test needs a full kona workspace build, which was not run for this write-up. The analysis was confirmed by reading both code paths and the regression tests the fix added.

## Recommendation

The fix is correct. It preserves the physical prefix and defers type validation to the same place op-node does, and it adds a shared conformance vector (`00 c3 80 80 80`) to both the Go and the Rust test suites. Further suggestions:

- Keep a differential fuzzer that feeds the same raw channel bytes to op-node's and kona's batch decoders and compares their verdicts. This issue, 00-1g (`is_last`) and 00-1h (brotli) are all byte-level decoder divergences of the kind such a fuzzer finds quickly.
- When a divergence fix reaches the respected fault-proof program, ship a new absolute prestate promptly and record the date it was deployed, so it is clear how long the respected program was exposed.

## References

- Fix commit: 40191ea14e039c4748f1135a843f1de201547d8e
- Pull request: https://github.com/ethereum-optimism/optimism/pull/21808
- Relevant files: `rust/kona/crates/protocol/protocol/src/utils.rs` (pre-fix), `rust/kona/crates/protocol/protocol/src/batch/transactions.rs`, `op-node/rollup/derive/span_batch.go`, `op-node/rollup/derive/span_batch_test.go`
- Karst / respected game type: `docs/public-docs/notices/archive/upgrade-19.mdx`, `docs/public-docs/op-stack/protocol/hardforks/karst.mdx`
- Span batch format spec: https://specs.optimism.io/protocol/delta/span-batches.html
