# kona-derive — CalldataSource ignored EIP-4844 (type-3) batcher transactions — pre-Ecotone derivation divergence from op-node

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/protocol/derive/src/sources/calldata.rs` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Informational |
| **Impact category** | Unintended chain split (network partition). Latent only: it needs the trusted batcher and a pre-Ecotone L2 block range |
| **Fix commit(s)** | `d25685cb6189c10907ec12ba6172ccbeb2cfb8ec` (PR #19355) — 2026-03-11 |
| **Vulnerable since** | Predates kona's import into the monorepo (`48a7a09bfc`, 2026-02-10) |

## Brief / Intro

Before the Ecotone upgrade, an OP Stack chain reads its batch data from the calldata of transactions sent to the batch-inbox address. The protocol spec and op-node accept every standard transaction type for this, including EIP-4844 blob-carrying (type-3) transactions, as long as the sender is the batcher. kona's calldata source quietly skipped type-3 transactions. If the batcher placed batch data in the calldata of a type-3 transaction during the pre-Ecotone period, op-node would derive L2 blocks from it and kona would not. The two clients would then produce different chains.

## Vulnerability Details

Parent `rust/kona/crates/protocol/derive/src/sources/calldata.rs:45-53`:

```rust
let (tx_kind, data) = match tx {
    TxEnvelope::Legacy(tx) => (tx.tx().to(), tx.tx().input()),
    TxEnvelope::Eip2930(tx) => (tx.tx().to(), tx.tx().input()),
    TxEnvelope::Eip1559(tx) => (tx.tx().to(), tx.tx().input()),
    _ => return None,                       // type-3 (and type-4) silently dropped
};
```

op-node reference, `op-node/rollup/derive/data_source.go:100-121` (`isValidBatchTx`), rejects only types above `BlobTxType` (other than deposits). `DataFromEVMTransactions` then returns `tx.Data()` for any valid transaction, type-3 included. The derivation spec (`derivation.md`, "Data sources") also lists type-3 as acceptable.

Fix:

```diff
                     TxEnvelope::Eip1559(tx) => (tx.tx().to(), tx.tx().input()),
+                    TxEnvelope::Eip4844(tx) => (tx.tx().to(), tx.tx().input()),
                     _ => return None,
```

`CalldataSource` is used only while Ecotone is inactive. After Ecotone, `BlobSource` handles type-3 calldata and blobs correctly.

### Attack scenario

1. An L2 chain is pre-Ecotone while its L1 has Dencun active, so type-3 transactions can be included on L1.
2. The batcher key (trusted, or compromised) sends a type-3 transaction to the batch inbox and puts frame data in its calldata.
3. op-node (and op-program) derive the frames. kona-node and the kona FPP ignore them. The safe chains diverge from that L2 block onwards.

## Impact Details

- **Preconditions:** (a) control of the batcher key; honest op-batcher never puts frames in the calldata of a blob transaction. (b) The L2 chain is pre-Ecotone at the time, after L1 Dencun. Every Superchain chain activated Ecotone in March 2024, alongside or just after L1 Dencun, so this window has closed. New chains start with Ecotone active at genesis.
- **What breaks:** a kona-node would follow a different safe chain from op-node, and kona-based fault-proof traces for that range would disagree with op-program. It applies only when replaying historical pre-Ecotone ranges that actually contain such a transaction, and none is known to exist.
- **Severity:** Informational. The underlying class (a derivation divergence, which would be a chain split) is serious. But the bug cannot be reached on any live chain, it needs the trusted batcher, and it concerns a pre-production client.

## Proof of Concept

The fix commit inverted the existing unit test. Before the fix, the test asserted that a type-3 transaction from the batcher to the inbox is ignored. After the fix, it asserts that the transaction's calldata is included:

```rust
#[tokio::test]
async fn test_load_calldata_valid_blob_tx() {
    let batch_inbox_address = address!("0123456789012345678901234567890123456789");
    let mut source = default_test_calldata_source();
    source.batch_inbox_address = batch_inbox_address;
    let tx = test_blob_tx(batch_inbox_address);          // signed type-3 tx to the inbox
    let block_info = BlockInfo::default();
    source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);
    assert!(!source.open);
    assert!(source.load_calldata(&BlockInfo::default(), tx.recover_signer().unwrap()).await.is_ok());
    assert!(!source.calldata.is_empty());                // parent: calldata.is_empty() == true
    assert!(source.open);
}
```

Run it (it fails against the parent version of `calldata.rs`):

```bash
cd rust && cargo test -p kona-derive --lib sources::calldata::tests::test_load_calldata_valid_blob_tx
```

For comparison with op-node, `isValidBatchTx` returns true for a `types.BlobTx` from the batcher to the inbox, so `DataFromEVMTransactions` returns its `Data()`.

Executed: no. I verified this by reading the code, to avoid a cold kona build.

## Recommendation

The fix adds the `Eip4844` arm. As defence in depth, replace the `_ => return None` catch-all with an explicit match over every `TxEnvelope` variant (reject `Eip7702` explicitly, as op-node does). A future transaction type would then cause a compile error instead of being silently dropped.

## References

- Fix commit: d25685cb6189c10907ec12ba6172ccbeb2cfb8ec
- Pull request: https://github.com/ethereum-optimism/optimism/pull/19355 (closes #19352)
- Relevant files: `rust/kona/crates/protocol/derive/src/sources/calldata.rs`, `op-node/rollup/derive/data_source.go`, `op-node/rollup/derive/calldata_source.go`
- Spec: https://specs.optimism.io/protocol/derivation.html#data-sources
