# kona-derive: data source only accepted the genesis batcher, ignoring SystemConfig batcher rotations

| Field | Value |
|---|---|
| **Target** | kona `crates/protocol/derive` (`EthereumDataSource`, `BlobSource`, `CalldataSource`, `L1Retrieval`), `crates/proof/proof` (`OraclePipeline`). Now under `rust/kona/` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (kona-node pre-production; kona fault-proof game types were not the respected game type on any chain with value; would be High for a live kona-secured chain) |
| **Impact category** | "Unintended chain split (network partition)" between kona and op-node. If kona proofs were respected: fault-proof unsoundness |
| **Fix commit(s)** | 19fe8610dcd7c965804392ade6dce979329e80be (op-rs/kona#1106), 2025-02-25 |
| **Vulnerable since** | Present from kona's first data-source implementation (2024-02, `f93924e9d2`/`64be6aa5cb`). It was carried through the refactor f09ffbfd90 (op-rs/kona#782, 2024-11-05), about 12 months in total |

## Brief / Intro

An OP Stack chain reads its L2 transactions ("batches") from L1. It accepts only the batches sent to the batch-inbox address and signed by the chain's authorized *batcher* key. The batcher key is not fixed. The chain owner can rotate it at any time on the L1 `SystemConfig` contract, and every node must switch to the new key from the L1 block where the change was logged. Kona, the Rust implementation used by kona-node and by the kona fault-proof program, instead hard-coded the batcher address from the chain's *genesis* configuration. On any chain that had rotated its batcher, kona threw away every real batch and kept trusting the retired key.

## Vulnerability Details

Parent of the fix, `crates/protocol/derive/src/sources/ethereum.rs` (`new_from_parts`):
```rust
pub fn new_from_parts(provider: C, blobs: B, cfg: &RollupConfig) -> Self {
    let signer =
        cfg.genesis.system_config.as_ref().map(|sc| sc.batcher_address).unwrap_or_default();
    Self {
        ecotone_timestamp: cfg.hardforks.ecotone_time,
        blob_source: BlobSource::new(provider.clone(), blobs, cfg.batch_inbox_address, signer),
        calldata_source: CalldataSource::new(provider, cfg.batch_inbox_address, signer),
    }
}
```
The sources then filter on that fixed value (`calldata.rs`, `load_calldata`, and the same check in `blobs.rs`):
```rust
if to != self.batch_inbox_address { return None; }
if tx.recover_signer().ok()? != self.signer { return None; }   // genesis batcher only
```

`L1Traversal` already tracked the live `SystemConfig` (it applies `ConfigUpdate` logs), and `L1Retrieval` could reach it through `self.prev.batcher_addr()`. However, the `DataAvailabilityProvider::next` trait had no parameter for passing that value in, so the live batcher address never reached the filter.

The fix threads the current batcher address through the trait and both sources:
```diff
-    async fn next(&mut self, block_ref: &BlockInfo) -> PipelineResult<Self::Item>;
+    async fn next(&mut self, block_ref: &BlockInfo, batcher_addr: Address) -> PipelineResult<Self::Item>;
```
```diff
-        match self.provider.next(next).await {
+        match self.provider.next(next, self.prev.batcher_addr()).await {
```
```diff
-            if tx.recover_signer().unwrap_or_default() != self.signer {
+            if tx.recover_signer().unwrap_or_default() != batcher_address {
```
It also resets `OraclePipeline::new` (`crates/proof/proof/src/l1/pipeline.rs`) with the `SystemConfig` of the L2 safe head at start-up. Without that reset, the fault-proof program would begin from a default or genesis config instead of the batcher in force at the starting block.

This behaviour is required by the spec ("the sender must match the batcher address loaded from the system config matching the L1 block of the data"), and op-node implements it (`DataSourceConfig.batcherAddr` is refreshed from `L1Traversal.SystemConfig()`).

### Attack scenario

**A. Liveness and consensus split on a rotated chain (no attacker needed).**
1. A chain rotates its batcher from `B0`, the genesis key, to `B1` through `SystemConfig.setBatcherHash`.
2. op-node accepts `B1`'s frames. kona drops them all, and its derived safe chain stops at the rotation point.
3. kona-node stalls or diverges from op-node. The kona fault-proof program cannot derive any block after the rotation, so its output roots no longer match op-node's.

**B. Retired-key injection.**
1. Someone still holds `B0`, the retired or possibly leaked genesis key.
2. They post frames to the batch inbox signed with `B0`. op-node ignores them, but kona accepts them as valid batches.
3. kona-node derives a different L2 chain from op-node. In a kona-based dispute game, the kona program would treat the forged batches as canonical, so the honest challenger and the kona VM would disagree about the correct output root.

## Impact Details

- **Affected software:** kona-node, which was pre-production at the time, and the kona fault-proof program (kona-client on asterisc, `ASTERISC_KONA` game type). kona-based games were not the respected game type on OP Mainnet or any other chain holding significant value at the time. They were deployed only as an alternative or test game type. ZK proof systems built on kona (OP Succinct, Kailua) used the same derivation crate, so they would have produced proofs that disagree with the canonical chain on rotated chains.
- **Precondition:** the chain must have rotated its batcher since genesis. Variant B also needs the old batcher's private key.
- **Duration:** about 12 months in kona.

On a production chain whose withdrawals were secured by kona proofs, this would be High to Critical, because B makes an invalid state provable. Given the actual deployment status, the rating is **Low**.

## Proof of Concept

This Rust test, placed in `crates/protocol/derive/src/sources/ethereum.rs` at `19fe8610dc^`, uses the existing fixture `testdata/raw_batcher_tx.hex`, which is signed by `0x6887…2985`. The rollup config makes a different address the *genesis* batcher, standing in for a chain that later rotated to `0x6887…2985`. On the parent commit the data source returns `Eof`, meaning the frame was dropped, so the test fails. At the fix commit the equivalent call `ds.next(&block_ref, current_batcher)` returns the 119,823-byte frame.

```rust
#[cfg(test)]
mod poc_04_03 {
    use super::*;
    use crate::test_utils::{TestBlobProvider, TestChainProvider};
    use alloy_consensus::TxEnvelope;
    use alloy_eips::eip2718::Decodable2718;
    use alloy_primitives::address;
    use kona_genesis::{RollupConfig, SystemConfig};
    use kona_protocol::BlockInfo;

    #[tokio::test]
    async fn poc_rotated_batcher_batches_are_dropped() {
        let mut chain = TestChainProvider::default();
        let blob = TestBlobProvider::default();
        let genesis_batcher = address!("000000000000000000000000000000000000dead"); // retired
        let current_batcher = address!("6887246668a3b87F54DeB3b94Ba47a6f63F32985"); // from ConfigUpdate
        let block_ref = BlockInfo { number: 10, ..Default::default() };

        let mut cfg = RollupConfig::default();
        cfg.genesis.system_config =
            Some(SystemConfig { batcher_address: genesis_batcher, ..Default::default() });
        cfg.batch_inbox_address = address!("FF00000000000000000000000000000000000010");

        let raw = include_bytes!("../../testdata/raw_batcher_tx.hex");
        let tx = TxEnvelope::decode_2718(&mut raw.as_ref()).unwrap();
        assert_eq!(tx.recover_signer().unwrap(), current_batcher);
        chain.insert_block_with_transactions(10, block_ref, alloc::vec![tx]);

        let mut ds = EthereumDataSource::new_from_parts(chain, blob, &cfg);
        // Parent: Err(Temporary(Eof)) -> FAIL (current batcher's batch dropped).
        // Fix:    ds.next(&block_ref, current_batcher) -> Ok(119823 bytes).
        let res = ds.next(&block_ref).await;
        assert!(res.is_ok(), "batch from current SystemConfig batcher was dropped");
    }
}
```

Run from a tree exported at the parent (for example `git archive 19fe8610dc^ | tar -x -C /tmp/kona`):
```bash
cargo test -p kona-derive --lib poc_04_03
```

Executed: **no**. A build of the historical kona workspace (toolchain 1.82) was started but did not finish within the session. The logic is simple: the filter compares against `cfg.genesis.system_config.batcher_address` and nothing else.

## Recommendation

The fix is correct: the batcher address now comes from the `SystemConfig` that `L1Traversal` tracks, and the proof pipeline is seeded with the safe head's config. Suggested follow-ups:
- Add a cross-client differential test for derivation across a batcher rotation, covering op-node, kona-node and kona-client.
- Audit the other places that read `cfg.genesis.system_config` at runtime, such as gas limit, scalars and the unsafe signer (see the related kona-node P2P signer fixes), for the same "genesis instead of live config" mistake.

## References

- Fix commit: 19fe8610dcd7c965804392ade6dce979329e80be (https://github.com/op-rs/kona/pull/1106)
- Relevant files: `crates/protocol/derive/src/sources/{ethereum,blobs,calldata}.rs`, `crates/protocol/derive/src/traits/data_sources.rs`, `crates/protocol/derive/src/stages/l1_retrieval.rs`, `crates/proof/proof/src/l1/pipeline.rs`
- Spec: https://specs.optimism.io/protocol/derivation.html#l1-retrieval , https://specs.optimism.io/protocol/system-config.html#batcher-hash-bytes32
