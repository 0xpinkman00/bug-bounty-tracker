# kona-protocol: L1-info deposit used Cancun blob-fee parameters after L1 Pectra (and mishandled the Sepolia "Pectra blob schedule" fork)

| Field | Value |
|---|---|
| **Target** | kona `crates/protocol/protocol/src/info/variant.rs` (`L1BlockInfoTx::try_new`), `crates/protocol/genesis/src/{rollup.rs,chain/hardfork.rs}`. Now under `rust/kona/` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (kona-node pre-production; kona proofs not respected; fixed about two months before L1 mainnet Pectra) |
| **Impact category** | "Unintended chain split (network partition)" between kona and op-node/op-geth on Pectra-enabled L1s; incorrect kona fault-proof outputs |
| **Fix commit(s)** | ce180542ad2967b2ee5cbf69b252d3eb6f4037f8 (op-rs/kona#1192), 2025-03-05; 4386e3a98221c79f34110dea6abcb07a761acedd (op-rs/kona#1195), 2025-03-06; follow-up d3d22dc53ca9f590d7b7be7a2d0c9c7101ae964e (op-rs/kona#1210), 2025-03-07 |
| **Vulnerable since** | kona's Ecotone L1-info implementation, which always used `BlobParams::cancun()`. It became wrong in practice when Holesky (2025-02-24) and Sepolia (2025-03-05) activated Pectra |

## Brief / Intro

Every L2 block begins with a system "L1 attributes" deposit. It writes facts about the current L1 block into the `L1Block` predeploy, including the L1 *blob base fee*, which L2 then uses to charge users for data. The blob base fee is computed from the L1 header's `excess_blob_gas` with a formula whose parameters changed in L1's Pectra upgrade (EIP-7691 raised the blob target and changed the update fraction). Kona always used the old Cancun parameters. After L1 Pectra, every L2 block kona built would therefore write a different blob base fee from op-node's, giving a different state root. Sepolia had a further complication: the OP Stack testnets themselves had kept the old formula by mistake, and that history was canonicalized. So kona also had to copy an optional "Pectra blob schedule" fork, and it took three commits to get this right.

## Vulnerability Details

Parent of the first fix, `crates/protocol/protocol/src/info/variant.rs` (Ecotone, Isthmus and Interop branches):
```rust
blob_base_fee: l1_header.blob_fee(BlobParams::cancun()).unwrap_or(1),
```

op-node takes the parameters from the L1 chain config and the L1 block time (`block.BlobBaseFee(l1ChainConfig)` in `op-node/rollup/derive/l1_block_info.go`). It falls back to Cancun only while `block.Time() < PectraBlobScheduleTime`:
```go
l1BlockInfo.BlobBaseFee = block.BlobBaseFee(l1ChainConfig)
if t := rollupCfg.PectraBlobScheduleTime; t != nil && block.Time() < *t {
    ... l1BlockInfo.BlobBaseFee = eth.CalcBlobFeeCancun(*ebg)
}
```

**Commit 1 (ce180542ad):** switch to Prague parameters whenever the L1 header carries `requests_hash`, meaning Pectra is active on L1:
```diff
+        let blob_fee_config =
+            l1_header.requests_hash.map(|_| BlobParams::prague()).unwrap_or(BlobParams::cancun());
 ...
-            blob_base_fee: l1_header.blob_fee(BlobParams::cancun()).unwrap_or(1),
+            blob_base_fee: l1_header.blob_fee(blob_fee_config).unwrap_or(1),
```
On its own this commit *broke* Sepolia and Holesky, because op-node there still used Cancun until the schedule fork.

**Commit 2 (4386e3a982):** add `pectra_blob_schedule_time` to the kona hardfork config, and use Prague only if that fork is unset or already active:
```rust
let blob_fee_config = l1_header.requests_hash.and_then(|_| {
    (rollup_config.hardforks.pectra_blob_schedule_time.is_none() ||
        rollup_config.is_pectra_blob_schedule_active(l2_block_time))
    .then_some(BlobParams::prague())
}).unwrap_or(BlobParams::cancun());
```
This commit checked the fork against the **L2** block time, while op-node checks it against the **L1** block time. Blocks whose L1 origin was just before the fork time but whose L2 time was after it would still diverge.

**Follow-up (d3d22dc53c):**
```diff
-                    rollup_config.is_pectra_blob_schedule_active(l2_block_time))
+                    rollup_config.is_pectra_blob_schedule_active(l1_header.timestamp))
```

Residual issue: after these commits the Isthmus and Interop branches used `BlobParams::prague()` without any condition. That is only correct if L1 has Pectra, which held on every real network where Isthmus was scheduled. kona later derived the parameters from an L1 chain config (1bd1621946, op-rs/kona#2892), which matches op-node's approach.

### Scenario

1. L1 activates Pectra. On mainnet this happened on 2025-05-07, after the fix.
2. op-node computes `blob_base_fee` with Prague parameters. kona, before the fix, uses Cancun. Given the same `excess_blob_gas`, the two results differ.
3. The L1-info deposit calldata differs, so the `L1Block` storage and the state root differ. L1 data fees charged to users also differ from that point on.
4. kona-node rejects or forks away from the canonical chain. The kona fault-proof program computes output roots that differ from the canonical ones for every block after the L1 fork, so an honest kona-based challenger would dispute valid proposals and lose.

## Impact Details

- **Affected software:** kona-node (pre-production), the kona fault-proof and ZK programs, and any kona-based sync of Pectra-era L1 data.
- **Actual exposure:**
  - *Mainnet:* the fix landed on 2025-03-05/07, well before L1 mainnet Pectra on 2025-05-07, so mainnet was never affected.
  - *Sepolia/Holesky:* pre-fix kona (always Cancun) happened to match the mis-configured testnet sequencers until each chain's `pectra_blob_schedule_time`, and diverged after it. Kona built from commit 1 alone diverged immediately. The windows lasted about a day each on testnets.
- **Why the rating is not higher:** no kona-secured game type protected value, and kona-node was not used in production.

Rated **Low**. For a production client or a respected proof system this would be a High, consensus-splitting bug.

## Proof of Concept

A unit test, added to the tests module of `variant.rs` in a kona tree at `ce180542ad^`, shows that kona's value differs from the Prague (op-node) value for a post-Pectra L1 header:

```rust
#[test]
fn poc_blob_base_fee_uses_cancun_after_pectra() {
    use alloy_consensus::Header;
    use alloy_eips::eip7840::BlobParams;
    use alloy_primitives::B256;

    let rollup_config = RollupConfig {
        hardforks: HardForkConfig { ecotone_time: Some(0), ..Default::default() },
        ..Default::default()
    };
    // Post-Pectra L1 header: requests_hash present, sizeable excess blob gas.
    let l1_header = Header {
        excess_blob_gas: Some(10_000_000),
        blob_gas_used: Some(0),
        requests_hash: Some(B256::ZERO),
        ..Default::default()
    };
    let info = L1BlockInfoTx::try_new(
        &rollup_config, &SystemConfig::default(), 0, &l1_header, 1,
    ).unwrap();

    let expected_prague = l1_header.blob_fee(BlobParams::prague()).unwrap();
    let cancun = l1_header.blob_fee(BlobParams::cancun()).unwrap();
    assert_ne!(expected_prague, cancun);
    // Parent commit: info.blob_base_fee() == cancun -> FAIL. Fix: == expected_prague -> PASS.
    assert_eq!(info.blob_base_fee(), U256::from(expected_prague));
}
```

```bash
cargo test -p kona-protocol --lib poc_blob_base_fee_uses_cancun_after_pectra
```
Adjust the accessor and constructor names to the crate API at `ce180542ad^`. `L1BlockInfoTx::blob_base_fee()` and `try_new(rollup_config, system_config, sequence_number, l1_header, l2_block_time)` existed at that time. Commit d3d22dc53c added rstest cases (`fork_active` / `fork_inactive` with right and wrong params) that serve as the regression test for the Sepolia schedule-fork logic.

Executed: **no**. The historical kona workspace was not built in this session.

## Recommendation

Take the blob parameters from the L1 chain's fork schedule (L1 timestamp compared against the L1 Prague/Osaka times and any BPO schedule), not from header-field heuristics. Kona eventually did this in op-rs/kona#2892. Keep one shared set of cross-client L1-info vectors between op-node and kona. The op-node kill switch in 6638905c0c, which refuses to start when a Sepolia/Holesky chain probably lacks `pectra_blob_schedule_time`, is a useful model for kona's config loader.

## References

- Fix commits: ce180542ad2967b2ee5cbf69b252d3eb6f4037f8 (https://github.com/op-rs/kona/pull/1192), 4386e3a98221c79f34110dea6abcb07a761acedd (https://github.com/op-rs/kona/pull/1195), d3d22dc53ca9f590d7b7be7a2d0c9c7101ae964e (https://github.com/op-rs/kona/pull/1210)
- Related op-node change: 6638905c0cbe190b6c3fdf99dfc8f67e60cd657c (PR #14922)
- Relevant files: `crates/protocol/protocol/src/info/variant.rs`, `crates/protocol/genesis/src/rollup.rs`, `op-node/rollup/derive/l1_block_info.go`
- Specs: https://specs.optimism.io/protocol/isthmus/overview.html , EIP-7691
