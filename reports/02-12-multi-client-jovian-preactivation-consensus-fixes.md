# Jovian hardfork: pre-activation consensus-divergence bugs across op-node, op-revm, alloy-op-evm, op-reth and kona

| Field | Value |
|---|---|
| **Target** | op-node `op-node/p2p/gossip.go`; op-revm `src/{constants,spec,l1block}.rs`; alloy-op-evm `src/block/mod.rs`; op-reth `chainspec/src/basefee.rs`, `payload/src/builder.rs`, `consensus/src/{lib.rs,validation/mod.rs}`; kona `crates/protocol/protocol/src/batch/single.rs` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Informational (each would have been up to High, "Unintended chain split", if it had reached a network at Jovian activation) |
| **Impact category** | "Unintended chain split (network partition)" / "Network not being able to confirm new transactions", at Jovian activation only |
| **Fix commit(s)** | a7c92d8412437f24273921178018e66fefbfecda (op-node #17940) 2025-10-21; c130c3fc7c06923d762ca88991eba56125b60b7e (bluealloy/revm#3120) 2025-10-22; 8b3b8e2c83929f27022dfdfa47618c5e105365f0 (alloy-rs/evm#201) 2025-10-22; 6c5f5e1981835902577a8a953c49a46c15a5d8ee (paradigmxyz/reth#19048) 2025-10-22; 5a68242085d2f4b5924a07afdc6433e5722c3d41 (op-rs/kona#2966) 2025-10-23; 4054284683d9b152ed9329079da284279786b15b (paradigmxyz/reth#19304) 2025-10-27; 1903a448cd8b0f4af9995decfe7be821fd7b0c11 (paradigmxyz/reth#19338) 2025-10-29 |
| **Vulnerable since** | The respective Jovian feature commits (Sept to Oct 2025). None was active on a public network. Jovian timestamps first entered the superchain-registry import in 9e3254b0a6 (2025-10-24): sepolia-dev-0 2025-10-30, Sepolia 2025-11-05, mainnet later. Every fix above predates the first activation. |

## Brief / Intro

Jovian is an OP Stack hardfork. Among other changes, it adds a *DA footprint* limit: each block's `blobGasUsed` header field now records how much data-availability space its transactions use, and that value feeds into the next block's base fee. It also adds a minimum base fee carried in `extraData`. Every client has to implement these rules byte-for-byte the same way, or nodes will disagree about which blocks are valid. In the weeks before Jovian activated, seven consensus bugs were found and fixed across five codebases. Had any of them reached a network, that network would have split or stalled at the moment of activation. All were fixed before any public activation, so this report records latent defects, not live exposure.

## Vulnerability Details

### 12a. op-node rejected every Jovian block on gossip (a7c92d8412)

`op-node/p2p/gossip.go:382-387` (parent):

```go
if blockVersion.HasBlobProperties() {
    // [REJECT] if the block is on a topic >= V3 and has a blob gas used value that is not zero
    if payload.BlobGasUsed == nil || *payload.BlobGasUsed != 0 {
        return pubsub.ValidationReject
```

After Jovian, `blobGasUsed` holds the DA footprint, which is non-zero for any block with user transactions. Every op-node would have rejected, and down-scored the peers relaying, every such unsafe block. Unsafe-block propagation would have stopped network-wide, and nodes would only advance through L1 derivation. Fix: allow a non-zero value once `cfg.IsDAFootprintBlockLimit(timestamp)`, and still reject `nil`.

### 12b. op-revm read the DA-footprint scalar from the wrong slot and mapped Jovian to the Osaka EVM (c130c3fc7c)

```diff
-pub const DA_FOOTPRINT_GAS_SCALAR_OFFSET: usize = 0;
+pub const DA_FOOTPRINT_GAS_SCALAR_OFFSET: usize = 18;
-pub const DA_FOOTPRINT_GAS_SCALAR_SLOT: U256 = U256::from_limbs([9u64, 0, 0, 0]);
+pub const DA_FOOTPRINT_GAS_SCALAR_SLOT: U256 = U256::from_limbs([8u64, 0, 0, 0]);
...
-            Self::ISTHMUS | Self::INTEROP => SpecId::PRAGUE,
-            Self::JOVIAN | Self::OSAKA => SpecId::OSAKA,
+            Self::ISTHMUS | Self::JOVIAN | Self::INTEROP => SpecId::PRAGUE,
```

The `L1Block` contract packs `daFootprintGasScalar` into slot 8 at byte offset 18, next to the operator-fee fields. op-revm read slot 9, offset 0, which is a different variable (or zero). Every DA footprint that op-reth or kona computed would have been wrong. Separately, mapping `JOVIAN` to `SpecId::OSAKA` would have switched on Fusaka EVM changes (new opcodes, precompile repricing, tx gas cap) that op-geth does not apply at Jovian. Either issue alone would split Rust clients from op-geth on the first Jovian block with user transactions.

### 12c. alloy-op-evm read the scalar from the underlying DB, bypassing in-block state (8b3b8e2c83)

Parent `src/block/mod.rs:142-160`:

```rust
let da_footprint_gas_scalar_slot = self.evm.db_mut().database        // <-- raw DB, not the State cache
    .storage(L1_BLOCK_CONTRACT, DA_FOOTPRINT_GAS_SCALAR_SLOT) ...
```

The L1-info deposit at the start of each block can update `daFootprintGasScalar`. Reading `.database` returns the *parent-state* value and ignores that write. The code also used op-revm's wrong slot and offset (12b). Fix: load the account into the `State` cache and use `L1BlockInfo::fetch_da_footprint_gas_scalar`, which reads the cached, up-to-date value.

### 12d. op-reth base fee ignored the DA footprint, and its builder ignored the DA limit (6c5f5e1981)

The Jovian base-fee rule uses `max(gasUsed, blobGasUsed)`. op-reth's `compute_jovian_base_fee` (parent `chainspec/src/basefee.rs:50-66`) still called `parent.next_block_base_fee(params)`, which uses `gasUsed` only. For any parent whose DA footprint exceeded its gas used, op-reth would have computed a different base fee than op-geth. Fix:

```rust
let gas_used = max(parent.gas_used(), parent.blob_gas_used().unwrap_or_default());
let next_base_fee = calc_next_block_base_fee(gas_used, parent.gas_limit(), parent.base_fee_per_gas().unwrap_or_default(), base_fee_params);
```

In the same commit, the payload builder (`payload/src/builder.rs`, `is_tx_over_limits`) gained the DA-footprint check `total_da_bytes_used * scalar <= block_gas_limit`. Without it, an op-reth sequencer could build blocks that exceed the DA footprint limit, and other nodes would reject them.

### 12e. kona accepted user transactions in the Jovian activation block (5a68242085)

op-node added the spec rule "drop non-empty batches for the Jovian activation block" (5f5e50fa73, 2025-10-23). Kona's `SingleBatch::check_batch` enforced it only for Interop:

```diff
-        if cfg.is_first_interop_block(self.timestamp) && !self.transactions.is_empty() {
+        if (cfg.is_first_jovian_block(self.timestamp) || cfg.is_first_interop_block(self.timestamp)) &&
+            !self.transactions.is_empty()
+        {
             return BatchValidity::Drop;
```

A batcher that included user transactions in the activation block would have made kona-node and kona-client accept a batch that op-node and op-program drop. This is a derivation split, and a disagreement between the two fault-proof programs.

### 12f. op-reth block validation for Jovian (4054284683, 1903a448cd)

- **Pre-execution** (`consensus/src/lib.rs`, parent of 4054284683): once Ecotone was active, op-reth required `blobGasUsed == 0`, so it would have rejected *every* Jovian block with user transactions. Fix: after Jovian, require only that the field is present.
- **Post-execution** (`consensus/src/validation/mod.rs`): op-reth did not compare the header's `blobGasUsed` with the DA footprint computed during execution. It would have accepted a block whose header misreports the footprint, and that value drives the next base fee. Fix: `if computed_blob_gas_used != header_blob_gas_used { return Err(BlobGasUsedDiff) }`.
- **Against parent** (parent of 1903a448cd, `consensus/src/lib.rs:193`): op-reth ran Ethereum's `validate_against_parent_4844`, which derives the expected `excessBlobGas` from the parent's `blobGasUsed`. With a non-zero DA footprint in the parent, it expects a non-zero `excessBlobGas`. OP requires 0, so op-reth would have rejected valid Jovian blocks. Fix: replace it with OP rules (`excessBlobGas == 0` always; `blobGasUsed == 0` only before Jovian). The same commit adds tests for the Jovian minimum-base-fee header rule.

### Attack scenario (had any bug shipped)

1. Jovian activates at timestamp T. The first post-T block with user transactions has a non-zero DA footprint in `blobGasUsed`.
2. Depending on the bug: op-node drops it from gossip (12a); op-reth rejects it (12f) or computes a different base fee for its child (12d); op-reth/kona compute a different footprint or run Osaka EVM rules (12b, 12c).
3. Nodes split into groups that disagree on the canonical chain, or the unsafe chain stalls. No attacker is needed; normal traffic at activation triggers every bug except 12e, which needs a batcher that puts transactions in the activation block.

## Impact Details

- **Exposure:** none on public networks. The earliest registry activation (sepolia-dev-0, 2025-10-30 16:00 UTC) comes after the last fix (1903a448cd, 2025-10-29). Sepolia (2025-11-05) and mainnet came later. These are pre-activation development bugs found by pre-release testing, including the imported monorepo action and acceptance suites (see 5a68242085).
- **Severity:** **Informational**. The nominal impact of each item would have been an unintended chain split or a network-wide unsafe-chain stall at activation, which is High.

## Proof of Concept

Most fixes shipped regression tests that fail on their parent commit:

| Item | Test | Command |
|---|---|---|
| 12a | `TestBlockValidator` case `V4AcceptNonZeroBlobGasUsedJovian` (`op-node/p2p/gossip_test.go:206` at a7c92d8412) | `go test ./op-node/p2p -run TestBlockValidator -v` |
| 12b/12c | alloy-op-evm `test_jovian_da_footprint_estimation{,_out_of_gas,_maxed_out_da_footprint}`, reworked to pack the scalar at slot 8, bytes 18..19 (`src/block/mod.rs` at 8b3b8e2c83) | `cargo test -p alloy-op-evm jovian_da_footprint` (in `rust/`) |
| 12d | `test_next_base_fee_jovian_blob_gas_used_greater_than_gas_used`, `..._less_than_gas_used`, `test_next_base_fee_jovian_min_base_fee` (`chainspec/src/basefee.rs`, added in 6c5f5e1981) | `cargo test -p reth-optimism-chainspec next_base_fee_jovian` |
| 12e | No Jovian-specific test was added (the fix only loosened the interop test's log assertion). See the PoC below | `cargo test -p kona-protocol poc_check_batch_drop_non_empty_jovian_transition` (in `rust/`) |
| 12f | `test_jovian_blob_gas_used_validation{,_mismatched}`, `test_header_da_footprint_validation`, `test_header_min_base_fee_validation{,_failure}`, `test_header_isthmus_validation` | `cargo test -p reth-optimism-consensus jovian` |

Minimal Go PoC for 12a. It is the core of the added case: a Jovian-time envelope with `blobGasUsed = 1` must be *accepted*. On the parent the validator returns `ValidationReject`.

```go
// op-node/p2p/gossip_test.go (inside TestBlockValidator)
jovianCfg := &rollup.Config{L2ChainID: big.NewInt(100), JovianTime: ptr.New(uint64(0))}
v := BuildBlocksValidator(testlog.Logger(t, log.LevelCrit), jovianCfg, runCfg, eth.BlockV4, mockGossipConf)
zero, one := uint64(0), uint64(1)
env := createEnvelope(&beaconHash, types.Withdrawals{}, &withdrawalsRoot, &zero /*excessBlobGas*/, &one /*blobGasUsed*/)
// ... sign and marshal as in the existing envelopeTests loop ...
require.Equal(t, pubsub.ValidationAccept, v(ctx, peerID, msg)) // parent: ValidationReject
```

PoC for 12e, adapted from `test_check_batch_drop_non_empty_interop_transition` in `crates/protocol/protocol/src/batch/single.rs`. On the parent, the Jovian-specific drop and its warning are missing, so the assertion on the warning fails:

```rust
#[test]
fn poc_check_batch_drop_non_empty_jovian_transition() {
    let trace_store: TraceStorage = Default::default();
    let layer = CollectingLayer::new(trace_store.clone());
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let single_batch = SingleBatch {
        parent_hash: BlockHash::ZERO, epoch_num: 1, epoch_hash: BlockHash::ZERO,
        timestamp: 1, transactions: example_transactions(),
    };
    let cfg = RollupConfig {
        max_sequencer_drift: 1,
        block_time: 1,
        // Isthmus already active so no earlier tx-type rule drops the batch; Jovian activates at t=1.
        hardforks: HardForkConfig { isthmus_time: Some(0), jovian_time: Some(1), ..Default::default() },
        ..Default::default()
    };
    let l1_blocks = vec![BlockInfo::default(), BlockInfo::default()];
    let l2_safe_head = L2BlockInfo { block_info: BlockInfo { timestamp: 0, ..Default::default() }, ..Default::default() };
    assert_eq!(
        single_batch.check_batch(&cfg, &l1_blocks, l2_safe_head, &BlockInfo::default()),
        BatchValidity::Drop
    );
    // Parent: this warning is never emitted (the rule only covered Interop).
    assert!(trace_store.get_by_level(Level::WARN).iter()
        .any(|s| s.contains("jovian or interop transition block")));
}
```

Executed: **no**. These are pre-activation issues, each covered by the fix's own regression tests. Running them at the parent commits would need checkouts, which this review does not allow.

## Recommendation

All seven fixes are correct. Process takeaways:

- Run cross-client differential tests (op-geth vs op-reth vs kona, op-node vs kona-node) on activation-boundary blocks, including blocks with non-zero DA footprint and scalar updates inside the block. The fix PR 5a68242085 started importing the monorepo's action tests into kona for this reason.
- Keep one source of truth for `L1Block` storage layouts (slot and offset constants), generated from the Solidity storage layout snapshot, instead of hand-copying them into op-revm.
- Treat gossip validation rules as consensus-critical for each fork. 12a would have taken down unsafe-block propagation on every chain.

## References

- Fix commits: a7c92d8412437f24273921178018e66fefbfecda, c130c3fc7c06923d762ca88991eba56125b60b7e, 8b3b8e2c83929f27022dfdfa47618c5e105365f0, 6c5f5e1981835902577a8a953c49a46c15a5d8ee, 5a68242085d2f4b5924a07afdc6433e5722c3d41, 4054284683d9b152ed9329079da284279786b15b, 1903a448cd8b0f4af9995decfe7be821fd7b0c11
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/17940, https://github.com/bluealloy/revm/pull/3120, https://github.com/alloy-rs/evm/pull/201, https://github.com/paradigmxyz/reth/pull/19048, https://github.com/op-rs/kona/pull/2966, https://github.com/paradigmxyz/reth/pull/19304, https://github.com/paradigmxyz/reth/pull/19338
- Related: op-node Jovian activation-block rule 5f5e50fa73 (#17984); registry timestamps 9e3254b0a6 (#18016)
- Spec: https://specs.optimism.io/protocol/jovian/exec-engine.html
