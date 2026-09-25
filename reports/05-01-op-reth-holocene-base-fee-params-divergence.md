# op-reth: Holocene EIP-1559 parameters read from the wrong block and ignored during validation, so op-reth nodes halt at activation or reject valid blocks

| Field | Value |
|---|---|
| **Target** | op-reth: `chainspec/src/lib.rs` (`OpChainSpec::next_block_base_fee`) and `consensus/src/lib.rs` (`OpBeaconConsensus::validate_header_against_parent`). Today these live at `rust/op-reth/crates/chainspec` and `rust/op-reth/crates/consensus` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Medium |
| **Impact category** | "Shutdown of greater than or equal to 10% or equal to but less than 30% of network processing nodes without brute force actions, but does not shut down the network". This assumes op-reth is a minority client and no production chain used an op-reth sequencer at the time. Downgraded from "Unintended chain split (network partition)" (High), because the affected nodes halt rather than follow a competing chain |
| **Fix commit(s)** | Bug A: `1d316d0d69d32c340cac3d843f9f10d05d47c914` (paradigmxyz/reth#13060), 2024-12-02. Bug B: `341db09082477cc2441631aa891558d0f32d59ef` (paradigmxyz/reth#13122), 2024-12-04 |
| **Vulnerable since** | `c4263f11a6` "feat: Eip1559 params in extradata" (paradigmxyz/reth#11887), 2024-10-30. This covered the OP Sepolia and Base Sepolia Holocene activation (1732633200, 2024-11-26). The fix landed before the mainnet activation (2025-01-09) |

## Brief / Intro

Holocene let each OP Stack chain set its own EIP-1559 fee parameters, the "denominator" and "elasticity" that control how quickly the L2 base fee moves. The chain operator sets them in the L1 `SystemConfig` contract. From Holocene on, each L2 block stores them in its `extraData` header field, and the next block's base fee is computed from the **parent** block's `extraData` values. op-reth, the Rust OP Stack execution client, had two bugs here:

- **Bug A:** op-reth decided whether to read `extraData` based on the *new* block's timestamp instead of the parent's. At the fork boundary it tried to decode Holocene parameters from a pre-Holocene parent, whose `extraData` is empty. Every attempt to build the first Holocene block therefore failed.
- **Bug B:** when checking blocks received from the network, op-reth used the generic Ethereum base-fee check, which ignores `extraData`. Once an operator set non-default parameters, op-reth rejected every valid block as having the "wrong" base fee.

Either way, op-reth nodes stop following the chain. No attacker is needed. Bug A fires at fork activation, and Bug B fires after a routine `SystemConfig` update by the chain operator.

## Vulnerability Details

### Spec

Holocene exec-engine spec, "Base fee computation": *"if Holocene is active in `parent_header.timestamp`, then the parameters from `parent_header.extraData` are used."* Pre-Holocene blocks have an empty `extraData`.

### Bug A: activation check uses the child timestamp (payload building)

`1d316d0^:chainspec/src/lib.rs:189-217`:
```rust
pub fn next_block_base_fee(&self, parent: &Header, timestamp: u64) -> Result<U256, DecodeError> {
    let is_holocene_activated = self
        .inner
        .is_fork_active_at_timestamp(reth_optimism_forks::OpHardfork::Holocene, timestamp); // child ts
    if is_holocene_activated {
        let (denominator, elasticity) = decode_holocene_1559_params(parent.extra_data.clone())?;
        ...
```
and `decode_holocene_1559_params` (`:244`) returns `Err(DecodeError::InsufficientData)` when `extra_data.len() < 9`.

The payload builder calls this through `OpEvmConfig::next_cfg_and_block_env` (`1d316d0^:evm/src/lib.rs:161`):
```rust
basefee: self.chain_spec.next_block_base_fee(parent, attributes.timestamp)?,
```
For the first block with `timestamp >= holocene_time`, the parent is pre-Holocene and has an empty `extraData`. The `?` turns the decode error into a payload-builder error. Every `engine_forkchoiceUpdated` with payload attributes for that block fails, deterministically and on every retry. Affected nodes:
- an op-reth **sequencer**, which cannot produce the activation block, so the chain halts;
- an op-reth **verifier whose op-node derives blocks from L1 through FCU+attributes**. This is consensus-layer sync, or any case where the unsafe block was not already imported over p2p. Its safe head stops at the fork boundary.

Fix (`1d316d0`):
```rust
-        let is_holocene_activated = self
-            .inner
-            .is_fork_active_at_timestamp(reth_optimism_forks::OpHardfork::Holocene, timestamp);
+        // > if Holocene is active in parent_header.timestamp, then the parameters from
+        // > parent_header.extraData are used.
+        let is_holocene_activated = self.inner.is_fork_active_at_timestamp(
+            reth_optimism_forks::OpHardfork::Holocene,
+            parent.timestamp,
+        );
```

### Bug B: header validation ignores `extraData` (block import)

`341db09^:consensus/src/lib.rs:103-127`:
```rust
fn validate_header_against_parent(&self, header: &SealedHeader, parent: &SealedHeader) -> Result<(), ConsensusError> {
    validate_against_parent_hash_number(header.header(), parent)?;
    ...
    validate_against_parent_eip1559_base_fee(   // generic L1 check
        header.header(),
        parent.header(),
        &self.chain_spec,                        // uses chainspec's static BaseFeeParams
    )?;
```
The generic check recomputes the expected base fee from the chain spec's static `BaseFeeParams`. After Holocene, the correct parameters are the ones in `parent.extraData`, which reflect the chain's `SystemConfig.eip1559Params`. Two cases:
- the chain keeps the defaults: `extraData` holds the same values as the chain spec, and the check happens to pass;
- the operator calls `SystemConfig.setEIP1559Params` with non-default values: every block after the change has a base fee op-geth and op-node consider correct, but op-reth returns `ConsensusError::BaseFeeDiff`. `engine_newPayload` answers `INVALID`, and the op-reth node stops at the first such block.

Fix (`341db09`) adds a Holocene-aware branch keyed on the parent timestamp:
```rust
+        if self.chain_spec.is_holocene_active_at_timestamp(parent.timestamp) {
+            let header_base_fee =
+                header.base_fee_per_gas().ok_or(ConsensusError::BaseFeeMissing)?;
+            let expected_base_fee = self
+                .chain_spec
+                .decode_holocene_base_fee(parent, header.timestamp)
+                .map_err(|_| ConsensusError::BaseFeeMissing)?;
+            if expected_base_fee != header_base_fee {
+                return Err(ConsensusError::BaseFeeDiff(GotExpected { expected: expected_base_fee, got: header_base_fee }))
+            }
+        } else {
+            validate_against_parent_eip1559_base_fee(header.header(), parent.header(), &self.chain_spec)?;
+        }
```
It also factors out `OpChainSpec::decode_holocene_base_fee`, so building and validation now share one code path.

### Attack scenario

Bug A (no attacker):
1. The Holocene timestamp passes (it did on OP Sepolia and Base Sepolia on 2024-11-26, while the bug was present).
2. op-node asks op-reth to build the first Holocene block with `engine_forkchoiceUpdated` plus attributes.
3. `next_block_base_fee` sees Holocene active at the child timestamp and tries to decode the empty parent `extraData`. Building fails with `InsufficientData` every time. An op-reth sequencer halts the chain. An op-reth node deriving from L1 stalls its safe head.

Bug B (trusted but routine trigger):
1. After Holocene, the chain operator calls `SystemConfig.setEIP1559Params(denominator, elasticity)` with non-default values. This is the feature Holocene was introduced for.
2. The next L2 blocks carry the new parameters in `extraData`, and their base fee is computed from them.
3. op-reth recomputes the base fee with the static chain-spec parameters, gets a different value, and rejects each block with `BaseFeeDiff`. The node stops following the chain until it is upgraded.

## Impact Details

- **Who is affected:** op-reth nodes only. op-geth and op-node were correct, so the canonical chain is unaffected unless op-reth is the sequencer. Some operators already ran op-reth as a verifier (for example on Base) and as a builder.
- **Bug A** is deterministic at fork activation. It hit the Sepolia activation window (2024-11-26 to the 2024-12-02 fix) for op-reth nodes that build or derive blocks. Nodes importing gossiped blocks through `newPayload` execute with the header's base fee and were unaffected. The generic validation also passes at the boundary because the parent is pre-Holocene.
- **Bug B** needs the `SystemConfig` owner to set non-default parameters. That is a trusted role, but using it is an expected operational action, not a misconfiguration. It then halts every op-reth verifier on that chain.
- **Mitigating factors:** both fixes landed about five weeks before the mainnet activation. No evidence was found that any production chain changed its EIP-1559 parameters, or ran an op-reth sequencer, while the bugs were present. The failure mode is a halt (the node rejects blocks or cannot build) rather than op-reth following a different canonical chain.
- **Severity:** Medium. This is a consensus-rule bug that stops a whole client implementation without any attacker action. It is not High, because it needs no adversary but also offers none any gain. It affects a minority client, and the core network keeps going if the sequencer runs op-geth.

## Proof of Concept

The monorepo imported op-reth's history with crate-relative paths (`chainspec/…`, `consensus/…`). Upstream these crates are `crates/optimism/{chainspec,consensus}` in `paradigmxyz/reth`. To run the tests, check out upstream reth at the commit before PR #13060 (Bug A) or #13122 (Bug B), add the test, and run `cargo test`. The tests fail there and pass on the fix commits.

**Bug A:** add to the `tests` module of `crates/optimism/chainspec/src/lib.rs`. It reuses the existing `holocene_chainspec()` helper, which activates Holocene at `1800000000`.
```rust
#[test]
fn poc_holocene_activation_block_base_fee() {
    let op_chain_spec = holocene_chainspec();
    // Last pre-Holocene block: empty extraData, as produced by op-geth/op-reth before Holocene.
    let parent = Header {
        base_fee_per_gas: Some(1_000_000),
        gas_used: 15_763_614,
        gas_limit: 144_000_000,
        timestamp: 1_799_999_998,
        extra_data: Bytes::new(),
        ..Default::default()
    };
    // First Holocene block.
    let res = op_chain_spec.next_block_base_fee(&parent, 1_800_000_000);
    // Parent commit: Err(DecodeError::InsufficientData) -> payload building fails.
    // Fixed commit: Ok(base fee computed from the chain-spec defaults).
    assert_eq!(
        res.expect("activation-block base fee must be computable"),
        U256::from(
            parent
                .next_block_base_fee(op_chain_spec.base_fee_params_at_timestamp(1_800_000_000))
                .unwrap()
        )
    );
}
```
```
cargo test -p reth-optimism-chainspec --features optimism poc_holocene_activation_block_base_fee
```

**Bug B:** add to `crates/optimism/consensus/src/lib.rs` under `#[cfg(test)]`. It builds a chain spec with Holocene at genesis, so both blocks are post-Holocene, and uses a parent whose `extraData` encodes denominator 8 and elasticity 8. Those values differ from the chain spec's static Base Sepolia parameters.
```rust
#[cfg(test)]
mod poc {
    use super::*;
    use alloy_primitives::Bytes;
    use reth_chainspec::{BaseFeeParams, ChainSpec, ForkCondition};
    use reth_optimism_chainspec::{OpChainSpec, BASE_SEPOLIA};
    use reth_optimism_forks::OpHardfork;
    use reth_primitives::SealedHeader;
    use std::sync::Arc;

    #[test]
    fn poc_holocene_custom_1559_params_rejected() {
        let mut hardforks = OpHardfork::base_sepolia();
        hardforks.insert(OpHardfork::Holocene.boxed(), ForkCondition::Timestamp(0));
        let spec = Arc::new(OpChainSpec {
            inner: ChainSpec {
                chain: BASE_SEPOLIA.inner.chain,
                genesis: BASE_SEPOLIA.inner.genesis.clone(),
                paris_block_and_final_difficulty: Some((0, U256::ZERO)),
                hardforks,
                base_fee_params: BASE_SEPOLIA.inner.base_fee_params.clone(),
                ..Default::default()
            },
        });
        let consensus = OpBeaconConsensus::new(spec);

        let parent = Header {
            number: 100,
            timestamp: 1_000,
            gas_limit: 30_000_000,
            gas_used: 20_000_000,
            base_fee_per_gas: Some(1_000_000),
            // version 0, denominator = 8, elasticity = 8
            extra_data: Bytes::from_static(&[0, 0, 0, 0, 8, 0, 0, 0, 8]),
            ..Default::default()
        };
        let parent = SealedHeader::seal(parent);
        // Base fee exactly as op-geth computes it from parent.extraData.
        let expected = parent.next_block_base_fee(BaseFeeParams::new(8, 8)).unwrap();
        let child = Header {
            parent_hash: parent.hash(),
            number: 101,
            timestamp: 1_002,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(expected),
            extra_data: Bytes::from_static(&[0, 0, 0, 0, 8, 0, 0, 0, 8]),
            ..Default::default()
        };
        let child = SealedHeader::seal(child);
        // Parent commit: Err(ConsensusError::BaseFeeDiff { .. }) -> valid block rejected.
        // Fixed commit: Ok(()).
        consensus.validate_header_against_parent(&child, &parent).unwrap();
    }
}
```
```
cargo test -p reth-optimism-consensus --features optimism poc_holocene_custom_1559_params_rejected
```
Field and constructor names follow the crate APIs at those commits. Small adjustments (for example the `SealedHeader` constructor) may be needed depending on the exact upstream revision.

Executed: no. The historical op-reth crates in this monorepo are not a buildable workspace on their own. Both conclusions were checked by reading the code at the parent commits.

## Recommendation

The fixes are correct: key the Holocene decision on `parent.timestamp`, and validate post-Holocene headers with the same `extraData`-derived parameters the builder uses (the shared `decode_holocene_base_fee`). Defense in depth:
- Map a decode failure of the parent's `extraData` in consensus to a dedicated error. The fix maps it to `BaseFeeMissing`, which is misleading when debugging.
- Add fork-boundary tests (last pre-fork parent, then first post-fork child) for every fork that changes header semantics. Both bugs sit exactly on that boundary.
- Cross-client differential tests (op-geth vs op-reth) on a devnet that changes `SystemConfig.eip1559Params` would have caught Bug B.

## References

- Fix commits: `1d316d0d69d32c340cac3d843f9f10d05d47c914`, `341db09082477cc2441631aa891558d0f32d59ef`
- Pull requests: https://github.com/paradigmxyz/reth/pull/13060, https://github.com/paradigmxyz/reth/pull/13122
- Introduced by: `c4263f11a6` (https://github.com/paradigmxyz/reth/pull/11887)
- Relevant files: `chainspec/src/lib.rs`, `consensus/src/lib.rs`, `evm/src/lib.rs` (now `rust/op-reth/crates/{chainspec,consensus,evm}`)
- Spec: https://github.com/ethereum-optimism/specs/blob/main/specs/protocol/holocene/exec-engine.md#base-fee-computation
