# kona executor: Holocene/Jovian header `extraData` used the pre-Canyon EIP-1559 denominator as the default, so the kona FPP computed wrong block hashes on chains with unset SystemConfig EIP-1559 params

| Field | Value |
|---|---|
| **Target** | kona fault-proof executor, `crates/proof/executor/src/util.rs` (`encode_holocene_eip_1559_params`, `encode_jovian_eip_1559_params`); now `rust/kona/crates/proof/executor/src/util.rs` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | Would-be fault-proof unsoundness / liveness for `CANNON_KONA` ("Unintended chain split" between the kona FPP and the canonical EL). No attacker is needed. Not realized in a respected game |
| **Fix commit(s)** | e97f03422545946480f1bffbfec995a2c15b9a70 (op-rs/kona#3188, fixes op-rs/kona#2993), 2025-12-16 |
| **Vulnerable since** | 36d81db7e9 `feat(jovian/min-base-fee): implement min-base fee in kona (op-rs/kona#2874)`, 2025-09-22. Before that, kona encoded `encode_canyon_base_fee_params(config)`, which was correct. The window was about 12 weeks on kona `main` |

## Brief / Intro

Since Holocene, each L2 block header stores the chain's EIP-1559 fee parameters (denominator and elasticity) in `extraData`. These values set the next block's base fee. The chain operator can set them in the L1 `SystemConfig`. If they were never set (`0,0`), every client must fall back to the chain's *post-Canyon* defaults (for OP Mainnet: denominator 250, elasticity 6). A refactor made kona's fault-proof executor fall back to the *pre-Canyon* denominator instead (OP Mainnet: 50). On any chain that left the SystemConfig parameters at zero, every block kona re-executed after Holocene had different `extraData`, and so a different block hash and output root, from the real chain. The kona fault-proof program would have called every honest proposal invalid.

## Vulnerability Details

`BaseFeeConfig` (kona-genesis) holds `eip1559_denominator` (pre-Canyon), `eip1559_denominator_canyon` and `eip1559_elasticity`. At the parent, `as_base_fee_params()` returned the **pre-Canyon** pair.

Parent of the fix, `crates/proof/executor/src/util.rs:69-99`:

```rust
pub(crate) fn encode_holocene_eip_1559_params(config: &RollupConfig, attributes: &OpPayloadAttributes)
    -> ExecutorResult<Bytes> {
    Ok(encode_holocene_extra_data(
        attributes.eip_1559_params.ok_or(ExecutorError::MissingEIP1559Params)?,
        config.chain_op_config.as_base_fee_params(),       // pre-Canyon default!
    )?)
}
// encode_jovian_eip_1559_params: same `as_base_fee_params()` default
```

`op_alloy_consensus::encode_holocene_extra_data(params, default)` writes `default` into the header when `params == 0`. op-node forwards the SystemConfig `eip1559Params` as-is, and those are zero when never configured. op-geth and op-reth substitute the Canyon parameters, as the Holocene spec requires. kona wrote `denominator = eip1559_denominator` (for example `0x00000032` instead of `0x000000fa`).

Consequences inside the FPP, for every Holocene+ block on an affected chain:

- The header `extraData` differs, so the block hash differs, so the output root differs from op-node's.
- The next block's base fee is derived from the parent's `extraData` (`decode_holocene_eip_1559_params_block_header`), so the fee schedule and gas accounting also diverge from the second block on.

Fix (`util.rs`; the other hunks only rename `as_base_fee_params` / `as_canyon_base_fee_params` to `pre_canyon_params` / `post_canyon_params`):

```rust
-        config.chain_op_config.as_base_fee_params(),
+        config.chain_op_config.post_canyon_params(),
```

**Correction to triage:** kona-node's `AttributesMatch` (`crates/node/engine/src/attributes.rs`) and `builder/env.rs` already used `as_canyon_base_fee_params()`. Their diff hunks are pure renames. kona-node was **not** affected. The bug was confined to the FPP executor.

### Failure scenario (no attacker)

1. A chain with `eip1559_denominator != eip1559_denominator_canyon` (true of OP Mainnet-style configs, 50 vs 250) has never called `SystemConfig.setEIP1559Params`.
2. Every post-Holocene block therefore carries `eip1559Params = 0` in its payload attributes.
3. kona-client re-executes block `N+1` from agreed block `N` and produces an output root that differs from op-node's for *every* block.
4. In a `CANNON_KONA` game, the honest proposer's correct root can be challenged by anyone. At the leaf, kona says INVALID, so the challenger wins and the proposer's bond is lost. An attacker proposing kona's wrong root would win against honest challengers. Every game on that chain is decided by kona's wrong view.

## Impact Details

- **Trigger:** none needed. The bug depends only on configuration and is deterministic.
- **Mitigating factors:**
  - The bug lived only from 2025-09-22 to 2025-12-16 on kona `main`. `CANNON_KONA` was first deployed with Upgrade 18 (`op-contracts/v6.0.0`, released 2026-01-14 / 2026-03-16), and the first kona-client tag in this repository after the fix (`kona-client/v1.2.12`, 2026-02-19) contains the fix. I could not check out the op-rs/kona `kona-client/v1.2.7` tag used for the Upgrade 18 prestate, but by date it very likely post-dates the fix.
  - `CANNON_KONA` was non-respected until Karst (2026-07-08).
  - A divergence this large (every block) would be caught immediately by kona-vs-op-program differential runs or by op-dispute-mon.
- **Severity:** Low. Had it shipped in a respected `CANNON_KONA` prestate, it would have been Critical (every honest proposal refutable, arbitrary roots defensible). As it happened, the fix came before any production use.

## Proof of Concept

The fix updated `util.rs` tests so the default case uses realistic, distinct denominators (50 pre-Canyon, 250 Canyon):

```rust
#[test]
fn test_encode_holocene_eip_1559_params_default() {
    let cfg = RollupConfig {
        chain_op_config: BaseFeeConfig {
            eip1559_denominator: 50,
            eip1559_elasticity: 64,
            eip1559_denominator_canyon: 250,
        },
        ..Default::default()
    };
    let attrs = OpPayloadAttributes { eip_1559_params: Some(B64::ZERO), ..Default::default() };
    assert_eq!(
        encode_holocene_eip_1559_params(&cfg, &attrs).unwrap(),
        bytes!("00000000fa00000040")     // version 0, denom 250, elasticity 64 (spec / op-geth)
    );
}
```

On the parent (with the test's config changed to 50/250), the function returns `0x000000003200000040` (denominator 50), and the assertion fails.

```bash
git worktree add /tmp/kona-01-04 e97f03422545946480f1bffbfec995a2c15b9a70^
# edit crates/proof/executor/src/util.rs test_encode_holocene_eip_1559_params_default as above
cd /tmp/kona-01-04 && cargo test -p kona-executor test_encode_holocene_eip_1559_params_default
# parent: left = 0x000000003200000040, right = 0x00000000fa00000040 -> FAIL; fix: PASS
```

Executed: no.

## Recommendation

The fix is correct, and the renaming (`pre_canyon_params` / `post_canyon_params`) removes the ambiguity that caused it. Keep unit tests where the pre-Canyon and Canyon values differ; the old test used 32/32, which hid the bug. Also run kona-client against real mainnet ranges from chains with unset SystemConfig fee parameters in CI before each prestate release.

## References

- Fix commit: e97f03422545946480f1bffbfec995a2c15b9a70 (op-rs/kona#3188; issue op-rs/kona#2993)
- Introduced: 36d81db7e97d6d01fc54345404b284398b7ce413 (op-rs/kona#2874)
- Relevant files: `rust/kona/crates/proof/executor/src/util.rs`, `rust/kona/crates/protocol/genesis/src/params.rs`, `rust/op-alloy/crates/consensus/src/eip1559.rs`
- Spec: https://specs.optimism.io/protocol/holocene/exec-engine.html#eip-1559-parameters-in-block-header
