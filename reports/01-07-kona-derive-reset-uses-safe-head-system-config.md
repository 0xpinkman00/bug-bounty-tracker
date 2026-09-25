# kona-derive — pipeline reset seeds L1 traversal with the safe head's SystemConfig instead of the walked-back one — batcher-rotation derivation divergence from op-node

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/protocol/derive/src/pipeline/core.rs`, `stages/traversal/{polling,indexed}.rs`, `rust/kona/crates/proof/proof/src/l1/pipeline.rs`, `rust/kona/crates/node/engine/src/task_queue/core.rs` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | Unintended chain split (network partition) between kona-node and op-node, and a kona fault-proof-program divergence. It needs a trusted-role action (batcher rotation) plus an unusual channel layout |
| **Fix commit(s)** | `31703ba851fbda67c661923e423650563aeefaa5` (PR #19792, optimism-private#452) — 2026-04-01 |
| **Vulnerable since** | Predates kona's import into the monorepo (`48a7a09bfc`, feat(rust): unify workspaces) |

## Brief / Intro

When a rollup node (re)starts derivation, it cannot start reading L1 exactly at the safe head's L1 block, because a channel (a bundle of compressed L2 batches) may have started up to `channel_timeout` L1 blocks earlier. So it rewinds L1 by that window and replays forward. While replaying, it must use the chain configuration (above all, which address is the authorized **batcher**) that was valid at the *start* of the window, and then apply any SystemConfig changes it sees on the way. op-node does exactly this. kona instead started the replay with the configuration of the *safe head*, i.e. the end of the window. If the batcher address changed inside the window, kona filtered batcher transactions with the wrong address for part of the replay, so it could derive a different L2 chain from op-node.

## Vulnerability Details

op-node's reference (`op-node/rollup/derive/pipeline.go:225-268`, `initialReset`) walks back **L2** blocks until their L1 origin is at least `ChannelTimeout` before the safe head's origin. It then uses `SystemConfigByL2Hash(pipelineL2)` of that walked-back L2 block as the traversal's starting config.

kona before the fix (parent of `31703ba851`):

`rust/kona/crates/protocol/derive/src/pipeline/core.rs:96-106`: the pipeline always resolved the config at the **safe head**:

```rust
mut s @ (Signal::Reset(ResetSignal { l2_safe_head, .. }) |
Signal::Activation(ActivationSignal { l2_safe_head, .. })) => {
    let system_config = self
        .l2_chain_provider
        .system_config_by_number(
            l2_safe_head.block_info.number,          // <-- safe head, not walked back
            Arc::clone(&self.rollup_config),
        )
        .await
        .map_err(Into::into)?;
    s = s.with_system_config(system_config);
```

`stages/traversal/polling.rs:146-149` then installed that config together with the walked-back L1 origin:

```rust
Signal::Reset(ResetSignal { l1_origin, system_config, .. }) | ... => {
    self.block = Some(l1_origin);
    self.system_config = system_config.expect("System config must be provided.");
```

The walked-back L1 origin came from `new_oracle_pipeline_cursor` in the FPP (`proof/src/sync.rs`, `safe.l1_origin - channel_timeout`) and from `Engine::reset` in kona-node (`task_queue/core.rs:120`). In both paths the system config was the safe head's (`proof/src/l1/pipeline.rs:86`, `task_queue/core.rs:136`).

The result: on replay of L1 blocks `[safe.l1_origin - channel_timeout, X)`, where `X` is the L1 block containing a batcher-rotation `ConfigUpdate` log, kona filters batch-inbox transactions by the **new** batcher `B`, while op-node filters by the **old** batcher `A`. Frames `A` posted before `X` are dropped by kona and kept by op-node. Frames `B` posted before `X` are kept by kona and dropped by op-node.

The fix adds `DerivationPipeline::initial_reset`, a port of op-node's L2 walk-back that returns both the L1 origin and the config of the walked-back L2 block:

```rust
loop {
    let before_l2_genesis = current.block_info.number <= self.rollup_config.genesis.l2.number;
    let before_l1_genesis = current.l1_origin.number <= self.rollup_config.genesis.l1.number;
    let before_channel_timeout = current.l1_origin.number + channel_timeout <= l1_origin_number;
    if before_l2_genesis || before_l1_genesis || before_channel_timeout { break; }
    current = self.l2_chain_provider.l2_block_info_by_number(current.block_info.number - 1).await...?;
}
let system_config = self.l2_chain_provider
    .system_config_by_number(current.block_info.number, Arc::clone(&self.rollup_config)).await...?;
Ok((current.l1_origin, system_config))
```

`ResetSignal` now carries only `l2_safe_head`, so callers can no longer pass a mismatched origin and config. Activation became a soft reset that does not touch the traversal config.

### Attack scenario

This is a divergence under specific operational conditions, not an attacker-driven exploit:

1. The chain operator rotates the batcher from `A` to `B` via `SystemConfig.setBatcherHash` at L1 block `X`.
2. A channel spans the rotation. For example, the new batcher `B` is started before the `ConfigUpdate` lands and opens a channel whose first frames are posted before `X` and whose last frames come after `X`. Or the old batcher's channel is completed by `B`.
3. A kona-node is reset (restart, reorg, engine reset), or a kona FPP run starts, with a safe head whose L1 origin is at or after `X` but within `channel_timeout` of it.
4. kona sees a different set of frames from op-node in the window. It can assemble a channel op-node drops, or miss one op-node assembles, so it marks different L2 blocks safe from different L1 data.

## Impact Details

- **kona-node:** safe/finalized head divergence from op-node. It is usually only a timing difference, because both clients end up deriving the honest batcher's blocks. It becomes a content divergence only if one side hits sequencing-window expiry and falls back to deposit-only blocks.
- **kona FPP (cannon-kona games):** the program proves "block N is safe given L1 head H" from a different set of frames than op-node/op-program. A disagreement over when N becomes safe could make an honest kona-backed challenger's trace disagree with the canonical `optimism_outputAtBlock` for claims near the rotation.
- **Preconditions and mitigations:**
  - A batcher rotation, which only the SystemConfig owner can do.
  - A channel that straddles the rotation, which a well-run rotation avoids.
  - A reset or proof start within `channel_timeout` L1 blocks (50 post-Granite) of the rotation.
  - Only kona is affected. kona-node is pre-production. op-node and op-program were never affected.
- **Severity:** Low. The class (derivation divergence) is serious, but reaching it needs a trusted-role action with an unusual channel layout inside a short window.

## Proof of Concept

**Executed: no.** Building kona-derive needs a full Rust workspace build, which I did not run.

The fix's regression test `test_initial_reset_walks_back_system_config` (`pipeline/core.rs`) calls `initial_reset`, which does not exist on the parent. The test below compiles on **both** the parent and the fix, because it uses only `Signal::Reset` and `ResetSignal { l2_safe_head, ..Default::default() }`. It shows which L2 block's config the reset asks for. Only block 90 (the walked-back block) has a config in the provider:

- On the parent, the reset requests the safe head's config (block 100) and fails with `SystemConfigNotFound(100)`.
- With the fix, the reset requests block 90's config and succeeds.

Add to `mod tests` in `rust/kona/crates/protocol/derive/src/pipeline/core.rs`:

```rust
#[tokio::test]
async fn poc_reset_uses_walked_back_system_config() {
    use alloy_eips::BlockNumHash;
    use alloy_primitives::address;
    let rollup_config = Arc::new(RollupConfig { channel_timeout: 10, ..Default::default() });
    let mut l2 = TestL2ChainProvider::default();
    // L2 blocks 89..=100; block N has L1 origin N-50. Safe head = 100 (origin 50).
    for n in 89u64..=100 {
        l2.blocks.push(L2BlockInfo {
            block_info: BlockInfo { number: n, ..Default::default() },
            l1_origin: BlockNumHash { number: n - 50, ..Default::default() },
            seq_num: 0,
        });
    }
    // Only the walked-back block (90, origin 40 = 50 - channel_timeout) has a config: old batcher.
    l2.system_configs.insert(
        90,
        SystemConfig { batcher_address: address!("000000000000000000000000000000000000aaaa"), ..Default::default() },
    );
    let mut pipeline = DerivationPipeline::new(TestNextAttributes::default(), rollup_config, l2);
    let safe = L2BlockInfo {
        block_info: BlockInfo { number: 100, ..Default::default() },
        l1_origin: BlockNumHash { number: 50, ..Default::default() },
        seq_num: 0,
    };
    // Parent: Err(Temporary(Provider("System config not found"))) (lookup of block 100) -> FAIL
    // Fix:    Ok(())                                                              -> PASS
    pipeline
        .signal(Signal::Reset(ResetSignal { l2_safe_head: safe, ..Default::default() }))
        .await
        .expect("reset must use the walked-back (block 90) system config");
}
```

Run (from `rust/`, on a checkout of `31703ba851^` and then `31703ba851`):

```sh
cargo test -p kona-derive --lib poc_reset_uses_walked_back_system_config
```

The fix's own test `test_initial_reset_walks_back_system_config` also asserts directly that the old batcher `0x…aaaa` from block 90 is returned rather than the new batcher `0x…bbbb` from block 100.

## Recommendation

The fix ports op-node's `initialReset` and makes the pipeline the single authority for the reset origin and config, which closes the issue. Suggestions:

- Add an action/e2e test that rotates the batcher and resets a kona-node and the kona FPP within `channel_timeout` blocks of the rotation, and compares the output against op-node.
- Keep the FPP cursor's L1 walk-back (restored during review) consistent with `initial_reset`, so preimages for the walked-back L1 range are always available.

## References

- Fix commit: `31703ba851fbda67c661923e423650563aeefaa5`
- Pull request: https://github.com/ethereum-optimism/optimism/pull/19792
- Private tracker: ethereum-optimism/optimism-private#452
- Reference implementation: `op-node/rollup/derive/pipeline.go` (`initialReset`)
- Relevant files: `rust/kona/crates/protocol/derive/src/pipeline/core.rs`, `rust/kona/crates/protocol/derive/src/stages/traversal/polling.rs`, `rust/kona/crates/proof/proof/src/l1/pipeline.rs`, `rust/kona/crates/proof/proof/src/sync.rs`, `rust/kona/crates/node/engine/src/task_queue/core.rs`
