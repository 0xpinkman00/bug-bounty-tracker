# kona-derive / kona-genesis — malformed SystemConfig update logs halted derivation (and later skipped valid updates) — divergence from op-node

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/protocol/derive/src/stages/traversal/{polling,indexed,mod}.rs`, `rust/kona/crates/protocol/derive/src/attributes/stateful.rs`, `rust/kona/crates/protocol/genesis/src/system/config.rs` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | Causes network processing nodes to halt (kona-node) and a kona fault-proof-program failure. Bug 3 is an unintended chain split (config divergence). All three need a log emitted by the SystemConfig contract, i.e. a trusted role |
| **Fix commit(s)** | `648778dea27e62a146cdcedb1fc68b88c0a0dc07` (PR #19358) — 2026-03-12; `1e2b9769611aa41fa7ff2d6584511e1323eff973` (PR #19503, audit finding AQ-10) — 2026-03-14; `400e2d02de46581fdcf0bb4d887facf977000c16` (PR #19688) — 2026-03-23 |
| **Vulnerable since** | Traversal: predates kona's monorepo import (`48a7a09bfc`). Attributes builder: divergent since op-node made the error non-fatal in `d67e74816e` (PR #18292, 2025-11-20). Bug 3: from `648778dea2` to `400e2d02de` |

## Brief / Intro

The L2 chain's settings (batcher address, fee scalars, gas limit, EIP-1559 parameters and so on) live in the `SystemConfig` contract on L1. Every change is emitted as a `ConfigUpdate` log, and rollup nodes replay these logs while deriving L2. op-node treats a log it cannot decode as "informational": it skips that log, applies all the others, and carries on. kona instead treated any undecodable log as a fatal error and stopped deriving for good. That applied both in its L1-traversal stage and in its payload-attributes builder. After the first fix made the error non-fatal, a second difference remained: one bad log made kona skip every later valid update in the same L1 block, which op-node would still apply. Only the SystemConfig contract can emit these logs, so triggering any of this needs the chain owner or a contract upgrade.

## Vulnerability Details

### Bug 1 — L1 traversal: Critical error on any update error (fixed by `648778dea2`)

Parent `rust/kona/crates/protocol/derive/src/stages/traversal/polling.rs:103-119` (`IndexedTraversal::provide_next_block` was identical):

```rust
match self.system_config.update_with_receipts(&receipts[..], addr, active) {
    Ok(true) => { ... info!("System config updated at block {next}.") }
    Ok(false) => { /* Ignore, no update applied */ }
    Err(err) => {
        error!(target: "l1_traversal", ?err, "Failed to update system config at block {}", ...);
        ...
        return Err(PipelineError::SystemConfigUpdate(err).crit());   // permanent halt
    }
}
```

op-node, `op-node/rollup/derive/l1_traversal.go:78-82`:

```go
if err := UpdateSystemConfigWithL1Receipts(&l1t.sysCfg, receipts.Geth(), l1t.cfg, nextL1Origin.Time); err != nil {
    // failure to apply is just informational, so we just log the error and continue
    l1t.log.Warn("failed to fully update L1 sysCfg with receipts from block", ...)
}
```

Fix: the `Err` arm logs a warning and continues.

### Bug 2 — Attributes builder: Critical error on any update error (fixed by `1e2b976961`, AQ-10)

Parent `rust/kona/crates/protocol/derive/src/attributes/stateful.rs:114-120`:

```rust
sys_config
    .update_with_receipts(&receipts, self.rollup_cfg.l1_system_config_address, ...)
    .map_err(|e| PipelineError::SystemConfigUpdate(e).crit())?;
```

op-node used to do the same, but since `d67e74816e` (2025-11-20) `op-node/rollup/derive/attributes.go:99-101` ignores the error:

```go
// errors from UpdateSystemConfigWithL1Receipts are ignored as they represent malformed or invalid updates
// and there is no recovery mechanism for malformed updates, we must process past them.
_ = UpdateSystemConfigWithL1Receipts(&sysConfig, receipts.Geth(), ba.rollupCfg, info.Time())
```

Fix: kona logs a warning and continues.

### Bug 3 — one bad log aborts all later updates in the block (fixed by `400e2d02de`)

Parent `rust/kona/crates/protocol/genesis/src/system/config.rs:122-147`:

```rust
for receipt in receipts {
    if Eip658Value::Eip658(false) == receipt.status { continue; }
    receipt.logs.iter().try_for_each(|log| {
        if log.address == l1_system_config_address && !topics.is_empty() && topics[0] == CONFIG_UPDATE_TOPIC {
            self.process_config_update_log(log, ecotone_active)?;   // first error aborts everything after it
            updated = true;
        }
        Ok::<(), SystemConfigUpdateError>(())
    })?;
}
```

op-node's `UpdateSystemConfigWithL1Receipts` (`op-node/rollup/derive/system_config.go:44-65`) processes every log and joins the errors with `errors.Join`, so valid updates after a bad one are still applied. Once Bugs 1 and 2 made the error non-fatal, this difference became a silent **config** divergence. For example, a batcher, gas-limit or fee-parameter update that follows a bad log in the same L1 block is applied by op-node but not by kona.

Fix: `update_with_receipts` now folds over every matching log and returns `(applied_kinds, errors)`. Both callers go through a shared `update_system_config_with_receipts` helper that logs the errors and continues.

### Attack scenario

1. The SystemConfig contract emits a `ConfigUpdate` log that kona's decoder rejects. Realistic sources:
   - a SystemConfig upgrade that introduces a new `UpdateType` or event version before kona supports it;
   - an encoding kona validates more strictly than op-node;
   - a buggy upgrade or initializer.
   Only the owner/upgrader controls this; an ordinary user cannot emit logs from the SystemConfig address.
2. **Bugs 1 and 2:** when kona reaches that L1 block, it returns a Critical error. kona-node stops deriving for good, and the kona FPP aborts for every proof whose L1 range includes that block. op-node carries on.
3. **Bug 3:** if a valid update follows the bad log in the same block (for example both are emitted by one upgrade transaction), op-node applies it and kona does not. The two clients then derive with different batcher, gas-limit or fee settings.

## Impact Details

- **kona-node:** permanent halt (Bugs 1 and 2) or a chain split (Bug 3) relative to op-node.
- **kona FPP / cannon-kona games:** an FPP that halts with an error ends in a failing exit status. If that happened, valid claims over the affected L1 range could be "disproven" in kona-backed games, and a split config (Bug 3) could make kona's output roots disagree with the canonical chain.
- **Mitigating factors:**
  - Every trigger needs a log from the SystemConfig contract, which is controlled by the chain's owner or governance (a trusted role).
  - The standard contracts only emit well-formed updates of known types.
  - kona-node is pre-production.
  - Bug 3 only existed for 11 days (between `648778dea2` and `400e2d02de`).
  - For the attributes builder, op-node itself halted on such logs until November 2025, so the divergence there lasted about four months.
- **Severity:** Low (Medium if a real kona-rejects/op-node-accepts log shape reachable by an ordinary SystemConfig upgrade were demonstrated; I did not find one).

## Proof of Concept

**Executed: no.** These are kona crate tests that need a Rust workspace build.

**Bug 1:** the fix rewrote `test_l1_traversal_system_config_update_fails` in `polling.rs`. It builds a chain genesis → block1 → block2, where block2 has a receipt containing a `ConfigUpdate` log with only one topic. On the parent the second `advance_origin()` returns `Critical(SystemConfigUpdate(..))`; with the fix it returns `Ok(())`:

```rust
let bad_log = Log {
    address: TraversalTestHelper::L1_SYS_CONFIG_ADDR,
    data: LogData::new_unchecked(vec![CONFIG_UPDATE_TOPIC], Bytes::default()),  // 1 topic, needs 3
};
provider.insert_receipts(second, vec![Receipt { status: Eip658Value::Eip658(true), logs: vec![bad_log], ..Default::default() }]);
let mut traversal = PollingTraversal::new(provider, Arc::new(rollup_config));
assert!(traversal.advance_origin().await.is_ok());   // genesis -> block1
assert!(traversal.advance_origin().await.is_ok(),    // block1 -> block2: parent FAILS here (Critical)
        "system config update failure should be non-fatal");
```

```sh
cargo test -p kona-derive --lib test_l1_traversal_system_config_update_fails   # on 648778dea2^ vs 648778dea2
```

**Bug 2:** `test_syscfg_update_error_is_nonfatal` (added in `1e2b976961`, `attributes/stateful.rs`) builds epoch-change attributes with a malformed log in the epoch's receipts. The parent returns a Critical error; the fix returns attributes.

**Bug 3:** this test compiles against both the parent API (`Result<bool, _>`) and the fixed API (a tuple), because the return value is discarded. Add it to `mod test` in `rust/kona/crates/protocol/genesis/src/system/config.rs`:

```rust
#[test]
fn poc_bad_log_does_not_block_later_valid_update() {
    let mut cfg = SystemConfig::default();
    let bad = Log {
        address: Address::ZERO,
        data: LogData::new_unchecked(vec![CONFIG_UPDATE_TOPIC], Default::default()), // malformed
    };
    let good = Log {
        address: Address::ZERO,
        data: LogData::new_unchecked(
            vec![
                CONFIG_UPDATE_TOPIC,
                CONFIG_UPDATE_EVENT_VERSION_0,
                b256!("0000000000000000000000000000000000000000000000000000000000000000"), // batcher
            ],
            hex!("00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000beef").into(),
        ),
    };
    let receipt = Receipt { status: Eip658Value::Eip658(true), cumulative_gas_used: 0, logs: vec![bad, good] };
    let _ = cfg.update_with_receipts(&[receipt], Address::ZERO, false);
    // op-node applies the batcher update despite the preceding bad log.
    // Parent (400e2d02de^): batcher_address == 0x0 -> FAIL.  Fix: 0x...beef -> PASS.
    assert_eq!(cfg.batcher_address, address!("000000000000000000000000000000000000beef"));
}
```

```sh
cargo test -p kona-genesis --lib poc_bad_log_does_not_block_later_valid_update   # on 400e2d02de^ vs 400e2d02de
```

## Recommendation

The three fixes together match op-node: errors are logged per log, every valid log is applied, and derivation continues. Suggestions:

- Add a differential test that feeds the same set of well-formed, malformed and unknown-type `ConfigUpdate` logs to op-node's `UpdateSystemConfigWithL1Receipts` and kona's `update_with_receipts`, and compares the resulting `SystemConfig`s.
- When a new SystemConfig `UpdateType` is added, update kona's decoder in the same release. Both clients now skip unknown types, but a type that one client understands and the other skips is still a config divergence.

## References

- Fix commits: `648778dea27e62a146cdcedb1fc68b88c0a0dc07`, `1e2b9769611aa41fa7ff2d6584511e1323eff973`, `400e2d02de46581fdcf0bb4d887facf977000c16`
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/19358, https://github.com/ethereum-optimism/optimism/pull/19503, https://github.com/ethereum-optimism/optimism/pull/19688
- Issue: https://github.com/ethereum-optimism/optimism/issues/19353
- Related op-node change: `d67e74816e` (PR #18292, "SystemConfig: Parse L1 Receipts Atomically Before Application")
- Relevant files: `rust/kona/crates/protocol/derive/src/stages/traversal/{polling,indexed,mod}.rs`, `rust/kona/crates/protocol/derive/src/attributes/stateful.rs`, `rust/kona/crates/protocol/genesis/src/system/config.rs`, `op-node/rollup/derive/{l1_traversal,attributes,system_config}.go`
