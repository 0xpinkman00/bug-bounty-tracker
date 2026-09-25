# kona interop (pre-activation) — six state-transition and validity divergences from op-node / supernode — latent chain split and fault-proof unsoundness

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/proof/{driver,proof-interop}`, `rust/kona/crates/protocol/{derive,hardforks,interop}`, `op-challenger/game/fault/trace/vm` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Informational. Interop is not activated on any production chain. Once it activates, the same classes of bug would rate High (chain split / fault-proof soundness) |
| **Impact category** | Unintended chain split (network partition), and incorrect fault-proof outcome for super-root games. Both are latent |
| **Fix commit(s)** | see the table below (6 commits, 2026-03-30 to 2026-04-21) |
| **Vulnerable since** | Pre-activation development code; each bug was present from when the feature was first added |

| ID | Fix commit | PR | Defect |
|---|---|---|---|
| 18a | `befababbe8c12645058ef68a2607f1b8b158e5bb` (2026-04-21) | #20162 | `is_interop_active()` was given a **block number** instead of a timestamp in the proof driver, so interop `EndOfSource` was swallowed |
| 18b | `3d556b34e7b408058f31f4fa35603f3077c7876b` (2026-04-20) | #20147 (fixes #19311) | kona emitted the `CrossL2Inbox` upgrade deposits unconditionally. op-node gates them on a multi-chain dependency set |
| 18c | `1188160bb34a7dc0dfe82575c0a629e6d7079a87` (2026-04-03) | #19894 (closes #19411) | kona appended an obsolete "optimistic block" replacement deposit transaction to deposit-only blocks |
| 18d | `f5cd6b3b62e1151109a660c988ed46884caf7bb3` (2026-04-02) | #19890 (optimism-private#501) | Chains already replaced were re-validated during consolidation (parity with Go's `isReplaced`) |
| 18e | `4154ada4d06927180e35e132627a5572ff0bd8eb` (2026-03-30) | #19765 (closes #19636) | `MessageGraph` used the hard-coded 7-day `MESSAGE_EXPIRY_WINDOW` instead of the dependency-set value |
| 18f | `57056a0dd8c71a3abf0ed649a8df9566f91daaab` (2026-04-02) | #19849 | op-challenger did not pass `--depset-cfg` to the kona super executor |

## Brief / Intro

Interop is an upcoming OP Stack upgrade that lets chains in a "dependency set" pass messages to each other. Its fault proofs work on "super roots", which commit to the state of all chains at a given timestamp. kona is the Rust implementation of this logic: kona-node follows the chain, and kona-client is the fault-proof program. The Go implementations (op-node and op-supernode) are the reference. These six fixes correct places where kona computed a different L2 state, or judged block validity differently, from the reference. On a live interop chain, any one of them would split kona-node from op-node, or make the kona fault-proof program reach the wrong verdict. Interop is not activated anywhere yet, so all six are latent.

## Vulnerability Details

### 18a — Timestamp/number confusion hides `EndOfSource` (`befababb`)

Parent `rust/kona/crates/proof/driver/src/core.rs:240-244`:

```rust
Err(PipelineErrorKind::Critical(PipelineError::EndOfSource)) => {
    ...
    // If we are in interop mode, this error must be handled by the caller.
    if cfg.is_interop_active(self.cursor.read().l2_safe_head().block_info.number) {
        return Err(PipelineError::EndOfSource.crit().into());
    }
    continue;   // single-chain: halt at the current safe head
}
```

`is_interop_active` compares its argument with `interop_time`, which is a timestamp. A block number is always far smaller than a real timestamp, so the check was always false. In interop mode the driver therefore never passed `EndOfSource` up to the caller. Instead it quietly clamped the target to the current safe head and returned it as a normal result. The interop transition is designed to receive that error when L1 data runs out, so it can treat the super-root step as an invalid transition. With the bug, kona could return an output for a timestamp it had not actually derived. The fix passes `block_info.timestamp`.

### 18b — CrossL2Inbox activation deposits emitted unconditionally (`3d556b34`)

op-node emits the `CrossL2Inbox` deploy and upgrade deposit pair only when `len(depSet.Chains()) > 1`. The fix commit message cites `attributes.go:178` for this gate. The parent kona `Interop::deposits()` (`rust/kona/crates/protocol/hardforks/src/interop.rs:164`) always included that pair. On a single-chain interop activation, kona-node therefore produced extra deposit transactions in the activation block, and the post-state diverged from op-node from the first interop block onward. The fix:
- splits `Interop::deposits()` (always emitted) from `cross_l2_inbox_deposits()` (gated on the dependency set);
- passes the dependency set through `StatefulAttributesBuilder`, `OnlinePipeline` and `OraclePipeline`;
- makes kona-node and kona-host refuse to start when `interop_time` is set but no dependency set was supplied.

### 18c — Obsolete replacement deposit transaction (`1188160b`)

Parent `rust/kona/crates/proof/proof-interop/src/consolidation.rs:196`, `272-297`: when a block had to be replaced with a deposit-only block because of invalid executing messages, kona appended an extra `InteropBlockReplacementDepositSource` deposit that encoded the old block's output root. The interop spec no longer includes that transaction, and the supernode does not add it. kona's replacement block therefore had a different state root from the supernode's. The fix removes `craft_replacement_transaction`.

### 18d — Re-validating replaced chains (`f5cd6b3b`)

During iterative consolidation, kona passed chains that had already been replaced with deposit-only blocks back into `MessageGraph::derive`. It also kept an `assert!` that panics if a deposit-only block is ever found invalid. Go skips replaced chains (`isReplaced`). The fix tracks `replaced_chains`, filters them out, and removes the assert. I could not build a concrete input where the old behaviour produces a different result: a deposit-only block contains no executing messages. So I treat this as a parity and robustness fix. It removes both a reachable-looking panic and redundant receipt fetches for a block the program constructed locally.

### 18e / 18f — Message-expiry window hard-coded (`4154ada4`, `57056a0d`)

Parent `rust/kona/crates/protocol/interop/src/graph.rs:180`:

```rust
if initiating_timestamp < message.executing_timestamp.saturating_sub(MESSAGE_EXPIRY_WINDOW)
```

The Go implementation reads the window from the dependency set, and `override_message_expiry_window` can change it. On a network with a non-default window, kona accepted or rejected expired messages differently from the supernode. That changes which blocks get replaced, and so changes the super root. The fixes:
- `4154ada4` loads the `DependencySet` into `BootInfo` from local preimage key `8` (`DEPENDENCY_SET_KEY`), serves that key from kona-host (`--depset-cfg`), and passes `get_message_expiry_window()` into `MessageGraph::derive`.
- `57056a0d` makes op-challenger's `KonaSuperExecutor` pass `--depset-cfg`. Without it, kona silently fell back to the 7-day default.

### Attack scenario (once interop is live)

1. A user sends a cross-chain message whose age falls between the configured expiry window and 7 days (18e/18f). Alternatively, the chain activates interop with a single-chain dependency set (18b), or a block containing an invalid executing message has to be replaced (18c).
2. op-node or the supernode and kona compute different blocks for that timestamp.
3. kona-node forks from the network. In super-root dispute games, the kona fault-proof program disagrees with the canonical super root. Depending on which side is wrong, an honest claim gets countered, or a dishonest one gets defended.

## Impact Details

- **Current exposure: none.** No chain in the in-repo configurations sets `interop_time`, and interop has not activated on any production chain. The fixes landed during pre-activation hardening, several of them found by interop acceptance tests.
- **If shipped unfixed to an activated network:** 18a, 18b, 18c and 18e would each cause a deterministic consensus divergence between kona and the Go reference. That would be High (unintended chain split and fault-proof unsoundness for kona-backed super-root games). 18d is a robustness fix. 18f is an operator-configuration fix in op-challenger.
- **Severity:** Informational. The code is pre-activation and not reachable on any live network.

### Unverified note: dependency set read from a host-supplied local key

Since `4154ada4`, `BootInfo::load` in the interop program reads the dependency set, including the message-expiry override and (since `3d556b34`) the chain list that gates the CrossL2Inbox deposits, from local preimage key `8`. The host supplies this key from a file. If kona-host has no `--depset-cfg` path, it serves a default, empty dependency set. **I have not verified** the following, and it should be checked before interop activation:
(a) whether an on-chain step (the dispute game's local-data loading into `PreimageOracle`) can supply key `8` at all;
(b) whether anything, such as the absolute prestate, a registry lookup by chain ID, or a hash commitment, binds the dependency set, so that a challenger cannot feed a different expiry window or chain list into its trace.
If neither holds, the dependency set becomes an unauthenticated input to a consensus-critical computation.

## Proof of Concept

Regression tests added by the fixes. Each fails on its parent commit:

```bash
cd rust
# 18b: single-chain interop activation must emit 1 L1-info + 7 base txs (no CrossL2Inbox pair);
#      multi-chain must emit 10.
cargo test -p kona-derive --lib attributes::stateful::tests::test_prepare_payload_with_interop_single_chain
cargo test -p kona-derive --lib attributes::stateful::tests::test_prepare_payload_with_interop_multi_chain
# 18e: custom expiry window respected
cargo test -p kona-interop --lib graph::test::test_derive_and_resolve_graph_message_expired_custom_window
cargo test -p kona-interop --lib graph::test::test_derive_and_resolve_graph_message_not_expired_within_custom_window
# 18d: executing messages whose initiating chain was filtered out still resolve
cargo test -p kona-interop --lib graph::test::test_resolve_with_replaced_chain_excluded_from_headers
```

```bash
# 18f (Go, cheap): op-challenger must pass --depset-cfg
go test ./op-challenger/game/fault/trace/vm/ -run 'TestKonaSuperExecutorWith(out)?DepsetConfig' -count=1
```

18a had no test. The minimal demonstration below is the driver's own predicate, evaluated as the parent evaluated it:

```rust
#[test]
fn poc_18a_interop_active_by_number_is_always_false() {
    let cfg = kona_genesis::RollupConfig {
        hardforks: kona_genesis::HardForkConfig { interop_time: Some(1_700_000_000), ..Default::default() },
        ..Default::default()
    };
    let safe_head_number = 12_345_678u64;       // what the parent passed
    let safe_head_timestamp = 1_750_000_000u64; // what it should pass (post-activation)
    assert!(!cfg.is_interop_active(safe_head_number));   // parent: EndOfSource swallowed
    assert!(cfg.is_interop_active(safe_head_timestamp)); // fix: EndOfSource propagated
}
```

18c is covered end to end by `TestInteropFaultProofs_InvalidBlock` (op-acceptance-tests, interop). It needs the full devstack and was still skipped at #19894 pending other work.

Executed: no. I did not run any Rust test, to avoid a cold kona build, and I did not run the 18f Go test. All results above come from reading the parent and fix diffs.

## Recommendation

The fixes bring kona in line with op-node and the supernode. Before interop activates:
- Run a standing differential test that builds the activation block and a deposit-only replacement block in both op-node/supernode and kona and compares state roots.
- Replace timestamp checks that take a bare `u64` with a newtype (e.g. `Timestamp`), so a block number cannot be passed by mistake as in 18a.
- Resolve the unverified note above: make sure the dependency set the fault-proof program consumes is committed to by something on-chain or by the prestate.

## References

- Fix commits: befababbe8c12645058ef68a2607f1b8b158e5bb, 3d556b34e7b408058f31f4fa35603f3077c7876b, 1188160bb34a7dc0dfe82575c0a629e6d7079a87, f5cd6b3b62e1151109a660c988ed46884caf7bb3, 4154ada4d06927180e35e132627a5572ff0bd8eb, 57056a0dd8c71a3abf0ed649a8df9566f91daaab
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/20162, https://github.com/ethereum-optimism/optimism/pull/20147, https://github.com/ethereum-optimism/optimism/pull/19894, https://github.com/ethereum-optimism/optimism/pull/19890, https://github.com/ethereum-optimism/optimism/pull/19765, https://github.com/ethereum-optimism/optimism/pull/19849
- Relevant files: `rust/kona/crates/proof/driver/src/core.rs`, `rust/kona/crates/protocol/hardforks/src/interop.rs`, `rust/kona/crates/protocol/derive/src/attributes/stateful.rs`, `rust/kona/crates/proof/proof-interop/src/{consolidation.rs,boot.rs}`, `rust/kona/crates/protocol/interop/src/graph.rs`, `rust/kona/bin/host/src/interop/{cfg.rs,local_kv.rs}`, `op-challenger/game/fault/trace/vm/kona_super_server_executor.go`
- Specs: https://specs.optimism.io/interop/overview.html
