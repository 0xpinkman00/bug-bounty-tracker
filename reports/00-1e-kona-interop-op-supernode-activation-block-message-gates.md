# Interop activation-boundary checks missing or wrong in kona `MessageGraph` and op-supernode, so node and fault-proof validity of executing messages diverge

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/protocol/interop/src/graph.rs` (kona-client interop FPP), `op-supernode/supernode/activity/interop/algo.go` (op-supernode cross-chain verifier) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | Unintended chain split (network partition) between op-supernode and the interop fault-proof program, in pre-activation interop code. No live network impact. |
| **Fix commit(s)** | 470272fc6bc56151ed20690297e07c54ea7f5793 (PR #20550), 2026-05-05; 2cc552564b58c78ba01184fc84d369ac59355813 (PR #20579), 2026-05-11; e45f4ca007569a0429e66d6657dae51e21acc89f (PR #20716), 2026-05-13 |
| **Vulnerable since** | kona: before the monorepo import (2026-02-10). op-supernode: since `verifyExecutingMessage` was introduced. All fixes are in `kona-client/v1.5.2` and later. |

## Brief / Intro

With OP Stack interop, a transaction on one chain can consume an "executing message" that points at a log (the "initiating message") emitted on another chain. The spec says the block in which interop activates is special: no executing message may appear in it, and no log in it (or before it) may be used as an initiating message. Every component must enforce the same rule, or they disagree about which blocks are valid. Three components got this wrong in different ways. kona's fault-proof program did not apply the rule on the executing side. kona treated a chain with no interop activation as having activated at time 0. op-supernode, the node that decides which interop blocks are safe, did not apply the rule at all. None of this was live: interop (the Lagoon hardfork) had not activated on any public network when these were fixed.

## Vulnerability Details

### A. kona: no executing-chain activation guard (470272fc6b)

`MessageGraph::check_single_dependency` (`graph.rs:346-382` at `470272fc6b^`) checked activation only for the **initiating** chain. The fix adds the executing-side guard, which op-supervisor (`depset/links.go` `CanExecute`) and op-program already had:

```rust
if !exec_rollup_config.is_interop_active(message.executing_timestamp) ||
    exec_rollup_config.is_first_interop_block(message.executing_timestamp)
{
    return Err(MessageGraphError::ExecutedTooEarly { .. });
}
```

**Reachability.** An executing message is an `ExecutingMessage` log emitted by the `CrossL2Inbox` predeploy. In the activation block, derivation orders transactions as L1-info deposit, then user deposits, then upgrade transactions (`op-node/rollup/derive/attributes.go:192-195`). The interop upgrade transactions that deploy and activate `CrossL2Inbox` (`InteropNetworkUpgradeTransactions`, `InteropActivateCrossL2InboxTransactions`) therefore run **after** every user-controlled transaction in that block. User transactions are also not allowed in fork-activation blocks. So a user cannot produce a valid `ExecutingMessage` log in the activation block, and in practice this gap is unreachable. It is a spec-parity fix.

### B. kona: `interop_time = None` treated as activation at time 0 (2cc552564b)

The parent code is at `graph.rs:375-382`:

```rust
} else if initiating_timestamp <
    rollup_config.hardforks.interop_time.unwrap_or_default() + rollup_config.block_time
{
    return Err(MessageGraphError::InitiatedTooEarly { .. });
}
```

When the initiating chain's rollup config has `interop_time = None`, the bound becomes `ts < 0 + block_time`. That is false for every real timestamp, so **any log** on that chain is accepted as an initiating message. op-supervisor's `IsInterop(ts)` is false when `InteropTime == nil`. The fix uses `!is_interop_active(ts) || is_first_interop_block(ts)`, which rejects `None`.

**Reachability.** This only matters if the dependency set contains a chain whose rollup config (embedded registry or oracle-supplied) has no interop time. That is a configuration inconsistency, not something an ordinary user can cause. The logs are real logs on the other chain, so calling them "forged" overstates it: the problem is accepting logs from a chain that is not interop-enabled.

### C. op-supernode: no activation guard on either side (e45f4ca007)

The parent code is at `op-supernode/supernode/activity/interop/algo.go:174-211`. `verifyExecutingMessage` checked existence in the source chain's logs DB, timestamp ordering and expiry. It **never consulted `i.activationTimestamp`**:

```go
func (i *Interop) verifyExecutingMessage(executingChain eth.ChainID, executingTimestamp uint64, logIdx uint32, execMsg *types.ExecutingMessage, view *frontierVerificationView) error {
    sourceDB, ok := i.logsDBs[execMsg.ChainID]
    ...
    if execMsg.Timestamp > executingTimestamp { ... ErrTimestampViolation }
    if execMsg.Timestamp+i.messageExpiryWindow < executingTimestamp { ... ErrMessageExpired }
    ...
    _, err := sourceDB.Contains(query)
    return err
}
```

The supernode's logs DB is populated from `activationTimestamp` **inclusive** (`interop.go:314-315`, `log_backfill.go`). So logs emitted **in the activation block** are present and pass `Contains`. Such logs include the events emitted by the interop upgrade transactions themselves, and events from user deposits included in that block. The fix adds both guards:

```go
if executingTimestamp < i.activationTimestamp+execChain.BlockTime() { ... ErrExecutedTooEarly }
if execMsg.Timestamp < i.activationTimestamp+initChain.BlockTime() { ... ErrInitiatedTooEarly }
```

**Reachability.** The initiating side is reachable by any user once interop is active. Send a transaction in block N > activation whose `CrossL2Inbox.validateMessage` call references a log from the activation block of a chain in the dependency set, for example a proxy `Upgraded` event emitted by the upgrade transactions. The parent op-supernode accepts it and marks block N cross-safe. kona and op-program reject it (kona's initiating-side check already covered the aligned activation block), so the fault proof would replace block N with a deposits-only block.

### Attack scenario (C, had interop been live)

1. Interop activates at timestamp `T_act` for chains A and B. The activation block on A emits an upgrade-transaction event `E`.
2. At `T > T_act + blockTime`, the attacker sends a transaction on B that executes a message identifying `E` (chain A, block at `T_act`, log index, checksum), for example an `L2ToL2CrossDomainMessenger`-style consumer that trusts `validateMessage`.
3. op-supernode (parent) validates the message and promotes B's block to cross-safe and eventually finalized. Light-CL op-nodes that follow the supernode do the same.
4. The fault proof (kona `MessageGraph`) marks the message invalid and replaces the block with deposits only. The supernode's safe chain and the provable chain diverge. Proposals built from supernode output roots lose their dispute games (proposer bond loss), and applications that acted on the cross-safe state acted on a block the protocol does not recognise.

## Impact Details

- **Live impact:** none. Lagoon/interop activation is "Not scheduled" for Mainnet and Sepolia in the registry snapshot (`docs/public-docs/snippets/generated/hardforks/lagoon.mdx`). The first testnet activation was planned for July 2026 (`docs/public-docs/notices/interop-prep.mdx`). All three fixes landed in May 2026 and are in `kona-client/v1.5.2` and later, including the U19 `cannon64-kona-interop` prestate (`v1.6.0-rc.2`).
- **Potential impact if live:** (C) is a divergence between the interop safety oracle (op-supernode) and the fault-proof program that any user can trigger. It would cause proposer bond loss and wrongly-safe blocks: Medium. (B) needs a config inconsistency. (A) is unreachable, as argued above.
- **Severity:** **Low** overall, because all of this is pre-activation code.

## Proof of Concept

**op-supernode (C).** The fix adds six `ActivationBoundary/*` rows to `TestVerifyInteropMessages` (`algo_test.go`). With `activationTs=1000` and block time 1, these rows fail on the parent (the result is valid when it should be invalid):

| Case | execTs | initTs | Expected |
|---|---|---|---|
| `ExecutingSide` | 1000 | 999 | invalid |
| `InitiatingSide` | 1001 | 1000 | invalid (log in activation block) |
| `PreActivationInitiating` | 1001 | 999 | invalid |
| `UnalignedActivation` (act=1, bt=2) | 2 | 2 | invalid |

```bash
go test ./op-supernode/supernode/activity/interop/ -run 'TestVerifyInteropMessages/ActivationBoundary' -count=1 -v
# parent (separate worktree at e45f4ca007^ with algo_test.go from e45f4ca007): the four rows above FAIL
# fix: all six rows pass
```

The Go package needs the generated `op-core/superchain/superchain-configs.zip`. In this review environment the build stopped at `pattern superchain-configs.zip: no matching files found`, so run the repo's superchain setup first.

**kona (A, B).** Unit tests in `rust/kona/crates/protocol/interop/src/graph.rs`:
- `test_derive_and_resolve_graph_executing_before_interop`, `..._unaligned_activation`, `..._executing_at_interop_activation` (from 470272fc6b): expect `ExecutedTooEarly`. On the parent the message resolves as valid.
- `test_derive_and_resolve_graph_initiating_chain_interop_time_none_rejected` (from 2cc552564b): sets the initiating chain's `interop_time = None` and expects chain B's executing message to be invalid. On the parent `resolve()` succeeds.

```bash
cd rust && cargo test -p kona-interop --lib graph::test
```

Executed: no. The Go test was attempted on the current tree but failed at setup because of the missing generated superchain configs archive.

## Recommendation

The fixes make all three activation gates symmetric: "interop active **and** not the first interop block" on both the executing and the initiating side, in kona and in op-supernode. They also treat an unset `interop_time` as "never active".

Further suggestions:
- Express the activation rule once, as a shared predicate with a shared test vector, for op-supernode, kona `MessageGraph` and op-interop-filter. The later fix `33fbe016b8` ("op-interop-filter: Reject pre-Lagoon initiating messages") shows the same gap existed in a fourth component.
- In op-supernode, do not index logs from the activation block into the verifiable logs DB. The guard would then hold by construction.

## References

- Fix commits: 470272fc6bc56151ed20690297e07c54ea7f5793, 2cc552564b58c78ba01184fc84d369ac59355813, e45f4ca007569a0429e66d6657dae51e21acc89f
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/20550, https://github.com/ethereum-optimism/optimism/pull/20579, https://github.com/ethereum-optimism/optimism/pull/20716 (issue #20684)
- Relevant files: `rust/kona/crates/protocol/interop/src/{graph.rs,errors.rs}`, `op-supernode/supernode/activity/interop/{algo.go,interop.go,log_backfill.go}`, `op-node/rollup/derive/attributes.go`
- Spec: https://specs.optimism.io/interop/messaging.html (message validity, activation block)
