# op-interop-filter / op-reth txpool / op-rbuilder — interop admission gaps let txs with invalid or unsafe executing messages reach sequencer blocks (incl. during failsafe)

| Field | Value |
|---|---|
| **Target** | `op-interop-filter/filter`, `rust/op-reth/crates/txpool/src/maintain.rs`, `rust/op-rbuilder/crates/op-rbuilder/src/builders/context.rs` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk |
| **Fix commit(s)** | 33fbe016b879d3c4a5187516cbab7668b4527627 (PR #22886), 2026-09-22; bdcf49a00d8d18104dde78c674f08c10dd70e8eb (PR #21447), 2026-06-23; 2bb37eb2e5999b49e52edd384f7ebf19d02e4703 (PR #21494), 2026-06-24 |
| **Vulnerable since** | Introduction of the respective interop admission code (exact commits unknown) |

## Brief / Intro

On an interop chain, a user transaction can "execute" a message sent from another chain by pointing at the log that initiated it. Nothing on-chain checks that the pointer is valid. The sequencer's software is expected to keep bad ones out of blocks. If one slips in, the block has to be invalidated and replaced later, which disrupts every chain in the interop set (see 00-3b). There are three admission layers: op-interop-filter (the validity oracle), the op-reth transaction pool, and the op-rbuilder block builder. Each had a gap that let invalid, stale or deliberately disallowed interop transactions through. One of those gaps also defeated the operator's emergency "failsafe" switch, which is supposed to stop all interop transactions.

**Interop status:** Lagoon/interop was not active on any production network while these bugs were live, and it is still not scheduled at HEAD (`docs/public-docs/snippets/generated/hardforks/lagoon.mdx`: "Not scheduled"; no `lagoon_time` in `rust/kona/crates/protocol/registry/etc/configs.json`). Before activation, op-reth rejects interop txs outright (`CrossChainTxPreInterop`).

## Vulnerability Details

### Bug 1: op-interop-filter accepts initiating messages from before or at Lagoon activation (33fbe016b8)

Parent commit, `op-interop-filter/filter/lockstep_cross_validator.go:167-...`:

```go
func validateMessageTiming(
    initTimestamp, inclusionTimestamp, messageExpiryWindow, timeout, execTimestamp uint64,
) error {
    // Rule 1: init must be strictly before inclusion
    if initTimestamp >= inclusionTimestamp { ... }
    ...
```

There was no check against the *source* chain's activation. The ingester back-fills logs from before Lagoon (`calculateStartingBlock` goes back `backfillDuration`). Any retained pre-activation log, or a log in the activation block itself, could therefore be referenced by an executing message and pass both `ValidateAccessEntry` (tx admission) and the background validation. The protocol (and op-supernode, and kona, see triage entry 1e) treats such messages as invalid, so the block that includes them gets invalidated. Fix:

```go
if !ingester.IsValidInitiatingTimestamp(initTimestamp) {   // IsInterop(ts) && !IsInteropActivationBlock(ts)
    return fmt.Errorf("initiating message on chain %s at timestamp %d is not after the Lagoon activation block: %w", ...)
}
```

Fresh databases also wait for the source activation block before ingesting.

### Bug 2: op-reth interop txpool kept invalid txs buildable (bdcf49a00d)

Parent commit, `rust/op-reth/crates/txpool/src/maintain.rs`:

- **Invalid verdict not evicted** (`:235-239`): revalidation removed a tx only if `err.is_bad_transaction()`. That predicate is reth's peer-penalty question, and it returned true only for `CrossChainTxPreInterop`. A definitive `InvalidEntry`/`Rejected` verdict from the filter left the tx pooled and **buildable until its ~2h cached deadline**.
  ```rust
  Some(Err(err)) => {
      if err.is_bad_transaction() {          // false for ValidationError(_)
          to_remove.push(*tx_item_from_stream.hash());
      }
  }
  ```
- **Private txs never revalidated** (`:124`, `:202`): the sweeps and the failsafe eviction iterated `pool.pooled_transactions()`, which skips `propagate=false` (Private-origin) txs, for example those submitted through `eth_sendRawTransactionConditional`. The builder still selects them through `best_transactions()`. They were therefore never revalidated and **never evicted on failsafe**.
- **Reorgs ignored** (`:173`, `if let CanonStateNotification::Commit { new } = event`): a `Reorg` notification was silently dropped. A local reorg can remove the initiating log that a pooled tx depends on.

The fix adds `InvalidCrossTx::is_now_invalid()`, scans `pool.all_transactions()`, and evicts all interop txs on `Reorg`.

### Bug 3: op-rbuilder ignored failsafe and deadlines (2bb37eb2e5)

Parent commit, `rust/op-rbuilder/crates/op-rbuilder/src/builders/context.rs:533`:

```rust
// TODO: remove this condition and feature once we are comfortable enabling interop for everything
if cfg!(feature = "interop") {
    if let Some(interop) = interop && !is_valid_interop(interop, self.config.attributes.timestamp()) {
        ...; continue;
    }
}
```

The `interop` cargo feature was **not in the default feature set** (`default = ["jemalloc", "docker-tests"]`), so standard builds skipped even the deadline check. The builder also never consulted the interop failsafe flag. Interop txs already in the pool, including the Private txs from bug 2 that the failsafe eviction missed, kept being included while the operator had failsafe on. The fix removes the feature gate, threads the shared `InteropFailsafe` handle through the builder, and skips any `is_interop_tx` while failsafe is enabled.

### Attack scenario (post-activation)

1. The attacker emits a log on chain B in (or before) the Lagoon activation block. Alternatively, the attacker submits a cross-chain tx whose initiating log they can reorg away, or that the filter will later judge invalid.
2. The attacker submits an executing tx on chain A through `eth_sendRawTransactionConditional` (Private origin) referencing that log. The filter accepts it (bug 1), or the tx survives an invalid verdict, a reorg or a failsafe sweep in the pool (bug 2).
3. op-rbuilder includes it, even with failsafe on and even past its deadline (bug 3).
4. op-supernode invalidates the block. Chain A has an unsafe reorg to a deposits-only replacement, and the whole dependency set goes through invalidation recovery (see 00-3b). The attacker can repeat this for the cost of gas.

## Impact Details

- **Effect**: griefing. The attacker forces unsafe-chain reorgs and invalidation recovery on the interop cluster, and can bypass the operator's emergency failsafe. Invalid messages never reach cross-safe or finalized state, so no funds are directly at risk.
- **Preconditions**: interop must be active. Bug 3's failsafe bypass also needs the operator to have enabled failsafe, which is exactly when it matters most.
- **Severity**: this would be Low to Medium on a live interop network (cheap, repeatable unsafe reorgs, and a defeated kill switch). Interop was never activated on a production network while these bugs were live, so the rating is **Low**. It is not downgraded further because the failsafe bypass undermines an incident-response control.

## Proof of Concept

**Bug 1** (Go). The fix adds `TestCrossValidator_UsesSourceChainLagoonActivation` (`op-interop-filter/filter/lockstep_cross_validator_test.go`); its first subtest expects `ErrConflict` for an access entry whose initiating log is at a pre-activation timestamp. A version for the parent (`33fbe016b8^`) uses the existing mock ingester, which knows nothing about activation. That is the point: the parent validator never asks.

```go
func TestPoC_PreActivationInitiatingMessageAccepted(t *testing.T) {
    checksum := messages.MessageChecksum{0x01}
    source := newMockChainIngester()
    source.AddLog(102, 10, 0, checksum, messages.BlockSeal{}) // log from before/at Lagoon activation
    source.SetLatestTimestamp(110)
    dest := newMockChainIngester()
    dest.SetLatestTimestamp(110)
    cv := newTestCrossValidator(map[eth.ChainID]ChainIngester{
        eth.ChainIDFromUInt64(testChainA): source,
        eth.ChainIDFromUInt64(testChainB): dest,
    }, testExpiryWindow, 105)
    err := cv.ValidateAccessEntry(makeAccess(testChainA, 102, 10, 0, checksum),
        safety.LocalUnsafe, makeExecDescriptor(testChainB, 106, 0))
    // Parent: err == nil. The pre-activation initiating message is admitted.
    require.ErrorIs(t, err, interop.ErrConflict)
}
```

On the fix, use the added subtest `access list rejects source message from the activation block`, with `source.SetFirstValidInitiatingTimestamp(104)`.

```
go test ./op-interop-filter/filter/ -count=1 -run 'TestCrossValidator_UsesSourceChainLagoonActivation|TestPoC_'
```

**Bug 2** (Rust). The regression tests in `rust/op-reth/crates/txpool/src/maintain/tests.rs` (added by bdcf49a00d) admit a `TransactionOrigin::Private` interop tx, return a definitive invalid verdict from a mock `InteropFilter`, run the revalidation sweep, and assert the tx is gone. They also cover eviction on `CanonStateNotification::Reorg`. The commit notes that the Private-origin test "fails on baseline".

```
cd rust && cargo test -p reth-optimism-txpool maintain::tests
```

**Bug 3** (Rust). The tests added in `context.rs` (`mod tests`) build a payload from a fixed tx list containing a normal tx and an interop tx (access list touching `CROSS_L2_INBOX_ADDRESS`), with `InteropFailsafe` enabled, and assert that only the normal tx is included. On the parent the interop tx is included.

```
cd rust/op-rbuilder && cargo test -p op-rbuilder builders::context::tests
```

Executed: no. The Go scratch trees were lost when the session restarted, and there was no Rust build cache.

## Recommendation

The fixes close each gap. Further suggestions:

- Put the activation-boundary rule in one place (`op-core/interop`) and use it in the filter, supernode, kona and op-reth, so the four implementations cannot drift. This rule has now been fixed separately in 1e and here.
- Enforce the failsafe in the builder independently of pool state, as the fix now does. Add an acceptance test that enables failsafe with Private interop txs already pooled.
- Consider rejecting interop txs from `eth_sendRawTransactionConditional` entirely unless explicitly enabled.

## References

- Fix commits: 33fbe016b8 (#22886, closes #22829), bdcf49a00d (#21447), 2bb37eb2e5 (#21494)
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/22886, https://github.com/ethereum-optimism/optimism/pull/21447, https://github.com/ethereum-optimism/optimism/pull/21494
- Relevant files: `op-interop-filter/filter/lockstep_cross_validator.go`, `op-interop-filter/filter/logsdb_chain_ingester.go`, `rust/op-reth/crates/txpool/src/maintain.rs`, `rust/op-reth/crates/txpool/src/error.rs`, `rust/op-rbuilder/crates/op-rbuilder/src/builders/context.rs`
