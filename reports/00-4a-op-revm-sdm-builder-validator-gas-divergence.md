# SDM (post-exec refunds): sequencer builds blocks that validators reject — warm-state leaks from failed or declined transactions

| Field | Value |
|---|---|
| **Target** | `rust/op-revm/src/handler.rs` (`OpHandler::catch_error`), `rust/alloy-op-evm/src/block/mod.rs` (`OpBlockExecutor`), `rust/op-rbuilder/crates/op-rbuilder/src/builders/context.rs`, `rust/op-reth/crates/payload/src/builder.rs` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low. On impact alone, A and B would be Medium. They are downgraded because SDM is gated on the unactivated Lagoon fork and is off by default. C is Informational |
| **Impact category** | A/B: "Unintended chain split (network partition)" / liveness. The sequencer produces unsafe blocks that every validator rejects. C: none directly; defence in depth |
| **Fix commit(s)** | A: 1d17ded0f6b6e770e3c9472b899ae8318bb2d7fa (PR #21723), 2026-07-16. B: 2b1a407ef040abfea854004239a80cf6530adf1c (PR #21359), 2026-06-17. C: a7ab3fd3c4fee8a6ee354ed22301ec596a3e7dda (PR #21502), 2026-06-23 |
| **Vulnerable since** | SDM executor and warming inspector added in eb9d2ca7f7 (PR #20213, 2026-04-29). The `OpHandler::catch_error` override that lacks `discard_tx` is older: revm #3780 fixed it upstream, but the fix did not reach the OP override. It only becomes consensus-relevant on the SDM Produce path |

## Brief / Intro

SDM ("post-exec refunds") is a new OP Stack feature scheduled for the Lagoon fork. When the sequencer builds a block with SDM on, it tracks which accounts and storage slots the block's transactions have already touched ("warmed"). Later transactions that touch the same state earn a gas refund. The sequencer records those refunds in a special trailing transaction (type `0x7D`). Validators re-execute only the transactions that are actually in the block and check that the gas totals agree.

Two bugs let transactions that never entered the block still leave "warmth" behind in the builder:

- A. A transaction that failed validation, for example with a stale nonce.
- B. A transaction the builder executed and then declined, for example because it went over a gas or DA limit.

The builder then charged or refunded later transactions differently from what validators compute, so validators rejected the block. Any user who can send transactions that the builder will skip could trigger this on purpose, which would repeatedly break unsafe-block production. The feature was never active on a production chain.

## Vulnerability Details

### A. `OpHandler::catch_error` did not discard the journal for non-deposit errors (PR #21723)

When a transaction fails *validation*, revm calls the handler's `catch_error`. Upstream revm's `EthHandler::catch_error` calls `journal.discard_tx()` (revm #3780). OP's override only reset the journal on the deposit path:

`rust/op-revm/src/handler.rs:395-455` (parent `1d17ded0f6^`)
```rust
fn catch_error(&self, evm: &mut Self::Evm, error: Self::Error)
    -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
    let is_deposit = evm.ctx().tx().tx_type() == DEPOSIT_TRANSACTION_TYPE;
    let is_tx_error = error.is_tx_error();
    let mut output = Err(error);

    // Deposit transaction can't fail so we manually handle it here.
    if is_tx_error && is_deposit {
        ...
        journal.checkpoint_revert(JournalCheckpoint::default());
        ...
        journal.commit_tx();
        ...
    }
    // <-- no `else { journal.discard_tx() }`: a failed non-deposit tx keeps its journal

    // do the cleanup
    evm.ctx().chain_mut().clear_tx_l1_cost();
    evm.ctx().local_mut().clear();
    evm.frame_stack().clear();
    output
}
```

revm loads the sender, and so marks it EIP-2929 warm, *before* it runs the nonce check and the EIP-3607 (sender-has-code) check. On the normal `transact` path, `finalize()` runs even on error and wipes the journal, so non-SDM chains are unaffected. The regression test `skipped_failed_tx_does_not_affect_next_tx_when_sdm_disabled` pins this. The SDM Produce path instead drives execution through `inspect_tx` / `begin_post_exec_tx`, which does not wipe the journal. The sender of the failed transaction therefore stays warm for the next transaction in the block.

Result: the builder skips failed tx `A` and then includes tx `B`, which touches `A`'s sender. The builder charges `B` 100 gas for a warm access. A validator never runs `A`, so it charges 2,600 gas for a cold access. The two gas totals differ by 2,500, and the validator rejects the block.

Fix (`rust/op-revm/src/handler.rs:396-459` at `1d17ded0f6`):
```rust
let output = if error.is_tx_error() {
    self.catch_error_tx_error(evm, error)   // deposit -> failed-deposit path; others -> discard
} else {
    self.discard_and_surface_error(evm, error)
};
...
fn discard_and_surface_error(&self, evm: &mut EVM, error: ERROR) -> Result<..., ERROR> {
    evm.ctx().journal_mut().discard_tx();
    Err(error)
}
```

### B. Declined op-rbuilder candidates kept their SDM block-warming (PR #21359)

SDM block-warming refunds are recorded by an inspector *during* execution, before the builder decides whether to commit. They are not journaled. op-rbuilder selects transactions through `execute_transaction_with_commit_condition` and returns `CommitChanges::No` for candidates that exceed a gas, DA or address limit, or that reverted and are excluded. `OpBlockExecutor` used the default trait implementation, which throws away the state changes but not the warming maps. A later committed transaction could then claim a refund "earned" from a transaction that is not in the block. Commit-only paths, meaning block import and `debug_replaySDMBlock` derivation, never see that warmth, so the producer's payload diverged. The e2e test measured an 18,400-gas refund against 0 across 6 divergent blocks.

Fix (`rust/alloy-op-evm/src/block/mod.rs`, new override at `2b1a407ef0`):
```rust
fn execute_transaction_with_commit_condition(&mut self, tx, f) -> Result<Option<GasOutput>, _> {
    let warming_snapshot = self.post_exec.is_producing().then(|| self.warming_state());
    let output = self.execute_transaction_without_commit(tx)?;
    if !f(&output).should_commit() {
        if let Some(snapshot) = warming_snapshot {
            self.seed_warming_state(snapshot);          // roll back phantom warming
        }
        return Ok(None);
    }
    Ok(Some(self.commit_transaction(output)))
}
```

### C. Related hardening (PR #21502)

- `finish()` accepted a Verify-mode block whose refund entries had all been used up by per-transaction settlement even though no trailing `0x7D` transaction ran. In that case the check that compares the payload bytes against the block was skipped. The fix adds a `missing_post_exec_tx()` guard. In op-reth the Verify payload is parsed from the block's own transactions, so we could not find a production path that reaches this. It is defence in depth.
- The op-reth payload builder read the runtime-mutable SDM opt-in twice: once for EVM setup and once to decide whether to append `0x7D`. An operator toggling the opt-in between the two reads could produce an inconsistent block. The fix snapshots the mode once. Only the operator can trigger this.

### Attack scenario (A and B)

1. Lagoon is active and the sequencer runs op-rbuilder or op-reth with SDM Produce enabled.
2. The attacker makes the builder attempt and then skip a transaction whose sender (or touched state) is then touched by a victim transaction, or by the attacker's own second transaction, in the same block:
   - (B) a DA-heavy or gas-heavy transaction the builder declines at its per-block limits, or a reverting bundle transaction that is excluded;
   - (A) a transaction that fails validation at build time. The pool normally pre-filters these, but a nonce race between pool validation and block building is enough.
3. The builder bills the later transaction as warm and/or records a block-warming refund in `0x7D`. Validators re-execute without the skipped transaction and compute different gas, then reject the block.
4. Every sequenced block that includes such a pattern is rejected, causing unsafe reorgs and a sequencing liveness failure for as long as the attacker keeps it up. The cost is ordinary transaction fees, or nothing for declined candidates, which are never included.

## Impact Details

- **What breaks:** the sequencer's unsafe blocks are invalid for every validator. That means repeated unsafe reorgs, and possibly a halt of unsafe-head progress, until the operator turns SDM off.
- **Who can trigger it:** any user (B clearly; A needs a race).
- **Mitigating factors:**
  - SDM is consensus-gated on **Lagoon**, which had not activated on any network.
  - It is also a runtime opt-in (off by default). The test comment says: "production config: Karst pre-Lagoon, opt-in OFF".
  - Safe-chain derivation uses the commit-only path, so no invalid state becomes safe or final. The damage is limited to the unsafe chain and to liveness.
  - No funds are at risk.
- **Severity:** Immunefi would rate a user-triggerable chain split or liveness failure on a live network as Medium or higher. Because the code was never live, we rate A and B **Low**. C is Informational.

## Proof of Concept

The fixes added regression tests that reproduce both divergences.

**A (op-revm journal leak).** The test drives a Produce-mode builder over `[A (fails NonceTooLow), B]`, where `B` runs `BALANCE(A.sender)`. It then drives a Verify-mode validator over `[B, 0x7D]` and compares `gas_used`:

`rust/alloy-op-evm/src/block/tests.rs`, module `warm_set_leak` (added in `1d17ded0f6`)
```rust
producer.set_post_exec_mode(PostExecMode::Produce);
producer.execute_transaction(&failing_a).expect_err(a_error_context);
producer.execute_transaction(&legacy_with_sender(PROBE_SENDER, 0, PROBE_CONTRACT, 200_000))
    .expect("probe tx B executes");
let entries = producer.take_post_exec_entries();
let post_exec_tx = recovered_post_exec(0, entries.clone());
producer.execute_transaction(&post_exec_tx).expect("producer appends 0x7D tx");
let (_, produced) = producer.finish().expect("producer finishes block");

verifier.set_post_exec_mode(PostExecMode::Verify(post_exec_payload(0, entries)));
verifier.execute_transaction(&legacy_with_sender(PROBE_SENDER, 0, PROBE_CONTRACT, 200_000)).unwrap();
verifier.execute_transaction(&post_exec_tx).unwrap();
let (_, verified) = verifier.finish().unwrap();

assert_eq!(produced.gas_used, verified.gas_used); // 2500-gas divergence pre-fix
```

**B (declined candidate).** `test_declined_candidate_does_not_warm_later_committed_tx` (added in `2b1a407ef0`). It runs `execute_transaction_with_commit_condition(&legacy_tx(0, target), |_| CommitChanges::No)` and then commits `legacy_tx(0, target)`. It asserts that `post_exec_entries()` is empty, meaning no phantom refund.

**How to run.** The tests only compile together with their fix, so the simplest reproduction is a mutation test in a scratch clone:

```bash
git clone <repo> /tmp/op && cd /tmp/op
# A
git checkout 1d17ded0f6
# re-introduce the bug: delete the single line `evm.ctx().journal_mut().discard_tx();`
# inside `fn discard_and_surface_error` (rust/op-revm/src/handler.rs:457)
sed -i '457{/journal_mut().discard_tx()/d}' rust/op-revm/src/handler.rs
cd rust && cargo test -p alloy-op-evm warm_set_leak
# expected: skipped_failed_tx_in_sdm_produce_does_not_diverge_builder_vs_validator and the
# EIP-3607 variant FAIL with "...2500-gas builder-vs-validator divergence..."; the
# SDM-disabled guard test passes.

# B
git checkout 2b1a407ef0
# delete the `execute_transaction_with_commit_condition` override in rust/alloy-op-evm/src/block/mod.rs
cargo test -p alloy-op-evm test_declined_candidate_does_not_warm_later_committed_tx
# expected: FAIL "an uncommitted candidate must not warm a later committed tx"
```

The op-rbuilder layer has matching tests (`skipped_failed_tx_does_not_warm_later_tx_in_produce_mode`, `skipped_eip3607_failed_tx_does_not_warm_later_tx_in_produce_mode`), and so does the Go e2e test `TestFlashblocksSDMPhantomWarmingDivergence` in `op-acceptance-tests/tests/flashblocks/flashblocks_sdm_phantom_test.go`. The commit bodies report that this test fails before the fix (`divergent_blocks=6, refund 18400 vs 0`).

Executed: no. A Rust workspace build was too expensive for this review. The red/green results above are the ones the fix authors report in the commit bodies.

## Recommendation

The fixes are correct and minimal:

- restore upstream's `discard_tx()` on every non-deposit error path;
- snapshot and restore the non-journaled warming state around declined candidates;
- require the trailing `0x7D` whenever a Verify payload is present;
- snapshot the SDM mode once per build.

The root cause of A is a *silent override*: an upstream revm fix did not reach OP's overriding handler. The PR added this case to `docs/ai/reth-update-review.md`. We also recommend:

- a differential test run in CI on every revm or reth bump: producer-with-skips against commit-only replay;
- treating any non-journaled per-block state, such as the SDM warming maps, as needing an explicit rollback hook whenever a new "execute but don't commit" API appears.

## References

- Fix commits: 1d17ded0f6b6e770e3c9472b899ae8318bb2d7fa, 2b1a407ef040abfea854004239a80cf6530adf1c, a7ab3fd3c4fee8a6ee354ed22301ec596a3e7dda
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/21723, https://github.com/ethereum-optimism/optimism/pull/21359, https://github.com/ethereum-optimism/optimism/pull/21502; issue https://github.com/ethereum-optimism/optimism/issues/21354; mirrors base/base#3806
- Relevant files: `rust/op-revm/src/handler.rs`, `rust/op-revm/src/catch_error_tests.rs`, `rust/alloy-op-evm/src/block/mod.rs`, `rust/alloy-op-evm/src/block/tests.rs`, `rust/op-rbuilder/crates/op-rbuilder/src/builders/context.rs`, `rust/op-reth/crates/payload/src/builder.rs`
- Upstream: revm #3780 (`EthHandler::catch_error` `discard_tx`)
