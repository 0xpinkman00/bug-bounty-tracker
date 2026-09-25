# op-revm: caller nonce was bumped before the fee/balance check and not journaled, so a rejected tx leaked a nonce increment into the multi-tx journal

| Field | Value |
|---|---|
| **Target** | op-revm `src/handler.rs`, `OpHandler::validate_against_state_and_deduct_caller` (now `rust/op-revm/src/handler.rs`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Informational (no production op-reth / kona code path reaches it; Low at most for third-party users of revm's multi-tx `transact_one` API) |
| **Impact category** | None of the in-scope impacts reached. The theoretical category is "Unintended chain split (network partition)" / incorrect block building for an embedder that reuses the EVM journal after a rejected tx |
| **Fix commit(s)** | a06ea3ae79b3b32aba9429cc884319036f28a49d (bluealloy/revm#2805), 2025-07-25. Released in op-revm 9.0.0 (2025-08-06). Follow-up test: 34345b24e6 (bluealloy/revm#2815) |
| **Vulnerable since** | 0b68166d80 "feat: transact multi tx" (bluealloy/revm#2517), 2025-05-24. Shipped in op-revm 6.0.0 through 8.1.0 (about 2.5 months) |

## Brief / Intro

op-revm is the OP Stack version of the revm EVM, used by op-reth and kona. Before executing a transaction, it checks that the sender can pay: gas, value, the L1 data fee and the operator fee. It also increments the sender's nonce. The nonce was incremented *before* the balance check, and the change was recorded in the undo log (the "journal") only *after* the check. When a transaction was rejected for insufficient funds, the undo step therefore did not know about the nonce change. The incremented nonce stayed in the EVM's cached state. This matters only for code that keeps using the same EVM instance after a rejected transaction without finalizing it (revm's `transact_one` multi-transaction API). op-reth and kona call `transact()`/`inspect_tx()` through alloy-op-evm. Those calls throw the cached state away after an error, so in practice the bug was not reachable in OP Stack production clients.

## Vulnerability Details

`src/handler.rs:150-213` (parent of fix, abbreviated)
```rust
let caller_account = journal.load_account_code(tx.caller())?.data;
if !is_deposit {
    validate_account_nonce_and_code(&mut caller_account.info, tx.nonce(), ...)?;
}

// Bump the nonce for calls. Nonce for CREATE will be bumped in `handle_create`.
if tx.kind().is_call() {
    caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);   // (1) mutate
}

let max_balance_spending = tx.max_balance_spending()?.saturating_add(additional_cost);
...
if !is_deposit && max_balance_spending > new_balance && !is_balance_check_disabled {
    return Err(InvalidTransaction::LackOfFundForMaxFee { .. }.into());            // (2) early return
}
...
journal.caller_accounting_journal_entry(tx.caller(), old_balance, tx.kind().is_call()); // (3) journal
```

If (2) returns, the journal entry (3) that would undo (1) is never pushed. `additional_cost` includes the L1 data fee and the Isthmus operator fee. An ordinary user can therefore hit (2) with a transaction that passes mempool checks but cannot cover the L1 fee at execution time.

What happens next depends on the caller:

- `ExecuteEvm::transact` (revm v83, `crates/handler/src/api.rs:64-72`) always calls `finalize()`, even on error. `finalize()` does `mem::take(state)` and resets the journal. The leaked nonce is dropped together with the error.
- `ExecuteEvm::transact_one` keeps the journal for the next transaction by design ("If the transaction fails, the journal will revert all changes of given transaction"). The leaked nonce stays in `journal.state`. The next transaction from the same sender then sees nonce + 1: it is rejected as `NonceTooHigh`, or it executes on top of a nonce that never changed on chain. A block or simulation built this way would disagree with every other client.
- `InspectEvm::inspect_tx` returns early on error *without* `finalize()`. The polluted journal survives only if the same EVM instance is reused afterwards.

**Reachability in production op-reth / kona (checked).**
- alloy-op-evm v0.14–v0.16 (the versions paired with op-revm 8.0.x/8.1.0) implements `transact_raw` as `if self.inspect { self.inner.inspect_tx(tx) } else { self.inner.transact(tx) }`. The current in-tree `rust/alloy-op-evm/src/lib.rs:368-372` does the same.
- reth's block executor, the op-reth payload builder, and RPC `eth_call`/`simulate` all go through `transact_raw`. On the non-inspect path the state is finalized and dropped. A rejected transaction makes the builder skip that transaction, and the next transaction reloads the sender from the `State` DB with the correct nonce.
- Inspect paths (tracing) replay transactions from existing, valid blocks, or they abort the whole request on the first error.
- A search of the Rust workspace finds `transact_one`/`inspect_one_tx` only in tests (`rust/op-revm/src/fast_lz.rs`, `rust/revm-ee-tests`) and in op-revm's own API definitions.

So the triage's concern about an op-reth sequencer building invalid blocks does not hold. The defect is real for any embedder (MEV builders, simulators, custom sequencers) that uses op-revm's multi-transaction API and continues after a rejected transaction.

**Fix.** The nonce increment moves after the balance check, immediately before the journal entry that covers it:

```diff
-        // Bump the nonce for calls. Nonce for CREATE will be bumped in `handle_create`.
-        if tx.kind().is_call() {
-            caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);
-        }
         let max_balance_spending = tx.max_balance_spending()?.saturating_add(additional_cost);
 ...
         caller_account.mark_touch();
         caller_account.info.balance = new_balance;
+        // Bump the nonce for calls. Nonce for CREATE will be bumped in `handle_create`.
+        if tx.kind().is_call() {
+            caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);
+        }
         journal.caller_accounting_journal_entry(tx.caller(), old_balance, tx.kind().is_call());
```

Deposits skip the balance check, so they were never affected.

### Attack scenario (only against a `transact_one`-based embedder)

1. A user sends tx A (nonce n) that pays gas but not the L1 data fee, followed by tx B (nonce n+1).
2. The builder runs A with `transact_one`. It fails with `LackOfFundForMaxFee` and is skipped, but the sender's cached nonce is now n+1.
3. B runs against the cached nonce n+1 and is included. Canonically, the sender's nonce is still n, so any validating client (op-geth, op-reth) rejects the block with an invalid nonce for B.

## Impact Details

- **OP Stack production clients:** no impact. op-reth and kona use the finalizing `transact()` path, and this was verified by the PoC below.
- **Third-party embedders** of op-revm 6.0.0–8.1.0 that use `transact_one`/`transact_many` and skip failed transactions: they could build blocks that other nodes reject (lost block, liveness) or return wrong simulation results. This is outside the in-scope assets.
- **Severity:** Informational for this program, since no in-scope client reaches it. The upstream fix and the added regression test are appropriate hardening.

## Proof of Concept

A standalone crate is built twice, once against the buggy release (op-revm 8.1.0 / revm 27.1.0) and once against the fixed one (op-revm 9.0.0 / revm 28.0.0). It shows both the leak through `transact_one` and the absence of a leak through `transact` (the path op-reth uses).

`Cargo.toml` (for the fixed variant, use `op-revm = "=9.0.0"` and `revm = "=28.0.0"`):
```toml
[package]
name = "poc-0204"
version = "0.1.0"
edition = "2021"

[dependencies]
op-revm = "=8.1.0"
revm = "=27.1.0"
```

`src/lib.rs`:
```rust
#[cfg(test)]
mod tests {
    use op_revm::{DefaultOp, OpBuilder, OpTransaction};
    use revm::{
        context::{Context, TxEnv},
        context_interface::{ContextTr, JournalTr},
        primitives::{Address, U256},
        ExecuteEvm,
    };

    fn underfunded_tx() -> OpTransaction<TxEnv> {
        // Caller Address::ZERO has zero balance in the empty DB, so value=1000 cannot be paid.
        OpTransaction::builder()
            .base(TxEnv::builder().caller(Address::ZERO).value(U256::from(1000)))
            .build_fill()
    }

    /// Multi-tx API: a rejected tx must not leave changes in the journal.
    #[test]
    fn poc_transact_one_leaks_nonce() {
        let mut evm = Context::op().build_op();
        let res = evm.transact_one(underfunded_tx());
        println!("result: {res:?}");
        assert!(res.is_err());
        let nonce = evm.0.ctx.journal_mut().load_account(Address::ZERO).unwrap().info.nonce;
        assert_eq!(nonce, 0, "rejected tx leaked a nonce bump into the EVM state");
    }

    /// Path used by alloy-op-evm / op-reth: transact() finalizes, so no leak on either version.
    #[test]
    fn transact_does_not_leak() {
        let mut evm = Context::op().build_op();
        assert!(evm.transact(underfunded_tx()).is_err());
        let nonce = evm.0.ctx.journal_mut().load_account(Address::ZERO).unwrap().info.nonce;
        assert_eq!(nonce, 0);
    }
}
```

Run: `cargo test -- --nocapture` in each variant.

**Executed: yes.** Output:
```
=== op-revm 8.1.0 (buggy)
result: Err(Transaction(Base(LackOfFundForMaxFee { fee: 1000, balance: 0 })))
assertion `left == right` failed: rejected tx leaked a nonce bump into the EVM state
  left: 1
 right: 0
test tests::transact_does_not_leak ... ok
test tests::poc_transact_one_leaks_nonce ... FAILED
=== op-revm 9.0.0 (fixed)
test tests::poc_transact_one_leaks_nonce ... ok
test tests::transact_does_not_leak ... ok
```

The upstream regression test is `test_tx_low_balance_nonce_unchanged` in `src/handler.rs` (added by 34345b24e6). It calls `validate_against_state_and_deduct_caller` directly and asserts that the nonce is 0.

## Recommendation

The fix is correct. Further suggestions:

- Enforce "mutate only after all fallible checks, and journal every mutation right away" in the handler, for example by having `caller_accounting_journal_entry` push the entry *before* the mutation.
- In op-revm's `catch_error` for non-deposit errors, consider calling `journal.discard_tx()` as mainnet revm does (`crates/handler/src/handler.rs:457` at v83). At this version op-revm returned `Err(error)` without discarding, so `transact_one` users relied entirely on nothing having been mutated before the error.

## References

- Fix commit: a06ea3ae79b3b32aba9429cc884319036f28a49d (https://github.com/bluealloy/revm/pull/2805)
- Introducing commit: 0b68166d80 (https://github.com/bluealloy/revm/pull/2517)
- Regression test: 34345b24e6 (https://github.com/bluealloy/revm/pull/2815)
- Relevant files: op-revm `src/handler.rs`; revm `crates/handler/src/api.rs` (`transact`, `transact_one`, `finalize`); revm `crates/inspector/src/inspect.rs` (`inspect_tx`); alloy-op-evm `src/lib.rs` (`transact_raw`)
