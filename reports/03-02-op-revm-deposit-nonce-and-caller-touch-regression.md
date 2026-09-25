# op-revm — deposit CALLs stop bumping the depositor nonce, and caller fee/nonce/mint changes can be dropped at commit (unreleased regression, yanked crates)

| Field | Value |
|---|---|
| **Target** | op-revm, `src/handler.rs` (`OpHandler::validate_against_state_and_deduct_caller`), upstream `bluealloy/revm` `crates/op-revm`; used by op-reth and kona |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (the defect class is High, but no node or proof-program release ever shipped it; see Impact) |
| **Impact category** | "Unintended chain split (network partition)" (would-be impact); actual exposure limited to published-then-yanked library versions |
| **Fix commit(s)** | 262101504858b4ad9425382db6b234eaacea7894 (bluealloy/revm#2495, mark caller touched); 38c23527173a7743b5085599bdd786dfb88d58ad (bluealloy/revm#2503, bump nonce on deposit), superseded by 7e521dc5065a92faefcf9f27f2dfa9576894b1b4 (bluealloy/revm#2504, final localized fix). All 2025-05-09. Related cleanup: 9484695e19b54094a8709db1cd98a8240cb9eb53 (bluealloy/revm#2499) |
| **Vulnerable since** | 048795b1427ec3a2606770d69065e69610860bf3 (bluealloy/revm#2460, upstream `bafd08f4a076`), 2025-04-29. Present in op-revm crates **3.1.0, 4.0.0 (and 4.0.1 for the nonce half)**, all of which are **yanked** on crates.io. Fixed in op-revm 4.0.2 |

## Brief / Intro

op-revm is the OP Stack's customization of the revm EVM. Before running a transaction it checks the sender, charges gas and L1 fees up front, bumps the sender's nonce, and credits minted ETH for L1→L2 deposits. A refactor merged "validate the sender" and "charge the sender" into one function and introduced two mistakes. (a) Deposit transactions that call a contract no longer increased the depositor's nonce. (b) The sender's account was no longer flagged as "touched", and revm's state commit silently discards changes to untouched accounts. Nodes running this code would disagree with op-geth on the state after almost any user transaction. The code was on revm `main` for 10 days and in three crate versions that were later yanked. No released op-reth or kona-client used it.

## Vulnerability Details

Before the refactor, the OP handler called `self.mainnet.deduct_caller(evm)`, which bumped the nonce for CALLs and touched the caller for both deposits and normal transactions. PR #2460 inlined the logic into the OP handler (`src/handler.rs` @ 048795b142, around lines 86-190):

```rust
let caller_account = journal.load_account_code(tx.caller())?.data;

if is_deposit {
    if let Some(mint) = mint {
        caller_account.info.balance =
            caller_account.info.balance.saturating_add(U256::from(mint));
    }
    // <-- (a) no nonce bump for deposit CALLs
} else {
    // bumps nonce (third arg = bump_nonce) only for non-deposits
    validate_account_nonce_and_code(
        &mut caller_account.info, tx.nonce(), tx.kind().is_call(),
        is_eip3607_disabled, is_nonce_check_disabled)?;
}
... // balance checks; caller_account.info.balance = balance.saturating_sub(gas + l1 + operator fee)
Ok(())   // <-- (b) no caller_account.mark_touch()
```

- **(a) Deposit nonce.** The OP deposit spec requires the `from` account's nonce to increase by one for deposit CALLs, as for any other transaction. CREATE nonces are bumped separately in `handle_create`. After the refactor only the non-deposit branch bumped the nonce.
- **(b) Missing touch.** Upstream mainnet `validate_against_state_and_deduct_caller` ends with `caller_account.mark_touch()` (revm `crates/handler/src/pre_execution.rs` at `bafd08f4`, "Touch account so we know it is changed."). The OP override omitted it. The balance and nonce changes were made by mutating `caller_account.info` directly, with no journal entry and no touch. revm's state commit ignores untouched accounts: `CacheState::apply_account_state` has `if !account.is_touched() { return None; }` and `CacheDB::commit` has `if !account.is_touched() { continue; }`. Nothing else reliably touches the caller later. `Journal::transfer` with `value == 0` touches only the recipient, and `reimburse_caller` also mutates the balance without touching. So for the common case of a zero-value call (an ERC-20 transfer, most contract interactions, most deposits), the gas fee, L1 data fee, operator fee, nonce increment and deposit mint were all computed and then dropped when the block's state was committed.

Fixes:

```diff
 // 2621015048 (#2495)
+        // Touch account so we know it is changed.
+        caller_account.mark_touch();
         Ok(())
```

```diff
 // 7e521dc506 (#2504, final form of #2503)
             if let Some(mint) = mint { ... }
+            if tx.kind().is_call() {
+                caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);
+            }
         } else {
```

9484695e19 (#2499) additionally clears the per-transaction `local` context in the OP `catch_error` path, which was an adjacent cleanup omission from the same refactor.

### Attack scenario (had it shipped)

1. The attacker (or any ordinary user) sends a zero-value L2 transaction, such as an ERC-20 transfer, from an EOA that the transaction does not otherwise touch.
2. An op-reth node on the affected op-revm executes it, and the sender's fee deduction and nonce bump are discarded at commit. The resulting state root differs from op-geth's, which charged the fee and bumped the nonce.
3. Because the nonce did not persist on that node, the same signed transaction is valid again in the next block and can be replayed for free, deepening the divergence. A deposit with `mint` and no value transfer would lose its minted ETH on that node. A deposit CALL leaves the depositor nonce one lower than on op-geth, so later contract-address derivations (CREATE from that account) diverge.
4. Nodes on the affected version split from the canonical chain. A sequencer on it would produce blocks every op-geth node rejects.

## Impact Details

- **Would-be impact:** a consensus failure triggered by ordinary traffic, which is at least High ("Unintended chain split (network partition)"). It would also have broken fee accounting (free transactions) and nonce replay protection on the affected nodes.
- **Actual exposure, verified:**
  - crates.io: `op-revm` 3.1.0 (2025-05-07), 4.0.0 (2025-05-07) and 4.0.1 (2025-05-09 10:48 UTC) are all **yanked**. 4.0.2 (2025-05-09 20:14 UTC) contains both fixes. 4.0.1 was published shortly after the touch fix merged (10:27 UTC) but before the nonce fix, so it at least lacked the nonce fix.
  - reth: `v1.3.12` pins op-revm 3.0.2 (pre-regression). `v1.4.0` through `v1.4.3` pin 4.0.2 (fixed). No reth or op-reth release in between.
  - kona: `kona-client/v1.0.0` (2025-05-01) and `v1.0.1` (2025-05-10) pin op-revm 3.0.2, so they are unaffected.
- The bug was caught about 10 days after it landed on `main`, before any consumer node release. Third-party projects that depended directly on op-revm 3.1.0 or 4.0.0 during the roughly two days those versions were live could have been affected. I found no evidence of this.
- Severity is set to **Low** to reflect that no production node release carried the bug. It should be treated as High if any deployment is found to have run op-revm 3.1.0, 4.0.0 or 4.0.1.

## Proof of Concept

A unit test in op-revm's `src/handler.rs` `tests` module. It is adapted from the existing `test_remove_l1_cost_non_deposit` test, which already builds a deposit with `mint` and calls `validate_against_state_and_deduct_caller`.

```rust
#[test]
fn poc_deposit_call_bumps_nonce_and_touches_caller() {
    let caller = Address::ZERO;
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        caller,
        AccountInfo { balance: U256::from(1000), nonce: 7, ..Default::default() },
    );
    let ctx = Context::op()
        .with_db(db)
        .with_chain(L1BlockInfo::default())
        .modify_cfg_chained(|cfg| cfg.spec = OpSpecId::REGOLITH)
        .modify_tx_chained(|tx| {
            // TxEnv default kind is TxKind::Call(Address::ZERO)
            tx.base.gas_limit = 100;
            tx.base.tx_type = DEPOSIT_TRANSACTION_TYPE;
            tx.deposit.mint = Some(10);
            tx.deposit.source_hash = B256::ZERO;
        });
    let mut evm = ctx.build_op();
    let handler = OpHandler::<_, EVMError<_, OpTransactionError>, EthFrame<_, _, _>>::new();
    handler.validate_against_state_and_deduct_caller(&mut evm).unwrap();

    let account = evm.ctx().journal().load_account(caller).unwrap();
    assert_eq!(account.info.balance, U256::from(1010));      // mint applied
    assert_eq!(account.info.nonce, 8, "deposit CALL must bump nonce");        // fails pre-#2504
    assert!(account.is_touched(), "caller must be touched or commit drops it"); // fails pre-#2495
}
```

Run against upstream revm:

```
git clone https://github.com/bluealloy/revm && cd revm
git checkout bafd08f4a076f10c5392bd31eb151be42859ab6e   # merge of #2460 -> expected FAIL (nonce 7, not touched)
cargo test -p op-revm poc_deposit_call_bumps_nonce_and_touches_caller
git checkout 336b866f9f0fa095adaafe95194a7815ea882db7   # merge of #2504 -> expected PASS
cargo test -p op-revm poc_deposit_call_bumps_nonce_and_touches_caller
```

To see the commit-level effect of (b), note that `CacheDB::commit` (`crates/database/src/in_memory_db.rs`) and `CacheState::apply_account_state` (`crates/database/src/states/cache.rs`) both skip `!is_touched()` accounts at `bafd08f4`. A zero-value non-deposit call executed with `transact_commit` on the regression commit leaves the sender's balance and nonce unchanged in the database.

Executed: no. The crate-version, yank and pin facts were verified via the crates.io API and the `Cargo.lock` files at the reth and kona release tags.

## Recommendation

The fixes restore the nonce bump for deposit CALLs and the `mark_touch()` call. Further hardening:
- Have the OP override call a shared upstream helper for the nonce and touch bookkeeping rather than re-implementing it. The final fix (#2504) deliberately localized the nonce bump. A regression test pinning "deposit CALL bumps nonce" and "caller is touched after deduction" should live next to it.
- Run the OP execution spec tests or op-geth differential fixtures on every revm refactor of handler internals, before crates are published rather than after.

## References

- Fix commits: 262101504858b4ad9425382db6b234eaacea7894, 38c23527173a7743b5085599bdd786dfb88d58ad, 7e521dc5065a92faefcf9f27f2dfa9576894b1b4, 9484695e19b54094a8709db1cd98a8240cb9eb53
- Pull requests: https://github.com/bluealloy/revm/pull/2495, https://github.com/bluealloy/revm/pull/2503, https://github.com/bluealloy/revm/pull/2504, https://github.com/bluealloy/revm/pull/2499; regression https://github.com/bluealloy/revm/pull/2460
- crates.io: https://crates.io/crates/op-revm/versions (3.1.0, 4.0.0, 4.0.1 yanked)
- Relevant files: `src/handler.rs` (imported op-revm history), current `rust/op-revm/src/handler.rs`
- Specs: https://specs.optimism.io/protocol/deposits.html#execution
