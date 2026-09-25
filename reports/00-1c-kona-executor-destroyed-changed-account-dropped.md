# kona-executor TrieDB drops re-created (`DestroyedChanged`) accounts and aborts on in-block create+destroy, giving wrong or unprovable state roots in the fault-proof program

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/proof/executor/src/db/mod.rs` (`TrieDB::update_accounts`, kona-client FPP) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Medium |
| **Impact category** | Theft of bonds / invalid resolution of non-respected `CANNON_KONA` dispute games. This would have been Critical (direct loss of funds through an invalid output root) in the respected game, but the fix shipped before kona became respected. |
| **Fix commit(s)** | f1930faf1b7c1bf597a40c26c1e039b1af32e5fe (PR #20640), 2026-05-11 |
| **Vulnerable since** | op-rs/kona `ffbb58eba4e` / `c0fbccdd21b` (2024-06). Reachable on every OP chain since Ecotone (EIP-6780 semantics). Present in every kona-client release before `v1.5.1`. |

## Brief / Intro

To check a disputed L2 state, kona's fault-proof program re-executes each L2 block and rebuilds the Ethereum state trie from the changes the EVM reports. If a contract self-destructed and the same address then received ETH again in a later transaction of the same block, kona deleted the account and never wrote it back. Separately, if a contract was created and self-destructed in the same block, kona tried to delete an account that had never been in the trie, hit an error and aborted. Either way, kona's answer for that block differs from the real chain: a wrong state root, or a crash that the dispute game treats as "invalid". Any user can set up this sequence with a few transactions.

## Vulnerability Details

revm reports per-account changes as a `BundleAccount` with a status. The relevant statuses (`revm-database` `account_status.rs`) are:
- `Destroyed` (info `None`): selfdestructed during the block.
- `DestroyedChanged` (info `Some`): destroyed, then changed again in a later tx of the same block, for example by an ETH transfer (`on_changed`: `Destroyed → DestroyedChanged`) or by a re-CREATE2.
- `DestroyedAgain` (info `None`): destroyed, re-created, destroyed again.

`was_destroyed()` is true for all three.

The parent code is at `rust/kona/crates/proof/executor/src/db/mod.rs:221-226` (`f1930faf1b^`):

```rust
// If the account was destroyed, delete it from the trie.
if bundle_account.was_destroyed() {
    self.root_node.delete(&account_path, &self.fetcher, &self.hinter)?;   // (2) KeyNotFound -> Err
    self.storage_roots.remove(address);
    continue;                                                             // (1) DestroyedChanged never re-inserted
}
```

**Bug 1: `DestroyedChanged` accounts vanish.** The account is deleted and the loop `continue`s, so its new balance, nonce, code and storage are never written. op-geth and op-reth keep the account, so kona's state root is wrong for any block with this pattern.

**Bug 2: `KeyNotFound` aborts state-root computation.** `TrieNode::delete` returns `TrieNodeError::KeyNotFound` when the path is absent (`Empty`, a mismatching `Leaf` or `Extension`, and so on). An account created and destroyed within the block (`LoadedNotExisting → InMemoryChange → Destroyed`) was never in the parent trie, so `?` propagates the error. The executor fails and kona-client exits with a failure status. In `FaultDisputeGame._verifyExecBisectionRoot`, an exit of `PANIC` or `INVALID` counts as "the disputed output root is wrong" (`FaultDisputeGame.sol:1179-1184`). So a canonical, honest output root for such a block cannot be defended.

EIP-6780 (active on OP chains since Ecotone) still lets `SELFDESTRUCT` delete an account when it was created in the **same transaction**. A contract that CREATE2s a child which self-destructs in its constructor or right after, followed by a separate transaction that sends ETH to that address, reaches both paths.

The fix:

```rust
if bundle_account.was_destroyed() {
    match self.root_node.delete(&account_path, &self.fetcher, &self.hinter) {
        Ok(()) | Err(TrieNodeError::KeyNotFound) => {}          // tolerate never-existed accounts
        Err(e) => return Err(e.into()),
    }
    self.storage_roots.remove(address);                        // wipe old storage
    if bundle_account.account_info().is_none() {               // Destroyed / DestroyedAgain
        continue;
    }
    // DestroyedChanged: fall through and re-insert the new account state
}
```

### Was kona the respected proof program while this was live?

No.
- The fix is contained in `kona-client/v1.5.1` (2026-05-12) and in every later tag, including `kona-client/v1.6.0-rc.2`. That tag is the prestate Upgrade 19 / Karst deployed when it made `CANNON_KONA` the respected game type (Sepolia 2026-06-17, Mainnet 2026-07-08; `docs/public-docs/notices/upgrade-19.mdx`). Checked with `git merge-base --is-ancestor f1930faf1b kona-client/v1.6.0-rc.2` → true.
- Before Karst, `CANNON_KONA` (added by Upgrade 18) existed as a bonded but **non-respected** game type ("This upgrade does not change the respected game type", `docs/public-docs/notices/archive/upgrade-18.mdx`). Withdrawals were proven against op-program `CANNON` games, which were unaffected.

### Attack scenario

1. **Setup (any L2 user).** Deploy a factory `F`. In tx A, `F` CREATE2s child `X`, and `X` runs `SELFDESTRUCT` in the same tx. In tx B of the same block, send 1 wei to `X`.
   - If `X` was pre-funded in an earlier block (an address with a balance but no code can still be CREATE2'd), the status is `DestroyedChanged` and `X` existed in the parent trie. kona deletes `X` and does not re-insert it, so kona's state root lacks `X` (Bug 1).
   - If `X` was fresh, the delete hits `KeyNotFound` and kona aborts (Bug 2).
2. **Bond theft (Bug 1 or 2).** The attacker counters honest proposals or honest challenger claims in `CANNON_KONA` games that cover this block. At the leaf, kona-in-Cannon either computes the attacker's root (Bug 1) or panics (Bug 2), which the contract reads as "honest root invalid". The honest side loses its bonds.
3. **Invalid root (Bug 1, potential).** With Bug 1, the attacker can make later behaviour depend on `X`'s existence. For example, contract `Y` calls `L2ToL1MessagePasser.initiateWithdrawal{value: v}` only if `X.balance == 0`. In kona's state the withdrawal happens; canonically it does not and `Y` keeps `v`. A game that resolves with kona's root would let the attacker withdraw `v` on L1 while still holding it on L2.

## Impact Details

- **Actual impact:** incorrect resolution and bond loss in `CANNON_KONA` games before Karst, on every chain that had deployed the U18 `CANNON_KONA` game type. Any user can trigger it. Honest challengers following U18 guidance played these games. Withdrawals were not at risk, because only `CANNON` (op-program) games were respected.
- **Potential impact:** had this bug reached the respected Karst prestate, step 3 would have been a permissionless double-spend against the `OptimismPortal` (Critical), limited only by Guardian intervention during the air-gap. Bug 2 alone would let anyone defeat honest proposals over any block with in-block create+destroy, delaying withdrawals and costing proposer bonds.
- **Severity:** **Medium**. Theft of dispute bonds in a live, non-respected game type, triggerable by any user. The Critical path was closed about a month before kona became respected.

## Proof of Concept

The fix adds `TrieDB` unit tests that fail on the parent. The two below are the key ones. The second is an additional test written for this report to cover the pure `KeyNotFound` case.

```rust
// rust/kona/crates/proof/executor/src/db/mod.rs, mod tests (imports as in the fix:
//   use alloy_primitives::{U256, b256}; use revm::database::{AccountStatus, BundleAccount};)

fn bundle_with_account(address: Address, account: BundleAccount) -> BundleState {
    let mut state = revm::primitives::HashMap::default();
    state.insert(address, account);
    BundleState { state, ..Default::default() }
}

// From the fix: DestroyedChanged account that was never in the parent trie
// (CREATE2 + SELFDESTRUCT in tx A, ETH transfer in tx B).
// Parent: Err(TrieDBError(KeyNotFound)). Fix: Ok(non-empty root).
#[test]
fn test_destroyed_changed_new_account_never_in_trie() {
    let mut db = new_test_db();
    let address = Address::repeat_byte(0x05);
    let new_info = AccountInfo { balance: U256::from(1_000_000_000_000_000_000u64), ..Default::default() };
    let root = db.state_root(&bundle_with_account(
        address,
        BundleAccount::new(None, Some(new_info), Default::default(), AccountStatus::DestroyedChanged),
    )).unwrap();
    assert_ne!(root, EMPTY_ROOT_HASH, "DestroyedChanged account never in parent trie must be re-inserted");
}

// Extra PoC: plain in-block create+selfdestruct (status Destroyed, never in parent trie).
// Parent: state_root returns Err (KeyNotFound) -> kona-client aborts. Fix: Ok(EMPTY_ROOT_HASH).
#[test]
fn poc_created_and_destroyed_in_block_aborts() {
    let mut db = new_test_db();
    let address = Address::repeat_byte(0x06);
    let res = db.state_root(&bundle_with_account(
        address,
        BundleAccount::new(None, None, Default::default(), AccountStatus::Destroyed),
    ));
    assert_eq!(res.unwrap(), EMPTY_ROOT_HASH);
}
```

The fix's `test_destroyed_changed_account_reinserted` covers Bug 1 on an account that did exist in the parent trie. On the parent it returns `EMPTY_ROOT_HASH`, because the re-funded account is missing.

```bash
# fixed tree
cd rust && cargo test -p kona-executor --lib db::tests
# parent tree (separate worktree), after pasting the tests above plus test_destroyed_changed_account_reinserted:
git worktree add /tmp/kona-parent f1930faf1b^
cd /tmp/kona-parent/rust && cargo test -p kona-executor --lib db::tests
# expected: test_destroyed_changed_account_reinserted, test_destroyed_changed_new_account_never_in_trie
#           and poc_created_and_destroyed_in_block_aborts FAIL on the parent
```

An end-to-end reproduction can use the kona proof action-test harness (`rust/kona/tests/proofs`). Deploy the factory in genesis, include txs A and B in one block, and run `env.RunFaultProofProgramFromGenesis` with the honest claim. On the parent the program fails to validate the honest claim.

Executed: no. Crate builds were not run. The status transitions were checked against `revm-database-43.0.1/src/states/account_status.rs` (`on_created`, `on_selfdestructed`, `on_changed`).

## Recommendation

The fix treats `KeyNotFound` on delete as a no-op and re-inserts `DestroyedChanged` accounts after wiping their storage. Together these match revm and op-reth semantics.

Further suggestions:
- Add a differential test that feeds revm-produced `BundleState`s for all `AccountStatus` variants, generated from real EVM traces rather than hand-built bundles, to both the kona `TrieDB` and reth's state-root calculation.
- Review other `was_destroyed()` users in kona's TrieDB and hinting code (for example storage-root caching) for the same "destroyed means gone" assumption.

## References

- Fix commit: f1930faf1b7c1bf597a40c26c1e039b1af32e5fe
- Pull request: https://github.com/ethereum-optimism/optimism/pull/20640
- Relevant files: `rust/kona/crates/proof/executor/src/db/mod.rs`, `rust/kona/crates/proof/mpt/src/node.rs` (`delete`), `packages/contracts-bedrock/src/dispute/FaultDisputeGame.sol` (`_verifyExecBisectionRoot`)
- EIP-6780: https://eips.ethereum.org/EIPS/eip-6780
- Respected-game-type evidence: `docs/public-docs/notices/archive/upgrade-18.mdx`, `docs/public-docs/notices/upgrade-19.mdx` (archived by `798b46044e`), tag `kona-client/v1.6.0-rc.2`
