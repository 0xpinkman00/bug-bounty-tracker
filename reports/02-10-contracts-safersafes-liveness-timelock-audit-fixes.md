# SaferSafes (LivenessModule2 / TimelockGuard): audit-driven fixes to ownership recovery, guard state and configuration validation

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/safe/{SaferSafes,LivenessModule2,TimelockGuard}.sol` |
| **Asset type** | Smart Contract |
| **Severity** | Low overall (per-item: 10a Low, 10b to 10e Informational) |
| **Impact category** | "Contract fails to deliver promised returns, but doesn't lose value" (liveness-recovery and timelock guarantees) |
| **Fix commit(s)** | 7221832a7a030c390e2dd1ce632bb87737fa8bab (PR #17808) 2025-10-17; d3abbbdfa8361be32d10cf9e6d3fb2ac2377447e (PR #17975) 2025-10-22; 59e86721a4665f0d84f618ca037f4af6c74ccba0 (PR #17995) 2025-10-23; 3c326a7e0ef3b335931791eefcb3b4b3e6f4612e (PR #18004) 2025-10-23; 391053e505c378c1d515b8844e57a6d16cb87aef (PR #18172) 2025-11-06 |
| **Vulnerable since** | LivenessModule2 5cefc951e3 (PR #17272, 2025-09-19); TimelockGuard a21294bcca (PR #17584, 2025-10-03); SaferSafes dc558e75e2 (PR #17767, 2025-10-10). Release exposure: the first four fixes predate `op-safe-contracts/v1.0.0` (cb54822c5e, 2025-10-24, SaferSafes 1.8.0), so they were never released. **#18172 is not in v1.0.0.** It shipped in `op-safe-contracts/v1.1.0` (SaferSafes 1.10.1, 2025-11-25). |

## Brief / Intro

SaferSafes is an add-on for Gnosis Safe multisigs, such as the ones that control OP Stack upgrades. It does two jobs. The **LivenessModule2** half lets a pre-agreed *fallback owner* take over a Safe whose signers have gone silent. The fallback owner opens a *challenge*. If the Safe does not respond within the response period, the fallback owner replaces all signers. The **TimelockGuard** half forces every Safe transaction to be *scheduled* and to wait a delay before it runs, so that a quorum of signers can cancel a malicious transaction. An external audit ahead of release found several gaps: in how the two halves interact, in guard state tracking, and in input validation. None of them can be triggered by an outside attacker. Each one either requires the Safe's own signers or fallback owner to act, or weakens a guarantee that the product promises. Four of the five fixes landed before the first release. The fifth (#18172) fixed configuration-validation gaps that were present in `op-safe-contracts/v1.0.0`.

---

## 10a. Ownership transfer left the (possibly faulty) guard active: fallback owner could stay locked out (#17808), Low

**Before (at 7221832a7a^), `LivenessModule2.changeOwnershipToFallback`:** the function removed all owners, swapped in the fallback owner, deleted `challengeStartTime` and emitted `ChallengeSucceeded`. It did **not** touch the Safe's guard.

The Safe guard checks every `execTransaction`. After recovery:
- If the guard is SaferSafes' own TimelockGuard, the fallback owner must schedule every action, removing the guard included, and wait the full `timelockDelay`, up to 365 days. Recovery therefore adds another full timelock delay on top of the liveness response period.
- If the guard is any other contract, for example a buggy or malicious guard that reverts every transaction, the fallback owner can never execute a transaction, `setGuard(address(0))` included. A module call cannot rescue the Safe here, because recovery only swaps owners. A faulty guard is also one of the likely *reasons* the Safe became unresponsive in the first place.

**Fix:** after the owner swap, the module calls into the Safe to remove whichever guard is set:

```solidity
// LivenessModule2.sol (at 7221832a7a)
targetSafe.execTransactionFromModule({
    to: _safe, value: 0, operation: Enum.Operation.Call,
    data: abi.encodeCall(GuardManager.setGuard, (address(0)))
});
```

The PR also adds `TimelockGuard.clearTimelockGuard()`. It lets a Safe that has disabled the guard wipe its delay and threshold and cancel up to 100 pending transactions.

**Impact:** the "fallback owner can always recover the Safe" guarantee could fail outright (third-party reverting guard) or be delayed by up to a year (TimelockGuard). Triggering it requires the Safe's signers to have installed that guard, and it was fixed before any release. **Low.**

## 10b. `challengeStartTime` cleared after the external module calls (#17975), Informational

**Before (d3abbbdfa8^, `LivenessModule2.sol:280-305`):** `delete challengeStartTime[_safe]` ran *after* the `removeOwner`/`swapOwner`/`setGuard` calls made through `execTransactionFromModule`. This breaks checks-effects-interactions: while those calls run, the challenge is still "active".

**Fix:** move the `delete` to just after the response-period check, before any interaction.

**Assessment:** with Safe 1.4.1, the only version supported after 10d, every such call targets the Safe itself (`to: _safe`) and runs `OwnerManager`/`GuardManager` code with no callback into third-party code. No reentrant path was found. `challenge()` also requires `msg.sender == fallbackOwner` and `challengeStartTime == 0`. This is hardening. **Informational.**

## 10c. Failed Safe transactions were never marked Executed (#17995), Informational

**Before (59e86721a4^, `TimelockGuard.checkAfterExecution`):**

```solidity
// If the transaction failed, then we return early and leave the transaction in its current
// state, which allows the transaction to be retried. This is consistent with the Safe's
// own behaviour, which does not increment the nonce if the call fails.
if (!_success) {
    return;
}
```

The comment is wrong. Safe 1.4.1 increments the nonce *before* execution and does not revert on inner failure when `safeTxGas != 0 || gasPrice != 0`. A failed transaction therefore consumes its nonce, and because the Safe tx hash includes the nonce, the scheduled entry can never run again. It stayed `Pending` for ever in `pendingTxHashes`, and `cancellationThreshold` was not reset.

**Fix:** move the state transition into `checkTransaction` (now non-`view`), which runs whether or not the call later fails. `checkAfterExecution` becomes a no-op:

```solidity
_resetCancellationThreshold(callingSafe);
scheduledTx.state = TransactionState.Executed;
_safeState[callingSafe].pendingTxHashes.remove(txHash);
emit TransactionExecuted(callingSafe, txHash);
```

**Impact:** stale pending entries, which monitoring tools read, and a cancellation threshold left higher than intended. No fund or authorization impact. **Informational.**

## 10d. Safe version checks too permissive (#18004), Informational

**Before:** TimelockGuard accepted any Safe `>= 1.3.0` (`SemverComp.lt(VERSION(), "1.3.0")`), and LivenessModule2 had no version check at all. Both contracts are documented as compatible **only** with Safe 1.4.1. Other versions differ in guard interfaces and module-guard hooks: 1.5.0 adds module guards and a guard ERC-165 check. On those versions the guard or module could behave unexpectedly or brick the Safe.

**Fix:** both `configureTimelockGuard` and `configureLivenessModule` require `SemverComp.eq(VERSION(), "1.4.1")`. **Informational** (configuration safety).

## 10e. Configuration validation gaps (#18172, shipped in op-safe-contracts v1.0.0), Informational

At `op-safe-contracts/v1.0.0` (`TimelockGuard.sol:440-465`, `LivenessModule2.sol:176-179`):

1. `configureTimelockGuard(0)` was allowed. A delay of 0 means "unconfigured", and `checkTransaction` returns early. A Safe could believe it was timelocked while it was not.
2. The guard could be configured on a Safe that had not enabled it. Configuration state existed for a Safe the guard never checks.
3. `fallbackOwner == address(safe)` was allowed. A successful challenge would make the Safe its sole owner. With threshold 1 and no external signer, it could then only act through modules, which effectively bricks it.

**Fix:**

```diff
-        if (_config.fallbackOwner == address(0)) {
+        if (_config.fallbackOwner == address(0) || _config.fallbackOwner == address(callingSafe)) {
             revert LivenessModule2_InvalidFallbackOwner();
...
+        if (!_isGuardEnabled(callingSafe)) {
+            revert TimelockGuard_GuardNotEnabled();
+        }
-        if (_timelockDelay > 365 days) {
+        if (_timelockDelay == 0 || _timelockDelay > 365 days) {
```

Also: `TransactionExecuted.txHash` became `indexed`. **Informational.** Each item needs the Safe's own quorum to choose a bad configuration.

---

## Attack scenario (10a, the most significant)

1. A Safe enables SaferSafes as module and guard, configures a 21-day liveness period with fallback owner F, and (a) a TimelockGuard delay of 7 days, or (b) later swaps in a third-party guard that turns out to revert all transactions.
2. The signers go silent. F calls `challenge(safe)`, waits 21 days, then calls `changeOwnershipToFallback(safe)`. F is now the sole owner.
3. (a) Every action F takes, including `setGuard(0)`, must first be scheduled and then wait 7 days. (b) Every `execTransaction` by F reverts in the guard, so the Safe and its assets and roles are permanently unusable.

## Impact Details

- SaferSafes guards governance multisigs. The harm is loss of the recovery guarantee, not direct theft. No outside attacker can trigger any item. Every path needs a choice by the Safe's signers (guard selection, configuration) or the fallback owner.
- 10a to 10d were fixed before any release. 10e was present in `op-safe-contracts/v1.0.0`, but it only affects Safes whose own signers chose a zero delay, an unenabled guard, or the Safe itself as fallback owner.
- Overall **Low**, driven by 10a. Had it shipped, a Safe with a faulty guard would have stayed unrecoverable despite a successful liveness challenge.

## Proof of Concept

Each fix came with regression tests: `test_changeOwnershipToFallback_*` (10a), `test_checkTransaction_failedTransaction_succeeds` (10c), `test_configure*_withWrongVersion_reverts` (10d), `test_configureTimelockGuard_zeroDelay_reverts`, `test_configureTimelockGuard_guardNotEnabled_reverts` and `test_configureLivenessModule_safeAddressFallbackOwner_reverts` (10e). The test below is adapted from `SaferSafes.t.sol` (`SaferSafes_TestInit`) for 10a. It fails on 7221832a7a^ (the guard is still set) and passes on the fix:

```solidity
// test/safe/SaferSafes.t.sol, inside a contract extending SaferSafes_TestInit
function test_poc_changeOwnershipToFallback_clearsGuard() external {
    // Configure guard (7d) and module (21d >= 2 * 7d) from the Safe.
    vm.startPrank(address(safeInstance.safe));
    saferSafes.configureTimelockGuard(7 days);
    saferSafes.configureLivenessModule(
        LivenessModule2.ModuleConfig({ livenessResponsePeriod: 21 days, fallbackOwner: fallbackOwner })
    );
    vm.stopPrank();

    vm.prank(fallbackOwner);
    saferSafes.challenge(address(safeInstance.safe));
    vm.warp(block.timestamp + 21 days + 1);
    vm.prank(fallbackOwner);
    saferSafes.changeOwnershipToFallback(address(safeInstance.safe));

    // keccak256("guard_manager.guard.address")
    bytes32 GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    address guard = abi.decode(safeInstance.safe.getStorageAt(uint256(GUARD_SLOT), 1), (address));
    // Parent: guard == address(saferSafes), so the fallback owner is still timelocked. Fix: address(0).
    assertEq(guard, address(0), "guard still active after recovery");
}
```

For 10e, the fix's own tests fail on `op-safe-contracts/v1.0.0` and pass on 391053e505:

```solidity
function test_configureTimelockGuard_zeroDelay_reverts() external {
    vm.expectRevert(TimelockGuard.TimelockGuard_InvalidTimelockDelay.selector);
    vm.prank(address(safeInstance.safe));
    timelockGuard.configureTimelockGuard(0);
}
function test_configureLivenessModule_safeAddressFallbackOwner_reverts() external {
    vm.expectRevert(LivenessModule2.LivenessModule2_InvalidFallbackOwner.selector);
    vm.prank(address(safeInstance.safe));
    livenessModule2.configureLivenessModule(
        LivenessModule2.ModuleConfig({ livenessResponsePeriod: CHALLENGE_PERIOD, fallbackOwner: address(safeInstance.safe) })
    );
}
```

Run:

```bash
cd packages/contracts-bedrock
forge test --match-path 'test/safe/*' -vvv
```

Executed: **no**. It needs a contracts build at each parent commit, and checkouts are not allowed in this review. The PoCs are adapted directly from the fixes' own regression tests.

## Recommendation

The fixes are appropriate. Further suggestions:

- Document for operators that a successful liveness challenge **removes any guard**, including third-party guards, so monitoring does not treat that as an attack.
- Consider the Safe 1.5 module-guard hook before widening version support. 10b's ordering fix should be kept, because later Safe versions do call external code on module transactions.
- Operators of Safes configured under `op-safe-contracts/v1.0.0` should confirm they did not set `timelockDelay == 0` or `fallbackOwner == safe`.

## References

- Fix commits: 7221832a7a030c390e2dd1ce632bb87737fa8bab, d3abbbdfa8361be32d10cf9e6d3fb2ac2377447e, 59e86721a4665f0d84f618ca037f4af6c74ccba0, 3c326a7e0ef3b335931791eefcb3b4b3e6f4612e, 391053e505c378c1d515b8844e57a6d16cb87aef
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/17808, https://github.com/ethereum-optimism/optimism/pull/17975, https://github.com/ethereum-optimism/optimism/pull/17995, https://github.com/ethereum-optimism/optimism/pull/18004, https://github.com/ethereum-optimism/optimism/pull/18172
- Relevant files: `packages/contracts-bedrock/src/safe/LivenessModule2.sol`, `packages/contracts-bedrock/src/safe/TimelockGuard.sol`, `packages/contracts-bedrock/src/safe/SaferSafes.sol`, `packages/contracts-bedrock/test/safe/{LivenessModule2,TimelockGuard,SaferSafes}.t.sol`
- Release tags: `op-safe-contracts/v1.0.0` (lacks #18172), `op-safe-contracts/v1.1.0` (includes #18172)
