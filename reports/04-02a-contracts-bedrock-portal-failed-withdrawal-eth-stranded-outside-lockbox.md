# OptimismPortal2 (ETHLockbox design): ETH from failed withdrawals stranded in the portal instead of returned to the lockbox

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/L1/OptimismPortal2.sol` (`finalizeWithdrawalTransactionExternalProof`) |
| **Asset type** | Smart Contract |
| **Severity** | Informational (accounting hygiene; no user loss beyond the protocol's existing failed-withdrawal semantics; pre-deployment code) |
| **Impact category** | "Contract fails to deliver promised returns, but doesn't lose value" (closest fit; value is stranded, not stolen) |
| **Fix commit(s)** | b671b67f75f6fe2041672d91bd3a6a777cd6a367 (PR #15513, "cantina contest updates"), 2025-04-30 |
| **Vulnerable since** | cbe992160b "feat: interop portal updates" (PR #14664), 2025-03-10. Upgrade 16 / ETHLockbox code on `develop`, found in the Cantina audit contest before any deployment. |

## Brief / Intro

Upgrade 16 moved the ETH that backs L2 ETH out of the `OptimismPortal` and into a new `ETHLockbox` contract. When a withdrawal is finalized, the portal first pulls the withdrawal's value out of the lockbox and then forwards it to the L2 user's chosen target. If that target call fails, the withdrawal is still marked as done, since the protocol does not allow replays. The ETH, however, stayed in the portal instead of going back to the lockbox. There it sat outside the lockbox's accounting, and no code path could ever use it again.

## Vulnerability Details

Parent of the fix, `src/L1/OptimismPortal2.sol` (`finalizeWithdrawalTransactionExternalProof`, around lines 598-653):

```solidity
// Mark the withdrawal as finalized so it can't be replayed.
finalizedWithdrawals[withdrawalHash] = true;

// Unlock the ETH from the ETHLockbox.
if (_tx.value > 0) ethLockbox.unlockETH(_tx.value);   // lockbox -> portal (donateETH)

l2Sender = _tx.sender;
bool success = SafeCall.callWithMinGas(_tx.target, _tx.gasLimit, _tx.value, _tx.data);
l2Sender = Constants.DEFAULT_L2_SENDER;

emit WithdrawalFinalized(withdrawalHash, success);
// <- if !success, `_tx.value` is now sitting in the portal's own balance
```

`ETHLockbox.unlockETH` sends the value to the portal through `donateETH()`. If `callWithMinGas` returns `false`, which happens whenever the target reverts, the portal keeps the value. Under the lockbox design, the portal has no function that moves its own balance anywhere except the value forwarded in a later withdrawal's call, and every later withdrawal unlocks its own value from the lockbox first. So the stranded ETH is never used again. It stays out of `migrateLiquidity`, it does not count toward the lockbox balance, and it could only be recovered through a contract upgrade.

Fix:
```diff
         emit WithdrawalFinalized(withdrawalHash, success);

+        // Send ETH back to the Lockbox or it'll get stuck here.
+        if (!success) {
+            ethLockbox.lockETH{ value: _tx.value }();
+        }
```

### Attack scenario

There is no attacker. Anyone whose withdrawal target reverts triggers this by accident:

1. A user withdraws 1 ETH on L2 to an L1 contract that reverts, or with a `gasLimit` that is too low for the call.
2. After the proof maturity delay, anyone finalizes the withdrawal. The lockbox sends 1 ETH to the portal, the call fails, and the withdrawal is marked finalized.
3. The 1 ETH stays in `OptimismPortal2` for good. The lockbox's balance, which is the ETH backing the chain (or the whole interop set after the super-root migration), is 1 ETH lower than the ETH the system actually holds.

## Impact Details

- **User funds:** no extra loss. Under OptimismPortal semantics, a failed withdrawal is final and its value is forfeit. Before the lockbox existed, that ETH also stayed in the portal. The user's position is the same before and after the fix.
- **Solvency:** not affected. The L2 ETH was burned when the withdrawal was initiated, and the lockbox paid out the same amount. The lockbox therefore still backs every remaining L2 ETH, and the stranded ETH was surplus.
- **What was actually wrong:** surplus value ends up in a contract that is not meant to hold ETH in the new design. It is left out of the lockbox's accounting and of any `migrateLiquidity` to a shared interop lockbox, and only an upgrade can recover it. This is value stuck in a contract, not theft.
- **Exposure:** the code was an unreleased Upgrade 16 candidate on `develop` for about seven weeks. The contest found it, and it was fixed before `op-contracts/v4.0.0`.

For these reasons the issue is rated Informational. The triage note described it as "permanent freezing of funds". That overstates the harm, because the value was already forfeit to the user under the protocol's documented behaviour.

## Proof of Concept

This adapts the regression assertion the fix added to `test/L1/OptimismPortal2.t.sol` (`OptimismPortal2_FinalizeWithdrawal_Test`, the test that finalizes a withdrawal whose target reverts). Before the fix, the test only checked that Bob's balance did not change. The fix added a check that the portal holds no ETH afterwards. Against the parent contract, that new assertion fails with `portal balance == _defaultTx.value`.

```solidity
// test/L1/OptimismPortal2.t.sol, inside OptimismPortal2_FinalizeWithdrawal_Test
// (same setup as the existing "..._targetFails_fails" test)
function test_poc_finalizeWithdrawal_failedCall_strandsEthInPortal() external {
    uint256 bobBalanceBefore = address(bob).balance;
    uint256 lockboxBefore = address(ethLockbox).balance;

    vm.etch(bob, hex"fe"); // bob's code always reverts (INVALID)

    optimismPortal2.proveWithdrawalTransaction({
        _tx: _defaultTx,
        _disputeGameIndex: _proposedGameIndex,
        _outputRootProof: _outputRootProof,
        _withdrawalProof: _withdrawalProof
    });

    game.resolveClaim(0, 0);
    game.resolve();
    vm.warp(block.timestamp + optimismPortal2.proofMaturityDelaySeconds() + 1);

    vm.expectEmit(address(optimismPortal2));
    emit WithdrawalFinalized(_withdrawalHash, false);
    optimismPortal2.finalizeWithdrawalTransaction(_defaultTx);

    assertEq(address(bob).balance, bobBalanceBefore);
    // Parent commit: FAILS - portal now holds _defaultTx.value, lockbox is short by the same.
    assertEq(address(optimismPortal2).balance, 0);
    assertEq(address(ethLockbox).balance, lockboxBefore);
}
```

Run (in a checkout of `b671b67f75^` and then of `b671b67f75`):
```bash
cd packages/contracts-bedrock
forge test --match-test test_poc_finalizeWithdrawal_failedCall_strandsEthInPortal -vvv
```

Executed: **no**. A full contracts-bedrock build of a historical commit was not run. The PoC mirrors the assertion the fix added to the existing test.

## Recommendation

The fix re-locks the value after a failed call (`ethLockbox.lockETH{value: _tx.value}()`), so all bridge ETH is again held in the lockbox. Suggested follow-ups:
- Add an invariant test that `address(optimismPortal2).balance == 0` after every public entry point on lockbox-enabled chains.
- Document clearly that the value of a failed withdrawal returns to the shared lockbox and is not refundable.

## References

- Fix commit: b671b67f75f6fe2041672d91bd3a6a777cd6a367
- Pull request: https://github.com/ethereum-optimism/optimism/pull/15513
- Introducing change: cbe992160b (https://github.com/ethereum-optimism/optimism/pull/14664)
- Relevant files: `packages/contracts-bedrock/src/L1/OptimismPortal2.sol`, `packages/contracts-bedrock/src/L1/ETHLockbox.sol`, `packages/contracts-bedrock/test/L1/OptimismPortal2.t.sol`
- Specs: https://specs.optimism.io/protocol/withdrawals.html
