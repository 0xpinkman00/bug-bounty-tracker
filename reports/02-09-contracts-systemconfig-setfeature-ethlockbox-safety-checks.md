# SystemConfig.setFeature(ETH_LOCKBOX) could be toggled with a lockbox still configured or while paused, silently unpausing the chain or routing withdrawals to an empty portal

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/L1/SystemConfig.sol` `setFeature` (interacting with `OptimismPortal2._isUsingLockbox` and `SystemConfig.paused`) |
| **Asset type** | Smart Contract |
| **Severity** | Informational (privileged-only misconfiguration guard; never in a release) |
| **Impact category** | Closest: "Unexpected unpause" / "Temporary freezing of funds". Requires the ProxyAdmin or its owner to act |
| **Fix commit(s)** | d10392338bb95252a9950abfb20556d351fe3056 (PR #17559), 2025-09-24 |
| **Vulnerable since** | 539c39a176 "feat: add feature flagging functionality to SystemConfig" (PR #17281), 2025-09-03. About 3 weeks on `develop`. Every `op-contracts/*` tag that contains 539c39a176 also contains the fix (checked with `git tag --contains`). |

## Brief / Intro

The `ETHLockbox` is a contract that holds the ETH bridged to an OP Stack chain, instead of the `OptimismPortal` holding it. In September 2025 a generic *feature flag* mechanism was added to `SystemConfig`, and `ETH_LOCKBOX` became one of those flags. Its value decides two things: where the portal sends and takes ETH, and which address the Guardian's per-chain pause is keyed on. The first version of `setFeature` let the ProxyAdmin owner flip the flag at any time. Flipping it off while the portal still had a lockbox would make withdrawals try to pay out from an empty portal. Flipping it in either direction while the chain was paused would change the pause key and silently unpause the chain. The fix adds two guard checks. Only the chain's ProxyAdmin or ProxyAdmin owner can call `setFeature`, so this is a guard against operator error, not an externally exploitable bug.

## Vulnerability Details

Parent of fix, `SystemConfig.sol:504-519`:

```solidity
function setFeature(bytes32 _feature, bool _enabled) external {
    _assertOnlyProxyAdminOrProxyAdminOwner();
    if (_enabled == isFeatureEnabled[_feature]) {
        revert SystemConfig_InvalidFeatureState();
    }
    isFeatureEnabled[_feature] = _enabled;       // no ETH_LOCKBOX-specific checks
    emit FeatureSet(_feature, _enabled);
}
```

**Problem 1: accounting split.** The portal decides whether to use the lockbox on each call (`OptimismPortal2.sol:613-615`):

```solidity
function _isUsingLockbox() internal view returns (bool) {
    return systemConfig.isFeatureEnabled(Features.ETH_LOCKBOX) && address(ethLockbox) != address(0);
}
```

The consistency check `_assertValidLockboxState()` (flag on implies lockbox set, and vice versa) runs only in `initialize` (line 237). If the flag is turned off after initialization:
- `depositTransaction` keeps new ETH in the portal instead of calling `ethLockbox.lockETH`.
- `finalizeWithdrawalTransaction` no longer calls `ethLockbox.unlockETH(_tx.value)`. It calls `SafeCall.callWithMinGas(_tx.target, _tx.gasLimit, _tx.value, ...)` from the portal's own balance. That balance is close to zero because the historical ETH is in the lockbox. The CALL fails for lack of balance and `success == false`, but the withdrawal has already been marked `finalizedWithdrawals[hash] = true`. The user's withdrawal is consumed without paying out, and the ETH stays in the lockbox until an admin intervenes.

**Problem 2: unexpected unpause.** `SystemConfig.paused()` picks the pause identifier from the same flag (`SystemConfig.sol:527-535`):

```solidity
address identifier = isFeatureEnabled[Features.ETH_LOCKBOX]
    ? address(IOptimismPortal2(payable(optimismPortal())).ethLockbox())
    : address(optimismPortal());
return superchainConfig.paused(address(0)) || superchainConfig.paused(identifier);
```

If the Guardian paused this chain locally, `superchainConfig.pause(lockbox)`, then flipping the flag off switches the identifier to the portal. `paused()` returns `false` and withdrawals resume, without the Guardian doing anything. The reverse (paused on the portal identifier, then the flag turned on) has the same effect.

The fix (`SystemConfig.sol:514-538` at d10392338b):

```solidity
if (_feature == Features.ETH_LOCKBOX) {
    // Can't disable while the portal still has a lockbox configured
    if (
        isFeatureEnabled[_feature] && !_enabled
            && address(IOptimismPortal2(payable(optimismPortal())).ethLockbox()) != address(0)
    ) {
        revert SystemConfig_InvalidFeatureState();
    }
    // Can't toggle while paused (would change the pause identifier)
    if (paused()) {
        revert SystemConfig_InvalidFeatureState();
    }
}
```

### Attack scenario (operator-error scenario)

1. A chain uses the lockbox: the flag is on and `portal.ethLockbox() != 0`. The Guardian pauses it with `superchainConfig.pause(lockbox)` during an incident.
2. The ProxyAdmin owner calls `systemConfig.setFeature(ETH_LOCKBOX, false)`, for example as part of a misconfigured upgrade batch.
3. `systemConfig.paused()` now returns `false`, so withdrawals can be finalized during the incident. Each finalization then tries to pay from the empty portal, fails, and burns the user's withdrawal.

## Impact Details

- **Preconditions:** the caller must be the chain's ProxyAdmin or ProxyAdmin owner, both highly trusted roles. No unprivileged path exists.
- **Consequence if triggered:** unpausing during an incident, and failed withdrawals that are still marked finalized (funds stay in the lockbox and need admin recovery).
- **Exposure:** about 3 weeks on `develop`. No `op-contracts` release shipped the unguarded version.
- **Severity:** **Informational**. This is defense in depth against privileged misconfiguration in unreleased code.

## Proof of Concept

The fix added three regression tests to `test/L1/SystemConfig.t.sol` (`SystemConfig_SetFeature_Test`): `test_setFeature_ethLockboxDisableWhileConfigured_reverts`, `test_setFeature_ethLockboxEnableWhilePaused_reverts` and `test_setFeature_ethLockboxDisableWhilePaused_reverts`. The test below is adapted from them to show the unexpected-unpause consequence explicitly. Add it to `SystemConfig_SetFeature_Test`. It fails on the parent because `setFeature` succeeds and the chain becomes unpaused. It passes on the fix because `setFeature` reverts.

```solidity
/// @notice PoC: flipping ETH_LOCKBOX while locally paused must not unpause the chain.
function test_poc_setFeature_ethLockboxToggleWhilePaused_doesNotUnpause() external {
    address proxyAdmin = address(systemConfig.proxyAdmin());

    // Ensure the lockbox feature is on and the portal has a lockbox configured.
    if (!systemConfig.isFeatureEnabled(Features.ETH_LOCKBOX)) {
        vm.prank(proxyAdmin);
        systemConfig.setFeature(Features.ETH_LOCKBOX, true);
    }
    address lockbox = address(optimismPortal2.ethLockbox());
    if (lockbox == address(0)) {
        lockbox = address(0xB0C5);
        StorageSlot memory slot = ForgeArtifacts.getSlot("OptimismPortal2", "ethLockbox");
        vm.store(address(optimismPortal2), bytes32(slot.slot), bytes32(uint256(uint160(lockbox))));
    }

    // Guardian pauses this chain locally (identifier = lockbox).
    vm.prank(superchainConfig.guardian());
    superchainConfig.pause(lockbox);
    assertTrue(systemConfig.paused());

    // Operator flips the flag. Parent: succeeds. Fix: reverts.
    vm.prank(proxyAdmin);
    try systemConfig.setFeature(Features.ETH_LOCKBOX, false) { } catch { }

    // Parent: false (the chain silently unpaused). Fix: still true.
    assertTrue(systemConfig.paused(), "chain was unpaused by a feature toggle");
}
```

Run:

```bash
cd packages/contracts-bedrock
forge test --match-contract SystemConfig_SetFeature_Test --match-test ethLockbox -vvv
```

Executed: **no**. It would need a full contracts build at both commits, and a checkout is not allowed in this review. The logic follows directly from the parent's `paused()` identifier selection and the lack of checks in `setFeature` shown above.

## Recommendation

The fix is appropriate. Additional hardening:

- Have `OptimismPortal2` call `_assertValidLockboxState()` at the start of `finalizeWithdrawalTransaction` and `depositTransaction`, not only at `initialize`. A flag/lockbox mismatch would then fail closed (revert) instead of burning withdrawals.
- Record the pause identifier at pause time rather than deriving it from mutable feature state.

## References

- Fix commit: d10392338bb95252a9950abfb20556d351fe3056
- Pull request: https://github.com/ethereum-optimism/optimism/pull/17559
- Introducing PR: https://github.com/ethereum-optimism/optimism/pull/17281
- Relevant files: `packages/contracts-bedrock/src/L1/SystemConfig.sol`, `packages/contracts-bedrock/src/L1/OptimismPortal2.sol`, `packages/contracts-bedrock/test/L1/SystemConfig.t.sol`
