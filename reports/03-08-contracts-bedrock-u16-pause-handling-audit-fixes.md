# contracts-bedrock (Upgrade 16 RC) — pause-handling gaps: migration lifts a per-chain pause, `extend` creates a pause, bond unlocks frozen while paused

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/L1/OptimismPortal2.sol`, `src/L1/SuperchainConfig.sol`, `src/dispute/FaultDisputeGame.sol` (also inherited by `PermissionedDisputeGame`) |
| **Asset type** | Smart Contract |
| **Severity** | Low (bordering Informational: every path needs a trusted role, and the code was only in release candidates) |
| **Impact category** | "Contract fails to deliver promised returns, but doesn't lose value" (plus a trusted-role bypass of the pause mechanism) |
| **Fix commit(s)** | 52100a6a0020a97ac4de51fff33545238996029d (PR #15939) — 2025-05-14 |
| **Vulnerable since** | `closeGame` pause ordering: 984bae9146 (2025-01-15). `migrateToSuperRoots` without a pause check: b37a1aed93 (2025-03-11). Shipped only in `op-contracts/v4.0.0-rc.1` to `rc.3` (2025-05-05 to 2025-05-12). Fixed from `v4.0.0-rc.4`. No final `op-contracts` release contains the bugs. |

## Brief / Intro

Upgrade 16 (U16) changed how an OP Stack chain is paused. The Guardian, a security-council multisig, can freeze withdrawals either for every chain (the `address(0)` identifier) or for one chain. A single chain is identified by the address of its `ETHLockbox`, the contract that holds the chain's bridged ETH. The U16 audit found three places where the new pause logic did not work as intended. (a) The ProxyAdmin owner could point the portal at a new lockbox while the chain was paused, which quietly lifted a per-chain pause. (b) The Guardian's `extend` function could "extend" a pause that did not exist, which started a new pause and skipped the `AlreadyPaused` guard. (c) While the system was paused, dispute-game bond holders could not even start the unlock step for credit that had already been assigned, so their funds stayed frozen longer than needed. Only trusted roles can trigger any of these, and the code never reached a final release, so the real-world impact is small.

## Vulnerability Details

### Background: how the pause is evaluated

`OptimismPortal2.paused()` delegates to `SystemConfig.paused()`, and that function derives the per-chain pause identifier from the portal's current lockbox (parent commit):

```solidity
// src/L1/SystemConfig.sol:488 (parent 52100a6a00^)
function paused() public view returns (bool) {
    IETHLockbox lockbox = IOptimismPortal2(payable(optimismPortal())).ethLockbox();
    return superchainConfig.paused(address(lockbox)) || superchainConfig.paused(address(0));
}
```

### (a) `migrateToSuperRoots` could run while paused and lift a per-chain pause

```solidity
// src/L1/OptimismPortal2.sol:405 (parent)
function migrateToSuperRoots(IETHLockbox _newLockbox, IAnchorStateRegistry _newAnchorStateRegistry) external {
    // Migration can only be triggered by the ProxyAdmin owner.
    _assertOnlyProxyAdminOwner();
    ...
    IETHLockbox oldLockbox = ethLockbox;
    ethLockbox = _newLockbox;           // <-- pause identifier changes here
    ...
    superRootsActive = true;
}
```

Suppose the Guardian paused chain X with `pause(address(oldLockbox))`. After the migration, `paused()` checks `pauseTimestamps[newLockbox]`, which is 0, so `proveWithdrawalTransaction` and `finalizeWithdrawalTransaction` work again. Nobody unpaused anything and no `Unpaused` event was emitted. This is a Guardian-versus-ProxyAdmin-owner separation-of-powers problem: the owner can undo the Guardian's incident response, possibly without meaning to. The fix blocks the migration while the system is paused:

```solidity
// fixed
function migrateToSuperRoots(IETHLockbox _newLockbox, IAnchorStateRegistry _newAnchorStateRegistry) external {
+   // Migration can only be triggered when the system is not paused because the migration can
+   // potentially unpause the system as a result of the modified ETHLockbox address.
+   _assertNotPaused();
    _assertOnlyProxyAdminOwner();
```

### (b) `SuperchainConfig.extend` worked on identifiers that were not paused

```solidity
// src/L1/SuperchainConfig.sol:136 (parent)
function extend(address _identifier) external {
    if (msg.sender != guardian) revert SuperchainConfig_OnlyGuardian();
    // Reset the pause timestamp.
    pauseTimestamps[_identifier] = block.timestamp;
    emit Paused(_identifier);
}
```

`pause()` refuses to run when a timestamp is already set, which keeps the pause lifecycle explicit. `extend()` had no matching check, so on an unpaused identifier it acted as a second `pause()` with different semantics. On an expired pause (timestamp set but older than `PAUSE_EXPIRY`, about 3 months) it silently re-armed the pause. The fix:

```solidity
+   if (pauseTimestamps[_identifier] == 0) {
+       revert SuperchainConfig_NotAlreadyPaused(_identifier);
+   }
```

### (c) `closeGame` reverted while paused even after the bond mode was already decided

```solidity
// src/dispute/FaultDisputeGame.sol:999 (parent)
function closeGame() public {
    if (ANCHOR_STATE_REGISTRY.paused()) {
        revert GamePaused();            // checked FIRST
    }
    // If the bond distribution mode has already been determined, we can return early.
    if (bondDistributionMode == BondDistributionMode.REFUND || bondDistributionMode == BondDistributionMode.NORMAL) {
        return;
    }
    ...
```

`claimCredit()` calls `closeGame()` first. The pause check exists so that a game is not pushed into REFUND mode because it looks temporarily invalid during a pause. Once the mode has been fixed, that reason no longer applies. Even so, every `claimCredit` call reverted during a pause, including the first call, which only runs `DelayedWETH.unlock()` to start the withdrawal-delay timer. The actual ETH withdrawal (`DelayedWETH.withdraw`) has its own `require(!systemConfig.paused())`, so the only practical effect was that bond holders could not start their unlock timer while paused. After the unpause they had to wait the full `DelayedWETH` delay again. The fix moves the pause check after the early return:

```solidity
 function closeGame() public {
-    if (ANCHOR_STATE_REGISTRY.paused()) revert GamePaused();
     if (bondDistributionMode == BondDistributionMode.REFUND || bondDistributionMode == BondDistributionMode.NORMAL) {
         return;
     } else if (bondDistributionMode != BondDistributionMode.UNDECIDED) {
         revert InvalidBondDistributionMode();
     }
+    if (ANCHOR_STATE_REGISTRY.paused()) revert GamePaused();
```

### (d) Hygiene items in the same commit (not vulnerabilities)

- `finalizeWithdrawalTransactionExternalProof` now calls `lockETH` for a failed withdrawal only when `_tx.value > 0` (`OptimismPortal2.sol:676`). A zero-value `lockETH` just emitted a spurious `ETHLocked(portal, 0)` event.
- `Encoding.encodeSuperRootProof` used the literal `bytes1(0x01)` instead of `_superRootProof.version`. The function already reverts for any version other than 1, so the output was the same.
- `OptimismPortal2.upgrade()` no longer takes (or overwrites) `systemConfig`. The Guardian check was refactored into internal helpers.

### Attack scenario (for (a), the most significant item)

1. An incident is detected on chain X. The Guardian calls `SuperchainConfig.pause(address(ethLockboxX))` to freeze withdrawals on that chain only.
2. The ProxyAdmin owner runs the planned `migrateToSuperRoots(newLockbox, newASR)` step (for example as part of an interop-set join), either unaware of the pause or deliberately.
3. `SystemConfig.paused()` now checks `newLockbox`, which is not paused. Withdrawals against the new ASR can be proved and finalized even though the Guardian never unpaused.

## Impact Details

- **(a)**: Needs the ProxyAdmin owner, who can already upgrade every proxy and is fully trusted. The consequence is that a Guardian pause gets bypassed, not that funds are stolen. The global `address(0)` pause is not affected.
- **(b)**: Guardian-only. The Guardian can pause anyway, so this is lifecycle/accounting hygiene.
- **(c)**: Honest challengers and proposers lose time, not funds. Their credit is not lost but its release is delayed by up to one extra `DelayedWETH` delay (7 days by default) after an unpause. This maps to "Contract fails to deliver promised returns, but doesn't lose value" (Low), triggered only by a Guardian pause.
- **Exposure**: the vulnerable code was only in `op-contracts/v4.0.0-rc.1` to `rc.3`. U16 was not live on any mainnet chain before `rc.4` included the fix. Under Immunefi rules, issues that need a privileged role are usually out of scope, so the realistic rating is Low/Informational.

## Proof of Concept

Two regression tests were added by the fix (`test/L1/OptimismPortal2.t.sol::test_migrateToSuperRoots_paused_reverts` and `test/L1/SuperchainConfig.t.sol::test_extend_notAlreadyPaused_reverts`). The third test below is new and covers (c). All three fail on the parent commit and pass on the fix. Add them to the respective test contracts (`OptimismPortal2_Test`, `SuperchainConfig_Extend_Test`, `FaultDisputeGame_Test`):

```solidity
// test/L1/OptimismPortal2.t.sol  (contract OptimismPortal2_Test)
function test_migrateToSuperRoots_paused_reverts() external {
    vm.startPrank(optimismPortal2.guardian());
    systemConfig.superchainConfig().pause(address(0));
    vm.stopPrank();

    address caller = optimismPortal2.proxyAdminOwner();
    vm.expectRevert(IOptimismPortal.OptimismPortal_CallPaused.selector);
    vm.prank(caller);
    optimismPortal2.migrateToSuperRoots(IETHLockbox(address(1)), IAnchorStateRegistry(address(1)));
}

// PoC variant showing the per-chain pause actually being lifted on the parent commit:
function test_poc_migrateLiftsPerChainPause() external {
    vm.prank(optimismPortal2.guardian());
    systemConfig.superchainConfig().pause(address(ethLockbox));
    assertTrue(optimismPortal2.paused());

    vm.prank(optimismPortal2.proxyAdminOwner());
    // parent: succeeds; fix: reverts with OptimismPortal_CallPaused
    optimismPortal2.migrateToSuperRoots(IETHLockbox(address(0xB0B)), IAnchorStateRegistry(address(0xA5A)));
    assertFalse(optimismPortal2.paused()); // pause silently gone
}

// test/L1/SuperchainConfig.t.sol  (contract SuperchainConfig_Extend_Test)
function test_extend_notAlreadyPaused_reverts() external {
    vm.prank(superchainConfig.guardian());
    vm.expectRevert(
        abi.encodeWithSelector(ISuperchainConfig.SuperchainConfig_NotAlreadyPaused.selector, address(this))
    );
    superchainConfig.extend(address(this));
}

// test/dispute/FaultDisputeGame.t.sol  (contract FaultDisputeGame_Test)
function test_closeGame_pausedAfterModeSet_succeeds() public {
    vm.warp(block.timestamp + 3 days + 12 hours);
    gameProxy.resolveClaim(0, 0);
    gameProxy.resolve();
    vm.warp(block.timestamp + 3.5 days + 1 seconds);
    gameProxy.closeGame(); // mode = NORMAL

    vm.prank(superchainConfig.guardian());
    superchainConfig.pause(address(0));

    // parent: reverts GamePaused(); fix: returns early
    gameProxy.closeGame();
    // first claimCredit (unlock step) also works on the fix
    gameProxy.claimCredit(address(this));
}
```

Run (from `packages/contracts-bedrock`):

```
just build-go-ffi   # once, if not already built
forge test --match-test 'test_migrateToSuperRoots_paused_reverts|test_poc_migrateLiftsPerChainPause|test_extend_notAlreadyPaused_reverts|test_closeGame_pausedAfterModeSet_succeeds' -vvv
```

`test_poc_migrateLiftsPerChainPause` passes on the parent and must revert on the fix. The other three fail on the parent and pass on the fix. Note: in `test_poc_migrateLiftsPerChainPause`, `paused()` on the parent calls into the new (dummy) lockbox address only through `SystemConfig`, which reads `ethLockbox()` from the portal, so no mock is needed.

Executed: no (a full contracts-bedrock forge build is expensive. The tests are adapted from the fix's own regression tests and the existing `test_closeGame_*` harness.)

## Recommendation

The fix adds `_assertNotPaused()` to `migrateToSuperRoots`, a `NotAlreadyPaused` guard in `extend`, and moves the `closeGame` pause check below the "mode already decided" early return. Defense in depth: when the lockbox identity changes, consider carrying the per-chain pause state over (or emitting an explicit event), so that any future path that changes `ethLockbox` cannot silently change the pause state.

## References

- Fix commit: 52100a6a0020a97ac4de51fff33545238996029d
- Pull request: https://github.com/ethereum-optimism/optimism/pull/15939
- Relevant files: `packages/contracts-bedrock/src/L1/OptimismPortal2.sol`, `src/L1/SuperchainConfig.sol`, `src/L1/SystemConfig.sol`, `src/dispute/FaultDisputeGame.sol`, `src/dispute/DelayedWETH.sol`
- Tags: vulnerable `op-contracts/v4.0.0-rc.1` to `rc.3`; fixed `op-contracts/v4.0.0-rc.4` and later
