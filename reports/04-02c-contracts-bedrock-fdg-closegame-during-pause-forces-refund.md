# FaultDisputeGame: `closeGame()` during a system pause locked games into REFUND mode, costing honest challengers their rewards

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/dispute/FaultDisputeGame.sol`, `SuperFaultDisputeGame.sol` (`closeGame` / `claimCredit`), with `AnchorStateRegistry.isGameProper` |
| **Asset type** | Smart Contract |
| **Severity** | Low (pre-deployment; would be Medium if deployed) |
| **Impact category** | "Theft of unclaimed yield" (the challenger's bond reward goes back to the losing party) / "Griefing" |
| **Fix commit(s)** | b671b67f75f6fe2041672d91bd3a6a777cd6a367 (PR #15513, "cantina contest updates"), 2025-04-30 |
| **Vulnerable since** | cbe992160b "feat: interop portal updates" (PR #14664), 2025-03-10, which added `if (paused()) return false;` to `AnchorStateRegistry.isGameProper`. Released contracts before this (`op-contracts/v3.0.0`, ASR 2.2.2) had no pause check in `isGameProper` and were not affected. Fixed before `op-contracts/v4.0.0`. |

## Brief / Intro

In OP Stack fault proofs, anyone who posts a claim in a dispute game locks up a bond. When the game ends, the winning side collects the losing side's bonds. There is a safety valve: if the game turns out to be "improper" (blacklisted, retired, or otherwise untrusted), the game enters *REFUND* mode and everyone just gets their own bond back. On the Upgrade 16 development branch, "the system is currently paused" was added as one of the reasons a game counts as improper. The decision to use REFUND mode is made once and can never be changed. So anyone, including a dishonest proposer who had just lost, could call `closeGame()` (or `claimCredit()`) on a finished game while the Guardian had the system paused. That locked the game into REFUND mode for good, and the honest challenger lost the reward they had won.

## Vulnerability Details

Parent of the fix, `src/dispute/AnchorStateRegistry.sol`:
```solidity
function isGameProper(IDisputeGame _game) public view returns (bool) {
    if (!isGameRegistered(_game)) return false;
    if (isGameBlacklisted(_game)) return false;
    if (isGameRetired(_game)) return false;
    // Must not be paused, temporarily causes game to be considered improper.
    if (paused()) return false;
    return true;
}
```

Parent of the fix, `src/dispute/FaultDisputeGame.sol:998` (`closeGame`, which `claimCredit` calls first):
```solidity
function closeGame() public {
    if (bondDistributionMode == BondDistributionMode.REFUND || bondDistributionMode == BondDistributionMode.NORMAL) {
        return;                                           // decision is final
    }
    ...
    bool finalized = ANCHOR_STATE_REGISTRY.isGameFinalized(IDisputeGame(address(this)));
    if (!finalized) revert GameNotFinalized();
    try ANCHOR_STATE_REGISTRY.setAnchorState(IDisputeGame(address(this))) { } catch { }

    bool properGame = ANCHOR_STATE_REGISTRY.isGameProper(IDisputeGame(address(this)));
    if (properGame) {
        bondDistributionMode = BondDistributionMode.NORMAL;
    } else {
        bondDistributionMode = BondDistributionMode.REFUND;   // <- pause makes this branch taken
    }
}
```

`isGameFinalized` only checks that the game is resolved and that the finality delay has passed. It does not look at the pause. So while the system is paused, every resolved and finalized game that has not yet been closed can be moved permanently to REFUND by a single permissionless call. The comment in the ASR says a pause makes the game improper only *temporarily*. `closeGame` turned that temporary state into a permanent one.

`SuperFaultDisputeGame.closeGame` has the same logic.

Fix (the same change in both games):
```diff
 function closeGame() public {
+    if (ANCHOR_STATE_REGISTRY.paused()) {
+        revert GamePaused();
+    }
```
Now a game can only reach REFUND mode through an explicit blacklist or retirement. Because `claimCredit` calls `closeGame` first, bond claims are also blocked during a pause (`test_claimCredit_gamePaused_reverts`).

### Attack scenario

1. Mallory proposes an invalid output root and posts a bond. Alice, an honest challenger, counters it. The game resolves `CHALLENGER_WINS`, which gives Alice credit for Mallory's bond in NORMAL mode.
2. The Guardian pauses the Superchain for an unrelated reason, such as an incident response. `SuperchainConfig.pause(address(0))` stays in effect for up to about 3 months (`PAUSE_EXPIRY = 7_884_000`).
3. After the game's finality delay has passed and while the pause is on, Mallory calls `game.claimCredit(mallory)`. `closeGame()` sees `isGameProper == false` and sets `bondDistributionMode = REFUND` permanently.
4. After unpausing, Mallory gets her bond back through `refundModeCredit`, and Alice only gets her own bond back. Alice loses the reward that the protocol relies on to pay honest challengers.

## Impact Details

- **Who loses:** the honest winning parties of every game that was resolved and finalized but not yet closed while a pause was active. Their unclaimed rewards (the losers' bonds) go back to the losers.
- **Who gains:** the losing parties, which includes dishonest proposers and challengers. It also weakens the economic deterrent against bad claims, because a pause gives a free way out.
- **Preconditions:** the Guardian must pause the system, which only happens in emergencies. The attacker needs no privilege, and the call is cheap.
- **Mitigating factors:** the code was an Upgrade 16 candidate on `develop` (Mar 10 to Apr 30, 2025). The Cantina contest found it and it was fixed before any tagged release or deployment. Deployed games at the time used ASR 2.2.2, which had no pause check in `isGameProper`.

If it had been deployed, this would be Medium: loss of unclaimed yield that depends on a pause. Because it never shipped, the rating is **Low**.

## Proof of Concept

This is adapted from `test_claimCredit_refundMode_succeeds` and the regression test `test_closeGame_gamePaused_reverts` that the fix added (`test/dispute/FaultDisputeGame.t.sol`). On the parent commit, the final assertions show REFUND mode and that Bob, the honest winner, receives only his own bond. On the fix, `claimCredit` reverts with `GamePaused` while paused, and after unpausing the game closes in NORMAL mode.

```solidity
// test/dispute/FaultDisputeGame.t.sol, inside FaultDisputeGame_Test
function test_poc_pauseForcesRefund() public {
    address alice = address(0xa11ce); // dishonest: attacks the (valid) root claim
    address bob   = address(0xb0b);   // honest: counters alice

    Claim claim = _dummyClaim();
    uint256 firstBond = _getRequiredBond(0);
    vm.deal(alice, firstBond);
    (,,,, Claim disputed,,) = gameProxy.claimData(0);
    vm.prank(alice);
    gameProxy.attack{ value: firstBond }(disputed, 0, claim);

    uint256 secondBond = _getRequiredBond(1);
    vm.deal(bob, secondBond);
    (,,,, disputed,,) = gameProxy.claimData(1);
    vm.prank(bob);
    gameProxy.attack{ value: secondBond }(disputed, 1, claim);

    vm.warp(block.timestamp + 3 days + 12 hours);
    gameProxy.resolveClaim(2, 0);
    gameProxy.resolveClaim(1, 0);
    gameProxy.resolveClaim(0, 0);
    gameProxy.resolve();
    vm.warp(block.timestamp + 3.5 days + 1 seconds); // past the finality delay

    // Guardian pauses the Superchain for an unrelated incident.
    vm.prank(superchainConfig.guardian());
    superchainConfig.pause(address(0));

    // Alice (the loser) closes the game while paused.
    // Parent: succeeds and locks REFUND.   Fix: reverts GamePaused().
    vm.prank(alice);
    gameProxy.claimCredit(alice);
    assertEq(uint8(gameProxy.bondDistributionMode()), uint8(BondDistributionMode.REFUND));

    // After unpause, alice recovers her bond; bob does not receive alice's bond.
    vm.prank(superchainConfig.guardian());
    superchainConfig.unpause(address(0));
    gameProxy.claimCredit(bob);
    vm.warp(block.timestamp + delayedWeth.delay() + 1 seconds);
    uint256 a0 = alice.balance; uint256 b0 = bob.balance;
    gameProxy.claimCredit(alice);
    gameProxy.claimCredit(bob);
    assertEq(alice.balance, a0 + firstBond);   // dishonest party refunded
    assertEq(bob.balance,   b0 + secondBond);  // honest party gets only own bond
}
```

On the fix commit, the equivalent regression test passes:
```solidity
function test_closeGame_gamePaused_reverts() public {
    vm.prank(superchainConfig.guardian());
    superchainConfig.pause(address(0));
    vm.expectRevert(GamePaused.selector);
    gameProxy.closeGame();
}
```

```bash
cd packages/contracts-bedrock
forge test --match-contract FaultDisputeGame_Test --match-test "test_poc_pauseForcesRefund|test_closeGame_gamePaused_reverts" -vvv
```

Executed: **no**. The contracts were not built at the historical commit. The PoC reuses the setup of existing tests in the same file.

## Recommendation

The fix, which blocks `closeGame` and therefore `claimCredit` while paused, is the right approach: a temporary condition should not feed into a permanent decision. More generally, any permissionless function that permanently records a decision based on a view that can change over time should check that the inputs are stable, or should exclude inputs that are only temporary. Keep the pause and blacklist semantics consistent between `isGameProper`, which the portal uses for withdrawal validity, and the bond-mode decision.

## References

- Fix commit: b671b67f75f6fe2041672d91bd3a6a777cd6a367
- Pull request: https://github.com/ethereum-optimism/optimism/pull/15513
- Introducing change: cbe992160b (https://github.com/ethereum-optimism/optimism/pull/14664)
- Relevant files: `packages/contracts-bedrock/src/dispute/FaultDisputeGame.sol`, `packages/contracts-bedrock/src/dispute/SuperFaultDisputeGame.sol`, `packages/contracts-bedrock/src/dispute/AnchorStateRegistry.sol`, `packages/contracts-bedrock/src/dispute/lib/Errors.sol`, `packages/contracts-bedrock/test/dispute/FaultDisputeGame.t.sol`
- Specs: https://specs.optimism.io/fault-proof/stage-one/bond-incentives.html
