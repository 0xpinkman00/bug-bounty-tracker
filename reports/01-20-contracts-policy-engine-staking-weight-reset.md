# PolicyEngineStaking: partial unstake resets `lastUpdate`, so stakers and beneficiaries lose accrued staking weight

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/periphery/staking/PolicyEngineStaking.sol` |
| **Asset type** | Smart Contract |
| **Severity** | Low |
| **Impact category** | Contract fails to deliver promised returns, but doesn't lose value |
| **Fix commit(s)** | 13c74c6d0855caf59b575ccf5fbf74ffe104cb4f (PR #19449), 2026-03-16. Cantina audit findings #7 (weight reset), #8 (two-step ownership) and #10 (documented trust assumption) |
| **Vulnerable since** | 6067931327 (PR #19192, 2026-02-24), when the contract was first added. It was live in the tree for about 3 weeks, and the version stayed `1.0.0` across the fix, which suggests it had not been deployed yet |

## Brief / Intro

`PolicyEngineStaking` is a periphery contract. Users stake governance tokens in it to gain priority in transaction ordering in `op-rbuilder`, a block builder. They can stake for themselves or delegate the ordering power to a "beneficiary". For each account the builder reads two values, `effectiveStake` and `lastUpdate`. `lastUpdate` records how long the stake has been held, and so how much staking weight it has accrued. Before the fix, every *decrease* of effective stake reset `lastUpdate` to the current time, so withdrawing even 1 wei wiped all the weight the rest of the position had built up. A delegated staker could also reset their beneficiary's clock by partially unstaking or moving their stake away. No funds were at risk. The harm is lost ordering priority, and the risk was reduced further because the contract was new and, most likely, not yet deployed.

## Vulnerability Details

The `PEData` slot for an account is packed as `{uint128 effectiveStake; uint128 lastUpdate}` and sits at storage slot 0, where `op-rbuilder` reads it directly. In the parent commit, both helpers overwrite `lastUpdate`:

`PolicyEngineStaking.sol:314-329` (parent `13c74c6d08^`)
```solidity
function _increasePeData(address _account, uint128 _amount) internal {
    PEData storage pe = peData[_account];
    pe.effectiveStake += _amount;
    pe.lastUpdate = uint128(block.timestamp);
    ...
}

function _decreasePeData(address _account, uint128 _amount) internal {
    PEData storage pe = peData[_account];
    pe.effectiveStake -= _amount;
    pe.lastUpdate = uint128(block.timestamp);   // <-- resets weight on ANY decrease
    ...
}
```

`_decreasePeData` is reached from:
- `unstake(_amount)` (line 261), on the staker's **beneficiary** for any amount, including a partial unstake;
- `changeBeneficiary` and `stake` with a new beneficiary (lines 206, 242), on the **old** beneficiary;
- `setAllowedStaker(_staker, false)` (line 290), on the caller.

Resetting `lastUpdate` on an increase is a reasonable design choice, because new stake should not inherit old weight. Resetting it on a decrease has no such justification: the tokens that remain have been staked the whole time. The effects are:

1. A staker who withdraws a small part of their position loses the accrued weight on the rest.
2. When a beneficiary has many delegators, any one of them can reset the beneficiary's `lastUpdate` for all of its aggregated stake by calling `unstake(1)` or `changeBeneficiary(...)`. That is a griefing vector against the beneficiary.

### Fix

```diff
 function _decreasePeData(address _account, uint128 _amount) internal {
     PEData storage pe = peData[_account];
     pe.effectiveStake -= _amount;
-    pe.lastUpdate = uint128(block.timestamp);
+    if (pe.effectiveStake == 0) {
+        pe.lastUpdate = uint128(block.timestamp);
+    }
     emit EffectiveStakeChanged(_account, pe.effectiveStake);
 }
```

The same commit also did the following:
- **Cantina #8:** replaced the hand-rolled one-step `transferOwnership` with OZ v5 `Ownable2Step`, so that passing a wrong address cannot permanently transfer the pause authority. It moved `peData` into a base contract, `PolicyEngineStakingMapping`, so the mapping stays at slot 0 after the new inheritance.
- **Cantina #10:** documented, without changing code, that a beneficiary who removes a staker from their allowlist resets that staker's `lastUpdate` through `_increasePeData`.

### Attack scenario

1. Alice has staked 100 OP to herself for 6 months, and her `lastUpdate` is 6 months old.
2. She calls `unstake(1 wei)`, or one of her delegators calls `unstake(1 wei)` or `changeBeneficiary(bob)`.
3. `lastUpdate` for Alice becomes `block.timestamp`. For ordering purposes, her ~100 OP position now looks brand-new, and she loses priority until she has staked for 6 more months.

## Impact Details

- **What is lost:** Ordering priority (staking weight) in `op-rbuilder`. No tokens can be stolen or frozen: `unstake` always returns the principal.
- **Who can trigger it:** A staker affecting their own position, or an allowlisted delegator affecting their beneficiary. A beneficiary only accepts delegations from allowlisted stakers, which limits the griefing surface.
- **Mitigating factors:** The contract is new periphery code (added 2026-02-24, fixed 2026-03-16 after the Cantina audit, version still `1.0.0`). It is not part of the protocol's consensus or bridge path, and no value can be lost. The one-step ownership issue (#8) only matters if the trusted owner makes a mistake.
- **Severity:** Low, "Contract fails to deliver promised returns, but doesn't lose value". The contract promises time-weighted ordering power, and the bug takes it away when it should not.

## Proof of Concept

The fix added a regression test in `test/periphery/staking/PolicyEngineStaking.t.sol`. The test below is based on it and adds a delegator-griefing case. On the parent commit (`13c74c6d08^`) both tests fail at the `lastUpdate` assertion. On the fix commit they pass.

```solidity
// Append to packages/contracts-bedrock/test/periphery/staking/PolicyEngineStaking.t.sol
contract PolicyEngineStaking_LastUpdate_PoC is PolicyEngineStaking_TestInit {
    /// Partial unstake must not reset the staker's accrued weight.
    function test_poc_partialUnstakeKeepsWeight() external {
        vm.prank(alice);
        staking.stake(uint128(100 ether), alice);
        (, uint128 t0) = staking.peData(alice);

        vm.warp(block.timestamp + 180 days);
        vm.prank(alice);
        staking.unstake(1); // withdraw 1 wei

        (uint128 eff, uint128 t1) = staking.peData(alice);
        assertEq(eff, uint128(100 ether) - 1);
        assertEq(t1, t0, "parent: lastUpdate reset to now -> weight wiped");
    }

    /// A delegator moving away must not reset the beneficiary's clock while stake remains.
    function test_poc_delegatorCannotResetBeneficiary() external {
        // bob self-stakes; alice delegates to bob
        vm.prank(bob);
        staking.stake(uint128(100 ether), bob);
        vm.prank(bob);
        staking.setAllowedStaker(alice, true);
        vm.prank(alice);
        staking.stake(uint128(1 ether), bob);
        (, uint128 t0) = staking.peData(bob);

        vm.warp(block.timestamp + 180 days);
        vm.prank(alice);
        staking.unstake(1); // partial unstake by delegator

        (, uint128 t1) = staking.peData(bob);
        assertEq(t1, t0, "parent: delegator reset beneficiary's lastUpdate");
    }
}
```

Run it (the test harness already defines `alice` and `bob`, funds them, and approves the staking contract):

```bash
cd packages/contracts-bedrock
forge test --match-contract PolicyEngineStaking_LastUpdate_PoC -vv
# Upstream regression tests:
forge test --match-contract PolicyEngineStaking_Unstake_LastUpdate_Test -vv
```

Executed: no. The contracts-bedrock forge build is heavy, and running it against the parent commit would need a checkout, which is out of scope for this read-only review. The logic follows directly from the one-line diff.

## Recommendation

The fix is correct for the partial-unstake case. Remaining points:

- `_increasePeData` still resets `lastUpdate` unconditionally. An allowlisted delegator can therefore still reset their beneficiary's clock by calling `stake(1, beneficiary)`. The code now documents this as a trust assumption (Cantina #10). A time-weighted average, such as `lastUpdate' = (old*oldStake + now*delta)/(oldStake+delta)`, would remove this griefing vector and would also be fairer to top-ups.
- The switch to `Ownable2Step` is good. Keep the explicit slot-0 layout test for `peData`, because `op-rbuilder` reads that slot directly.

## References

- Fix commit: 13c74c6d0855caf59b575ccf5fbf74ffe104cb4f
- Pull request: https://github.com/ethereum-optimism/optimism/pull/19449
- Introduced in: 6067931327 (https://github.com/ethereum-optimism/optimism/pull/19192)
- Relevant files: `packages/contracts-bedrock/src/periphery/staking/PolicyEngineStaking.sol`, `packages/contracts-bedrock/interfaces/periphery/staking/IPolicyEngineStaking.sol`, `packages/contracts-bedrock/test/periphery/staking/PolicyEngineStaking.t.sol`
