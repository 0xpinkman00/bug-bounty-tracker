# OPContractsManager upgrade registers the CANNON_KONA dispute game with a zero init bond, so anyone can create those games for free

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/L1/OPContractsManager.sol`, `OPContractsManagerUpgrader._doChainUpgrade` (CANNON_KONA branch) |
| **Asset type** | Smart Contract |
| **Severity** | Informational (would have been Low, "Griefing", had it shipped) |
| **Impact category** | "Griefing (e.g. no profit motive for an attacker, but damage to the users or the protocol)" |
| **Fix commit(s)** | 0250809e1e2365ecb46444262846bd8b827c3268 (PR #18100), 2025-11-02 |
| **Vulnerable since** | 60f0c8d0be "opcm: Add CANNON_KONA support for opcm.upgrade" (PR #18059), 2025-10-30. Live for 3 days on `develop` only. No `op-contracts/*` tag contains the bug without the fix (checked with `git tag --contains`). Also gated behind the `DEPLOY_V2_DISPUTE_GAMES` and `CANNON_KONA` dev-feature flags. |

## Brief / Intro

OP Stack chains settle withdrawals through *dispute games*. Anyone can propose an L2 state root by creating a game in the `DisputeGameFactory`, and must post an *init bond* when doing so. The bond pays honest challengers who prove the proposal wrong, and it makes spamming games costly. When `OPContractsManager.upgrade` added the new `CANNON_KONA` game type (the Kona-based fault proof), it installed the game implementation but never set the bond. The factory's default is 0, so anyone could create `CANNON_KONA` games for free. The bug was caught three days after it was introduced. It never shipped in a release and sat behind development feature flags.

## Vulnerability Details

Parent of fix, `OPContractsManager.sol:1060-1081`:

```solidity
if (
    isDevFeatureEnabled(DevFeatures.CANNON_KONA)
        && _opChainConfig.cannonKonaPrestate.raw() != bytes32(0)
) {
    setNewPermissionlessGameImplV2({
        _impls: _impls,
        _l2ChainId: _l2ChainId,
        _newAbsolutePrestate: _opChainConfig.cannonKonaPrestate,
        _newDelayedWeth: getWETH(dgf, permissionlessDisputeGame, GameTypes.CANNON),
        _newAnchorStateRegistryProxy: getAnchorStateRegistry(dgf, permissionlessDisputeGame, GameTypes.CANNON),
        _gameType: GameTypes.CANNON_KONA,
        _disputeGameFactory: disputeGameFactory
    });
    // <-- no setInitBond(CANNON_KONA, ...)
}
```

`setNewPermissionlessGameImplV2` calls `setImplementation(gameType, impl, args)` only. `DisputeGameFactory.create` enforces the bond by equality:

```solidity
// DisputeGameFactory.sol:163
if (msg.value != initBonds[_gameType]) revert IncorrectBondAmount();
```

`initBonds[CANNON_KONA]` was never written, so it stays 0 and `create{value: 0}(CANNON_KONA, ...)` succeeds. The other OPCM paths that add games (`addGameType`, line 743; interop migration, lines 1995/2035) all call `setInitBond`. Only the upgrade path missed it.

The fix copies the CANNON bond:

```diff
                         _gameType: GameTypes.CANNON_KONA,
                         _disputeGameFactory: disputeGameFactory
                     });
+                    uint256 initialCannonGameBond = disputeGameFactory.initBonds(GameTypes.CANNON);
+                    disputeGameFactory.setInitBond(GameTypes.CANNON_KONA, initialCannonGameBond);
```

### Attack scenario

1. A chain is upgraded with the `CANNON_KONA` dev feature on and a `cannonKonaPrestate`. The DGF now has a `CANNON_KONA` implementation with `initBonds[CANNON_KONA] == 0`.
2. The attacker calls `create{value: 0}(CANNON_KONA, bogusRoot, extraData)` repeatedly. It pays only gas.
3. Honest `op-challenger` instances configured for `CANNON_KONA` must counter each bogus root by posting the depth-1 bond and paying gas. When they win, they recover their own bonds plus the creator's bond, which is 0. So the protocol's economic reward for challenging is gone, and challenger capital is locked in `DelayedWETH` for the duration of every game.

## Impact Details

- **What breaks:** the spam deterrent and the challenger reward for one game type. Withdrawals are not at risk. `CANNON_KONA` was not the respected game type, so a bogus `CANNON_KONA` root cannot finalize withdrawals or move the anchor state.
- **Mitigating factors:** the code path needed both the `DEPLOY_V2_DISPUTE_GAMES` and `CANNON_KONA` dev features. It existed for 3 days. No `op-contracts` release tag contains it. Running `upgrade` also requires the ProxyAdmin owner to delegatecall OPCM.
- **Severity:** would have been Low (griefing) if deployed. Because it never shipped, it is **Informational**.

## Proof of Concept

The fix extended the fork-based upgrade harness to assert that every live game type has the expected bond. Stripped down to the relevant assertion (`test/L1/OPContractsManager.t.sol`, `OPContractsManager_Upgrade_Harness._runOpcmUpgradeAndChecks`, lines 353-383 at the fix):

```solidity
// after runCurrentUpgrade(upgrader) with DEV_FEATURE__CANNON_KONA and
// DEV_FEATURE__DEPLOY_V2_DISPUTE_GAMES enabled and cannonKonaPrestate != 0
uint256 bondAmount = disputeGameFactory.initBonds(GameTypes.PERMISSIONED_CANNON);

// Fails on 0250809e1e^ (initBonds(CANNON_KONA) == 0), passes on the fix.
assertEq(bondAmount, disputeGameFactory.initBonds(GameTypes.CANNON_KONA));

// Direct demonstration of the free creation on the parent commit:
vm.prank(attacker);
disputeGameFactory.create{ value: 0 }(GameTypes.CANNON_KONA, Claim.wrap(bytes32(uint256(1))), abi.encode(l2BlockNumber));
// parent: succeeds; fix: reverts with IncorrectBondAmount()
```

Run (fork test; needs an L1 archive RPC):

```bash
cd packages/contracts-bedrock
export ETH_RPC_URL=<mainnet archive RPC>
DEV_FEATURE__CANNON_KONA=true DEV_FEATURE__DEPLOY_V2_DISPUTE_GAMES=true \
  forge test --fork-url $ETH_RPC_URL \
  --match-contract OPContractsManager_Upgrade_Test --match-test test_upgradeOPChainOnly_succeeds -vvv
```

Executed: **no**. It needs a mainnet fork RPC and a full contracts build. The PoC is taken from the fix's own regression assertion (`assertEq(bondAmount, disputeGameFactory.initBonds(gt))`). The source inspection above confirms that the parent never writes `initBonds[CANNON_KONA]` on this path.

## Recommendation

The fix sets the `CANNON_KONA` bond equal to the `CANNON` bond during upgrade, which is correct. Defense in depth:

- Make `setNewPermissionlessGameImplV2` (or its successor) take the bond as a required argument, so that a game type cannot be installed without one.
- Have `OPContractsManagerStandardValidator` assert `initBonds[gt] > 0` for every game type with a non-zero implementation.

## References

- Fix commit: 0250809e1e2365ecb46444262846bd8b827c3268
- Pull request: https://github.com/ethereum-optimism/optimism/pull/18100
- Introducing PR: https://github.com/ethereum-optimism/optimism/pull/18059
- Relevant files: `packages/contracts-bedrock/src/L1/OPContractsManager.sol`, `packages/contracts-bedrock/src/dispute/DisputeGameFactory.sol`, `packages/contracts-bedrock/test/L1/OPContractsManager.t.sol`
