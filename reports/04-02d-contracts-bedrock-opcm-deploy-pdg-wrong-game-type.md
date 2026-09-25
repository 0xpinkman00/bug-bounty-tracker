# OPContractsManager.deploy: PermissionedDisputeGame built with a caller-supplied game type but registered as PERMISSIONED_CANNON

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/L1/OPContractsManager.sol` (`OPContractsManagerDeployer.deploy`; also `OPContractsManager.updatePrestate`) |
| **Asset type** | Smart Contract |
| **Severity** | Informational (only reachable through the deployer's own non-standard input; fails visibly; the chain owner can fix it) |
| **Impact category** | If triggered: "Temporary freezing of funds" (withdrawals on the new chain cannot be proven until the DGF owner re-registers the game) |
| **Fix commit(s)** | b671b67f75f6fe2041672d91bd3a6a777cd6a367 (PR #15513, "cantina contest updates"), 2025-04-30 |
| **Vulnerable since** | Present in released OPCMs: `op-contracts/v1.8.0` (2024-12), `v2.0.0` (2025-02) and `v3.0.0` (2025-03) all pass `_input.disputeGameType` into the PDG constructor |

## Brief / Intro

`OPContractsManager` (OPCM) is the on-chain factory that deploys a new OP Stack chain's L1 contracts in one transaction. During that deployment it creates the chain's *permissioned* dispute game (PDG), which lets a single trusted proposer post output roots, and registers it in the `DisputeGameFactory` under the fixed slot `PERMISSIONED_CANNON` (game type 1). The PDG's own `gameType()` was taken from a field in the deployer's input. If the two values differed, every game the factory created would report a game type that the factory does not know about. The `AnchorStateRegistry` would then treat all of those games as unregistered and not respected. No withdrawal on the new chain could be proven until governance fixed the registration.

## Vulnerability Details

Parent of the fix, `src/L1/OPContractsManager.sol:986-993`:
```solidity
output.permissionedDisputeGame = IPermissionedDisputeGame(
    Blueprint.deployFrom(
        ...
        encodePermissionedFDGConstructor(
            IFaultDisputeGame.GameConstructorParams({
                gameType: _input.disputeGameType,        // <- caller-controlled
                ...
```
The same function, around line 1072:
```solidity
setDGFImplementation(
    output.disputeGameFactoryProxy,
    GameTypes.PERMISSIONED_CANNON,                    // <- fixed slot
    IDisputeGame(address(output.permissionedDisputeGame))
);
```
The ASR is also initialized with `respectedGameType = GameTypes.PERMISSIONED_CANNON` (`encodeAnchorStateRegistryInitializer`).

If `_input.disputeGameType != 1`:
- `DisputeGameFactory.create(1, ...)` clones the PDG. The game's `gameData()` then returns `(X, root, extraData)`.
- `AnchorStateRegistry.isGameRegistered` looks up `games(X, root, extraData)`, finds nothing, and returns `false`. `isGameProper` fails, so `OptimismPortal2.proveWithdrawalTransaction` reverts and the bonds of every closed game are refunded.
- `wasRespectedGameTypeWhenCreated` is `X == 1`, which is `false`.

Fix:
```diff
-                        gameType: _input.disputeGameType,
+                        gameType: GameTypes.PERMISSIONED_CANNON,
```

### Side note: `updatePrestate` delegatecall guard (not exploitable)

The same PR added `if (address(this) == address(thisOPCM)) revert OnlyDelegatecall();` to `OPContractsManager.updatePrestate`, which matches the other OPCM entry points. Without the guard, calling it directly delegatecalls `OPContractsManagerGameTypeAdder.updatePrestate` in the OPCM's own context. That path eventually calls `DisputeGameFactory.setImplementation`, which is `onlyOwner`. The OPCM is not the owner, so the whole call reverts. This was a consistency and clarity fix, not a vulnerability.

### Scenario

1. A chain operator runs the OPCM `deploy` with `disputeGameType` set to something other than `1`, for example by mistake or because they assumed the field controlled which game gets deployed.
2. The chain launches. Deposits work, and ETH is locked in L1 contracts.
3. The proposer creates PDG games, but the ASR sees none of them as registered or respected. Withdrawals cannot be proven, and bonds go to REFUND.
4. Recovery needs the DGF owner (the chain's ProxyAdmin owner) to deploy and register a correctly typed PDG. Games created before that are useless.

## Impact Details

- Only the entity deploying the chain can trigger it, and only by supplying a non-standard value. Standard deployments through op-deployer use game type 1.
- The failure is visible immediately, and no third party can profit from it.
- Funds are only stuck until the chain owner re-registers a correct PDG, so the freeze is temporary and needs a privileged action to undo.

Rated **Informational**: a configuration footgun in deployment tooling, with no attacker.

## Proof of Concept

Foundry sketch using the existing OPCM deploy test harness (`test/L1/OPContractsManager.t.sol`, `OPContractsManager_Deploy_Test`-style setup):

```solidity
function test_poc_deploy_nonStandardGameType_breaksRegistration() public {
    IOPContractsManager.DeployInput memory input = toOPCMDeployInput(doi); // existing helper
    input.disputeGameType = GameType.wrap(1234);                           // non-standard

    IOPContractsManager.DeployOutput memory out = opcm.deploy(input);

    // Registered under PERMISSIONED_CANNON ...
    assertEq(address(out.disputeGameFactoryProxy.gameImpls(GameTypes.PERMISSIONED_CANNON)),
             address(out.permissionedDisputeGame));
    // ... but the game reports a different type.
    // Parent commit: 1234  -> every game created is unregistered in the ASR.
    // Fix commit:    1     -> consistent.
    assertEq(out.permissionedDisputeGame.gameType().raw(), GameTypes.PERMISSIONED_CANNON.raw());
}
```

```bash
cd packages/contracts-bedrock
forge test --match-test test_poc_deploy_nonStandardGameType_breaksRegistration -vvv
```

Executed: **no**. This is a sketch. Adapt the helper names to the harness at `b671b67f75^`.

## Recommendation

The fix hard-codes `PERMISSIONED_CANNON`. The now-unneeded `disputeGameType` field could also be removed from `DeployInput`, or `deploy` could revert when it is not `PERMISSIONED_CANNON`, so that operators do not believe the field has an effect. `StandardValidator` should check that `dgf.gameImpls(t).gameType() == t` for every registered type.

## References

- Fix commit: b671b67f75f6fe2041672d91bd3a6a777cd6a367
- Pull request: https://github.com/ethereum-optimism/optimism/pull/15513
- Relevant files: `packages/contracts-bedrock/src/L1/OPContractsManager.sol`, `packages/contracts-bedrock/src/dispute/AnchorStateRegistry.sol`
