# AnchorStateRegistry.isGameRegistered accepted games bound to a different AnchorStateRegistry

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/dispute/AnchorStateRegistry.sol` (`isGameRegistered`) |
| **Asset type** | Smart Contract |
| **Severity** | Informational (defense in depth; needs an upgrade misconfiguration to matter; pre-deployment) |
| **Impact category** | None directly exploitable. If misconfigured: "Direct theft of any user funds" class via withdrawal proofs against a game the registry should not trust |
| **Fix commit(s)** | b671b67f75f6fe2041672d91bd3a6a777cd6a367 (PR #15513, "cantina contest updates"), 2025-04-30 |
| **Vulnerable since** | The ASR `isGameRegistered` design (ASR v2.x/v3.x). Only a factory-membership check was ever done before this fix. |

## Brief / Intro

The `AnchorStateRegistry` (ASR) is the contract the `OptimismPortal` asks "can I trust this dispute game?" before accepting a withdrawal proof. Its first check, `isGameRegistered`, only confirmed that the game was created by the `DisputeGameFactory`. It did not confirm that the game was actually wired to *this* registry. Each game reads its respected game type, anchor state and retirement data from its own registry. So a game that points at a different, older registry could be judged by the new registry using facts the new registry never checked. In practice another safeguard already blocked this: a newly initialized registry retires every earlier game. That makes the issue a hardening fix raised in the audit contest.

## Vulnerability Details

Parent of the fix, `src/dispute/AnchorStateRegistry.sol`:

```solidity
function isGameRegistered(IDisputeGame _game) public view returns (bool) {
    (GameType gameType, Claim rootClaim, bytes memory extraData) = _game.gameData();
    (IDisputeGame _factoryRegisteredGame,) =
        disputeGameFactory.games({ _gameType: gameType, _rootClaim: rootClaim, _extraData: extraData });
    return address(_factoryRegisteredGame) == address(_game);
}
```

`isGameProper`, and through it `isGameClaimValid` (which the portal uses in `proveWithdrawalTransaction` and `checkWithdrawal`), depends on this check. Some of the other ASR checks trust data held in the game, and that data was set by the game's *own* registry:
- `isGameRespected` returns `_game.wasRespectedGameTypeWhenCreated()`. The game computes this value from its own ASR at creation time.
- The game's starting anchor comes from its own ASR's `getAnchorRoot()`.

If a factory had a game implementation that still pointed at an old ASR, for example after a botched migration to a new ASR/factory pair, games created after the new ASR's `initialize` would pass the new registry's retirement check. They would also carry the old registry's view of "respected" and of the anchor. The new registry would then treat them as proper.

Fix:
```diff
-        return address(_factoryRegisteredGame) == address(_game);
+        address asr = address(IFaultDisputeGame(address(_game)).anchorStateRegistry());
+        return address(factoryRegisteredGame) == address(_game) && asr == address(this);
```

### Attack scenario (requires a misconfiguration)

1. During an ASR swap, such as `OptimismPortal2.migrateToSuperRoots`, the new factory, or a factory shared with another registry, still has a game implementation whose immutable `anchorStateRegistry` is the old ASR.
2. After the new ASR is initialized, a proposer creates a game from that implementation. The new ASR's retirement timestamp does not retire it, because it was created later.
3. The old ASR supplies the game's "respected at creation" flag and its anchor. The new ASR's `isGameProper`/`isGameClaimValid` accepts the game even though it was never bound to the new registry's rules.

## Impact Details

- In a correctly executed upgrade this cannot be reached. `initialize` sets `retirementTimestamp = block.timestamp`, which retires every game created before the registry existed, and OPCM deploys new game implementations with the new ASR address in the same transaction. The fix's own comment says the change is meant to avoid "potential footguns in the future".
- Triggering it needs a mistake by the ProxyAdmin owner (governance), not an outside action.
- The code was pre-deployment (Upgrade 16 candidate) when the contest reported it.

Rated **Informational**.

## Proof of Concept

This is the regression test the fix added to `test/dispute/AnchorStateRegistry.t.sol`. On the parent commit `isGameRegistered` returns `true`, so `assertFalse` fails. On the fix it returns `false`.

```solidity
contract AnchorStateRegistry_IsGameRegistered_Test is AnchorStateRegistry_Init {
    function test_isGameRegistered_isNotSameAnchorStateRegistry_succeeds(address _anchorStateRegistry) public {
        vm.assume(_anchorStateRegistry != address(anchorStateRegistry));

        // The game is genuinely in the factory, but claims a different ASR.
        vm.mockCall(
            address(gameProxy), abi.encodeCall(gameProxy.anchorStateRegistry, ()), abi.encode(_anchorStateRegistry)
        );

        // Parent commit: returns true -> FAIL. Fix: returns false -> PASS.
        assertFalse(anchorStateRegistry.isGameRegistered(gameProxy));
    }
}
```

```bash
cd packages/contracts-bedrock
forge test --match-test test_isGameRegistered_isNotSameAnchorStateRegistry_succeeds -vvv
```

Executed: **no**. The test was not run against a historical build. It is taken from the fix commit.

## Recommendation

The fix is correct. Adding `anchorStateRegistry()` to `IDisputeGame` would also remove the unchecked cast from `IDisputeGame` to `IFaultDisputeGame`, as the fix's own comment suggests. Also consider making the `StandardValidator` check that every registered game implementation's `anchorStateRegistry()` equals the portal's ASR.

## References

- Fix commit: b671b67f75f6fe2041672d91bd3a6a777cd6a367
- Pull request: https://github.com/ethereum-optimism/optimism/pull/15513
- Relevant files: `packages/contracts-bedrock/src/dispute/AnchorStateRegistry.sol`, `packages/contracts-bedrock/test/dispute/AnchorStateRegistry.t.sol`
- Specs: https://specs.optimism.io/fault-proof/stage-one/anchor-state-registry.html
