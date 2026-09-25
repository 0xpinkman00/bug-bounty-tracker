# ZKDisputeGame / OPCM: `rootClaimByChainId` ignores its chain-ID argument, plus missing config validation (internal review remediations)

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/dispute/zk/ZKDisputeGame.sol`, `src/L1/opcm/OPContractsManagerV2.sol`, `src/L1/OPContractsManagerStandardValidator.sol`, `op-deployer/pkg/deployer/upgrade/embedded/upgrade.go` |
| **Asset type** | Smart Contract |
| **Severity** | Informational. Triage suggested Medium for `rootClaimByChainId`, but we could not find any on-chain consumer that reaches it |
| **Impact category** | None directly. Defence in depth: an API that returns a wrong value for a wrong input, and deployment and upgrade validation gaps that only a trusted role can hit |
| **Fix commit(s)** | 7831b7dfaaea31e4bcd56221e5e2a4a2a96a7393 (PR #20548), 2026-05-19 |
| **Vulnerable since** | `ZKDisputeGame` as first introduced. The game is behind the `ZK_DISPUTE_GAME` dev-feature flag and was not a respected game type on any production chain |

## Brief / Intro

`ZKDisputeGame` is a new dispute game in which an L2 state claim is defended with a zero-knowledge validity proof instead of the interactive bisection game. An internal review found one API bug in the game: `rootClaimByChainId(chainId)` returned the game's root claim for *any* chain ID. It also found several places where the OP Contracts Manager (OPCM), the StandardValidator and op-deployer accepted dangerous configurations: zero verifier address, zero prestate, zero durations, zero bonds, zero implementation address, and a zero anchor root. All were fixed in one PR. We checked every caller of `rootClaimByChainId`. None of them can be handed a ZK game on that code path, and every other item requires a trusted deployer or upgrader to misconfigure the chain. We therefore rate the whole set as hardening.

## Vulnerability Details

### 1. `rootClaimByChainId` ignored its argument

`packages/contracts-bedrock/src/dispute/zk/ZKDisputeGame.sol:239-242` (parent `7831b7dfaa^`)
```solidity
/// @notice Getter for the root claim for a given L2 chain ID.
function rootClaimByChainId(uint256) public pure returns (Claim rootClaim_) {
    rootClaim_ = rootClaim();
}
```
The sibling `FaultDisputeGame.rootClaimByChainId` reverts with `UnknownChainId` when the chain ID does not match. `SuperFaultDisputeGame` looks the chain up in the super-root proof. The ZK game broke that contract.

Fix:
```solidity
function rootClaimByChainId(uint256 _chainId) public pure returns (Claim rootClaim_) {
    if (_chainId != l2ChainId()) revert UnknownChainId();
    rootClaim_ = rootClaim();
}
```

**Reachability.** The only on-chain caller is `OptimismPortal2.proveWithdrawalTransaction`:

`packages/contracts-bedrock/src/L1/OptimismPortal2.sol:415-423` (parent)
```solidity
if (GameTypes.isSuperGame(disputeGameProxy.gameType())) {
    outputRootClaim = disputeGameProxy.rootClaimByChainId(systemConfig.l2ChainId());
} else {
    outputRootClaim = disputeGameProxy.rootClaim();
}
```
`GameTypes.isSuperGame` (`src/dispute/lib/Types.sol:99-103`) returns true only for `SUPER_CANNON`, `SUPER_PERMISSIONED_CANNON`, `SUPER_ASTERISC_KONA` and `SUPER_CANNON_KONA`. It does not include `ZK_DISPUTE_GAME`, so the portal reads `rootClaim()` for ZK games. Before accepting any game, the portal also requires it to be proper and respected in its own `AnchorStateRegistry`. No off-chain Go or Rust code calls `rootClaimByChainId`, excluding generated bindings and tests. The wrong return value was therefore latent. It would have become exploitable only if the ZK game were later added to `isSuperGame`, or a new consumer relied on the chain-ID check to reject a foreign game.

### 2. Configuration validation gaps (review items L-1 to L-3, I-0, I-5, I-6)

| Item | Parent behaviour | Fix |
|---|---|---|
| I-0 | With no parent game, `initialize` took `anchorStateRegistry().getAnchorRoot()` as the starting root, even if it was `0` | `if (startingProposal.root.raw() == bytes32(0)) revert AnchorRootNotFound();` |
| L-2 | StandardValidator checked only `chainId`, `weth` and `asr` in the ZK game args | Also checks `absolutePrestate != 0`, that `verifier` is non-zero and has code, `maxChallengeDuration > 0`, `maxProveDuration > 0` and `challengerBond > 0` (errors `ZKDG-70` to `ZKDG-110`). op-deployer's upgrade encoder rejects the same values |
| L-3 | OPCM could enable a game type whose implementation in the container was `address(0)` or had no code | `revert OPContractsManagerV2_ZeroGameImplementation(gameType)` |
| I-6 | OPCM allowed an enabled game with `initBond == 0` | Reverts with `OPContractsManagerV2_InvalidGameConfigs()` |
| L-1 | StandardValidator validated the ZK game based on the dev-feature bitmap | It now treats the factory's registered implementation as the source of truth |
| I-5 | Game-type ordering | Reordered |

For example, a ZK game deployed with `maxChallengeDuration == 0` or `maxProveDuration == 0` could be resolved almost immediately. A game with `challengerBond == 0` makes challenging free, which is a griefing risk. A verifier with no code would make `prove()` behave unpredictably. All of these values are chosen by the chain operator or the OPCM caller.

### Attack scenario

No unprivileged attack path exists at the parent commit:

1. `rootClaimByChainId`: the portal never calls it for ZK games (see above).
2. Configuration gaps: a trusted deployer or upgrader has to supply the bad parameters, and the StandardValidator run that operators perform after an upgrade was the intended safety net. This fix strengthens it.

## Impact Details

No direct impact. The fixes close a latent API foot-gun that would matter for a future ZK super-root game or a new portal code path, and they make misconfiguration by trusted roles fail loudly at deploy or upgrade time. The code is gated by the `ZK_DISPUTE_GAME` dev feature and was not respected on any production chain. **Informational.**

## Proof of Concept

The fix added this regression test (`test/dispute/zk/ZKDisputeGame.t.sol:1452-1464` at `7831b7dfaa`). It fails on the parent, where the call returns `rootClaim()` for any chain ID, and passes on the fix:

```solidity
contract ZKDisputeGame_RootClaim_Test is ZKDisputeGame_TestInit {
    function test_rootClaimByChainId_succeeds() public view {
        assertEq(game.rootClaimByChainId(game.l2ChainId()).raw(), game.rootClaim().raw());
    }

    function testFuzz_rootClaimByChainId_wrongChainId_reverts(uint256 _chainId) public {
        vm.assume(_chainId != game.l2ChainId());
        vm.expectRevert(UnknownChainId.selector);
        game.rootClaimByChainId(_chainId);
    }
}
```
To reproduce the failure, copy `ZKDisputeGame_RootClaim_Test` into the parent tree's `ZKDisputeGame.t.sol` (with `UnknownChainId` imported from `src/dispute/lib/Errors.sol`) in a scratch clone, then run:
```bash
cd packages/contracts-bedrock
forge test --match-contract ZKDisputeGame_RootClaim_Test -vvv
# parent 7831b7dfaa^ : testFuzz_rootClaimByChainId_wrongChainId_reverts FAILS ("call did not revert")
# fix    7831b7dfaa  : PASS
```
The fix commit also added validator tests (`ZKDG-70` to `ZKDG-110`), OPCM tests for zero implementation and zero init bond, and Go tests in `op-deployer/pkg/deployer/upgrade/embedded/upgrade_test.go`.

Executed: no. A full contracts-bedrock build was too expensive for this review.

## Recommendation

The fixes are appropriate. Further suggestions:

- Add a unit test to the StandardValidator or the `IDisputeGame` interface suite asserting that *every* game implementation's `rootClaimByChainId` reverts on a foreign chain ID. This would catch the same mistake in future game types.
- If a ZK super-root game is ever added to `isSuperGame`, review the portal path again.

## References

- Fix commit: 7831b7dfaaea31e4bcd56221e5e2a4a2a96a7393
- Pull request: https://github.com/ethereum-optimism/optimism/pull/20548
- Relevant files: `packages/contracts-bedrock/src/dispute/zk/ZKDisputeGame.sol`, `src/L1/OptimismPortal2.sol`, `src/dispute/lib/Types.sol`, `src/L1/opcm/OPContractsManagerV2.sol`, `src/L1/OPContractsManagerStandardValidator.sol`, `op-deployer/pkg/deployer/upgrade/embedded/upgrade.go`
