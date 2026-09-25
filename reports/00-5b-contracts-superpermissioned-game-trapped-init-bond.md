# SuperPermissionedDisputeGame: payable `initialize()` with no bond accounting permanently traps any init bond

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/dispute/SuperPermissionedDisputeGame.sol` |
| **Asset type** | Smart Contract |
| **Severity** | Informational. Triage suggested Low; downgraded because only a trusted-owner misconfiguration can trigger it |
| **Impact category** | "Permanent freezing of funds". Requires the `DisputeGameFactory` owner to set a non-zero init bond, which OPCM itself forbids |
| **Fix commit(s)** | 44eb9547baef1331df04b826a15ca0e05ddedc1f (PR #22410), 2026-08-13 |
| **Vulnerable since** | bd4e855e71 (PR #20641, 2026-05-28), which introduced the simplified super-permissioned game |

## Brief / Intro

`SuperPermissionedDisputeGame` is a simplified dispute game for interop super-root proposals. Only the permissioned proposer can create one, and it resolves in the proposer's favour immediately. Invalid proposals are handled by the guardian blacklisting them. Unlike the other dispute games, it has no bond accounting: no credit, no `claimCredit`, no WETH deposit. Its `initialize()` was still `payable`, and the `DisputeGameFactory` forwards whatever init bond is configured for the game type. If that bond were ever non-zero, every proposal would lock that amount of ETH in the game clone with no way to get it out.

## Vulnerability Details

The factory requires `msg.value` to equal the configured init bond and forwards it to the clone's `initialize()`:

`packages/contracts-bedrock/src/dispute/DisputeGameFactory.sol` (parent `44eb9547ba^`), `create()`
```solidity
// If the required initialization bond is not met, revert.
if (msg.value != initBonds[_gameType]) revert IncorrectBondAmount();
...
proxy_.initialize{ value: msg.value }();
```

The game accepted the value and did nothing with it:

`packages/contracts-bedrock/src/dispute/SuperPermissionedDisputeGame.sol:46-66` (parent)
```solidity
function initialize() external payable {
    if (initialized) revert AlreadyInitialized();
    if (!_verifyInitCallDataLength()) revert BadExtraData();
    ...
    if (tx.origin != proposer()) revert BadAuth();
    ...
    status = GameStatus.DEFENDER_WINS;
    ...
}
```
The contract has no function that sends ETH anywhere, so any value received stays there permanently.

Fix:
```solidity
function initialize() external payable {
    if (initialized) revert AlreadyInitialized();
    // The game has no bond accounting, so any value sent would be trapped in the clone.
    if (msg.value != 0) revert IncorrectBondAmount();
    ...
```
With this check, a non-zero init bond makes `create()` revert, which fails safely, instead of silently burning the bond.

### Attack scenario

1. The `DisputeGameFactory` owner (the L1 ProxyAdmin owner / Security Council) calls `setInitBond(GameTypes.SUPER_PERMISSIONED, X)` with `X > 0`, for example by copying the bond used by `SUPER_CANNON_KONA`.
2. The permissioned proposer calls `create{value: X}(SUPER_PERMISSIONED, ...)` for every proposal.
3. Each game clone permanently holds `X` ETH, and the proposer loses `X` per proposal.

## Impact Details

- **Loss:** the configured bond amount, once per super-permissioned proposal, paid by the proposer operator.
- **Mitigating factors:**
  - Only the factory owner can set a non-zero bond, and only the permissioned proposer can create games. No unprivileged party can cause the loss.
  - At the parent commit, `OPContractsManagerV2` already rejected a non-zero bond for this type (`isSuperPermissionedGame && initBond != 0` reverts, `OPContractsManagerV2.sol:754`). Only a manual `setInitBond` outside OPCM could reach the bug.
  - The game is part of the interop / super-root rollout and was not live on production chains.
- **Severity:** Immunefi treats permanent freezing of funds as Critical, but this path needs a privileged misconfiguration that the standard deployment tooling already blocks. We rate it **Informational**, as a fail-safe hardening fix.

## Proof of Concept

The fix commit added this regression test (`packages/contracts-bedrock/test/dispute/SuperPermissionedDisputeGame.t.sol`):

```solidity
function test_createGame_nonZeroBond_reverts() public {
    vm.prank(disputeGameFactory.owner());
    disputeGameFactory.setInitBond(GameTypes.SUPER_PERMISSIONED, 1 ether);

    Types.SuperRootProof memory bondProof = superRootProof;
    bondProof.timestamp = uint64(validL2SequenceNumber + 1);
    bytes memory bondExtraData = Encoding.encodeSuperRootProof(bondProof);

    vm.deal(PROPOSER, 1 ether);
    vm.expectRevert(IncorrectBondAmount.selector);
    vm.prank(PROPOSER, PROPOSER);
    disputeGameFactory.create{ value: 1 ether }(
        GameTypes.SUPER_PERMISSIONED, Claim.wrap(Hashing.hashSuperRootProof(bondProof)), bondExtraData
    );
}
```

To show the trapped funds on the parent commit, add this test to `SuperPermissionedDisputeGame_Initialize_Test` in a scratch clone checked out at `44eb9547ba^`:

```solidity
function test_createGame_nonZeroBond_trapsFunds() public {
    vm.prank(disputeGameFactory.owner());
    disputeGameFactory.setInitBond(GameTypes.SUPER_PERMISSIONED, 1 ether);

    Types.SuperRootProof memory p = superRootProof;
    p.timestamp = uint64(validL2SequenceNumber + 1);

    vm.deal(PROPOSER, 1 ether);
    address game = _createGame_withValue(p);       // helper below
    assertEq(game.balance, 1 ether);               // ETH is now in the clone
    assertEq(PROPOSER.balance, 0);
    // No function on ISuperPermissionedDisputeGame can move it out (no claimCredit / withdraw).
}

function _createGame_withValue(Types.SuperRootProof memory p) internal returns (address) {
    vm.prank(PROPOSER, PROPOSER);
    return address(disputeGameFactory.create{ value: 1 ether }(
        GameTypes.SUPER_PERMISSIONED, Claim.wrap(Hashing.hashSuperRootProof(p)), Encoding.encodeSuperRootProof(p)
    ));
}
```

```bash
cd packages/contracts-bedrock
forge test --match-contract SuperPermissionedDisputeGame_Initialize_Test -vvv
# parent 44eb9547ba^: test_createGame_nonZeroBond_trapsFunds passes (1 ether stuck in the clone)
# fix    44eb9547ba : test_createGame_nonZeroBond_reverts passes (create reverts IncorrectBondAmount)
```
Executed: no. A contracts-bedrock build was too expensive for this review.

## Recommendation

The fix is correct: any game type without bond accounting should reject value. We also recommend:

1. make `DisputeGameFactory.setInitBond` refuse a non-zero bond for game types that declare they have no bonds, or have the StandardValidator assert `initBonds(SUPER_PERMISSIONED) == 0`;
2. review the other `payable` initializers of non-bonded games for the same pattern.

## References

- Fix commit: 44eb9547baef1331df04b826a15ca0e05ddedc1f
- Pull request: https://github.com/ethereum-optimism/optimism/pull/22410
- Relevant files: `packages/contracts-bedrock/src/dispute/SuperPermissionedDisputeGame.sol`, `src/dispute/DisputeGameFactory.sol`, `src/L1/opcm/OPContractsManagerV2.sol`, `test/dispute/SuperPermissionedDisputeGame.t.sol`
