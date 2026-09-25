# uint64 hardening: dispute games accepted L2 block numbers ≥ 2^64, and span-batch `v` recovery overflowed for very large chain IDs

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/dispute/FaultDisputeGame.sol`, `PermissionedDisputeGame.sol`, `src/dispute/zk/OptimisticZkGame.sol`; `op-node/rollup/derive/span_batch_txs.go` |
| **Asset type** | Smart Contract (A); Blockchain/DLT (B) |
| **Severity** | Informational |
| **Impact category** | None directly. A: defence in depth for the anchor state / proposal-liveness invariant. B: correctness for configurations that do not exist |
| **Fix commit(s)** | A: 6be6e2036b704bc34b1bffa8f6c9822000ad69ed (PR #18903, 2026-01-23). B: b8a91297ea47b224a071db3ae6a721445e9fc8d1 (PR #18921, 2026-01-27) |
| **Vulnerable since** | A: since the games were introduced (FDG `l2BlockNumber` has always been a `uint256` read from `extraData`). B: d6e1259b0d (span batches, 2023-09-18) |

## Brief / Intro

OP Stack chains number their L2 blocks with 64-bit integers everywhere off-chain: in op-node, op-geth/op-reth, the JSON-RPC API and the fault-proof program. Two places did not enforce that limit. (A) The on-chain dispute games accepted a proposal for an L2 block number of 2^64 or more, a block that can never exist. (B) op-node's span-batch decoder computed a legacy transaction's signature `v` value (`chainId*2+35+yParity`) in 64-bit arithmetic, which silently wraps for absurdly large chain IDs. Neither issue was exploitable in practice. Both fixes make the code match the implicit invariants.

## Vulnerability Details

### A. Dispute games accepted `l2BlockNumber > type(uint64).max`

`FaultDisputeGame.initialize` only checked that the proposal is newer than the anchor:

`FaultDisputeGame.sol:275` (parent `6be6e2036b^`)
```solidity
if (l2BlockNumber() <= rootBlockNumber) revert UnexpectedRootClaim(rootClaim());
```
`OptimisticZkGame.initialize` (`OptimisticZkGame.sol:296`) had the same check. `l2BlockNumber()` is a `uint256` taken from caller-supplied `extraData`, so anyone could create a game claiming, for example, block `2^64 + 5`.

The concern is that if such a game ever resolved `DEFENDER_WINS` and was used as the new anchor, `AnchorStateRegistry.setAnchorState` would move the anchor beyond any block the chain can reach. Every later game must have `l2BlockNumber > anchor`, and no honest proposer or client can produce an output root for a block beyond 2^64. Proposals would stall and so would withdrawals.

Why this is only defence in depth:
- The honest `op-challenger` reads the value with a clamp: `faultdisputegame.go:211-214` returns `math.MaxUint64` when `!val.IsUint64()`. It then treats the claim like any other proposal beyond the safe head and disputes it. For a "valid root at an impossible block" claim, the existing `challengeRootL2Block` mechanism lets anyone prove the block-number mismatch from the output-root preimage.
- `addLocalData` passes `min(anchor + traceIndex + 1, l2BlockNumber)` to the VM (`FaultDisputeGame.sol:604-609`), so the bisected block number never needs more than 64 bits, and on-chain and off-chain local inputs agree.
- An unchallenged invalid root is already a total failure of the security model, whatever the block number.

Fix:
```diff
 if (l2BlockNumber() <= rootBlockNumber) revert UnexpectedRootClaim(rootClaim());
+if (l2BlockNumber() > type(uint64).max) revert UnexpectedRootClaim(rootClaim());
```
The zk game has the equivalent check. `SuperFaultDisputeGame` already reads a uint64 timestamp from the super root.

### B. Span-batch `v` recovery overflowed uint64

`span_batch_txs.go:262-268` (parent `b8a91297ea^`)
```go
type spanBatchSignature struct {
    v uint64
    ...
}
...
} else {
    // EIP-155
    v = chainID.Uint64()*2 + 35 + bit
}
```
For `chainID ≥ 2^63 - 17`, `chainID*2 + 35` wraps. `chainID.Uint64()` also silently truncates chain IDs of 2^64 or more. The decoder would then rebuild the legacy transaction with the wrong `v`, so the derived transaction would recover a different sender or fail validation on the execution layer. The encoder (`AddTxs`, `txSig.v = v.Uint64()`) truncated in the same way.

Fix: `v` becomes a `*big.Int` throughout, computed as `chainID*2 + 35 + bit` with big-integer arithmetic. The remaining narrowing conversions in op-node (`deposit_log.go`, `p2p/discovery.go`, `p2p/prepared.go`, the batch decoder CLI) switch from `Uint64()` to `bigs.Uint64Strict()`, which panics instead of truncating silently.

Why it is Informational: the L2 chain ID is fixed by the chain operator in the rollup config. No OP Stack chain uses a chain ID anywhere near 2^63. Such a chain could not run anyway, because the EL and JSON-RPC tooling assume much smaller chain IDs, and kona models the chain ID as `u64`. A batcher cannot trigger the overflow: `v` is recomputed from the configured chain ID, not read from batch data.

### Attack scenario (A, hypothetical)

1. An attacker creates a permissionless FDG with `l2BlockNumber = 2^64 + 5` and some root claim, posting the normal bond.
2. For harm to follow, the game must resolve `DEFENDER_WINS` and become the anchor. That only happens if every honest challenger fails to act, and in that case the attacker could just as well have proposed a malicious root at a real block number.
3. In reality, the honest challenger (which clamps and disputes the claim) counters it, and the attacker loses the bond.

## Impact Details

- **A:** No realistic impact beyond what an uncontested invalid claim already implies. The fix closes an "anchor beyond the reachable block range" failure mode as defence in depth. **Informational.**
- **B:** Only reachable with a chain ID above ~9.2×10^18, a configuration that no deployment can use. **Informational.**

## Proof of Concept

**A — Foundry.** The fix added `testFuzz_initialize_cannotProposeLargeBlockNumber_reverts` in `test/dispute/FaultDisputeGame.t.sol`, and an equivalent test in `test/dispute/zk/OptimisticZkGame.t.sol`. A minimal, non-fuzz version for the same test contract:

```solidity
    function test_poc_initialize_l2BlockNumberAboveUint64_reverts() public {
        uint256 bn = uint256(type(uint64).max) + 1;
        Claim root = Claim.wrap(bytes32(uint256(0xdead)));
        // parent: game created successfully; fix: reverts UnexpectedRootClaim
        vm.expectRevert(abi.encodeWithSelector(UnexpectedRootClaim.selector, root));
        disputeGameFactory.create{ value: initBond }(GAME_TYPE, root, abi.encode(bn));
    }
```
```bash
cd packages/contracts-bedrock
forge test --match-test test_poc_initialize_l2BlockNumberAboveUint64_reverts -vv
```

**B — standalone Go**, showing the arithmetic in the old and new `recoverV`:

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	chainID, _ := new(big.Int).SetString("9223372036854775808", 10) // 2^63
	var bit uint64 = 1
	oldV := chainID.Uint64()*2 + 35 + bit // pre-fix formula (span_batch_txs.go:268)
	newV := new(big.Int).Mul(chainID, big.NewInt(2))
	newV.Add(newV, big.NewInt(35))
	newV.Add(newV, big.NewInt(int64(bit)))
	fmt.Println("old v:", oldV)
	fmt.Println("new v:", newV)
}
```
```bash
go run main.go
# old v: 36
# new v: 18446744073709551652
```
PR #18921 updated the round-trip tests in `op-node/rollup/derive/batch_test.go` and `span_batch_txs_test.go`:
```bash
go test ./op-node/rollup/derive/ -run 'TestSpanBatchTxs|TestBatchRoundTrip' -v
```

Executed: B standalone arithmetic: yes (output shown above). A Foundry test: no (heavy build, and testing the parent commit would need a checkout).

## Recommendation

Both fixes are appropriate. More generally, enforce protocol-wide integer widths at the boundaries where untrusted or configured `uint256`/`*big.Int` values enter (game `extraData`, chain config, deposit logs). Prefer strict conversions (`bigs.Uint64Strict`, `SafeCast.toUint64`) to silent truncation, as the op-node part of this change does.

## References

- Fix commits: 6be6e2036b704bc34b1bffa8f6c9822000ad69ed, b8a91297ea47b224a071db3ae6a721445e9fc8d1
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/18903, https://github.com/ethereum-optimism/optimism/pull/18921
- Relevant files: `packages/contracts-bedrock/src/dispute/FaultDisputeGame.sol`, `src/dispute/zk/OptimisticZkGame.sol`, `op-challenger/game/fault/contracts/faultdisputegame.go`, `op-node/rollup/derive/span_batch_txs.go`, `op-node/rollup/derive/deposit_log.go`
