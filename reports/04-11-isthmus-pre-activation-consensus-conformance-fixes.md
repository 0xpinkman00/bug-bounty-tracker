# Isthmus pre-activation consensus-conformance fixes across op-reth, alloy-op-evm, op-alloy, kona, op-program and op-service

| Field | Value |
|---|---|
| **Target** | op-reth (payload builder, consensus), alloy-op-evm (system calls), op-alloy (engine types), kona-executor, op-program client, op-service `eth` types, contracts-bedrock `Preinstalls` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Informational overall. Every item was fixed before Isthmus activated on OP Mainnet (2025-05-09). One item (11-C) was hit on OP Sepolia for about 2.5 h after its activation (2025-04-17 16:00 UTC), in op-reth only; I rate it Low. |
| **Impact category** | If shipped at activation: "Unintended chain split (network partition)" / "Network not being able to confirm new transactions (total network shutdown)" for the affected client |
| **Fix commit(s)** | See the per-item list below (16 commits, 2025-01-29 to 2025-04-17) |
| **Vulnerable since** | Each item came with its feature's initial Isthmus/Prague implementation, earlier in the same development cycle |

## Brief / Intro

Isthmus is the OP Stack hard fork that brings Ethereum's Prague/Pectra features to L2. It also moves the L2→L1 withdrawal commitment (the storage root of the `L2ToL1MessagePasser` contract) into the block header's `withdrawalsRoot` field. Every client must implement these header and state changes identically, or its block hashes and state roots stop matching the rest of the network. That means a chain split, or a node that halts on valid blocks. Leading up to activation, many mismatches of this kind were found and fixed in the Rust clients (op-reth, alloy-op-evm, kona) and in the Go fault-proof program and utilities. None of them reached mainnet. They are grouped here because they share a root cause (incomplete Isthmus/Prague conformance) and a mitigating factor (pre-activation).

## Vulnerability Details

Spec references: Isthmus `withdrawalsRoot` = storage root of `0x4200…0016` after the block; `requestsHash` = `EMPTY_REQUESTS_HASH` = `sha256("")` = `0xe3b0c442…b855`; EIP-7002/7251 request contracts are **not** called on L2; the EIP-2935 blockhash system call **is** applied.

### 11-A op-reth builder left `requests_hash` unset after Isthmus. 0f0c82c8fd (paradigmxyz/reth#15444), 2025-04-01
`OpPayloadBuilder` hard-coded `requests_hash: None`. The fix sets `Some(EMPTY_REQUESTS_HASH)` when Isthmus is active. An op-reth sequencer would have produced headers whose hash differs from op-geth's for the same block, and every other client would reject them.

### 11-B op-reth checked the body's withdrawals root against the header after Isthmus. d02062ba02 (reth#15773), 2025-04-16
Generic `validate_body_against_header` compares `calculate_withdrawals_root(body.withdrawals)` with `header.withdrawals_root`. Post-Isthmus that header field holds the message-passer storage root, so every valid Isthmus block failed the check. The fix adds `validate_body_against_header_op`, which skips the withdrawals comparison after Isthmus. Without it, op-reth nodes would halt at the activation block. It was fixed about 23 h before Sepolia activation.

### 11-C op-reth post-execution Isthmus check failed without canonical parent state. dadcafa0fb (reth#15796), 2025-04-17 18:22 UTC
```rust
// before
let state = self.provider.state_by_block_hash(block.parent_hash()).map_err(|err| {
    ConsensusError::Other(format!("failed to verify block post-execution: {err}"))
})?;
// after
let Ok(state) = self.provider.state_by_block_hash(block.parent_hash()) else {
    // FIXME: ... parent block isn't necessarily part of the canonical chain yet ...
    return Ok(())
};
```
When a block's parent was only in memory (not yet persisted or canonical, which is common with engine-API sync and reorgs), op-reth rejected valid Isthmus blocks. This was committed about 2.4 h after Sepolia activated, so op-reth Sepolia nodes could have stalled in that window. Note that the fix **skips** the `withdrawalsRoot` check in that case. It is weaker validation, not a complete fix. Current code verifies the root against the engine's parent state (`rust/op-reth/crates/node/src/engine.rs:149`, `isthmus::verify_withdrawals_root_prehashed`), so the gap has since been closed.

### 11-D op-reth builder computed the message-passer root without the block's own writes. 94f62ffe15 (reth#14307), 2025-02-14
`storage_root(ADDRESS_L2_TO_L1_MESSAGE_PASSER, Default::default())` used an empty change set, so the header got the *parent's* root. The fix passes the block's `HashedStorage` updates for that account. With the bug, an op-reth sequencer's first block containing a withdrawal would be rejected by every other client.

### 11-E op-reth did not apply the EIP-2935 blockhash system call. b41748cc46 (reth#14832), 2025-03-04
A one-line addition: `apply_blockhashes_contract_call(parent_hash, ...)` in the OP block executor. Without it, the history-storage contract's state differs from op-geth's, so the state root differs from the first Isthmus block onward.

### 11-F alloy-op-evm system calls leaked state and used the wrong tx type. 1eee9c5a72 (alloy-rs/evm#44), ef2e6cdd61 (alloy-rs/evm#45), 2025-03-19/21
`transact_system_call` committed every touched account (the system caller and the block beneficiary) into the state changes. It should keep only the target contract (`res.state.retain(|addr, _| *addr == contract)`). It also ran the call as `tx_type: 0` rather than the deposit type, which brings L1-fee and operator-fee handling into play. Both change the state root compared with op-geth.

### 11-G op-alloy engine types used `EMPTY_ROOT_HASH` for the requests hash. 2c2f6fa52b (alloy-rs/op-alloy#463), 2025-03-06
The conversion of `OpExecutionPayloadV4` to a block set `requests_hash = EMPTY_ROOT_HASH` (the empty-trie root, `0x56e8…b421`) and validated against it. Every consumer (op-reth, kona) would then compute Isthmus block hashes wrongly.

### 11-H kona-executor `SHA256_EMPTY` constant was wrong. 024c3aa2e1 (op-rs/kona#1267), 2025-03-14
```diff
 pub(crate) const SHA256_EMPTY: B256 =
-    b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"); // keccak256("")
+    b256!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); // sha256("")
```
It is used as the Isthmus `requests_hash` (`crates/proof/executor/src/executor/mod.rs:380`). Every kona-executed Isthmus block would hash differently, so a kona fault proof would compute wrong output roots.

### 11-I kona-executor withdrawals root at the wrong block, and L1-only request calls. 86f28223fb (op-rs/kona#974), 7a92938637 (op-rs/kona#990), 2025-01-29/02-03
#974: the account proof for the message passer was always hinted and fetched at the parent block, and the Isthmus root was disabled when interop was active. #990: removed the EIP-7002 and EIP-7251 pre-block contract calls. Those contracts are L1-only, and calling them on L2 alters state.

### 11-J op-program ran Prague requests processing after Isthmus. 5be024ccd3 (#14623), 2025-03-06
`op-program/client/l2/engineapi/block_processor.go`: the request-processing step ran whenever `IsPrague`. The fix adds `&& !IsIsthmus`, so the fault-proof program matches op-geth.

### 11-K op-program `NewPayloadV4` accepted a nil `withdrawalsRoot` post-Isthmus. 9d86edb584 (#14836), 2025-03-14
It now returns `INVALID` / `InvalidParams` rather than continuing with a nil root. 9e879c8e56 (#14180) is related, but is an optimization rather than a fix: the program reads the message-passer root from the Isthmus header instead of opening the storage trie.

### 11-L op-service ignored the implied Isthmus requests hash. 1d5770cd93 (#14361), 2025-02-18
The V4 gossip/SSZ envelope does not carry `requestsHash`; it is implied empty. `CheckBlockHash` rebuilt the header without it, so op-node's gossip validator (and the non-trusted RPC path) would have rejected every valid Isthmus unsafe block. The fix adds `BlockVersion.ImpliesRequestsRoot()` and the `RequestsHash` field.

### 11-M L2 genesis preinstall used the pre-final EIP-2935 address. bb5f63b18a (#14844), 2025-03-13
`Preinstalls.HistoryStorage` changed from `0x0F792be4…CCCC` to the final Prague address `0x0000F908…2935`, with its sender. This follows a late upstream EIP change rather than being a coding error. A chain generated with the old address would have the system call (11-E) target an empty account.

### Attack scenario
No attacker is needed. At Isthmus activation, a network running a mix of affected and unaffected clients splits, or the affected client halts:
1. The Isthmus activation block (or the first block with a withdrawal or a reorg) is produced.
2. The affected client computes a different header hash or state root (11-A, D, E, F, G, H, I, J), or rejects a valid block (11-B, C, K, L).
3. Result: a network partition between client implementations, affected nodes halting, or fault-proof programs (kona, op-program) computing output roots that honest challengers cannot defend.

## Impact Details

Had any of these reached mainnet at activation, the impact would have been High to Critical. A sequencer on an affected op-reth (Base ran reth-based nodes) produces blocks that the other clients reject, and a buggy proof program undermines dispute-game soundness. However:
- All were found through devnets, tests and differential checks, and fixed before mainnet activation. 11-B was fixed about 23 h before Sepolia activation.
- 11-C was live on OP Sepolia op-reth nodes for about 2.4 h, causing liveness problems only (valid blocks rejected). It also shipped a temporary validation weakening that was closed later.
- kona-based proofs were not securing mainnet funds at the time.

So I rate the cluster **Informational**, and 11-C **Low** (testnet-only liveness plus temporary validation weakening).

## Proof of Concept

Executed: **yes** for the constant checks below. **No** for the client-level tests, which need a full historical reth/kona/op-program build.

Constant checks behind 11-G and 11-H:
```bash
$ printf '' | sha256sum          # EMPTY_REQUESTS_HASH (EIP-7685)
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -
$ cast keccak ''                 # value kona used as SHA256_EMPTY before 024c3aa2e1
0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
```
The pre-fix kona constant was `keccak256("")`, so every kona Isthmus header's `requests_hash` was wrong.

Client-level regression tests added by the fixes (these fail on each parent):
- 11-K: `op-program/client/l2/engineapi` test case `{6, 8, "Invalid parameters", true}` in `TestNewPayloadV4` (9d86edb584). `go test ./op-program/client/l2/engineapi -run TestNewPayload`
- 11-L: `op-e2e/actions/upgrades/isthmus_fork_test.go` genesis `CheckBlockHash` assertions (1d5770cd93). `cd op-e2e && go test ./actions/upgrades -run TestIsthmus`
- 11-A/B/D: op-reth e2e and unit tests in the respective reth PRs (#15444, #15773, #14307).

Minimal PoC for 11-H (Rust, drop into `crates/proof/executor/src/constants.rs` tests at `024c3aa2e1^`; fails there, passes at the fix):
```rust
#[test]
fn sha256_empty_is_sha256_of_empty_string() {
    use sha2::{Digest, Sha256};
    assert_eq!(super::SHA256_EMPTY.as_slice(), Sha256::digest([]).as_slice());
}
```

## Recommendation

The individual fixes are correct, apart from 11-C's temporary skip, which was later replaced by a full check. Process recommendations:
- Keep cross-client differential tests (op-geth vs op-reth vs kona) that execute the activation block and blocks with withdrawals, reorgs and side chains on devnets. This caught most of these issues.
- Derive constants such as `EMPTY_REQUESTS_HASH` from shared upstream definitions (`alloy_eips::eip7685::EMPTY_REQUESTS_HASH`) instead of hand-written literals.
- Treat "skip validation when state is missing" (11-C) as a tracked security debt with an owner and deadline.

## References

- op-reth: 0f0c82c8fd (paradigmxyz/reth#15444), d02062ba02 (#15773), dadcafa0fb (#15796), 94f62ffe15 (#14307), b41748cc46 (#14832)
- alloy-op-evm: 1eee9c5a72 (alloy-rs/evm#44), ef2e6cdd61 (alloy-rs/evm#45)
- op-alloy: 2c2f6fa52b (alloy-rs/op-alloy#463)
- kona: 024c3aa2e1 (op-rs/kona#1267), 86f28223fb (#974), 7a92938637 (#990)
- op-program: 5be024ccd3 (#14623), 9d86edb584 (#14836), 9e879c8e56 (#14180)
- op-service: 1d5770cd93 (#14361)
- contracts-bedrock: bb5f63b18a (#14844)
- Spec: https://specs.optimism.io/protocol/isthmus/exec-engine.html, https://specs.optimism.io/protocol/isthmus/overview.html
