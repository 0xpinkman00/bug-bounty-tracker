# Interop (pre-mainnet) cross-chain message safety-rule fixes in op-supervisor, op-program, kona-interop, op-reth and L2 interop contracts

| Field | Value |
|---|---|
| **Target** | `op-supervisor/supervisor/backend/{cross,db}`, `op-program/client/interop`, kona `crates/protocol/interop` + interop client, op-reth interop txpool, contracts-bedrock `src/L2/*` interop contracts |
| **Asset type** | Blockchain/DLT (plus Smart Contract for 12-G) |
| **Severity** | Informational. Interop was not active on any production chain, only on devnets. |
| **Impact category** | If live: "Unintended chain split (network partition)" / invalid cross-chain messages accepted as cross-safe (a forged-message class that can lead to "Direct loss of funds") |
| **Fix commit(s)** | 4465688458 (#15568), 5b3fcfd8cd (#15376), 1d05a2a8d9 (#14463), ec9fee9382 (#15553), 13b6f4341c (op-rs/kona#1506), ef21b9b701 (#14973), 4764cdcff9 (#14994), e7fbc9ed3f (op-rs/kona#1024), 8f607a74ea (#973), 695d6a2b95 (#1006), 8bd3436219 (#1011), 334ecc484d (paradigmxyz/reth#15467), 0f476b44a3 (#14790). Dates 2025-01-29 to 2025-04-28. |
| **Vulnerable since** | The respective in-development interop implementations (2024 to early 2025) |

## Brief / Intro

OP Stack *interop* lets a transaction on one chain "execute" a message that was *initiated*, meaning emitted as a log, on another chain in the same cluster. A block is only safe if every message it executes points to a real log that is old enough, not expired, and does not depend on itself in a loop. Two components enforce these rules: `op-supervisor` for live nodes, and the fault-proof programs (op-program, kona) for disputes. If they accept a message that breaks a rule, a chain can include a transaction that acts on a message that never validly happened. The canonical example is minting bridged tokens on chain B without a valid burn on chain A. If the supervisor and the proof programs disagree, honest output proposals can also become impossible to defend. Several such gaps were fixed in early 2025. Interop had not launched on any production chain, so no funds were at risk.

## Vulnerability Details

### 12-A Supervisor and op-program cycle detection missed cycles through ordinary logs. 4465688458 (#15568), 2025-04-28
Messages executed within the same timestamp must not form dependency cycles. The spec counts both "executing message → its initiating log" edges and the ordinary "earlier log → later log in the same block" ordering. `buildGraph` skipped every edge whose initiating log was not itself an executing message:

`op-supervisor/supervisor/backend/cross/cycle.go:176-183` (parent)
```go
// Check if we care about the init message
initChainMsgs, ok := execMsgs[m.Chain]
if !ok {
    continue
}
if _, ok := initChainMsgs[m.LogIdx]; !ok {
    continue
}
```
Any cycle that closes through ordinary log order therefore went undetected. For example, an executing message at log 0 that references log 2 of the *same block* (a log emitted later) forms the cycle 0→2→1→0. So does a cross-chain loop A0→B0→A1→A0. The fix deletes these lines so that every initiating log becomes a graph node. `op-program/client/interop/consolidate.go:252` calls the same `cross.HazardCycleChecks`, so the fault-proof program had the same gap. The supervisor and the program agreed with each other, but both disagreed with the spec, and so with kona or any spec-conformant implementation. The practical effect: a block that executes a message whose initiating log is emitted *later* in the same block (a causality violation) was treated as valid and could be promoted to cross-safe.

### 12-B op-program consolidation errored instead of replacing invalid blocks. 5b3fcfd8cd (#15376), 2025-04-17
If an executing message pointed to a non-existent log or chain head, `consolidate.go` returned a plain `"log not found"` / `ethereum.NotFound`. It should have wrapped `supervisortypes.ErrConflict`. The consolidation step replaces an invalid block with a deposit-only block only when it sees `ErrConflict`. Otherwise the program aborts. So a block with a bogus executing message could not be *proven* invalid, and an honest challenger could not win against a proposal that included it.

### 12-C Message expiry missing or wrong. 1d05a2a8d9 (#14463), ec9fee9382 (#15553), 13b6f4341c (op-rs/kona#1506)
The spec expires initiating messages after `MESSAGE_EXPIRY_WINDOW` = 30 days. `op-supervisor`'s `CheckMessage` did not take the executing timestamp, so it could not enforce expiry at all. #14463 added `ExecutingDescriptor` and `CheckMessagesV2`, and #15553 short-circuits inclusion checks of expired messages in both the supervisor (`hazard_set.go`) and op-program. kona used `180 * 24 * 60 * 60` (180 days) and never checked expiry in its graph. #1506 set the value to 30 days and added the check. Without these fixes, expired messages were accepted, and kona and op-program/supervisor would disagree about messages 30 to 180 days old.

### 12-D Supervisor returned `ErrFuture` instead of `ErrConflict` for out-of-range logs. ef21b9b701 (#14973), 4764cdcff9 (#14994)
`logs.DB.Contains` returned `ErrFuture` ("not known yet, retry") for a log index past the end of a block that is already complete. It should return `ErrConflict` ("invalid"). Executing messages pointing past a block's last log therefore stayed pending forever instead of invalidating the block. #14994 fixes a related case in which deep local-safe invalidation was not propagated.

### 12-E kona interop timestamp invariant and superchain STF transitions. e7fbc9ed3f (op-rs/kona#1024), 8f607a74ea (#973), 695d6a2b95 (#1006), 8bd3436219 (#1011)
kona checked the "initiating timestamp ≤ executing timestamp" invariant against only one of the two relevant timestamps. The fix checks it against both the executing block and the horizon timestamp. It also had several wrong transitions in the superchain state-transition function: no-op sub-transitions, pre-state handling, and hint routing. These are proof-program correctness issues. In a live system they would make kona disagree with op-program on super-root outputs.

### 12-F op-reth down-scored peers for interop txs invalidated by reorg. 334ecc484d (paradigmxyz/reth#15467)
`InvalidInboxEntry::MinimumSafety { got: SafetyLevel::Invalid }` was marked as a "bad transaction" that penalizes the peer. An executing tx can become invalid through a reorg on the source chain without the relaying peer doing anything wrong. An attacker who can trigger such reorgs, or who just waits for them, could get honest peers down-scored and disconnected (peer-ban griefing).

### 12-G Interop contracts audit fixes. 0f476b44a3 (#14790), 2025-03-12
These came from an external review of the pre-release L2 interop contracts. Among the changes: `L2ToL2CrossDomainMessenger.relayMessage` now marks `successfulMessages[hash] = true` before the external call (the function was already `nonReentrant`, so this is checks-effects-interactions hardening) and bubbles up the revert data. `SuperchainWETH.approve` now rejects non-infinite Permit2 allowances, to match its hard-coded infinite Permit2 allowance. `CrossL2Inbox` was redesigned. Unused `OptimismPortalInterop` and `SystemConfigInterop` were removed. None of this code was deployed on a production chain.

### Attack scenario (12-A, if interop had been live)
1. An attacker sends a block-building-friendly bundle on chain A. Tx 1 executes a message whose `Identifier` points to log index *k* in the same block, and a later tx emits log *k*.
2. `buildGraph` ignores the edge from the ordinary log *k* back to the executing message's own position, so no cycle is found. The block passes `HazardCycleChecks` in both the supervisor and op-program and becomes cross-safe.
3. The executing message was "valid" only because of a log emitted after it. That breaks the causality invariant, which is what makes cross-chain messages sound. A spec-conformant verifier such as kona rejects the block, which splits consensus between implementations.

## Impact Details

- **No production impact.** Interop had not activated on any mainnet or public testnet chain in production use. The fixes were made during devnet development and before audits finished.
- If live, the most serious items would be 12-A, 12-C and 12-D. They allow invalid executing messages to become cross-safe, and they create disagreement between proof programs and nodes. That class can lead to forged cross-chain mints (High/Critical). 12-B would let a proposal with an invalid block go unchallengeable in the dispute game. 12-F is peer-level griefing (Low).
- Rated **Informational** because none of the code was live.

## Proof of Concept

Executed: **yes** for 12-A. I ran the fix's `cycle_test.go` against the parent's `cycle.go`:

```bash
H=4465688458
d=$(mktemp -d)
git archive $H^ go.mod go.sum op-supervisor op-service op-node op-alt-da op-program op-chain-ops | tar -x -C $d
git show $H:op-supervisor/supervisor/backend/cross/cycle_test.go > $d/op-supervisor/supervisor/backend/cross/cycle_test.go
(cd $d && go test ./op-supervisor/supervisor/backend/cross/ -run TestHazardCycleChecks -count=1)
```

Parent (`4465688458^`):
```
--- FAIL: TestHazardCycleChecksCycle (0.00s)
    --- FAIL: TestHazardCycleChecksCycle/Cycle/3-cycle_in_single_chain
    --- FAIL: TestHazardCycleChecksCycle/Cycle/cycle_through_single_chain,_exec_message_prior_to_init_and_adjacent
    --- FAIL: TestHazardCycleChecksCycle/Cycle/cycle_through_single_chain,_exec_message_prior_to_init_and_not_adjacent
    --- FAIL: TestHazardCycleChecksCycle/Cycle/3-cycle_across_chains
FAIL
```
Fix (`4465688458`): `ok  github.com/ethereum-optimism/optimism/op-supervisor/supervisor/backend/cross 0.343s`

The key failing case (from the fix's test file):
```go
{
    // 0->2->1->0
    name: "cycle through single chain, exec message prior to init and not adjacent",
    chainBlocks: map[string]chainBlockDef{
        "1": {logCount: 3, messages: map[uint32]*types.ExecutingMessage{0: execMsg("1", 2)}},
    },
    expectErr: ErrCycle,
},
```

For the other items (not executed), the fix commits add regression tests that fail on their parents:
- 12-B: new cases in `op-program/client/interop/interop_test.go` for a missing log/head, which expect the block to be replaced (5b3fcfd8cd).
- 12-C: expired-message cases in `op-program/client/interop/interop_test.go` and `op-supervisor/supervisor/backend/cross/safe_update_test.go` (ec9fee9382); kona `test_derive_and_reduce_simple_graph_message_expired` in `graph.rs` (13b6f4341c): `cargo test -p kona-interop message_expired`.
- 12-D: `op-supervisor/supervisor/backend/db/logs/db_test.go` out-of-range-in-complete-block expects `ErrConflict` (ef21b9b701).

## Recommendation

The fixes bring each component in line with the interop spec. Before interop launches:
- Build a shared, spec-derived test vector suite (cycles, expiry, out-of-range, timestamp invariant) and run it against op-supervisor, op-program **and** kona. 12-A shows that sharing code between the supervisor and op-program hides a spec deviation from differential testing.
- Fuzz `buildGraph` against a reference cycle detector over random intra-timestamp log/exec layouts.
- Get the redesigned `CrossL2Inbox` / `L2ToL2CrossDomainMessenger` re-audited once the design is final.

## References

- Fix commits: 4465688458, 5b3fcfd8cd, 1d05a2a8d9, ec9fee9382, ef21b9b701, 4764cdcff9, 0f476b44a3 (ethereum-optimism/optimism PRs #15568, #15376, #14463, #15553, #14973, #14994, #14790); 13b6f4341c, e7fbc9ed3f, 8f607a74ea, 695d6a2b95, 8bd3436219 (op-rs/kona #1506, #1024, #973, #1006, #1011); 334ecc484d (paradigmxyz/reth#15467)
- Relevant files: `op-supervisor/supervisor/backend/cross/cycle.go`, `op-supervisor/supervisor/backend/cross/hazard_set.go`, `op-supervisor/supervisor/backend/db/logs/db.go`, `op-program/client/interop/consolidate.go`, kona `crates/protocol/interop/src/{graph,constants}.rs`, `packages/contracts-bedrock/src/L2/{L2ToL2CrossDomainMessenger,SuperchainWETH,CrossL2Inbox}.sol`
- Specs: https://specs.optimism.io/interop/messaging.html (invariants, expiry), https://specs.optimism.io/interop/verifier.html (cycle / dependency rules)
