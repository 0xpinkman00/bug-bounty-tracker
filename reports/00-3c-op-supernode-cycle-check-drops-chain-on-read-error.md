# op-supernode — interop cycle detection silently drops a chain on logs-DB read error — same-timestamp cycle can be missed

| Field | Value |
|---|---|
| **Target** | `op-supernode/supernode/activity/interop/cycle.go` (`verifyCycleMessages`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Informational |
| **Impact category** | A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk (latent; fail-open only under a local fault) |
| **Fix commit(s)** | 5785782073cff346635834bfcd8624e60c5b2cee (PR #21303), 2026-06-09 |
| **Vulnerable since** | Introduction of same-timestamp cycle verification in op-supernode (exact commit unknown) |

## Brief / Intro

Interop allows a block to use a message from another chain's block that has the *same* timestamp. That creates a risk of circular dependencies: chain A's message depends on chain B's log, and B's message depends on A's log, in the same instant. The protocol forbids such cycles, and op-supernode runs a separate cycle check (a topological sort over all same-timestamp messages). When that check could not read one chain's block from its local logs database, it quietly left the chain out of the graph instead of stopping. Leaving a chain out also removes every edge that points to it, so a real cycle could disappear and the blocks involved could be accepted as valid.

**Interop status:** Lagoon/interop was not active on any production network while this bug was live, and it is still not scheduled at HEAD (`docs/public-docs/snippets/generated/hardforks/lagoon.mdx`; no `lagoon_time` in `rust/kona/crates/protocol/registry/etc/configs.json`).

## Vulnerability Details

Parent commit, `op-supernode/supernode/activity/interop/cycle.go:180-200`:

```go
for chainID, blockID := range blocksAtTimestamp {
    if frontierBlock, ok := view.block(chainID); ok { ...; continue }
    db, ok := i.logsDBs[chainID]
    if !ok { continue }
    blockRef, _, execMsgs, err := db.OpenBlock(blockID.Number)   // :193
    if err != nil {
        // Can't open block - no EMs to add to the graph for this chain
        // This can happen if the logsDB is empty or the block hasn't been indexed
        continue
    }
    ...
    chainEMs[chainID] = execMsgs
}
graph := buildCycleGraph(ts, chainEMs)
if err := checkCycle(graph); err != nil { ... mark InvalidHeads ... }
return result, nil
```

A read failure is treated as "this chain has no same-timestamp executing messages". `buildCycleGraph` then drops that chain's nodes and all cross-chain edges into it, so `checkCycle` can succeed on a graph that in reality contains a cycle. The main message check, `verifyInteropMessages`, already returns an error on the same kind of failure. The two checks were inconsistent.

Fix:

```go
blockRef, _, execMsgs, err := db.OpenBlock(blockID.Number)
if err != nil {
    return Result{}, fmt.Errorf("chain %s: failed to open block %d for cycle verification: %w", chainID, blockID.Number, err)
}
// A block at a different timestamp legitimately contributes no same-timestamp messages.
if blockRef.Time != ts { continue }
```

The round now retries instead of reaching a verdict on incomplete data.

### Attack scenario (post-activation)

1. A same-timestamp cycle is constructed across chains A and B. Each executing message references a log emitted by the other chain at the same timestamp. This needs precise prediction of block number, log index and timestamp, which in practice means sequencer cooperation or very careful timing.
2. At the moment the supernode verifies that timestamp, chain B's block is not served from the frontier view, and the logs-DB `OpenBlock` for B fails. This could be a not-yet-indexed block, a disk error, or a DB being reopened.
3. B is dropped from the graph, no cycle is found, and both blocks are recorded as verified or cross-safe.
4. The fault-proof program, which does detect the cycle, would replace those blocks. Proposals or consumers relying on the supernode's verdict would then disagree with the proof.

## Impact Details

- **Effect**: the supernode may accept cycle-participating blocks as cross-safe. Consequences include a safe label on invalid blocks, and supernode-derived proposals that disagree with the FPP (proposer bond at risk).
- **Why Informational**:
  - The attacker cannot cause the `OpenBlock` failure. It requires a local data-availability fault on the supernode, and normally the frontier view supplies the block, so the logs-DB branch is a fallback.
  - The attacker must also construct a genuine same-timestamp cycle, and both conditions have to coincide.
  - Interop was never activated on a production network while the bug was live.
- This is a real fail-open safety flaw, though, and was correctly fixed.

## Proof of Concept

Regression test added by the fix (`op-supernode/supernode/activity/interop/cycle_test.go`):

```go
func TestVerifyCycleMessages_OpenBlockErrorReturnsError(t *testing.T) {
    t.Parallel()
    chainID := eth.ChainIDFromUInt64(10)
    block := eth.BlockID{Number: 100, Hash: common.HexToHash("0x123")}
    mockDB := &algoMockLogsDB{openBlockErr: errors.New("database read failed")}
    i := &Interop{log: gethlog.New(), logsDBs: map[eth.ChainID]LogsDB{chainID: mockDB}}
    // A nil view forces the logsDB branch.
    _, err := i.verifyCycleMessages(testTS, map[eth.ChainID]eth.BlockID{chainID: block}, nil)
    require.Error(t, err, "unavailable block data must surface as an error, not silently drop the chain")
}
```

On the parent, `verifyCycleMessages` returns `(Result{...}, nil)` and the test fails at `require.Error`. On the fix it passes. The companion test `TestVerifyCycleMessages_BlockNotAtTimestampSkippedWithoutError` confirms that the legitimate skip is kept.

```
go test ./op-supernode/supernode/activity/interop/ -count=1 -run 'TestVerifyCycleMessages_'
```

For the parent run, copy the fix's `cycle_test.go` into a tree at `5785782073^`. `algoMockLogsDB` with `openBlockErr` must exist there; if it does not, add the field to the mock.

Executed: no. The scratch trees were lost when the session restarted before this run.

## Recommendation

The fix is correct: fail closed and retry the round. Also consider:

- Share a single "collect executing messages for timestamp" helper between `verifyInteropMessages` and `verifyCycleMessages`, so that data-availability handling cannot diverge again.
- Add a metric for cycle-verification retries so that persistent logs-DB faults are noticed.

## References

- Fix commit: 5785782073cff346635834bfcd8624e60c5b2cee
- Pull request: https://github.com/ethereum-optimism/optimism/pull/21303
- Relevant files: `op-supernode/supernode/activity/interop/cycle.go`, `op-supernode/supernode/activity/interop/algo.go`
