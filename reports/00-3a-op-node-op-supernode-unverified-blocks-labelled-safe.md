# op-node / op-supernode — interop safe head advanced past cross-chain verification in three paths (L1 reorg, EL-sync completion, verifier read error)

| Field | Value |
|---|---|
| **Target** | `op-node/rollup/engine/engine_controller.go`, `op-supernode/supernode/activity/interop/interop.go`, `op-supernode/supernode/chain_container/super_authority.go` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (pre-activation; would be Medium on a live interop network) |
| **Impact category** | A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk |
| **Fix commit(s)** | f294f1e7068401b6f6c8e134782a77409e7f1e41 (PR #21049), 2026-05-28; 77ff5b91a552ac6f221b8a7784381c8c33015ccb (PR #22986), 2026-09-22; 5e26774cc066d8ac91729d6d7f47e0366bf9c8f2 (PR #22982), 2026-09-24 |
| **Vulnerable since** | Introduction of the SuperAuthority safe-head bound in op-node. The EL-sync path dates from 001cbedd99 (2026-04-13). |

## Brief / Intro

With interop (the Lagoon fork), an L2 block is only truly "safe" once op-supernode has checked every cross-chain message it contains. Each such message has to point at a real log on another chain. Until that check passes, the block is only *local-safe*: derived from L1, but not yet cross-verified. op-node asks the supernode (its "SuperAuthority") for the verified head and should never label a block safe beyond it. Three code paths broke that rule and published unverified local-safe blocks as the `safe` head: after an L1 reorg, when EL sync completes, and when the verifier returned a read error. A block containing an invalid cross-chain message could therefore briefly appear as `safe` to wallets, bridges and indexers before being replaced.

**Interop status:** at every fix commit, and at HEAD (2026-09-24), Lagoon/interop is not active on any production network. `docs/public-docs/snippets/generated/hardforks/lagoon.mdx` lists Mainnet and Sepolia activation as "Not scheduled". The vendored registry snapshot (`rust/kona/crates/protocol/registry/etc/configs.json`, 2026-08-21) has no `lagoon_time` for any chain, and only a devnet (chain 420130015) has an interop dependency set. The OP Sepolia / Unichain Sepolia activation targeted for July 2026 (`docs/public-docs/notices/interop-prep.mdx`) was never pinned. Before activation these paths return local-safe by design, so none of the bugs had any effect on live networks.

## Vulnerability Details

### Bug 1: verifier read error promotes local-safe (f294f1e706, "bug A")

In the parent commit, `op-supernode/supernode/chain_container/super_authority.go:32-37`:

```go
bId, ts, err := v.LatestVerifiedL2Block(c.chainID)
if err != nil {
    c.log.Warn("FullyVerifiedL2Head: verifier read failed, signaling local-safe fallback", ...)
    return eth.BlockID{}, true          // "useLocalSafe"
}
```

`op-node/rollup/engine/engine_controller.go:203-209` (parent) honours that flag:

```go
fvshid, useLocalSafe := e.superAuthority.FullyVerifiedL2Head()
if useLocalSafe {
    return e.localSafeHead
}
```

A transient error in the verified-DB read therefore advanced cross-safe to local-safe with no verification at all. The same code had a second problem. A post-activation verifier with nothing verified yet returned `(BlockID{}, false)`, which op-node resolved to genesis. That published genesis as cross-safe and wrote a synthetic safe-DB entry. This is a regression, not a safety issue. The fix replaces the boolean with a tri-state `VerifierHead{PreActivation | Anchor | Verified}` plus an `ok` flag. On `ok=false`, op-node uses the canonicality-checked cross-safe cache or floors at `FinalizedHead`, and never uses local-safe.

### Bug 2: EL-sync completion publishes the resume point as safe (77ff5b91a5)

In the parent commit, `engine_controller.go:841-853`, EL-sync completion runs this:

```go
safeRef, finalizedRef, err := e.headsAfterELSync(ctx, ref)
fc.SafeBlockHash = safeRef.Hash             // line 846
...
e.SetLocalSafeHead(safeRef)
e.onSafeUpdate(ctx, safeRef, safeRef)       // line 852: cross-safe := local-safe
```

`safeRef` is the safe-DB tip or the retracted synced tip, which is a *local-safe* resume point. It was sent to the EL as the forkchoice `safe` hash and reported as cross-safe, bypassing `SafeL2Head()` and its SuperAuthority bound. Fix:

```go
e.SetFinalizedHead(finalizedRef)
crossSafe := e.SafeL2Head()                  // bounded by verified head
fc.SafeBlockHash = crossSafe.Hash
e.onSafeUpdate(ctx, crossSafe, safeRef)
```

The window lasts one forkchoice update per restart into EL sync, because the next update recomputes `SafeL2Head`.

### Bug 3: L1 reorg leaves stale verified head, local-safe promoted (5e26774cc0)

In the parent commit, `engine_controller.go:244-247`:

```go
func (e *EngineController) resolveVerifiedAsSafe(block eth.BlockID) eth.L2BlockRef {
    if block.Number > e.localSafeHead.Number {
        e.log.Warn("super authority safe head ahead of local safe head, using local safe", ...)
        return e.localSafeHead
    }
```

After an L1 reorg, derivation resets local-safe below the supernode's last verified block. On the supernode side, `observeRound` first called `checkChainsReady(nextTimestamp)`. That returned `ethereum.NotFound`, because local-safe is now below the frontier, and the round returned early *before* the L1-consistency check that would have rewound the stale verified state. The stale verified head therefore stayed "ahead" indefinitely. As derivation re-advanced local-safe on the new L1 branch, op-node kept labelling each new, unverified local-safe block as safe. The fix makes two changes:

- op-node: `return e.crossSafeFallback("ahead-of-local-safe")`, which returns the cached canonical verified block or the finalized head.
- op-supernode: `observeRound` checks `SameL1Chain(LastVerified.L1Inclusion)` before `checkChainsReady`, and `checkPreconditions` gives `DecisionRewind` priority over `DecisionWait`.

### Attack scenario (post-activation, bug 3)

1. The attacker sends a transaction on chain A with an executing message that references a non-existent log on chain B. It lands in an unsafe block, for example through a mempool-filter gap (see 00-3d), and is batched to L1.
2. An L1 reorg occurs. These happen naturally, and the attacker only needs to time the submission.
3. op-node on chain A derives the invalid block as local-safe on the new L1 branch. The supernode's verified state is stale and is not rewound, so op-node labels the block `safe` and sends it to the EL as the forkchoice safe hash.
4. A bridge, CEX or indexer that credits on `safe` acts on state that includes the invalid message. Once the supernode catches up, the block is replaced by a deposits-only block, so a "safe" block is reorged out.

## Impact Details

- **What breaks**: the invariant that `safe` means cross-verified on interop chains. Consumers that trust `safe` could act on transactions that are later removed, which can cause double spends against off-chain services.
- **Not affected**: fault proofs and super-root proposals, which are computed from the supernode's own verified data and the FPP. L1 withdrawals are not directly at risk.
- **Preconditions**: interop must be active. There must also be an L1 reorg (bug 3), a node restarting into EL sync (bug 2), or a verifier DB read error (bug 1), combined with an unsafe block that actually contains an invalid executing message.
- **Severity**: on a live interop network this would be Medium, because an invalid block briefly carries the safe label. Interop was never activated on any production network while these bugs were live (see Interop status above). The code was reachable only on devnets, so the rating is **Low**.

## Proof of Concept

The regression tests added by the fixes serve as the PoC. Bugs 2 and 3 were executed against both the parent and the fix trees, which were extracted with `git archive` into a scratch directory. `op-core/superchain/superchain-configs.zip` is gitignored, so it was replaced there by a stub zip.

**Bug 3**: `op-node/rollup/engine/super_authority_safe_head_test.go` (from 5e26774cc0):

```go
func TestSafeL2Head_VerifiedAheadOfLocalSafe_UsesCrossSafeCache(t *testing.T) {
    localSafe := eth.L2BlockRef{Hash: common.Hash{0xaa}, Number: 100}
    localFinalized := eth.L2BlockRef{Hash: common.Hash{0xbb}, Number: 40}
    cached := eth.L2BlockRef{Hash: common.Hash{0xcc}, Number: 80}
    staleVerified := eth.BlockID{Hash: common.Hash{0xff}, Number: 200}
    ... // engine controller with mockSuperAuthority{fullyVerifiedL2Head: cached, Source: Verified}
    require.Equal(t, cached, ec.SafeL2Head())          // fills cross-safe cache
    sa.fullyVerifiedL2Head = staleVerified             // verified head now "ahead" (post-L1-reorg)
    got := ec.SafeL2Head()
    require.Equal(t, cached, got, "the controller must reuse the cached verified block")
}
```

Result on the parent (5e26774cc0^):

```
--- FAIL: TestSafeL2Head_VerifiedAheadOfLocalSafe_UsesCrossSafeCache
    WARN super authority safe head ahead of local safe head, using local safe super_authority_safe=ff..:200 local_safe=aa..:100
    expected: {Hash:0xcc.., Number:80}  actual: {Hash:0xaa.., Number:100}
```

Unverified local-safe block 100 is returned as safe. On the fix: `--- PASS`.

Supernode side: `TestInterop_ProgressAndRecord_L1InconsistencyRewindsWhenChainsNotReady` (`op-supernode/supernode/activity/interop/interop_test.go`). On the parent it fails with `expected: 0x65 actual: 0x66 — the stale verified entry must be removed`. On the fix: PASS.

**Bug 2**: `TestInsertUnsafePayload_ELSync_boundsSafeLabelByVerifiedHead` (`op-node/rollup/engine/engine_el_sync_completion_test.go`, from 77ff5b91a5). On the parent the mock engine receives:

```
ForkchoiceUpdate  safeBlockHash: 0x33..  (refA3 = resume point, unverified)
expected          safeBlockHash: 0x6b8a.. (refA0 = authority-bounded head)
--- FAIL
```

On the fix: `--- PASS` (together with `TestInsertUnsafePayload_ELSync_safeLabelUsesNewFinalizedHead`).

Commands, run from a tree at the parent or fix commit, with the fix's test files copied in for the parent run:

```
go test ./op-node/rollup/engine/ -count=1 -run 'TestSafeL2Head_VerifiedAheadOfLocalSafe_UsesCrossSafeCache|TestInsertUnsafePayload_ELSync_boundsSafeLabelByVerifiedHead'
go test ./op-supernode/supernode/activity/interop/ -count=1 -run TestInterop_ProgressAndRecord_L1InconsistencyRewindsWhenChainsNotReady
```

**Bug 1**: PoC against the parent API (f294f1e706^). Place it in `op-supernode/supernode/chain_container/`, where it reuses that package's test helpers:

```go
func TestPoC_VerifierReadError_PromotesUnverifiedLocalSafe(t *testing.T) {
    cc := newTestChainContainer(t, eth.ChainIDFromUInt64(420))
    localSafe := eth.L2BlockRef{Number: 100, Hash: [32]byte{0xaa}, Time: 2000}
    setSyncStatus(t, cc, &eth.SyncStatus{LocalSafeL2: localSafe})
    cc.RegisterVerifier(&mockVerificationActivityForSuperAuthority{
        isActiveAtFn:      func(uint64) bool { return true }, // interop active
        latestVerifiedErr: errors.New("verified DB read failed"),
    })
    ec := engine.NewEngineController(context.Background(), &testutils.MockEngine{},
        testlog.Logger(t, log.LevelDebug), metrics.NoopMetrics, &rollup.Config{},
        &sync.Config{}, &testutils.MockL1Source{}, &testutils.MockEmitter{}, cc)
    ec.SetLocalSafeHead(localSafe)
    ec.SetFinalizedHead(eth.L2BlockRef{Number: 40, Hash: [32]byte{0xbb}})
    require.NotEqual(t, localSafe, ec.SafeL2Head(),
        "unverified local-safe block was labelled cross-safe after a verifier read error")
}
```

This is expected to fail on the parent: `SafeL2Head()` returns `localSafe` through the `useLocalSafe` branch. The fix's equivalent under the new API is `TestSafeL2Head_VerifierError_FloorsAtFinalized` (`super_authority_safe_head_test.go`), which asserts the result is `localFinalized`.

Executed: yes for bugs 2 and 3 (fail on parent, pass on fix). No for bug 1: the scratch run was killed by the environment before it finished.

## Recommendation

The fixes close all three paths. Defence-in-depth suggestions:

- Keep a single chokepoint. Every write of `fc.SafeBlockHash` and every `onSafeUpdate` cross-safe argument should go through `SafeL2Head()`. A lint or test could assert that no other assignment exists.
- When the verified head is stale or ahead of local-safe, keep the safe label at the last canonical verified block rather than falling back to finalized. The fix already does this through `crossSafeCache`.
- Emit a metric or alert whenever the fallback path is taken (5e26774cc0 adds `RecordSuperAuthorityReorgSignal`).

## References

- Fix commits: f294f1e706 (#21049), 77ff5b91a5 (#22986), 5e26774cc0 (#22982, fixes #22845)
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/21049, https://github.com/ethereum-optimism/optimism/pull/22986, https://github.com/ethereum-optimism/optimism/pull/22982
- Relevant files: `op-node/rollup/engine/engine_controller.go`, `op-node/rollup/iface.go`, `op-supernode/supernode/activity/interop/interop.go`, `op-supernode/supernode/chain_container/super_authority.go`
- Interop activation status: `docs/public-docs/snippets/generated/hardforks/lagoon.mdx`, `docs/public-docs/notices/interop-prep.mdx`
