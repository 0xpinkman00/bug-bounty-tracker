# op-node / op-supernode — SuperAuthority deny-list bypassed via consolidation, unsafe sync and follow-mode sequencing — invalidated interop blocks re-adopted

| Field | Value |
|---|---|
| **Target** | `op-node/rollup/attributes/attributes.go`, `op-node/rollup/engine/engine_controller.go`, `op-supernode/supernode/chain_container/{invalidation.go,super_authority.go}` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (pre-activation; would be Medium on a live interop network) |
| **Impact category** | A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk |
| **Fix commit(s)** | 732b8452c8a2ee7a30235829b8c015186475363e (PR #21970), 2026-07-24; c5c7c760c0813c11dad2d91a7cbb9b4a088feca2 (PR #21991), 2026-07-24; 00ca51a426cc11addd2deef29f0291740656dc85 (PR #21155), 2026-06-02 |
| **Vulnerable since** | Introduction of the SuperAuthority deny-list (block invalidation) in op-node/op-supernode. Exact commit unknown. |

## Brief / Intro

Under interop, op-supernode checks cross-chain messages. When a block contains an invalid executing message, the supernode *invalidates* it. It puts the block's hash on a **deny-list**, rewinds the chain, and has op-node replace the block with a "deposits-only" version that drops the offending user transactions. op-node consulted the deny-list in only one place: the path where derivation *builds* a new block. Three other paths ignored it:

- the path where derivation *consolidates*, meaning it accepts an existing block that matches L1 data;
- unsafe block ingestion from gossip or EL sync;
- a light op-node that is also a sequencer ("follow mode").

Through these paths the invalidated block could come back and be promoted to local-safe, or the node could loop through invalidation and reset indefinitely. The invalid cross-chain message survived, and chain progress stalled.

**Interop status:** Lagoon/interop was not active on any production network while these bugs were live, and it is still not scheduled at HEAD (`docs/public-docs/snippets/generated/hardforks/lagoon.mdx`: Mainnet and Sepolia "Not scheduled"; no `lagoon_time` in the vendored registry `rust/kona/crates/protocol/registry/etc/configs.json`). PR #21991 says the livelock was observed on the devnet `interop-reorg-2` on 2026-07-21.

## Vulnerability Details

### Bug 1: consolidation promotes a denied block (732b8452c8)

In the parent commit, `op-node/rollup/attributes/attributes.go:200-247` (`consolidateNextSafeAttributes`), when the existing unsafe block matches the derived attributes:

```go
} else {
    ref, err := derive.PayloadToBlockRef(eq.cfg, envelope.ExecutionPayload)
    ...
    eq.engineController.TryUpdatePendingSafe(eq.ctx, ref, attributes.Concluding, attributes.DerivedFrom)
    eq.engineController.TryUpdateLocalSafe(eq.ctx, ref, attributes.Concluding, attributes.DerivedFrom)  // :244
}
```

The deny-list check existed only in `engine/payload_process.go`, which is reached on a *mismatch*. The invalid block was built from the same L1 batch that derivation replays, so the attributes match it byte-for-byte. If unsafe sync had re-adopted the denied block, consolidation promoted it straight to pending-safe and local-safe with no check. Fix:

```go
denied, err := eq.engineController.IsDenied(uint64(payload.BlockNumber), payload.BlockHash)
if err != nil { emit EngineTemporaryErrorEvent; return }   // fail closed
if denied { eq.reorgOutUnsafeChain(attributes); return }  // force build path -> deposits-only replacement
```

### Bug 2: unsafe ingestion re-adopts the denied branch (c5c7c760c0)

In the parent commit, `engine_controller.go:1367-1377` (`AddUnsafePayload`) and `:755` (`insertUnsafePayload`) queued and inserted gossip or EL-sync payloads with no deny-list consultation. After an invalidation and rewind, the sequencer's far-ahead unsafe tip, which descends from the denied block, kept arriving. The driver's gap-fill inserted it. `NewPayload` returned `SYNCING`, and the follow-up forkchoice update pointed the EL at the denied branch, which the EL backfilled and made canonical again. This undid the replacement. The interim `SYNCING` responses triggered `ResetError` → `FindL2Heads`, which walked local-safe back a full sequencing window on every chain. The verifier then saw the same invalid message again and invalidated it again, in a loop. The devnet incident describes a safe-head sawtooth walking back about 40k blocks per cycle.

The fix gates ingestion while `MaxDeniedHeight() > FinalizedHead().Number`:

```go
if e.unsafeDenyGatingActive() {
    for e.unsafePayloads.Pop() != nil {}   // drain denied-branch payloads buffered before the rewind
    return nil
}
```

The same gate is applied in `AddUnsafePayload`. `DenyList.MaxDeniedHeight()` was added in `invalidation.go`.

### Bug 3: follow-mode sequencer keeps its invalid fork (00ca51a426)

In the parent commit, `engine_controller.go:1459` (`FollowSource`): when a light CL that also sequences diverged from the supernode's replacement chain, it did only a soft `followExternalRefs(true)`. Its own next sequenced block overwrote that update before the forkchoice update landed. The result was head on the fork and safe on upstream, which op-reth rejects as an inconsistent forkchoice. The reset then re-selected the fork through the deny-list-unaware `FindL2Heads`, and the follower oscillated indefinitely while continuing to build on the block with the invalid message (#21119). The fix calls `forceReset(...)` onto the upstream refs when an origin-selector resetter is wired, which is the sequencer case.

### Attack scenario (post-activation)

1. The attacker includes a transaction with an invalid executing message on chain A, for example one that references a non-existent log. It lands in an unsafe block N. See 00-3d for mempool-filter gaps.
2. The supernode invalidates N, adds its hash to the deny-list and rewinds. op-node builds N' (deposits-only).
3. Honest peers keep gossiping the sequencer's blocks N+1… built on N. Gap-fill or EL sync re-canonicalizes N (bug 2), then consolidation matches N against the L1 batch and promotes it to local-safe (bug 1). A follow-mode sequencer never adopts N' (bug 3).
4. Result: repeated invalidate, rewind and reset cycles, with local-safe walked back a sequencing window each time. Safe-head progress stalls on every chain in the dependency set, and the invalid message persists in the unsafe or local-safe chain.

## Impact Details

- **Primary effect**: loss of liveness, meaning safe-head stall or oscillation across the whole interop cluster, triggered by one transaction.
- **Secondary effect**: the invalid executing message persists in unsafe and local-safe state. It does not reach cross-safe, because the verifier rejects it again every round, so fault proofs and withdrawals are not directly affected.
- **Preconditions**: interop must be active, and an invalid executing message must reach a sequenced block. Sequencer-side filters (op-interop-filter, the txpool) are meant to prevent that. The re-adoption itself happens naturally through honest gossip and EL sync, with no further attacker action.
- **Severity**: this would be Medium on a live interop network (a single cheap transaction halts safe progress for the dependency set until operators step in). Interop was never active on a production network, and the only observed occurrence was on a devnet, so the rating is **Low**.

## Proof of Concept

The regression tests added by the fixes are the PoC:

- Bug 1: `op-node/rollup/attributes/attributes_test.go`, subtests `consolidation passes but block denied` and `deny-list check error stalls without promoting`. The core of the test:

  ```go
  l2.ExpectPayloadByNumber(refA1.Number, payloadA1, nil)
  engDeriver.On("IsDenied", uint64(payloadA1.ExecutionPayload.BlockNumber), payloadA1.ExecutionPayload.BlockHash).Return(true, nil).Once()
  emitter.ExpectOnce(engine.BuildStartEvent{Attributes: attr})   // must reorg, not promote
  ah.OnEvent(ctx, engine.PendingSafeUpdateEvent{PendingSafe: refA0, Unsafe: refA1})
  require.True(t, ah.sentAttributes)
  ```

  On the parent, `IsDenied` does not exist on the interface, and the handler instead calls `TryUpdatePendingSafe` / `TryUpdateLocalSafe` for `refA1`, which promotes the block.

- Bug 2: `op-node/rollup/engine/unsafe_ingestion_deny_test.go`: `TestInsertUnsafePayloadDroppedDuringRecovery`, `TestAddUnsafePayloadNotQueuedDuringRecovery`, `TestQueuedPayloadDrainedDuringRecovery`. A variant that compiles against the parent API (the parent's `mockSuperAuthority` already has `denyBlock`):

  ```go
  func TestPoC_UnsafePayloadAcceptedDespiteDenial(t *testing.T) {
      cfg, refA0, refA1, payloadA1 := buildSimpleCfgAndPayload(t)
      eng := &testutils.MockEngine{}
      sa := newMockSuperAuthority()
      sa.denyBlock(refA1.Number, refA1.Hash)           // A1 is invalidated
      ec := NewEngineController(context.Background(), eng, testlog.Logger(t, 0), metrics.NoopMetrics,
          cfg, &sync.Config{SyncMode: sync.CLSync}, &testutils.MockL1Source{}, &testutils.MockEmitter{}, sa)
      ec.SetUnsafeHead(refA0); ec.SetLocalSafeHead(refA0); ec.SetFinalizedHead(refA0)
      eng.ExpectNewPayload(payloadA1.ExecutionPayload, nil, &eth.PayloadStatusV1{Status: eth.ExecutionValid}, nil)
      eng.ExpectForkchoiceUpdate(&eth.ForkchoiceState{HeadBlockHash: refA1.Hash, SafeBlockHash: refA0.Hash, FinalizedBlockHash: refA0.Hash},
          nil, &eth.ForkchoiceUpdatedResult{PayloadStatus: eth.PayloadStatusV1{Status: eth.ExecutionValid}}, nil)
      require.NoError(t, ec.InsertUnsafePayload(context.Background(), payloadA1, refA1))
      // Parent: the denied block becomes the unsafe head.
      require.NotEqual(t, refA1, ec.UnsafeL2Head(), "denied block re-adopted via unsafe ingestion")
  }
  ```

  On the parent, the engine receives `NewPayload` and a forkchoice update for the denied block and the unsafe head becomes A1, so the final assertion fails. On the fix, the payload is dropped without any engine interaction; use the fix's own test, which does not set engine expectations.

- Bug 3: `TestFollowSource_SequencerDivergenceForcesReset` in `op-node/rollup/engine/engine_controller_test.go` asserts that `ResetOrigins` is called and the engine is sent a forkchoice update onto the upstream block 5. On the parent the soft path is taken instead.

Commands, from a checkout at the fix commit (for the parent, copy the test in):

```
go test ./op-node/rollup/attributes/ -count=1 -run 'TestAttributesHandler'
go test ./op-node/rollup/engine/ -count=1 -run 'TestInsertUnsafePayloadDroppedDuringRecovery|TestAddUnsafePayloadNotQueuedDuringRecovery|TestQueuedPayloadDrainedDuringRecovery|TestFollowSource_SequencerDivergenceForcesReset'
```

Executed: no. The scratch trees used for other PoCs were lost when the session restarted before these runs.

## Recommendation

The three fixes are complementary:

- Consolidation now checks the deny-list and fails closed on read errors.
- Unsafe ingestion is gated until finality passes the highest denied height.
- Follow-mode sequencers force-reset onto the upstream chain.

Remaining suggestions:

- `unsafeDenyGatingActive` fails *open* on a deny-list read error. That is a deliberate liveness trade-off, but it should be alerted on.
- Make `FindL2Heads` deny-list-aware, so that a reset can never re-select a denied block, as happened in the #21119 loop.
- Add an end-to-end acceptance test covering invalidation followed by re-gossip of the denied branch (#21993 in the PR stack).

## References

- Fix commits: 732b8452c8 (#21970), c5c7c760c0 (#21991), 00ca51a426 (#21155, issue #21119)
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/21970, https://github.com/ethereum-optimism/optimism/pull/21991, https://github.com/ethereum-optimism/optimism/pull/21155
- Relevant files: `op-node/rollup/attributes/attributes.go`, `op-node/rollup/engine/engine_controller.go`, `op-node/rollup/iface.go`, `op-supernode/supernode/chain_container/invalidation.go`, `op-supernode/supernode/chain_container/super_authority.go`
