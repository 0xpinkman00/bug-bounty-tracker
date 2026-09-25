# kona-derive — L1Retrieval did not clear the data-availability provider on reset — stale batch data leaks across a pipeline reset

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/protocol/derive/src/stages/l1_retrieval.rs` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | Unintended chain split (network partition) for kona-node; causes network processing nodes to derive from non-canonical or misattributed L1 data |
| **Fix commit(s)** | `dabac64ca6870262728ecedbe58236b588fdfb65` (PR #19687) — 2026-03-25 |
| **Vulnerable since** | Predates kona's import into the monorepo (`48a7a09bfc`, feat(rust): unify workspaces) |

## Brief / Intro

A rollup node reads L2 batch data out of L1 blocks, one L1 block at a time. kona's `L1Retrieval` stage asks a "data-availability provider" (DAP) for that data. The DAP loads all batcher transactions or blobs of an L1 block into a buffer, then hands them out one by one. When the pipeline is reset, for example after an L1 reorg, it should throw that buffer away and restart from the new L1 position. kona reset its L1 position but did not empty the buffer. After a mid-block reset, kona could therefore feed the leftover data of the old L1 block (possibly a block that no longer exists after a reorg) into derivation, as if it belonged to the new position. op-node reopens its data source on reset, so the two clients could see different batch data.

## Vulnerability Details

Parent `rust/kona/crates/protocol/derive/src/stages/l1_retrieval.rs:120-133`:

```rust
async fn signal(&mut self, signal: Signal) -> PipelineResult<()> {
    self.prev.signal(signal).await?;
    match signal {
        Signal::Reset(ResetSignal { l1_origin, .. }) |
        Signal::Activation(ActivationSignal { l1_origin, .. }) => {
            self.next = Some(l1_origin);          // position reset ...
        }                                          // ... but self.provider is NOT cleared
        _ => {}
    }
    Ok(())
}
```

The concrete DAPs ignore the requested block while they are "open". Parent `sources/calldata.rs:33-40` (and the same pattern in `sources/blobs.rs:110-117`):

```rust
async fn load_calldata(&mut self, block_ref: &BlockInfo, batcher_address: Address) -> ... {
    if self.open {
        return Ok(());      // keep serving the buffer loaded for the *previous* block_ref
    }
    ...
```

The buffer is only cleared when `next_data` receives `Eof` from the provider (`l1_retrieval.rs:95-103`). If a reset arrives while the DAP still holds unread entries, the next `next_data()` call returns those stale entries under the new `self.next` origin. Only after they are exhausted does kona load the correct block.

op-node's `L1Retrieval.Reset` (`op-node/rollup/derive/l1_retrieval.go:78-85`) calls `dataSrc.OpenData(ctx, base, …)`, replacing its data iterator with one for the new base block, so no stale data can survive.

Fix:

```diff
             Signal::Reset(ResetSignal { l1_origin, .. }) |
             Signal::Activation(ActivationSignal { l1_origin, .. }) => {
+                self.provider.clear();
                 self.next = Some(l1_origin);
             }
```

### Attack scenario

No attacker action is needed. The trigger is timing:

1. kona is partway through an L1 block `P` that contains several batcher transactions or blobs. The DAP is `open` with unread frames buffered.
2. A reset is delivered before those frames are consumed. Examples: a kona-node engine or derivation reset following an L1 reorg that removes `P`, or a `Reset` error raised mid-block by a later stage (e.g. `AttributesBuilder` / `L1OriginMismatch`).
3. The pipeline rewinds to an earlier L1 origin `O` (`O` is up to `channel_timeout` blocks before the safe head's origin), but the first frames it reads are the leftovers of `P`, attributed to `O`.
4. Consequences:
   - If `P` was reorged out, kona ingests frames that are not on the canonical L1 chain.
   - If `P` is still canonical, its frames are seen twice, the first time with the wrong L1 block. Channel-open blocks and batch inclusion blocks are then computed from `O` instead of `P`, which can time out channels early or reject batches as "future" where op-node accepts them.

## Impact Details

- **kona-node:** can derive a different safe chain from op-node after a badly timed reset. In most cases the divergence is temporary or only affects when blocks become safe, because the stale frames come from the honest batcher. A persistent split needs the misattribution to change which batches are accepted.
- **kona FPP:** L1 is fixed inside a proof, so there are no reorgs. The only resets are the initial one (with an empty DAP) and rare mid-block reset errors. Exposure is therefore very limited.
- **Mitigating factors:**
  - Nobody controls the trigger; it depends on reset timing.
  - The main reorg-reset path (`ReorgDetected` raised in `advance_origin`) runs after the DAP has already returned `Eof` and been cleared.
  - kona-node is pre-production.
- **Severity:** Low.

## Proof of Concept

**Executed: no.** I started a build of `kona-derive` on a snapshot of the parent commit, but it did not finish within this session.

The fix adds regression tests. The core one compiles unchanged on the parent, because the parent's `ResetSignal` already has the `system_config` field. Add to `mod tests` in `rust/kona/crates/protocol/derive/src/stages/l1_retrieval.rs`:

```rust
/// Stale DAP data buffered before a reset must not be served after it.
#[tokio::test]
async fn poc_reset_serves_stale_dap_data() {
    let traversal = TraversalTestHelper::new_populated();
    // Pre-load a stale entry, as if we were mid-way through the previous L1 block.
    let dap = TestDAP { results: vec![Ok(Bytes::from_static(b"stale"))] };
    let mut retrieval = L1Retrieval::new(traversal, dap);
    retrieval.next = Some(BlockInfo::default());
    let reset =
        ResetSignal { system_config: Some(Default::default()), ..Default::default() }.signal();
    retrieval.signal(reset).await.unwrap();
    let res = retrieval.next_data().await;
    // Parent: Ok(b"stale")  -> FAIL.   Fix: Err(Eof) -> PASS.
    assert_eq!(res, Err(PipelineError::Eof.temp()), "stale pre-reset data was served: {res:?}");
}
```

Run from `rust/` on a checkout of `dabac64ca6^` and then `dabac64ca6`:

```sh
cargo test -p kona-derive --lib poc_reset_serves_stale_dap_data
```

The upstream tests `test_l1_retrieval_reset_clears_stale_data` and `test_l1_retrieval_activation_clears_stale_data` in the fix commit have the same shape.

## Recommendation

The fix clears the provider on reset and activation, which matches op-node. It was kept in the later refactor (`31703ba851`, `Stage::reset` still calls `provider.clear()`). Defence in depth:

- Make the DAP sources remember the block they were opened for, and refuse to serve (or auto-clear) when `next()` is called with a different `block_ref`. Then correctness no longer depends on every caller remembering to clear.
- Add an action test that injects a reset between two frames of a multi-transaction L1 block and compares the result with op-node.

## References

- Fix commit: `dabac64ca6870262728ecedbe58236b588fdfb65`
- Pull request: https://github.com/ethereum-optimism/optimism/pull/19687
- Reference implementation: `op-node/rollup/derive/l1_retrieval.go` (`Reset`)
- Relevant files: `rust/kona/crates/protocol/derive/src/stages/l1_retrieval.rs`, `rust/kona/crates/protocol/derive/src/sources/{calldata,blobs,ethereum}.rs`
