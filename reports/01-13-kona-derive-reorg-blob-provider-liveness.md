# kona-derive / kona-node — wrong error classification on L1 reorgs and blob-provider anomalies — node halt, stall or crash

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/protocol/derive` (blob source, batch mux), `rust/kona/crates/providers/*`, `rust/kona/crates/node/service` (sequencer actor) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (overall). Individual sub-issues are Low or Informational, see the table below |
| **Impact category** | Shutdown of greater than or equal to 10% or equal to but less than 30% of network processing nodes without brute force actions, but does not shut down the network. In practice this applies only to kona-node operators, a small share of nodes |
| **Fix commit(s)** | see the table below (6 commits, 2026-03-02 to 2026-04-07) |
| **Vulnerable since** | All six defects predate kona's import into the monorepo (`48a7a09bfc`, 2026-02-10, "unify workspaces"). The origin in the upstream kona repo was not determined |

| ID | Fix commit | PR | Defect | Consequence | Rating |
|---|---|---|---|---|---|
| 13a | `9f3b9093547e15b8399b227d4a231d31e986e8ca` (2026-03-11) | #19362 | Blob **under-fill** was mapped to `Critical` | kona-node derivation halts permanently until restart | Low |
| 13b | `ee4d492a87b015874bddf772b719d877fb798ab4` (2026-03-02) | #19344 | Hash-based `BlockNotFound` (reorged-out L1 block) was mapped to `Temporary` | Derivation retries forever. The safe head stalls | Low |
| 13c | `7c54d1e86494a20b2d15f038e5b0b4eef6289742` (2026-03-05) | #19357 | `BlobSource` re-wrapped chain-provider errors as `Temporary`, which hid 13b's `Reset` | Same as 13b on the blob path | Low |
| 13d | `7f9662a6613e83035d85b9fffa6eb2b55e9e0c80` (2026-03-12) | #19364 | Blob **over-fill** was silently accepted | Parity gap with op-node only. The production provider filters by hash | Informational |
| 13e | `7da40558c66893624a7a79bca1964836ebdffba4` (2026-03-11) | #19360 | Holocene `BatchQueue` to `BatchValidator` hand-off dropped `origin` | Duplicate L1 block in the epoch window, or a `MissingOrigin` critical halt, at the Holocene activation block | Informational (one-shot, historical) |
| 13f | `8e333b19ec185321c7c7ae85e4b5f7a087b9a220` (2026-04-07) | #19945 | Sequencer origin selector ran `unreachable!()` when the L1 origin disappeared | The kona-node sequencer panics on an L1 reorg | Low |

## Brief / Intro

kona-node is the Rust consensus-layer client for OP Stack chains. Its derivation pipeline reads L1 blocks and blobs and turns them into L2 blocks. Each pipeline error is classed as `Temporary` (retry), `Reset` (walk back and re-derive) or `Critical` (stop). op-node, the reference implementation, resets on L1 reorgs and on blob inconsistencies. kona classed several of these cases wrongly, or panicked. So an ordinary L1 reorg, or a flaky beacon node, could halt a kona-node, leave it spinning with a frozen safe head, or crash its sequencer. Nobody needs to attack for this to happen: normal L1 behaviour is enough. The impact is limited to kona-node operators.

## Vulnerability Details

### 13a — Blob under-fill was Critical (`9f3b9093`)

Parent `rust/kona/crates/protocol/derive/src/sources/blob_data.rs:155`:

```rust
if index >= blobs.len() {
    return Err(BlobDecodingError::InvalidLength);   // -> BlobProviderError::BlobDecoding -> .crit()
}
```

`From<BlobProviderError> for PipelineErrorKind` maps `BlobDecoding(_)` to `PipelineError::Provider(..).crit()`. A `Critical` error ends the derivation actor. op-node treats the same condition as a reset (`fillBlobPointers` wraps it in `NewResetError`). The fix adds a dedicated variant that resets:

```rust
-            return Err(BlobDecodingError::InvalidLength);
+            return Err(BlobProviderError::NotEnoughBlobs { expected: index, actual: blobs.len() });
...
+            BlobProviderError::NotEnoughBlobs { .. } => ResetError::BlobsUnderFill(val).reset(),
```

### 13b and 13c — Reorged-out L1 block was treated as Temporary (`ee4d492a`, `7c54d1e8`)

Parent `rust/kona/crates/providers/providers-alloy/src/chain_provider.rs:130`:

```rust
AlloyChainProviderError::BlockNotFound(id) => {
    Self::Temporary(PipelineError::Provider(format!("L1 Block not found: {id}")))
}
```

Suppose a block that the pipeline looked up by hash has been reorged out. Retrying that lookup can never succeed, but kona retried it forever. The fix resets for `BlockId::Hash` and keeps `Temporary` for `BlockId::Number`, since a missing block by number just means it has not been produced yet. The same change applies to `BufferedProviderError::BlockNotFound`.

The blob path still dropped that classification. Parent `sources/blobs.rs:119`:

```rust
let info = self.chain_provider.block_info_and_transactions_by_hash(block_ref.hash).await.map_err(
    |e| -> PipelineErrorKind { BlobProviderError::Backend(e.to_string()).into() },  // always Temporary
)?;
```

Fix `7c54d1e8` replaces this with `.map_err(Into::into)`, which keeps the provider's `Reset`.

### 13d — Blob over-fill was accepted (`7f9662a6`)

After the fill loop, kona never checked that every returned blob had been used. op-node returns a reset error (`"got too many blobs"`). The fix adds:

```rust
+        if filled_blobs < blobs.len() {
+            return Err(ResetError::BlobsOverFill { filled: filled_blobs, returned: blobs.len() }.reset());
+        }
```

In kona-node, `OnlineBlobProvider::get_and_validate_blobs` fetches blobs through `fetch_filtered_blobs(slot, blob_hashes)`, which filters and validates them against the requested versioned hashes. Over-fill is therefore not reachable with the shipped provider. This sub-item is a parity and defence-in-depth fix only.

### 13e — Holocene mux hand-off lost `origin` (`7da40558`)

Parent `stages/batch/batch_provider.rs:72-78`:

```rust
let batch_queue = self.batch_queue.take().expect("Must have batch queue");
let mut bv = BatchValidator::new(self.cfg.clone(), batch_queue.prev);
bv.l1_blocks = batch_queue.l1_blocks;
// origin NOT copied -> bv.origin == None
```

On its first call, `BatchValidator::update_origins` (`batch_validator.rs:78`) sees `None != Some(prev.origin)` and runs the "new origin" branch. That branch either pushes the current L1 block onto `l1_blocks` a second time, corrupting the two-slot epoch window, or, when the origin is behind, clears `l1_blocks`, so that `next_batch` returns `MissingOrigin.crit()`. Go's `BatchMux.TransformHolocene` copies both fields. The fix adds `bv.origin = batch_queue.origin;`. This runs only once per chain, when derivation crosses the Holocene activation block (a small window after an L1 reorg around activation can trigger it again). All production chains activated Holocene in early 2025, so today it matters only to a kona-node that syncs derivation across that historical boundary.

### 13f — Sequencer panic on a missing L1 origin (`8e333b19`)

Parent `crates/node/service/src/actors/sequencer/origin_selector.rs`:

```rust
self.current = self.l1.get_block_by_hash(unsafe_head.l1_origin.hash).await?;   // Ok(None) on reorg
...
let Some(current) = self.current else {
    unreachable!("Current L1 origin should always be set by `select_origins`");
};
```

When an L1 reorg removes the unsafe head's L1 origin, `get_block_by_hash` returns `Ok(None)` and the sequencer task panics. The commit links a CI run in which this happened. The fix returns `L1OriginSelectorError::OriginNotFound`, and the actor then calls `reset_engine_forkchoice()`.

### Attack scenario

1. No attacker is needed. An L1 reorg happens (for example, a 1–2 block reorg of the block that holds a batcher blob transaction or the sequencer's current L1 origin), or the beacon/blob endpoint returns incomplete data.
2. Depending on the path, kona-node hits a `Critical` error (13a, 13e), retries a lookup that can never succeed (13b, 13c), or panics in the sequencer actor (13f).
3. The kona-node's safe head stops advancing until an operator restarts it. A kona-node sequencer stops producing blocks.

## Impact Details

- **Affected:** kona-node operators only. op-node is not affected. The kona fault-proof program is not affected by 13a–13d: its oracle-backed blob and chain providers either return exactly the requested data or block. For 13e, the kona FPP would only be exposed in a dispute over the Holocene activation range, which is long past.
- **No consensus divergence** in 13a–13d and 13f. These are liveness problems: the node stops or spins instead of resetting. 13e could corrupt the epoch window and so diverge at the Holocene boundary, but only once per chain, historically.
- **Mitigating factors:** kona-node has a small operator share. Recovery is a restart (or waiting for the reorg to be observed through another path). No funds are at risk. 13f needs the kona-node to be the sequencer, which is not the case on production OP Stack chains.
- **Severity:** Low. Natural events crash or stall a minority client. 13d and 13e are Informational.

## Proof of Concept

Each fix added a regression test that fails, or panics, on its parent commit. Read-only way to reproduce: add the named test to the parent version of the file (for example with `git show <hash>^:<path>` into a scratch copy of the crate), then run:

```bash
cd rust
# 13a: under-fill must be Reset (fails on 9f3b9093^: returns Critical via BlobDecodingError::InvalidLength)
cargo test -p kona-derive --lib errors::sources::tests
cargo test -p kona-derive --lib sources::blob_data::tests::test_fill_oob_index
# 13b: hash-based BlockNotFound must be Reset
cargo test -p kona-providers-alloy --lib chain_provider::tests::test_from_alloy_chain_provider_error
cargo test -p kona-providers-local  --lib buffered::tests::test_block_not_found_is_reset_via_provider
# 13c: BlobSource must preserve Reset
cargo test -p kona-derive --lib sources::blobs::tests::test_load_blobs_block_not_found_triggers_reset
# 13d: over-fill must Reset
cargo test -p kona-derive --lib sources::blobs::tests::test_load_blobs_overfill_triggers_reset
# 13e: origin copied across the Holocene transition
cargo test -p kona-derive --lib stages::batch::batch_provider::test::test_spec_batch_provider_holocene_transition_origin_transferred
# 13f: recovery-mode origin lookup miss (panics with `unreachable!` on 8e333b19^)
cargo test -p kona-node-service --lib test_next_l1_origin_recovery_mode_not_found
```

The core of the 13c regression test (from `7c54d1e8`), which by itself shows the downgrade:

```rust
#[tokio::test]
async fn test_load_blobs_block_not_found_triggers_reset() {
    let chain_provider = BlockNotFoundChainProvider;           // every call -> ResetError::BlockNotFound
    let blob_fetcher = crate::test_utils::TestBlobProvider::default();
    let mut source = BlobSource::new(chain_provider, blob_fetcher, Address::ZERO);
    let err = source.load_blobs(&BlockInfo::default(), Address::ZERO).await.unwrap_err();
    assert!(matches!(err, PipelineErrorKind::Reset(_)), "got {err:?}"); // parent: Temporary
}
```

Executed: no. I did not run the Rust tests because a cold build of the kona workspace is expensive. I checked the claims by reading the parent and fix diffs.

## Recommendation

The fixes bring kona's error classification in line with op-node: reset on a missing hash-addressed block, on blob under-fill or over-fill, and on a missing L1 origin. They also copy `origin` across the Holocene mux transition. Further suggestions:
- Add a differential test that feeds the same provider fault into op-node and kona and compares the error class, so later refactors cannot regress it again. 13c was itself a regression that hid the fix in 13b.
- Remove the remaining `unreachable!` and `expect` calls on paths reachable from external data in node actors.

## References

- Fix commits: 9f3b9093547e15b8399b227d4a231d31e986e8ca, ee4d492a87b015874bddf772b719d877fb798ab4, 7c54d1e86494a20b2d15f038e5b0b4eef6289742, 7f9662a6613e83035d85b9fffa6eb2b55e9e0c80, 7da40558c66893624a7a79bca1964836ebdffba4, 8e333b19ec185321c7c7ae85e4b5f7a087b9a220
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/19362, /19344, /19357, /19364, /19360, /19945
- Issues: #19359, #19363, #19354, #19356
- Relevant files: `rust/kona/crates/protocol/derive/src/{errors/pipeline.rs,errors/sources.rs,sources/blob_data.rs,sources/blobs.rs,stages/batch/batch_provider.rs}`, `rust/kona/crates/providers/providers-alloy/src/chain_provider.rs`, `rust/kona/crates/providers/providers-local/src/buffered.rs`, `rust/kona/crates/node/service/src/actors/sequencer/{actor.rs,origin_selector.rs}`
- Go reference: `op-node/rollup/derive/blob_data_source.go` (`fillBlobPointers`), `op-node/rollup/derive/batch_mux.go` (`TransformHolocene`)
