# kona-derive: several derivation divergences from op-node (grouped; pre-production and mostly pre-Holocene-activation)

| Field | Value |
|---|---|
| **Target** | `kona-derive` (derivation pipeline) and `kona-client` driver, in paths from the kona repo at fix time (`crates/derive/src/...`, `bin/client/src/l1/driver.rs`). The current location is `rust/kona/crates/protocol/derive/`. |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low overall. Individual items are Low or Informational; see the table below. |
| **Impact category** | Class: "Unintended chain split (network partition)", as a derivation or fault-proof divergence between kona and op-node/op-program. Discounted because kona did not secure any production dispute game, and most items were only reachable under Holocene before Holocene activated anywhere. |
| **Fix commit(s)** | `33b136a0b7a82742db044d7027082f412e00b30a` (op-rs/kona#776, 2024-11-04); `3c7ec85e950e16023076a2b1ffd35ccf14c7c7a2` (op-rs/kona#876, 2025-01-02); `7b1bc011b894a398c12e33632c39c7663a04ad5f` (op-rs/kona#700, 2024-10-17); `76ee650c72c6812d5ad820925acb2f93c34b5010` (op-rs/kona#692, 2024-10-15); `bc5c2b12edaa3ad127177e8c8206bf243bafb0c3` (op-rs/kona#683, 2024-10-10); `0b6297dd1f7a886c4c51b436c9d756968ad67021` (op-rs/kona#688, 2024-10-14); `08fa0e1fd760fde752fa95c5f2e28ee7a530434c` (op-rs/kona#733, 2024-10-25) |
| **Vulnerable since** | Varies per sub-issue (see each section) |

| Sub-issue | Fix | Reachable when | Who can trigger | Severity |
|---|---|---|---|---|
| A. Reset/activation system config discarded | #776 | Any pipeline reset. Masked in `kona-client` after #733; before #733 it caused a panic. | Any reorg or Holocene activation | Informational |
| B. Past span batch advances the L1 origin | #876 | Holocene. Live on Sepolia from 2024-11-26 to 2025-01-02 and fixed before the mainnet activation. | Batcher (honest duplicate or resubmitted span batches are enough) | Low |
| C. Holocene `ChannelAssembler` missing the channel-size limit | #700 | Holocene only, fixed before any activation | Batcher | Informational |
| D. Span-batch element limit and channel RLP limit mismatch | #692 | All forks, and Fjord specifically for the element count | Batcher | Low |
| E. `BatchQueue` clears `l1_blocks` on channel flush | #683 | Holocene only, fixed before any activation | Batcher or sequencer, by posting a block that fails to execute | Informational |
| F. Holocene prefix and timestamp checks | #688, #733 | Holocene only, fixed before any activation | Batcher | Informational |

## Brief / Intro

The OP Stack derives the L2 chain deterministically from data that the batcher posts to L1. op-node's derivation pipeline is the reference implementation, and op-program (the Go fault-proof program) reuses it. kona is a Rust re-implementation meant to serve as a second fault-proof program. For kona to be safe, every input sequence must produce exactly the same L2 blocks as op-node. Each item below is a case where kona's pipeline behaved differently on some L1 or batcher input: it derived different blocks, stalled, or crashed. In a live dispute game, any such difference lets the kona VM rule a valid output root invalid, or the reverse. In autumn 2024, however, kona did not back any production game, and most of these paths were only active under the Holocene hardfork before Holocene had activated.

## Vulnerability Details

### A. Reset/activation signal: the refreshed `SystemConfig` was discarded (#776)

`DerivationPipeline::signal` looked up the L2 system config at the safe head and then threw it away. `Signal::with_system_config` is a by-value `const fn` that returns a new `Signal` (`crates/derive/src/traits/pipeline.rs:39`):

```rust
// crates/derive/src/pipeline/core.rs:95-106 (parent of 33b136a0b7)
s @ Signal::Reset(ResetSignal { l2_safe_head, .. }) |
s @ Signal::Activation(ActivationSignal { l2_safe_head, .. }) => {
    let system_config = self.l2_chain_provider
        .system_config_by_number(l2_safe_head.block_info.number, Arc::clone(&self.rollup_config))
        .await ...?;
    s.with_system_config(system_config);   // result dropped
    match self.attributes.signal(s).await { ... }
```

So the stages received whatever `system_config` the caller had put in the signal. `L1Traversal` does `self.system_config = system_config.expect("System config must be provided.")` (`crates/derive/src/stages/l1_traversal.rs:138`). This became reachable when the pattern was introduced in op-rs/kona#696 (2024-10-15). From then until #733 (2024-10-25), `kona-client`'s driver passed `system_config: None` on every reset and on Holocene activation, so the first pipeline reset made the client panic. #733 changed the driver to compute the config itself; after that the discard was masked in `kona-client`, but it still affected any other pipeline user that relied on the pipeline to fill in the config.

The fix: `mut s @ ...` and `s = s.with_system_config(system_config);`.

### B. `BatchStream`: a Holocene "past" span batch returned `Eof` (#876)

```rust
// crates/derive/src/stages/batch/batch_stream.rs:164-171 (parent of 3c7ec85e95)
BatchValidity::Past => {
    if !self.is_active()? { ... return Err(PipelineError::InvalidBatchValidity.crit()); }
    return Err(PipelineError::Eof.temp());
}
```

In kona's pipeline, `Eof` means "this L1 block is exhausted". `DerivationPipeline::step` responds by calling `advance_origin()` (`crates/derive/src/pipeline/core.rs:172-177`). op-node's `BatchStage` instead returns `NotEnoughData` for past batches, and simply reads the next batch from the same L1 block (`op-node/rollup/derive/batch_stage.go:143-146`: "NotEnoughData to read in next batch until we're through all past batches").

So each past span batch moved kona's L1 origin forward by one block while frames from the current block were still being read. Everything after that is evaluated against the wrong origin: the inclusion block used for sequence-window checks, the channel-timeout checks, and when `BatchValidator` starts force-including empty batches. With several past batches in a row, the origin can move ahead by several blocks. Past span batches are not exotic: a batcher that resubmits a span batch after a fee bump, a reorg, or a restart produces them.

The fix returns `NotEnoughData.temp()`, and `test_past_span_batch` was added. Note that the neighbouring `BatchValidity::Drop` arm had the same `Eof` problem. #876 did not change it; it stayed until op-rs/kona#2840 (commit `d695b93c21`, 2025-09-10).

### C. Holocene `ChannelAssembler` accepted oversized channels (#700)

In Holocene, channel assembly moves to a single-channel `ChannelAssembler`. op-node drops a channel once its size exceeds `MaxRLPBytesPerChannel` (10 MB before Fjord, 100 MB from Fjord). kona's new assembler (`crates/derive/src/stages/channel/channel_assembler.rs:~110-130`) added frames with no size check, so it would forward channels that op-node discards. The fix adds:

```rust
let max_rlp_bytes_per_channel = if self.cfg.is_fjord_active(origin.timestamp) {
    MAX_RLP_BYTES_PER_CHANNEL_FJORD } else { MAX_RLP_BYTES_PER_CHANNEL_BEDROCK };
if channel.size() > max_rlp_bytes_per_channel as usize {
    self.channel = None;
    return Err(PipelineError::NotEnoughData.temp());
}
```

### D. Span-batch element limit and channel-reader RLP limit did not match op-node (#692)

op-node limits span-batch element counts (`block_count`, each `block_tx_count`, `total_block_tx_count`) to `MaxSpanBatchElementCount = 10_000_000` (`op-node/rollup/derive/params.go:22`). kona limited them to a byte budget that depended on the fork:

```rust
// crates/derive/src/batch/span_batch/payload.rs:55,73-74 (parent of 76ee650c72)
pub const fn max_span_batch_size(&self, is_fjord_active: bool) -> usize {
    if is_fjord_active { FJORD_MAX_SPAN_BATCH_BYTES as usize /* 100_000_000 */ }
    else { MAX_SPAN_BATCH_BYTES as usize /* 10_000_000 */ } }
...
if block_count as usize > max_span_batch_size { return Err(TooBigSpanBatchSize) }
```

After Fjord, a span batch with between 10,000,001 and 100,000,000 elements was rejected by op-node at decode time but accepted by kona's decoder. kona then materialised tens of millions of `SpanBatchElement`s and transactions, far beyond the 100 MB heap that `kona-client` reserves. That would crash the proof program, whereas op-node simply drops the batch.

The channel reader was also inconsistent. zlib channels were decompressed with no size limit at all (`channel_reader.rs:212`: `decompress_to_vec_zlib(&data)`), and brotli channels were always capped at the Fjord limit (`stages/utils.rs:50`). op-node caps the decompressed RLP stream at `MaxRLPBytesPerChannel` for the origin's fork (`op-node/rollup/derive/channel.go:210`). The fix replaces the byte limits with `MAX_SPAN_BATCH_ELEMENTS = 10_000_000` and threads the per-fork `max_rlp_bytes_per_channel` into `BatchReader`.

### E. `BatchQueue::flush_channel` cleared `l1_blocks` (#683)

```rust
// crates/derive/src/stages/batch_queue.rs:482-486 (parent of bc5c2b12ed)
async fn flush_channel(&mut self) -> PipelineResult<()> {
    self.batches.clear();
    self.l1_blocks.clear();      // removed by the fix
    self.next_spans.clear();
    self.prev.flush_channel().await
}
```

Under Holocene, `kona-client` sends `Signal::FlushChannel` whenever a derived block fails to execute and is replaced by a deposit-only block (`bin/client/src/l1/driver.rs:~194-202`). op-node's flush keeps the batch queue's L1 epoch window. kona emptied it, so the next `derive_next_batch` hit `MissingOrigin.crit()` (`batch_queue.rs:121-123`) and the next `add_batch` hit `panic!("Cannot add batch without an origin")` (`batch_queue.rs:249-251`), at least until the origin advanced. Either way, the proof program aborts on a valid chain.

### F. Holocene batch-check details (#688, #733)

- `SingleBatch::check_batch` chose Holocene rules based on the batch's own timestamp instead of the L1 inclusion block's timestamp, and still returned `Future` rather than `Drop` for future batches under Holocene (`crates/derive/src/batch/single_batch.rs:~55-70`). The span-batch prefix checks were refactored to match the spec, and they now also take the inclusion block and return the parent block.
- `BatchValidator` computed `next_timestamp = epoch.timestamp + block_time` instead of `parent.block_info.timestamp + block_time` (`crates/derive/src/stages/batch/batch_validator.rs:140`), which is wrong for every block except the first in an epoch. It also did not bind the batch's `parent_hash` to the actual parent.
- The client driver passed `system_config: None` on resets (see A).

All of these landed before Holocene activated on any public network.

### Attack scenario (representative: sub-issue B)

1. After Holocene activation, the batcher (honest, but resubmitting after a fee bump or a reorg) posts span batch `S` twice, or posts a span batch that fully overlaps the safe chain. Both copies land in L1 block `N`, followed by further new frames in `N`.
2. op-node sees the second copy as `Past`, returns `NotEnoughData`, and keeps reading block `N`'s remaining data.
3. kona sees `Past`, returns `Eof`, and advances its L1 origin to `N+1`. It then processes the rest of block `N` as though it had been included in `N+1`, and repeats this for each further past batch. Sequence-window, channel-timeout and forced-empty-batch decisions are now made against a later L1 origin than op-node uses.
4. If an input sequence exists where that shifts a validity decision, kona derives a different L2 chain or output root than op-program. In a kona-backed game, the loser would be whichever party kona sided against.

## Impact Details

- Every item is a consensus or derivation difference between kona and the reference implementation, or a crash of the kona program on valid input. In a production kona-backed game these belong to the fault-proof unsoundness or liveness class (High).
- **Preconditions:** all items except A require specific content from the batcher. Only the configured batcher address can post data that derivation reads. For B, honest batcher behaviour (duplicate or resubmitted span batches) is enough. C, D and F need unusual batch content that an honest batcher would not produce, so they effectively need a buggy or compromised batcher.
- **Exposure:** C, E and F were Holocene-only and fixed before Holocene activated on Sepolia (2024-11-26). B was exposed on Sepolia for about five weeks and fixed a week before the mainnet activation (2025-01-09). A only caused a panic in `kona-client` between 2024-10-15 and 2024-10-25. D was fork-independent.
- **Most important:** during this period kona did not secure any production dispute game (asterisc-kona was testnet-only), and op-node and op-program were unaffected. On that basis the group is rated Low, with A, C, E and F Informational.

## Proof of Concept

These tests are adapted from the regression tests that the fixes added. Each one fails on the parent of its fix and passes on the fix. Because these commits come from the imported kona history, the paths are relative to the repository root at those commits.

**B. Past span batch (from #876, `crates/derive/src/stages/batch/batch_stream.rs`, `mod test`):**

```rust
#[tokio::test]
async fn test_past_span_batch() {
    let mock_batch = SpanBatch {
        batches: vec![
            SpanBatchElement { epoch_num: 1, timestamp: 2, ..Default::default() },
            SpanBatchElement { epoch_num: 1, timestamp: 4, ..Default::default() },
        ],
        ..Default::default()
    };
    let mock_origins = [BlockInfo { number: 1, timestamp: 12, ..Default::default() }];
    let config = Arc::new(RollupConfig { holocene_time: Some(0), ..RollupConfig::default() });
    let prev = TestBatchStreamProvider::new(vec![Ok(Batch::Span(mock_batch))]);
    let mut stream = BatchStream::new(prev, config, TestL2ChainProvider::default());
    assert!(stream.is_active().unwrap());
    let parent = L2BlockInfo {
        block_info: BlockInfo { number: 10, timestamp: 100, ..Default::default() },
        l1_origin: alloy_eips::NumHash::default(),
        seq_num: 0,
    };
    // Parent: Err(Eof.temp()) -> pipeline advances L1 origin. Fix / op-node: NotEnoughData.
    let err = stream.next_batch(parent, &mock_origins).await.unwrap_err();
    assert_eq!(err, PipelineError::NotEnoughData.temp());
}
```

**E. `l1_blocks` retained across flush (from #683, `crates/derive/src/stages/batch_queue.rs`, test `test_batch_queue_flush`):** after `bq.flush_channel().await`, assert `!bq.l1_blocks.is_empty()`. The parent empties it.

**C. Channel-size limit (from #700, `channel_assembler.rs`):** `test_assembler_size_limit_exceeded_bedrock` and `test_assembler_size_limit_exceeded_fjord` feed a second frame of `MAX_RLP_BYTES_PER_CHANNEL_*` bytes and assert that `assembler.channel.is_none()`. On the parent the oversized channel is kept.

**D. Element limit (parent API; `crates/derive/src/batch/span_batch/payload.rs`, `mod test`):**

```rust
#[test]
fn poc_span_batch_element_limit_post_fjord() {
    // op-node: MaxSpanBatchElementCount = 10_000_000 -> rejects.
    let block_count = 10_000_001u64;
    let mut buf = [0u8; 10];
    let mut encoded = unsigned_varint::encode::u64(block_count, &mut buf);
    let mut payload = SpanBatchPayload::default();
    // Parent: Ok (limit is 100_000_000 once Fjord is active) -> divergence.
    assert_eq!(
        payload.decode_block_count(&mut encoded, /* is_fjord_active */ true).unwrap_err(),
        SpanBatchError::TooBigSpanBatchSize
    );
}
// On the fix the signature drops the bool: `payload.decode_block_count(&mut encoded)`;
// the fix's own `test_decode_block_count_errors` uses MAX_SPAN_BATCH_ELEMENTS + 1.
```

**Run (read-only; nothing in the working tree changes):**

```bash
cd /home/trevor/workspace/audits/optimism
run() { c=$1; t=$2; d=/tmp/kona-$(git rev-parse --short $c); mkdir -p $d
        git archive $c | tar -x -C $d; (cd $d && cargo test -p kona-derive "$t"); }
# B: fails on parent (after pasting the test), passes on fix (test is already present)
run 3c7ec85e95^ test_past_span_batch; run 3c7ec85e95 test_past_span_batch
# C: tests present on fix; paste them into the parent to see them fail
run 7b1bc011b8 test_assembler_size_limit_exceeded
# E
run bc5c2b12ed test_batch_queue_flush
# D: paste poc_span_batch_element_limit_post_fjord into the parent
run 76ee650c72^ poc_span_batch_element_limit_post_fjord
```

Executed: no. The tests were taken from, or adapted from, the upstream regression tests; building the historical kona workspaces was skipped.

## Recommendation

The fixes address each point. Some residual issues were not addressed by these commits:

- **B:** the `BatchValidity::Drop` arm of `BatchStream` kept returning `Eof` (the same premature origin advance) until op-rs/kona#2840 (`d695b93c21`, 2025-09-10). Any "stop reading this L1 block" error in a batch stage should be audited against op-node's `NotEnoughData` semantics.
- **D:** after #692 the zlib path still decompressed the whole channel before checking its length, so memory use was still unbounded. It also dropped the whole channel instead of truncating it at `MaxRLPBytesPerChannel` as op-node does, so batches that fit before the limit were still handled differently. Bounded, truncating decompression landed only in `c390d771c6` (#455, 2026-02-19).
- **A:** make `with_system_config` `#[must_use]` (or take `&mut self`) so the compiler catches this kind of discarded result, and do not `expect()` on signal fields in consensus code.
- **General:** run kona against op-node on differential fuzzing and action tests (the op-e2e Holocene action-test suite, which #733 wired up), including batcher-controlled adversarial inputs, before relying on kona in a production game.

## References

- Fix commits: `33b136a0b7`, `3c7ec85e95`, `7b1bc011b8`, `76ee650c72`, `bc5c2b12ed`, `0b6297dd1f`, `08fa0e1fd7`
- Pull requests: https://github.com/op-rs/kona/pull/776, /876, /700, /692, /683, /688, /733
- Follow-up fixes: op-rs/kona#2840 (`d695b93c21`), bounded zlib decompression (`c390d771c6`)
- op-node reference: `op-node/rollup/derive/batch_stage.go`, `batch_queue.go`, `channel.go`, `params.go`
- Specs: https://specs.optimism.io/protocol/holocene/derivation.html, https://specs.optimism.io/protocol/delta/span-batches.html
