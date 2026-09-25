# kona derivation: four ways batcher-posted data was interpreted differently from op-node (frame ordering, brotli gate, oversized span-batch txs, singular-batch extraction errors)

| Field | Value |
|---|---|
| **Target** | kona-derive / kona-protocol: `stages/channel/channel_assembler.rs`, `protocol/src/batch/reader.rs`, `protocol/src/utils.rs` (`read_tx_data`), `stages/batch/batch_stream.rs`. Used by kona-client (FPP) and kona-node |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (Medium if the batcher is treated as untrusted) |
| **Impact category** | "Unintended chain split (network partition)" between kona-node and op-node, and matching kona FPP divergence (fault-proof unsoundness for `CANNON_KONA`). All four need data posted by the authorized batcher |
| **Fix commit(s)** | (A) 5bf7b7a8fb1a4901bbf9fccbd6a3738067bad8f1, PR #20011, optimism-private#482, 2026-04-14 · (B) e2253914e7b7eaa7559916809e08c947fe493a21, PR #20004, optimism-private#485, 2026-04-13 · (C) d2fdc04e938a4599ce1b83c60ffe1ab0eb6d738a, PR #19904, Cantina #28, 2026-04-02 · (D) 8924fbe38d1b8a92569b4043b89a12fc87a00a2b, op-rs/kona#3059, port of op-node #18283, 2025-12-03 |
| **Vulnerable since** | (A)–(C): since the respective kona code was written (Holocene ChannelAssembler; Fjord brotli support; span-batch tx decoding). First fixed in `kona-client/v1.5.1` (2026-05-12). (D): op-node itself treated the case as Critical until 848a9c2621 (2025-11-21), so kona diverged only between 2025-11-21 and 2025-12-03. Fixed in `kona-client/v1.2.12` |

## Brief / Intro

The batcher posts L2 transaction batches to L1 as "frames" that make up "channels". Each channel is a compressed stream of batches, and "span batches" pack many L2 blocks into one batch. Every node must turn exactly the same L1 data into exactly the same L2 chain. These four fixes close cases where kona (the Rust consensus client and fault-proof program) and op-node (the reference Go client) read the same batcher data differently. They cover out-of-order frames, the rule for when brotli compression is allowed, span-batch transactions larger than the protocol limit, and span batches that fail late validation. In every case only the authorized batcher can post the triggering data. The result would be kona-node forking from op-node, and `CANNON_KONA` fault proofs disagreeing with the canonical chain.

## Vulnerability Details

### (A) Holocene strict frame ordering not enforced across L1 transactions

Holocene requires the frames of a channel to arrive strictly in order. op-node's `ChannelAssembler` uses `requireInOrder`. kona's `ChannelAssembler` reused the pre-Holocene `Channel`, which stores frames in a `HashMap<u16, Frame>` and accepts any order (parent, `protocol/src/channel.rs:95-140`). `FrameQueue::prune` only compares neighbouring frames *inside one queue load*, so a gap across L1 transactions got through:

```rust
// parent, stages/channel/channel_assembler.rs:93
self.channel = Some(Channel::new(next_frame.id, origin));   // out-of-order-tolerant channel
...
if channel.add_frame(next_frame, origin).is_err() { ... }
```

With T1 = `[F0,F1,F2]`, T2 = `[F4,F5,F6(last)]` and T3 = `[F3]`, op-node drops F4–F6 (F3 was expected), while kona assembles the whole channel once F3 arrives. The two derive different batches. Fix: a new `OrderedChannel` that rejects `frame.number != inputs.len()` (`ChannelError::FrameOutOfOrder`).

### (B) Fjord brotli gate checked the batch timestamp, not the L1 origin

```rust
// parent, protocol/src/batch/reader.rs next_batch()
if self.brotli_used && !cfg.is_fjord_active(batch.timestamp()) {   // batcher-controlled timestamp
    return None;
}
```

op-node checks `IsFjord(origin.Time)`. A brotli channel under a post-Fjord L1 origin whose first batch has a pre-Fjord timestamp is accepted by op-node: the stale batch is dropped by normal validation and later batches are used. kona's reader returns `None` there, and the cursor never advances past it, so the rest of the channel is lost. Fix: `BatchReader::new(.., origin_timestamp)` and `cfg.is_fjord_active(self.origin_timestamp)`.

### (C) Span-batch transactions larger than `MAX_SPAN_BATCH_ELEMENTS` accepted

```rust
// parent, protocol/src/utils.rs:116-120
let payload_length_with_header = rlp_header.payload_length + rlp_header.length();
let payload = r[0..payload_length_with_header].to_vec();          // no size cap, no bounds check
```

op-node decodes each tx with `rlp.NewStream(r, MaxSpanBatchElementCount)` (10,000,000 bytes) and rejects the span batch if a tx exceeds it. kona accepted such a tx, which fits within the Fjord 100 MB channel limit. The missing bounds check also made a truncated payload panic (covered in 01-06). Fix: return `TooBigSpanBatchSize` above the limit, and `InvalidTransactionData` if `r.len() < payload_length_with_header`.

### (D) Singular-batch extraction failure was a Critical (halting) error

```rust
// parent, derive/src/stages/batch/batch_stream.rs try_hydrate_buffer()
self.buffer.extend(
    span.get_singular_batches(l1_origins, parent).map_err(|e| {
        PipelineError::BadEncoding(PipelineEncodingError::from(e)).crit()   // halts derivation
    })?,
);
```

A span batch can pass the prefix checks and still fail in `get_singular_batches`, for example when a future block's L1 origin is behind the safe head's. op-node #18283 (2025-11-21) changed this to "drop the span batch and flush the channel" and clarified the spec (specs#863). kona kept the Critical error until this fix. That halts kona-node permanently. In the FPP, the program exits 1 (INVALID) even for an honest claim. The fix mirrors op-node: log, `flush()`, and return `NotEnoughData`. The commit itself notes that only the post-Holocene `BatchValidator` path was fixed there, with the pre-Holocene `BatchQueue` path left as a TODO.

### Attack scenario (generic)

1. A malicious or compromised batcher posts one of: out-of-order frames split across transactions (A); a brotli channel starting with a pre-Fjord-timestamped batch (B); a span batch containing a transaction over 10 MB (C); or a span batch that passes prefix checks but has a too-old L1 origin for a block past the safe head (D).
2. op-node derives chain X. kona-node derives chain Y (A, B, C) or halts (D).
3. kona-node operators fork off the canonical chain. In `CANNON_KONA` games covering that L1 range, kona-client's view is decisive, so honest proposals can be countered (INVALID) and roots that match kona's divergent view can be defended.

## Impact Details

- **Precondition:** the batcher is a trusted role (`SystemConfig.batcherHash`). An honest op-batcher never produces (A)–(C). Case (D) comes from op-node's own "too old batch epoch" handling. Its origin (#18283) suggests edge cases around reorgs, but I found no evidence that an honest batcher produced it in production.
- **Deployment:** kona-node was an experimental alternative client. `CANNON_KONA` was deployed but non-respected throughout, until Karst on 2026-07-08. All four fixes shipped before the Karst prestate (`kona-client/v1.6.0-rc.2`). The worst realized impact is therefore bond loss in `CANNON_KONA` games, and only with a malicious batcher.
- **Severity:** Low. These are consensus divergences, but only a trusted role can trigger them, and the affected components were not yet authoritative. If the batcher were considered untrusted, they would be Medium ("unintended chain split" on a secondary client plus FPP unsoundness in a non-respected game).

## Proof of Concept

Each fix added regression tests that fail on its parent:

| Case | Test (at fix commit) | Behaviour on parent |
|---|---|---|
| A | `ordered_channel.rs::test_attack_scenario_cross_tx_out_of_order`, `test_out_of_order_frame_rejected` | The type does not exist. The equivalent against `Channel` accepts F4 (shown below) |
| B | Behaviour test below (the fix only updated constructor calls) | Returns `None` for a brotli channel under a post-Fjord origin |
| C | `utils.rs::test_read_tx_data_exceeds_max_span_batch_elements`, `test_read_tx_data_truncated_payload` | Accepts a 10,000,001-byte tx / panics on slice |
| D | `batch_stream.rs::test_span_batch_extraction_error_flushes_stage` | Returns `PipelineErrorKind::Critical` |

Case A on the parent (append to `mod test` in `rust/kona/crates/protocol/protocol/src/channel.rs` at `5bf7b7a8fb^`):

```rust
#[test]
fn poc_channel_accepts_cross_tx_out_of_order_frames() {
    let id = [0xAA; 16];
    let f = |n: u16, last: bool| Frame { id, number: n, data: vec![n as u8], is_last: last };
    let b = BlockInfo::default();
    let mut ch = Channel::new(id, b);
    for n in 0..3 { ch.add_frame(f(n, false), b).unwrap(); }      // T1
    ch.add_frame(f(4, false), b).unwrap();                        // T2: op-node drops these
    ch.add_frame(f(5, false), b).unwrap();
    ch.add_frame(f(6, true), b).unwrap();
    ch.add_frame(f(3, false), b).unwrap();                        // T3
    assert!(ch.is_ready());   // kona (parent): channel complete -> diverges from op-node
}
```

Case B on the parent (append to `mod test` in `protocol/src/batch/reader.rs` at `e2253914e7^`):

```rust
#[test]
fn poc_brotli_gate_uses_batch_timestamp() {
    // brotli channel whose single batch has timestamp 0; Fjord active at t=100
    let raw = /* 0x01 || brotli(rlp(bytes(0x00 || rlp(SingleBatch{timestamp:0,..})))) */;
    let cfg = RollupConfig { hardforks: HardForkConfig { fjord_time: Some(100), ..Default::default() }, ..Default::default() };
    let mut r = BatchReader::new(raw, MAX_RLP_BYTES_PER_CHANNEL_FJORD as usize);
    // op-node (origin.Time >= 100) would decode the batch; kona (parent) returns None
    assert!(r.next_batch(&cfg).is_none());
}
```

Commands, using a throwaway worktree per case:

```bash
git worktree add /tmp/k05a 5bf7b7a8fb^ && cd /tmp/k05a/rust && cargo test -p kona-protocol poc_channel_accepts_cross_tx_out_of_order_frames   # passes = bug present
git worktree add /tmp/k05c d2fdc04e93  && cd /tmp/k05c/rust && cargo test -p kona-protocol read_tx_data     # fix: pass
git worktree add /tmp/k05d 8924fbe38d  && cd /tmp/k05d && cargo test -p kona-derive test_span_batch_extraction_error_flushes_stage
```

For (D) on the parent, revert the `batch_stream.rs` hunk and rerun: the stage returns a Critical error instead of `NotEnoughData`. The (B) PoC needs a brotli-encoded fixture, which I have not supplied here. It follows `test_batch_reader_fjord` in the same file.

Executed: no.

## Recommendation

The fixes match op-node. Remaining suggestions:

- Finish the (D) fix for the pre-Holocene `BatchQueue` path, as the commit itself notes. It matters for proving historical ranges.
- These are all "same input, different parse" bugs. A shared differential fuzzer that feeds identical L1 data to op-node's and kona's derivation stages, compares the resulting batches and attributes, and includes adversarial frame and channel shapes would have found all four (and entries 01-01c and 01-06).

## References

- Fix commits: 5bf7b7a8fb1a4901bbf9fccbd6a3738067bad8f1 (#20011), e2253914e7b7eaa7559916809e08c947fe493a21 (#20004), d2fdc04e938a4599ce1b83c60ffe1ab0eb6d738a (#19904), 8924fbe38d1b8a92569b4043b89a12fc87a00a2b (op-rs/kona#3059)
- op-node reference: 848a9c26215f48fcd68e56ca86b1bdd76beb5518 (#18283), `op-node/rollup/derive/channel_assembler.go`, `channel.go`, `span_batch_txs.go`, `batch_stage.go`
- Specs: https://specs.optimism.io/protocol/holocene/derivation.html (frame ordering, span batch dropping), https://specs.optimism.io/protocol/fjord/derivation.html (brotli activation), specs PR #863
- Related: 01-01c, 01-06
