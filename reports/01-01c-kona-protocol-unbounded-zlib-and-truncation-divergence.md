# kona-protocol: unbounded zlib channel decompression (zip bomb), and reject-instead-of-truncate semantics that diverged from op-node

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/protocol/protocol/src/batch/reader.rs` (`BatchReader::decompress`) and `rust/kona/crates/protocol/protocol/src/brotli.rs` (`decompress_brotli`). Shared by kona-client (FPP) and kona-node |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | "Causing network processing nodes to crash" (kona-node / kona FPP out of memory) and "Unintended chain split (network partition)" between kona and op-node. Both need the authorized batcher key |
| **Fix commit(s)** | b08e543ddfb2c49be51a351c10135bdedcb8152d (PR #19775, private fix optimism-private #455), 2026-03-26 |
| **Vulnerable since** | zlib path: 86d0b4e62e `feat(protocol): Batch Reader (alloy-rs/op-alloy#265)`, 2024-11-15. Brotli doubling check: 8758745998 (alloy-rs/op-alloy#335), 2025-01-03. First fixed release: `kona-client/v1.2.13` |

## Brief / Intro

The batcher posts L2 transaction data to L1 in compressed "channels". Every node decompresses them to rebuild the L2 chain. The spec caps the decompressed size, at 100 MB since Fjord. If a channel is larger, nodes must keep the first 100 MB and carry on. kona's zlib path decompressed the *entire* stream into memory first and only then checked the size. A tiny zip bomb could therefore exhaust memory. kona also *rejected* oversized channels outright, where the spec and op-node truncate. It discarded all output after a mid-stream decode error, where op-node keeps the batches decoded before the error. Only the authorized batcher can post channel data, which is why this is Low.

## Vulnerability Details

Parent of the fix, `reader.rs:82-95`:

```rust
if (compression_type & 0x0F) == Self::ZLIB_DEFLATE_COMPRESSION_METHOD || ... {
    self.decompressed =
        decompress_to_vec_zlib(&data).map_err(|_| DecompressionError::ZlibError)?;   // line 86: unbounded

    if self.decompressed.len() > self.max_rlp_bytes_per_channel {
        return Err(DecompressionError::RlpTooLarge(..));                            // line 90: reject, not truncate
    }
}
```

Three problems:

1. **Zip bomb.** `decompress_to_vec_zlib` has no output limit. DEFLATE reaches roughly 1000:1, so a channel of a few MB inflates to several GB before the size check runs. kona-node aborts on allocation failure. Inside Cannon, the FPP's allocator panics when mapping fails (`kona-std-fpvm/src/malloc.rs`), and the panic handler exits with code 2 (`kona-std-fpvm-proc/src/lib.rs`). Code 2 is the PANIC VM status, which `FaultDisputeGame` treats like INVALID.
2. **Reject vs truncate.** The spec says: "If the decompressed data exceeds the limit, things proceed as though the channel contained only the first MAX_RLP_BYTES_PER_CHANNEL decompressed bytes." op-node follows this. kona dropped the whole channel.
3. **Errors discard partial output.** On a corrupt stream, op-node keeps the batches decoded before the error. kona dropped everything. The brotli path had the same issue. In addition, `brotli.rs:61-63` returned `BatchTooLarge` as soon as the *doubled buffer size* crossed the limit, even when the real output would have fit.

Fix (`reader.rs`):

```rust
match decompress_to_vec_zlib_with_limit(&data, self.max_rlp_bytes_per_channel) {
    Ok(decompressed) => self.decompressed = decompressed,
    Err(e) if (e.status == TINFLStatus::HasMoreOutput || !e.output.is_empty()) => {
        self.decompressed = e.output;          // truncate at limit / keep partial output
    }
    Err(_) => return Err(DecompressionError::ZlibError),
}
```

`brotli.rs` now grows the buffer to `min(2*len, limit)`, stops at the limit (truncation), and returns partial output on error when some bytes were written.

### Attack scenario

1. A compromised or buggy batcher posts a post-Fjord zlib channel of a few MB that inflates to more than 1 GB. Alternatively, it posts a channel that inflates to just over 100 MB, or a stream that is corrupt after the first few batches.
2. op-node truncates the channel or keeps the good prefix, and derives L2 blocks from those batches.
3. kona-node runs out of memory and crashes, and crashes again on every restart because the data is permanently on L1. In the other variants it drops the channel and derives a different chain.
4. The kona FPP either panics (PANIC status, meaning "claim invalid") or computes a different output root. So `CANNON_KONA` games covering that range disagree with op-node's canonical roots, and honest proposals can be countered.

## Impact Details

- **Precondition:** only the batcher address in `SystemConfig` can post data that derivation reads. This is a trusted role. An honest op-batcher never produces a zip bomb, an over-limit channel, or a corrupt stream.
- **Escalation:** the bug turns a batcher-key compromise, which normally only allows censorship or liveness attacks, into a break of kona fault-proof soundness and a kona-node crash.
- **Deployment state:** `CANNON_KONA` was non-respected during the whole vulnerable window (it became respected with Karst, 2026-07-08), and kona-node was an experimental alternative consensus client.
- **Severity:** Low, because of the trusted-role precondition and limited deployment. Without the batcher-trust assumption it would be Medium.

## Proof of Concept

A Rust unit test for `kona-protocol` at the parent commit. It shows that the whole bomb is materialised and then rejected instead of truncated.

```rust
// append to `mod test` in rust/kona/crates/protocol/protocol/src/batch/reader.rs at b08e543ddf^
#[test]
fn poc_zlib_bomb_unbounded_and_rejected() {
    use miniz_oxide::deflate::{compress_to_vec_zlib, CompressionLevel};
    const LIMIT: usize = 1 << 20;          // max_rlp_bytes_per_channel = 1 MiB
    const BOMB: usize = 64 << 20;          // 64 MiB of zeros -> ~64 KiB compressed
    let compressed = compress_to_vec_zlib(&vec![0u8; BOMB], CompressionLevel::BestCompression as u8);
    assert!(compressed.len() < BOMB / 500);

    let mut reader = BatchReader::new(compressed, LIMIT);
    let res = reader.decompress();

    // Parent: all 64 MiB are allocated, then the channel is rejected.
    assert!(matches!(res, Err(DecompressionError::RlpTooLarge(n, LIMIT)) if n == BOMB));
    // Fix commit: assert!(res.is_ok()); assert_eq!(reader.decompressed.len(), LIMIT);
}
```

```bash
git worktree add /tmp/kona-01-01c b08e543ddf^
# paste the test, then:
cd /tmp/kona-01-01c/rust && cargo test -p kona-protocol poc_zlib_bomb_unbounded_and_rejected
```

The fix commit's own regression tests also fail on the parent and pass on the fix: `test_zlib_truncation_instead_of_rejection` and `test_zlib_truncation_yields_decodable_batches` (`reader.rs`), and `test_brotli_truncation_instead_of_rejection` and `test_brotli_buffer_doubling_regression` (`brotli.rs`). Run `cargo test -p kona-protocol truncation`.

Executed: no.

## Recommendation

The fix is correct: zlib is bounded, brotli growth is capped, and partial output is kept, which matches op-node. A later brotli edge case (input and output exhausted in the same step) was fixed in 54ee88feb2 (report 00-1h). A differential fuzz target comparing op-node's and kona's channel readers on random, truncated and oversized channels would catch this whole class.

## References

- Fix commit: b08e543ddfb2c49be51a351c10135bdedcb8152d
- Pull request: https://github.com/ethereum-optimism/optimism/pull/19775
- Relevant files: `rust/kona/crates/protocol/protocol/src/batch/reader.rs`, `rust/kona/crates/protocol/protocol/src/brotli.rs`, `op-node/rollup/derive/channel.go`
- Spec: https://specs.optimism.io/protocol/fjord/derivation.html
- Related: 01-01a, 01-01b (same PR); 00-1h
