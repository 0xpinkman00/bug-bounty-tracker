# kona brotli decompression: output cut short when input and output buffers ran out together, so kona decoded fewer batches than op-node from truncated channels

| Field | Value |
|---|---|
| **Target** | kona protocol channel decompression, `rust/kona/crates/protocol/protocol/src/brotli.rs` (`decompress_brotli`). Used by kona-client (fault-proof program) and kona-node |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | "Unintended chain split (network partition)" between kona and op-node, limited to non-respected `CANNON_KONA` games and the experimental kona-node, and needing the authorized batcher |
| **Fix commit(s)** | 54ee88feb2ade652528f0b614ce858760797e267 (PR #20598, refs #19333), 2026-05-13 |
| **Vulnerable since** | The output-buffer growth loop in its pre-fix form (last touched in b08e543ddf, 2026-03-26; the file arrived with the monorepo import 48a7a09bfc, 2026-02-10). Fixed before `kona-client/v1.5.2` (2026-05-18) and before the Karst prestate `kona-client/v1.6.0-rc.2` |

## Brief / Intro

Since the Fjord upgrade, batchers may compress channels with brotli. Every node decompresses a channel and then reads batches out of it. If a channel is truncated, meaning the compressed stream stops early, the spec says to use whatever the decoder produced before the error. op-node does this with Go's streaming `brotli.NewReader`. kona's own decompression loop had an edge case: when the input and the output buffer ran out in the same step, it stopped early and returned *fewer* bytes than op-node. kona could then read fewer batches from the same channel and derive a different L2 chain. Truncated channels come only from the authorized batcher, and the bug was fixed before kona became the respected fault-proof program.

## Vulnerability Details

Parent of the fix, `rust/kona/crates/protocol/protocol/src/brotli.rs:35-80`:

```rust
let mut output = vec![0; core::cmp::min(data.len(), max_rlp_bytes_per_channel)];
...
loop {
    let result = brotli::BrotliDecompressStream(&mut available_in, &mut input_offset, data,
        &mut available_out, &mut output_offset, &mut output, &mut written, &mut brotli_state);
    let old_len = output.len();
    match result {
        BrotliResult::NeedsMoreOutput if old_len >= max_rlp_bytes_per_channel => break,
        BrotliResult::NeedsMoreOutput => {           // only this arm grows the buffer
            let new_len = core::cmp::min((old_len * 2).max(1), max_rlp_bytes_per_channel);
            output.resize(new_len, 0);
            available_out += new_len - old_len;
        }
        _ if written == 0 => return Err(...),
        // Success, NeedsMoreInput or ResultFailure with some output written: return partial data.
        _ => break,
    }
}
output.truncate(written);
```

Root cause:

1. The output buffer starts at the size of the compressed input and is doubled only on `NeedsMoreOutput`.
2. If `available_in` and `available_out` both reach 0 in the same call to `BrotliDecompressStream`, the brotli crate returns `NeedsMoreInput`, which takes priority over `NeedsMoreOutput`. The decoder still holds output it could flush if given more room.
3. The loop treats `NeedsMoreInput` as the end and returns `written` bytes, without giving brotli more output space.
4. On a complete stream this is harmless, because brotli finishes with `ResultSuccess`. On a **truncated** stream, Go's `brotli.NewReader` keeps calling the decoder with fresh output space (its bufio layer re-reads) and yields every byte that can be decoded before hitting EOF. kona yields a shorter prefix.
5. The channel reader decodes RLP batches from the decompressed bytes until it hits an error. With fewer bytes, kona reads fewer batches, or a truncated last batch, compared with op-node.

### The fix

```diff
-            BrotliResult::NeedsMoreOutput if old_len >= max_rlp_bytes_per_channel => break,
-            BrotliResult::NeedsMoreOutput => {
+            BrotliResult::NeedsMoreOutput | BrotliResult::NeedsMoreInput
+                if available_out == 0 && old_len >= max_rlp_bytes_per_channel =>
+            {
+                break;
+            }
+            BrotliResult::NeedsMoreOutput | BrotliResult::NeedsMoreInput if available_out == 0 => {
                 let new_len = core::cmp::min((old_len * 2).max(1), max_rlp_bytes_per_channel);
                 output.resize(new_len, 0);
                 available_out += new_len - old_len;
             }
```

When the output buffer is full, `NeedsMoreInput` is now handled like `NeedsMoreOutput`: the buffer grows, or decompression stops at the spec's size cap. Only a `NeedsMoreInput` with output space left over, which means the input really is exhausted, ends the loop.

### Attack scenario

1. The batcher key posts a channel whose brotli-compressed payload is cut off at a point where kona's output buffer happens to be exactly full when the input runs out. The first buffer is the size of the input, so the batcher can find such a cut point by trying lengths.
2. op-node decompresses the prefix fully and derives batches `B1..Bn`.
3. kona gets a shorter prefix and derives only `B1..Bk` with `k < n`, or loses part of the last batch.
4. The two implementations derive different safe L2 blocks, so their output roots differ.

## Impact Details

- **Fault proofs:** the fix (2026-05-13) is in `kona-client/v1.5.2` (2026-05-18) and in the Karst prestate `kona-client/v1.6.0-rc.2`. `CANNON_KONA` became the respected game type only with Karst (Sepolia 2026-06-17, Mainnet 2026-07-08; `docs/public-docs/notices/archive/upgrade-19.mdx`). While the bug was live, type-8 games were optional and non-respected (`docs/public-docs/notices/archive/upgrade-18.mdx:17,37`). The only exposure was bonds in those games. Withdrawals were not at risk.
- **kona-node:** experimental and not production-ready (`docs/public-docs/releases/kona-node.mdx:23`). It would fork from op-node peers.
- **Who can trigger it:** only the authorized batcher. An honest batcher never posts truncated channels.
- **Severity: Low.** It is a real cross-client derivation divergence, but it needs a privileged key and was fixed before kona's result mattered for withdrawals.

## Proof of Concept

The fix added `test_decompress_truncated_matches_streaming_reader` to `rust/kona/crates/protocol/protocol/src/brotli.rs`. It sweeps truncation points of a compressed stream and asserts that kona's output matches the brotli crate's streaming `Decompressor` byte for byte. That reader behaves like Go's `brotli.NewReader`. The test only uses functions that already exist at the parent commit, so it can be copied into the `mod test` block of `brotli.rs` at `54ee88feb2^` unchanged:

```rust
#[test]
fn test_decompress_truncated_matches_streaming_reader() {
    use std::io::Read;
    let data: Vec<u8> = (0..2000).map(|i| ((i * 7) % 256) as u8).collect();
    let compressed = {
        let params = brotli::enc::BrotliEncoderParams::default();
        let mut output = alloc::vec::Vec::new();
        let mut input = &data[..];
        brotli::BrotliCompress(&mut input, &mut output, &params).unwrap();
        output
    };
    let mut any_partial = false;
    for trunc_len in (1..compressed.len()).step_by(3) {
        let truncated = &compressed[..trunc_len];
        let mut reader_out = alloc::vec::Vec::new();
        let mut reader = brotli::Decompressor::new(truncated, 4096);
        let _ = reader.read_to_end(&mut reader_out);          // reference (= Go brotli.NewReader)
        let kona_out = decompress_brotli(truncated, MAX_RLP_BYTES_PER_CHANNEL_FJORD as usize)
            .unwrap_or_default();
        if !reader_out.is_empty() { any_partial = true; }
        assert_eq!(kona_out, reader_out, "mismatch at truncation len {trunc_len}"); // FAILS on parent
    }
    assert!(any_partial);
}
```

Run it (from `rust/`):

```
cargo test -p kona-protocol --lib test_decompress_truncated_matches_streaming_reader
```

The commit message reports that on the parent, `kona_out` is shorter than `reader_out` for at least one truncation length ("kona produced significantly fewer output bytes than op-node from the same input"). On `54ee88feb2` the test passes.

Executed: no. A kona workspace build was not run. The result rests on the regression test the fix added and on reading the code.

## Recommendation

The fix is correct. A cleaner long-term option is to replace the hand-rolled `BrotliDecompressStream` loop with the crate's streaming `Decompressor` reader capped at `max_rlp_bytes_per_channel`. That reader is what the test uses as its reference, and using it removes this whole class of buffer-management edge cases. The same differential-fuzzing suggestion as in 00-1f and 00-1g applies: comparing channel decompression plus batch decoding between op-node and kona on random and truncated inputs would have caught this. Later related hardening: f9da6547b8 bumps `brotli-decompressor` to 5.0.1.

## References

- Fix commit: 54ee88feb2ade652528f0b614ce858760797e267
- Pull request: https://github.com/ethereum-optimism/optimism/pull/20598 (issue https://github.com/ethereum-optimism/optimism/issues/19333)
- Relevant files: `rust/kona/crates/protocol/protocol/src/brotli.rs`, `op-node/rollup/derive/channel.go` (brotli reader)
- Spec (Fjord channel format / brotli): https://specs.optimism.io/protocol/fjord/derivation.html
