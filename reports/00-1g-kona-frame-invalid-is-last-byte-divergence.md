# kona frame decoding: an `is_last` byte other than 0 or 1 was treated as `false` instead of invalidating the batcher transaction (derivation divergence from op-node)

| Field | Value |
|---|---|
| **Target** | kona protocol frame decoding, `rust/kona/crates/protocol/protocol/src/frame.rs` (`Frame::decode`). Used by kona-client (fault-proof program) and kona-node |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | "Unintended chain split (network partition)" between kona and op-node, limited to non-respected `CANNON_KONA` games and the experimental kona-node, and needing the authorized batcher |
| **Fix commit(s)** | 1cff94d9ba93e59d1185f12b609ad3d0a20c21f7 (PR #20590, fixes #19335), 2026-05-12 |
| **Vulnerable since** | Present at the monorepo import of kona (48a7a09bfc, 2026-02-10) and inherited from the standalone kona repo. Fixed before `kona-client/v1.5.2` (2026-05-18) and before the Karst prestate `kona-client/v1.6.0-rc.2` |

## Brief / Intro

The batcher posts L2 data to L1 as *frames*. Each frame is a piece of a compressed *channel*, and its last byte, `is_last`, says whether it is the final piece. The derivation spec allows only `0` or `1` for that byte. Any other value makes the frame invalid, and op-node then discards every frame in that L1 transaction. kona read the byte as `is_last = (byte == 1)`, so a value such as `2` was quietly treated as "not last" and the frame was kept. The same L1 data could therefore produce different L2 chains in kona and in op-node. Only the authorized batcher can post frames, and the fix landed before kona became the respected fault-proof program, so the practical impact is small.

## Vulnerability Details

Parent of the fix, `rust/kona/crates/protocol/protocol/src/frame.rs:191-213`:

```rust
pub fn decode(encoded: &[u8]) -> Result<(usize, Self), FrameDecodingError> {
    const BASE_FRAME_LEN: usize = 16 + 2 + 4 + 1;
    ...
    let data = encoded[22..22 + data_len].to_vec();
    let is_last = encoded[22 + data_len] == 1;      // 2..=255 silently become `false`
    Ok((BASE_FRAME_LEN + data_len, Self { id, number, data, is_last }))
}
```

`Frame::parse_frames` (same file, line 230) stops at the first `decode` error and rejects the whole batcher transaction. Because `decode` never returned an error for a bad `is_last`, that rejection never happened.

op-node, `op-node/rollup/derive/frame.go:99-107`:

```go
if isLastByte, err := r.ReadByte(); err != nil {
    return fmt.Errorf("reading final byte (is_last): %w", eofAsUnexpectedMissing(err))
} else if isLastByte == 0 {
    f.IsLast = false
} else if isLastByte == 1 {
    f.IsLast = true
} else {
    return errors.New("invalid byte as is_last")
}
```

`ParseFrames` (`frame.go:131`) returns the error, and the L1 transaction contributes no frames.

### The fix

```diff
-        let is_last = encoded[22 + data_len] == 1;
+        let is_last = match encoded[DATA_START + data_len] {
+            0 => false,
+            1 => true,
+            b => return Err(FrameDecodingError::InvalidIsLast(b)),
+        };
```

A new `FrameDecodingError::InvalidIsLast(u8)` variant makes `parse_frames` fail, so kona now rejects the whole batcher transaction just as op-node does. The commit also rewrites the length bound as `data_len > encoded.len() - BASE_FRAME_LEN`, which is equivalent to the old `data_len >= encoded.len() - 22`.

### Attack scenario

1. The batcher key posts a batcher transaction to the batch inbox that contains one or more frames, one of them with `is_last = 0x02`.
2. op-node rejects every frame in that transaction. kona keeps them all and treats the bad frame as a non-final frame of its channel.
3. The channel banks now differ. kona can later complete and decode a channel from these frames plus later ones, while op-node never sees these frames. The two derive different batches, so they produce different safe L2 blocks and different output roots.

## Impact Details

- **Fault proofs:** kona-client decides `CANNON_KONA` (game type 8) disputes. The fix (2026-05-12) is already in `kona-client/v1.5.2` (2026-05-18) and in `kona-client/v1.6.0-rc.2`, the prestate Karst shipped when it made `CANNON_KONA` the respected game type (Sepolia 2026-06-17, Mainnet 2026-07-08; see `docs/public-docs/notices/archive/upgrade-19.mdx`). While the bug was live, kona was **not** the respected program: Upgrade 18 added game type 8 "alongside" `CANNON`, and "withdrawals continue to use the respected game type" (`docs/public-docs/notices/archive/upgrade-18.mdx:17,37`). The worst case was losing bonds in non-respected type-8 games. Withdrawals were not at risk.
- **kona-node:** the docs describe it as "experimental" and "not production ready" (`docs/public-docs/releases/kona-node.mdx:23`). A kona-node would fork from op-node peers.
- **Who can trigger it:** only the chain's authorized batcher. Frames from any other sender are ignored.
- **Severity:** a consensus-level divergence between two client implementations, but it needs a privileged key and was fixed before kona became authoritative. **Low**.

## Proof of Concept

The fix added `test_decode_invalid_is_last` to `rust/kona/crates/protocol/protocol/src/frame.rs`. The version below works on the parent commit, where `FrameDecodingError::InvalidIsLast` does not exist yet, and shows both the divergent behaviour and the fixed behaviour. Add it to the `mod test` block of `frame.rs` at `1cff94d9ba^`:

```rust
#[test]
fn poc_invalid_is_last_is_accepted() {
    let frame = Frame { id: [0xFF; 16], number: 0xEE, data: vec![0xDD; 16], is_last: true };
    let mut encoded = frame.encode();
    let last = encoded.len() - 1;
    encoded[last] = 2; // op-node: "invalid byte as is_last" -> whole tx rejected

    // Also via parse_frames, which is what the pipeline calls on batcher tx data.
    let mut tx_data = vec![DERIVATION_VERSION_0];
    tx_data.extend_from_slice(&encoded);

    // Parent: both succeed and the frame is treated as non-final. Fixed: both must error.
    assert!(Frame::decode(&encoded).is_err(), "is_last=2 must be rejected");        // FAILS on parent
    assert!(Frame::parse_frames(&tx_data).is_err(), "tx must contribute no frames"); // FAILS on parent
}
```

Run it (from `rust/`):

```
cargo test -p kona-protocol --lib poc_invalid_is_last_is_accepted
```

On `1cff94d9ba^` both assertions fail: `decode` returns `Ok` with `is_last == false`. On `1cff94d9ba` both pass, as does the upstream test `cargo test -p kona-protocol --lib test_decode_invalid_is_last`. op-node's matching test is `go test ./op-node/rollup/derive -run TestFrameUnmarshalInvalidIsLast`.

Executed: no. A kona workspace build was not run. The result was confirmed by reading the code on both sides.

## Recommendation

The fix is correct and minimal. It matches the spec and op-node. Further suggestions:

- Run a Go-vs-Rust differential fuzzer over `ParseFrames` / `Frame::parse_frames` and the channel-bank logic. Byte-level decoder mismatches such as this one, 00-1f and 00-1h are exactly what such fuzzing catches.
- Where the spec defines a byte as a boolean, decode it strictly across the Rust codebase, not with `== 1`.

## References

- Fix commit: 1cff94d9ba93e59d1185f12b609ad3d0a20c21f7
- Pull request: https://github.com/ethereum-optimism/optimism/pull/20590 (issue https://github.com/ethereum-optimism/optimism/issues/19335)
- Relevant files: `rust/kona/crates/protocol/protocol/src/frame.rs`, `op-node/rollup/derive/frame.go`
- Spec (frame format): https://specs.optimism.io/protocol/derivation.html#frame-format
- Respected-game-type timeline: `docs/public-docs/notices/archive/upgrade-18.mdx`, `docs/public-docs/notices/archive/upgrade-19.mdx`
