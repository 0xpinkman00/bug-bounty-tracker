# kona-protocol: panics while decoding malformed batcher data (unknown batch type, truncated span-batch fields)

| Field | Value |
|---|---|
| **Target** | kona-protocol batch decoding: `batch/type.rs` (`BatchType::from`), `batch/core.rs` (`Batch::decode`), `batch/prefix.rs`, `batch/transactions.rs`, `utils.rs` (`read_tx_data`). Used by kona-node and kona-client (FPP) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | "Causing network processing nodes to crash" (kona-node) and fault-proof liveness/soundness for `CANNON_KONA` (FPP panic = VM status PANIC). Needs data from the authorized batcher |
| **Fix commit(s)** | 88cd69c83a01986e98508b4ab9415e45de7415fa (PR #20000, optimism-private#484), 2026-04-10 · 37c98925e438efa476c6b598b5113b73dc6dbe76 (PR #19361), 2026-03-11 · d2fdc04e938a4599ce1b83c60ffe1ab0eb6d738a (PR #19904, truncated-payload part, Cantina #25), 2026-04-02 |
| **Vulnerable since** | These decoders have existed since kona's batch types were first written (2024). Fixed in `kona-client/v1.2.13` (#19361) and `kona-client/v1.5.1` (#20000, #19904) |

## Brief / Intro

Nodes read L2 batches out of data the batcher posts to L1. The first byte of each batch says its type (0 = single, 1 = span). The spec says a batch with an unknown type or corrupt contents must simply be ignored, which op-node does. kona instead **panicked** in several places: on any unknown type byte, and when a span batch was cut short in the middle of its parent-hash check, L1-origin check, signature list, recipient list, or a transaction body. A panic crashes kona-node, and it crashes again on every restart because the data stays on L1. Inside the fault-proof program, a panic ends the run with the PANIC status, which dispute games treat as "claim invalid", so even honest proposals for that range could be refuted. Only the authorized batcher can post this data.

## Vulnerability Details

Unknown batch type, parent of 88cd69c83a (`batch/type.rs:31-39`, `batch/core.rs:44-46`):

```rust
impl From<u8> for BatchType {
    fn from(val: u8) -> Self {
        match val {
            SINGLE_BATCH_TYPE => Self::Single,
            SPAN_BATCH_TYPE => Self::Span,
            _ => panic!("Invalid batch type: {val}"),      // reachable from L1 data
        }
    }
}
// Batch::decode
let batch_type = BatchType::from(r[0]);
```

Truncated span-batch fields, parent of 37c98925e4 (`prefix.rs`, `transactions.rs`):

```rust
let (parent_check, rest) = r.split_at(20);          // panics if r.len() < 20 (parent/L1-origin check)
let r_val = U256::from_be_slice(&r[..32]);          // decode_tx_sigs: panics if r.len() < 64
let s_val = U256::from_be_slice(&r[32..64]);
let to = Address::from_slice(&r[..20]);             // decode_tx_tos: panics if r.len() < 20
```

Truncated tx payload, parent of d2fdc04e93 (`utils.rs:118`):

```rust
let payload = r[0..payload_length_with_header].to_vec();   // RLP header claims more than is left
```

`BatchReader::next_batch` calls `Batch::decode` directly on the decompressed channel bytes, so all of these are reachable from batch-inbox data. op-node's equivalents return errors: `io.ReadFull` / `ErrUnexpectedEOF`, and `unrecognized batch type`. The batch is then dropped and derivation continues.

Fixes: `TryFrom<u8>` with `BatchDecodingError::UnknownBatchType`, plus explicit length checks that return `SpanBatchError::Decoding(..)` before each slice.

### Attack scenario

1. The batcher (compromised or buggy) posts a valid channel whose decompressed content contains a batch starting with byte `0x02`, or a span batch truncated inside its signature list.
2. op-node drops the batch and keeps deriving.
3. kona-node panics in its derivation task. On restart it re-reads the same L1 data and panics again, so it is stuck until the node software is patched.
4. kona-client panics while deriving any L2 block whose derivation reads that channel, and the VM status is PANIC. In a `CANNON_KONA` game, an honest output claim over that range can be attacked with a PANIC execution root (`FaultDisputeGame._verifyExecBisectionRoot` accepts PANIC like INVALID), and the honest challenger's own trace shows the same PANIC. Honest proposers lose those games.

## Impact Details

- **Precondition:** batcher-controlled input, which is a trusted role. An honest op-batcher never emits unknown batch types or truncated batches.
- **Deployment:** kona-node was an experimental client. `CANNON_KONA` was deployed but non-respected until Karst (2026-07-08). All three fixes shipped before the Karst prestate.
- **Severity:** Low. This is a node crash and fault-proof denial on non-authoritative components, triggerable only by a trusted role. It would be Medium if the batcher were untrusted.

## Proof of Concept

Regression tests added by the fixes panic on the parent commits:

- `batch/core.rs::test_unknown_batch_type_returns_error` (88cd69c83a). It feeds `[0xFF, 0x00]` to `Batch::decode`. On the parent it panics with `Invalid batch type: 255`.
- `batch/prefix.rs::test_decode_parent_check_truncated`, `test_decode_l1_origin_check_truncated`, `test_decode_parent_check_empty`, and `batch/transactions.rs::test_decode_tx_sigs_truncated`, `test_decode_tx_tos_truncated`, `test_decode_tx_tos_empty` (37c98925e4).
- `utils.rs::test_read_tx_data_truncated_payload` (d2fdc04e93). It uses `[0xf8, 0x64, 0x00, 0x00, 0x00]`: the header claims 100 bytes but only 3 are present.

Minimal PoC that runs on the parent of 88cd69c83a (append to `mod tests` in `rust/kona/crates/protocol/protocol/src/batch/core.rs`):

```rust
#[test]
#[should_panic(expected = "Invalid batch type")]
fn poc_unknown_batch_type_panics() {
    let data = [0x02u8, 0x00];   // batch type 2 does not exist
    let _ = Batch::decode(&mut data.as_slice(), &RollupConfig::default());
}
```

```bash
git worktree add /tmp/k06 88cd69c83a01986e98508b4ab9415e45de7415fa^
cd /tmp/k06/rust && cargo test -p kona-protocol poc_unknown_batch_type_panics   # passes on parent (panic observed)
# at 88cd69c83a the same input returns Err(BatchDecodingError::UnknownBatchType(2)); the should_panic test fails
```

Executed: no.

## Recommendation

The fixes are correct. Also:

- Deny `clippy::indexing_slicing`, `clippy::panic` and `clippy::unwrap_used` in kona-protocol and kona-derive, whose inputs come from L1, and use checked accessors (`get(..)`, `split_at_checked`).
- Fuzz `Batch::decode` and `BatchReader::next_batch` with `cargo-fuzz`. Every one of these panics is a single-input crash that a fuzzer finds in seconds.

## References

- Fix commits: 88cd69c83a01986e98508b4ab9415e45de7415fa (#20000), 37c98925e438efa476c6b598b5113b73dc6dbe76 (#19361), d2fdc04e938a4599ce1b83c60ffe1ab0eb6d738a (#19904)
- Relevant files: `rust/kona/crates/protocol/protocol/src/batch/{type,core,errors,prefix,transactions}.rs`, `rust/kona/crates/protocol/protocol/src/utils.rs`, `rust/kona/crates/proof/std-fpvm-proc/src/lib.rs` (panic handler exits 2), `packages/contracts-bedrock/src/dispute/FaultDisputeGame.sol`
- Spec: https://specs.optimism.io/protocol/derivation.html#batch-format (unknown versions are invalid and ignored)
- Related: 01-05 (oversized tx part of d2fdc04e93), 01-01c
