# kona-derive: an all-zero EIP-4844 blob from the batcher is a critical pipeline error, halting kona-node and kona-client where op-node continues

| Field | Value |
|---|---|
| **Target** | kona `crates/protocol/derive/src/sources/blob_data.rs` (`BlobData::fill`), used by kona-node and by the `kona-client` fault-proof program. Now under `rust/kona/` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (would be Medium if kona-node or a kona-based proof system were in production for the chain) |
| **Impact category** | "Unintended chain split (network partition)" between kona and op-node derivation, limited here to non-production kona components and requiring the authorized batcher key |
| **Fix commit(s)** | c831a5f7638661676f784cdbf3fb990b8b1691d1 (op-rs/kona#3001), 2025-11-04 |
| **Vulnerable since** | At least f09ffbfd90 "fix(derive): Data Availability Provider Abstraction" (op-rs/kona#782), 2024-11-05. About 12 months |

## Brief / Intro

Since the Ecotone upgrade, the batcher usually posts L2 transaction data in EIP-4844 "blobs". A blob is 128 KiB of field elements that carries a length-prefixed payload. An all-zero blob is perfectly valid on Ethereum. Decoded with the OP Stack blob encoding, it is simply empty data, and op-node quietly ignores it. kona's blob source instead treated an all-zero blob as "missing data" and escalated that to a *critical* derivation error. A batcher that posts a single all-zero blob therefore stops every kona-based derivation, both the kona-node rollup node and the kona fault-proof / ZK program, at that L1 block, while op-node keeps deriving. The two client families then disagree about the safe chain.

## Vulnerability Details

`BlobSource::load_blobs` gathers the blobs of every transaction that the batcher sent to the batch inbox. It then calls `fill` for each one:

`crates/protocol/derive/src/sources/blob_data.rs:145-165` (parent of fix)
```rust
pub(crate) fn fill(&mut self, blobs: &[Box<Blob>], index: usize) -> Result<bool, BlobDecodingError> {
    if self.calldata.is_some() { return Ok(false); }
    if index >= blobs.len() { return Err(BlobDecodingError::InvalidLength); }

    if blobs[index].is_empty() || blobs[index].is_zero() {
        return Err(BlobDecodingError::MissingData);
    }
    self.data = Some(Bytes::from(*blobs[index]));
    Ok(true)
}
```

The error travels upward. In `crates/protocol/derive/src/sources/blobs.rs:151-159` the error is turned into a `BlobProviderError::BlobDecoding` with `e.into()`. Then, in `crates/protocol/derive/src/errors/sources.rs:48`:

```rust
BlobProviderError::BlobDecoding(_) => PipelineError::Provider(val.to_string()).crit(),
```

The whole L1 block's data then fails with `PipelineErrorKind::Critical`:
- kona-node: `crates/node/service/src/actors/derivation.rs:300-304` returns the error, and the derivation actor stops.
- kona-client: `crates/proof/driver/src/pipeline.rs:154-157` returns the error, and the program exits with a failure instead of producing an output root.

op-node has no such check. `fillBlobPointers` in `op-node/rollup/derive/blob_data_source.go` just stores the blob. Decoding an all-zero blob gives version 0 and length 0, which is empty data. The frame parser drops that without error. kona's own `BlobData::decode` also returns empty bytes for an all-zero blob. Only the `is_zero()` pre-check was wrong.

**Fix:**
```diff
-        if blobs[index].is_empty() || blobs[index].is_zero() {
+        if blobs[index].is_empty() {
             return Err(BlobDecodingError::MissingData);
         }
```
The unit test `test_fill_zero_blob` was changed to expect `Ok(true)`.

### Attack scenario

1. The batcher signs a type-3 transaction to the batch inbox that carries one blob of 131072 zero bytes. Its KZG commitment is the point at infinity, which is valid under EIP-4844.
2. op-node decodes the blob as empty data, ignores it, and continues deriving.
3. Every kona-node reaches that L1 block, hits `BlobDecodingError::MissingData` → `Critical`, and halts derivation. It does so again after a restart.
4. Any kona-client run (cannon-kona or kona-based ZK proving) whose L1 range includes that block exits with an error. The program cannot prove any output root past that point.

## Impact Details

- **kona-node:** the safe head stops at the bad L1 block, so it diverges from op-node. It is a liveness split between client implementations, not a fork into two valid chains.
- **kona-client proofs:** the program cannot finish. With CANNON_KONA dispute games, the honest party would have no valid trace past that L1 block. For third-party systems that run kona derivation inside a ZK proof (OP Succinct-style validity proofs, which are outside this repository), no proof could be produced, so withdrawals and finalization would stall until an upgrade.
- **Mitigating factors:** (a) only the chain's batcher key can post data that derivation reads (`to == batch inbox` and signer == batcher). An honest op-batcher never produces an all-zero blob. (b) At fix time kona-node was not the production rollup node, and CANNON_KONA was still dev-feature gated in the OP contracts. (c) No funds are directly at risk. The halt is recoverable with a software upgrade.
- **Severity:** Low within this program's scope, because the component was pre-production and the trigger needs a trusted role. It would be Medium for a chain that depended on kona in production, as a batcher-triggerable halt and split.

## Proof of Concept

The fix updated `test_fill_zero_blob` to expect `Ok(true)`. The self-contained test below also shows the severity the error was given. Append it to `crates/protocol/derive/src/sources/blob_data.rs`:

```rust
#[cfg(test)]
mod poc_zero_blob {
    use super::*;
    use crate::{BlobProviderError, PipelineErrorKind};

    /// An all-zero blob is valid under EIP-4844; op-node decodes it to empty data and ignores it.
    #[test]
    fn poc_all_zero_blob_is_not_an_error() {
        let blobs = vec![Box::new(Blob::ZERO)];
        let mut blob_data = BlobData::default();
        let res = blob_data.fill(&blobs, 0);
        if let Err(e) = res.clone() {
            let kind: PipelineErrorKind = BlobProviderError::from(e).into();
            panic!("fill() rejected an all-zero blob with {e:?}; pipeline severity: {kind:?}");
        }
        assert_eq!(res, Ok(true));
        assert_eq!(blob_data.decode().unwrap(), Bytes::new()); // same as op-node: empty data
    }
}
```

Run it on each tree (the commit is in the imported op-rs/kona history, whose root is the kona workspace):

```bash
H=c831a5f7638661676f784cdbf3fb990b8b1691d1
for rev in "$H^" "$H"; do
  d=/tmp/poc-0203/$(echo $rev | tr '^' p); mkdir -p $d && git archive $rev | tar -x -C $d
  # append the test above to $d/crates/protocol/derive/src/sources/blob_data.rs
  (cd $d && cargo test -p kona-derive --all-features --lib poc_all_zero_blob)
done
```

Expected on the parent: panic `fill() rejected an all-zero blob with MissingData; pipeline severity: Critical(Provider("..."))`. Expected on the fix: `test result: ok`.

**Executed: no.** The kona workspace build was started but did not complete in this session. The claims above rest on reading the code: the `fill` check at the parent, the `BlobDecoding → crit()` mapping in `errors/sources.rs:48`, and the fix's updated unit test, which asserts `Ok(true)` for `Blob::ZERO`.

## Recommendation

The fix is correct. Further suggestions:

- Review the other `.crit()` mappings for data that comes from the batcher or L1 (`BlobProviderError::BlobDecoding`, `SidecarLengthMismatch`). Malformed batcher data should be skipped, as op-node does, and not treated as critical. Only real provider or consistency failures should be critical.
- Add differential tests that run the same L1 fixtures (including edge-case blobs: all-zero, maximum length, invalid version) through op-node and kona-derive.

## References

- Fix commit: c831a5f7638661676f784cdbf3fb990b8b1691d1 (https://github.com/op-rs/kona/pull/3001)
- Relevant files: `crates/protocol/derive/src/sources/blob_data.rs`, `crates/protocol/derive/src/sources/blobs.rs`, `crates/protocol/derive/src/errors/sources.rs`, `crates/node/service/src/actors/derivation.rs`, `crates/proof/driver/src/pipeline.rs`; op-node reference `op-node/rollup/derive/blob_data_source.go`
- Spec: https://specs.optimism.io/protocol/ecotone/derivation.html#blob-encoding
