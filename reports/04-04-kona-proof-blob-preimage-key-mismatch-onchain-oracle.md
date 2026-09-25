# kona fault-proof program: blob preimage keys did not match the on-chain PreimageOracle, so blob steps could not be proven on-chain

| Field | Value |
|---|---|
| **Target** | kona `crates/proof/proof/src/l1/blob_provider.rs` (`OracleBlobProvider`), `bin/host/src/single/handler.rs`, `bin/host/src/interop/handler.rs`. Now under `rust/kona/` |
| **Asset type** | Blockchain/DLT (fault-proof program, used together with the on-chain `PreimageOracle`) |
| **Severity** | Low (kona-based game types were not respected on any chain with value; would be High/Critical for a live kona-secured game type) |
| **Impact category** | If live: "Direct loss of funds" (honest parties' dispute bonds) and fault-proof unsoundness, i.e. an invalid output root that can be defended on-chain |
| **Fix commit(s)** | b053d346f46e7255af109c7b31400136d583f849 (op-rs/kona#1473), 2025-04-21 |
| **Vulnerable since** | 620718579f "feat(client/host): Oracle-backed Blob fetcher" (op-rs/kona#255), 2024-06-16, about 10 months |

## Brief / Intro

A fault-proof program runs inside a small VM (Cannon or Asterisc). It gets outside data, such as L1 blobs, by asking a *preimage oracle* for the value stored under a key. Off-chain, the host program answers these requests. On-chain, when a dispute narrows down to one VM instruction that reads oracle data, someone must first load that exact key and value into the `PreimageOracle` contract, which only accepts values it can verify cryptographically. Kona built its blob keys differently from the contract. Off-chain, kona's client and host agreed with each other, so tests passed. On-chain, the value the contract accepts under kona's key is a different number from the one the host supplied off-chain. An honest party could therefore never prove a blob-reading step, and a dishonest party could use the difference.

## Vulnerability Details

EIP-4844 blobs are polynomials. The *i*-th field element of a blob is the polynomial evaluated at `z = ω_i`, the *i*-th bit-reversed 4096th root of unity. The on-chain oracle (`src/cannon/PreimageOracle.sol`, `loadBlobPreimagePart`) checks `(z, y)` against the commitment with the point-evaluation precompile and stores `y` under:

```solidity
// Compute the key: `keccak256(commitment ++ z)`.
calldatacopy(ptr, _commitment.offset, 0x30)
mstore(add(ptr, 0x30), _z)
let h := keccak256(ptr, 0x50)
key := or(and(h, not(shl(248, 0xFF))), shl(248, 0x05))   // type-5 blob key
```

op-program uses the same key, `commitment ++ ω_i` (see `op-service/kzg/roots_of_unity.go`).

Kona (parent of the fix, `crates/proof/proof/src/l1/blob_provider.rs`, `get_blob`) used the *index* `i` instead:
```rust
let mut field_element_key = [0u8; 80];
field_element_key[..48].copy_from_slice(commitment.as_ref());
for i in 0..FIELD_ELEMENTS_PER_BLOB {
    field_element_key[72..].copy_from_slice(i.to_be_bytes().as_ref());   // uint256(i), not ω_i
    ...
    self.oracle.get_exact(PreimageKey::new(*keccak256(field_element_key), PreimageKeyType::Blob), ...)
```
The host (`bin/host/src/single/handler.rs`, and the same code in `interop/handler.rs`) stored `blob[i]`, the true field element, under that same key, so off-chain runs were self-consistent.

On-chain, the only value `loadBlobPreimagePart` can store under `keccak(commitment ++ uint256(i))` is `y = p(i)`, the blob polynomial evaluated at the *integer* `i`, because the precompile must verify `p(z) = y` with `z = i`. For almost every `i`, `p(i) ≠ p(ω_i) = blob[i]`. One easy case to see: bit-reversed index 1 is `ω^2048 = -1`, so the value provable for kona's key `i = 0` is `p(0)`, and neither key holds the value kona expected.

Fix: derive the key from the bit-reversed root of unity, exactly as the contract does:
```diff
-            field_element_key[72..].copy_from_slice(i.to_be_bytes().as_ref());
+            field_element_key[48..]
+                .copy_from_slice(ROOTS_OF_UNITY[i as usize].into_bigint().to_bytes_be().as_ref());
```
The same change is made in both host handlers, together with a new `ROOTS_OF_UNITY` table and a test (`test_roots_of_unity`) that checks each `ω_i` against c-kzg. The 4097th entry (the whole-blob KZG proof, keyed by `uint256(4096)`) was intentionally left as is for ZK users.

### Attack scenario (for a kona-based game type)

1. A dispute game uses kona-client on a fault-proof VM. The disputed L2 block range is derived from L1 blocks that carry blob batches, which has been the normal case since Ecotone.
2. The bisection ends on a VM step that reads a blob field element through a type-5 key.
3. The honest party, whose host serves `blob[i]`, must load the preimage on-chain before calling `step`. The contract will only store `p(i)` under that key. The honest party's off-chain trace assumed `blob[i]`, so its committed post-state does not match what the on-chain VM computes. It loses the step and its bonds.
4. A dishonest party can go further. Running kona with oracle values `p(i)`, the only values the contract accepts, gives a well-defined but wrong derivation, where the blob decodes to garbage and the batch is dropped. That leads to a different output root, and the on-chain VM agrees with every step of it. An invalid root can then be defended and a valid one can be successfully challenged.

## Impact Details

- **Where it applies:** every kona-based interactive fault-proof game (for example `ASTERISC_KONA`) whose disputed range reads blob data. Off-chain determinism tests could not catch this, because host and client shared the same wrong convention.
- **Consequence if live:** honest challengers or defenders lose their bonds. In the worst case an invalid output root finalizes, which would allow fraudulent withdrawals if that game type were respected by the portal.
- **Mitigating factors:** at the time, no chain used a kona-based game type as its respected game type for withdrawals. OP Mainnet and others used Cannon with op-program, which already used the correct keys. kona game types ran only as secondary or test deployments. ZK users of kona check whole blobs against the commitment using the unchanged 4097th key, so they were not affected.

Given the deployment status, the rating is **Low**. For a chain that respected a kona game type it would be Critical (a provably invalid state root).

## Proof of Concept

This test shows that the key kona asked for can only be loaded on-chain with `y = p(i)`, and that this value differs from the blob element the host served. Place it in `crates/proof/proof/src/l1/blob_provider.rs` tests (the fix commit adds the `c-kzg` and `rand` dev-dependencies it needs; at the parent, add `c-kzg = "2"` as a dev-dependency):

```rust
#[test]
fn poc_kona_blob_key_value_not_loadable_onchain() {
    use alloy_eips::eip4844::env_settings::EnvKzgSettings;
    use c_kzg::{Blob, Bytes32, BYTES_PER_BLOB};

    let kzg = EnvKzgSettings::default();
    let mut bytes = [0u8; BYTES_PER_BLOB];
    for i in 0..4096usize { bytes[i * 32 + 31] = (i % 251) as u8 + 1; } // distinct, in-range elements
    let blob = Blob::new(bytes);

    for i in [0u64, 1, 2, 7, 4095] {
        // What PreimageOracle.loadBlobPreimagePart would accept for kona's OLD key
        // keccak(commitment ++ uint256(i)): it verifies p(z)=y with z = i.
        let mut z = [0u8; 32];
        z[24..].copy_from_slice(&i.to_be_bytes());
        let (_proof, y_onchain) = kzg.get().compute_kzg_proof(&blob, &Bytes32::new(z)).unwrap();

        // What kona's host served off-chain under the same key.
        let served = &bytes[(i as usize) * 32..(i as usize + 1) * 32];

        assert_ne!(y_onchain.as_slice(), served, "i={i}: on-chain value would match (unexpected)");
    }
}
```

Run (in a kona tree at `b053d346f4^` with the dev-dep added):
```bash
cargo test -p kona-proof --lib poc_kona_blob_key_value_not_loadable_onchain
```
The test passes. It shows the *mismatch* between the value that can be loaded on-chain under the old key and the value served off-chain, which is the root cause. The fix's own `test_roots_of_unity` shows the reverse: with `z = ROOTS_OF_UNITY[i]`, the evaluation equals `blob[i]` and the KZG proof verifies. The key kona now requests is therefore loadable on-chain with the correct value.

Executed: **no**. The historical kona workspace was not built in this session.

## Recommendation

The fix is correct. Suggested follow-ups:
- Add a cross-implementation test that computes the blob preimage keys from op-program's host and kona's host for the same sidecar and asserts they are equal, so the two stay in sync.
- For every preimage type, add an "on-chain loadability" test that replays kona's oracle requests from a trace against `PreimageOracle` in Foundry. That would have caught this bug.

## References

- Fix commit: b053d346f46e7255af109c7b31400136d583f849 (https://github.com/op-rs/kona/pull/1473)
- Introducing commit: 620718579f (https://github.com/op-rs/kona/pull/255)
- Relevant files: `crates/proof/proof/src/l1/blob_provider.rs`, `bin/host/src/single/handler.rs`, `bin/host/src/interop/handler.rs`, `packages/contracts-bedrock/src/cannon/PreimageOracle.sol`, `op-service/kzg/roots_of_unity.go`
- Spec: https://specs.optimism.io/fault-proof/index.html#type-5-global-eip-4844-point-evaluation-key
