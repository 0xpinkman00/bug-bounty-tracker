# kona-client FPVM precompiles: post-Jovian specs (INTEROP/OSAKA) mapped to the Isthmus accelerated set, a latent divergence caught before activation

| Field | Value |
|---|---|
| **Target** | `rust/kona/bin/client/src/fpvm_evm/precompiles/provider.rs` (`OpFpvmPrecompiles::new_with_spec`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Informational (latent, pre-activation) |
| **Impact category** | None realized. Had it reached a hardfork that selects `OpSpecId::OSAKA` (later renamed `KARST`) or `INTEROP`, it would have been fault-proof unsoundness ("Unintended chain split" between the kona FPP and the EL) |
| **Fix commit(s)** | 44beaad6cb7a1b4100f4c6248eb6274a29154497 (PR #20003, optimism-private#470), 2026-04-13 |
| **Vulnerable since** | e0b86ed25d (op-rs/kona#2934, 2025-10-14) for the non-accelerated grouping. The accelerated grouping has existed since the INTEROP/OSAKA variants were introduced. First fixed release: `kona-client/v1.5.1` (before the Karst prestate `kona-client/v1.6.0-rc.2`) |

## Brief / Intro

kona's fault-proof program replaces some EVM precompiles with "accelerated" versions that ask the host for the result, and uses op-revm's regular precompiles for the rest. Jovian added input-size caps to four precompiles (bn254 pairing and the BLS12-381 G1/G2 MSM and pairing). The mapping from hardfork spec to precompile set was wrong in two places. The triage claim was that Jovian limits were not enforced on the live Jovian fork. **That claim is incorrect:** on `JOVIAN` the accelerated Jovian versions of all four capped precompiles were active and override the wrong inner set. The part that really was wrong only applied to the later `INTEROP` and `OSAKA` specs. kona did not select either spec on any production chain when the fix landed.

## Vulnerability Details

Parent of the fix, `provider.rs:43-66`:

```rust
let precompiles = match spec {
    ...
    OpSpecId::GRANITE | OpSpecId::HOLOCENE => granite(),
    OpSpecId::ISTHMUS | OpSpecId::INTEROP | OpSpecId::OSAKA | OpSpecId::JOVIAN => isthmus(),  // (1)
};
let accelerated_precompiles = match spec {
    ...
    OpSpecId::ISTHMUS | OpSpecId::INTEROP | OpSpecId::OSAKA => accelerated_isthmus::<H, O>(), // (2)
    OpSpecId::JOVIAN => accelerated_jovian::<H, O>(),
};
```

`run()` checks `accelerated_precompiles` first and uses `inner` only as a fallback.

- **(1) JOVIAN → `isthmus()` inner set: no observable effect.** op-revm's `jovian()` is `isthmus()` with exactly four entries replaced (`rust/op-revm/src/precompiles.rs:90-115`: bn254 pair, BLS G1 MSM, G2 MSM, pairing). `accelerated_jovian()` overrides those same four addresses with Jovian-limited versions. For example, `fpvm_bn128_pair_jovian` rejects `input.len() > BN256_MAX_PAIRING_SIZE_JOVIAN` (81,984) before hinting. So on JOVIAN the inner set is never consulted for a capped precompile, and the address set (`contains`, `warm_addresses`) is the same.
- **(2) INTEROP / OSAKA → `accelerated_isthmus()`: real but latent.** With both sets on Isthmus limits, a bn254 pairing input between 81,984 and 112,687 bytes would succeed in kona and fail in op-reth, and the same for the three BLS precompiles. But at the parent commit `RollupConfig::spec_id` (`rust/kona/crates/protocol/genesis/src/rollup.rs:173-193`) returned only `INTEROP` (interop active, which was true of no production chain) or a spec up to `JOVIAN`. `OSAKA` was never selected.

Fix:

```rust
-            OpSpecId::ISTHMUS | OpSpecId::INTEROP | OpSpecId::OSAKA | OpSpecId::JOVIAN => isthmus(),
+            OpSpecId::ISTHMUS => isthmus(),
+            OpSpecId::JOVIAN | OpSpecId::INTEROP | OpSpecId::OSAKA => jovian(),
 ...
-            OpSpecId::ISTHMUS | OpSpecId::INTEROP | OpSpecId::OSAKA => accelerated_isthmus::<H, O>(),
-            OpSpecId::JOVIAN => accelerated_jovian::<H, O>(),
+            OpSpecId::ISTHMUS => accelerated_isthmus::<H, O>(),
+            OpSpecId::JOVIAN | OpSpecId::INTEROP | OpSpecId::OSAKA => accelerated_jovian::<H, O>(),
```

This matches `op_revm::OpPrecompiles::new_with_spec` (`rust/op-revm/src/precompiles.rs:28-41`).

### Attack scenario (had it shipped past activation)

1. A chain activates a fork that kona maps to `OSAKA`. `OSAKA` was later renamed `KARST`, and Karst activated on mainnet on 2026-07-08.
2. Any user calls the bn254 pairing precompile with 90,000 bytes of input from a contract that branches on success.
3. op-reth fails the call (Jovian limit). kona-client succeeds (Isthmus limit), so kona's post-state root differs.
4. `CANNON_KONA` games covering that block are decided against the canonical chain. After Karst `CANNON_KONA` is the respected game type, so this would have been Critical.

## Impact Details

No impact was realized. Point (1) is behaviourally neutral. Point (2) could only trigger on specs kona did not select in production when the fix landed. The fix reached `kona-client/v1.5.1` (2026-05-12), ahead of the Karst prestate. The report is kept as Informational because the fix did prevent a would-be Critical divergence at the next hardfork.

## Proof of Concept

The fix's regression test `test_post_jovian_specs_use_jovian_precompiles` asserts that INTEROP and OSAKA get the Jovian accelerated address set and the `jovian()` inner set. It fails on the parent. A behavioural version for the OSAKA gap:

```rust
// add to `mod test` in rust/kona/bin/client/src/fpvm_evm/precompiles/provider.rs at 44beaad6cb^
#[test]
fn poc_osaka_accepts_oversized_bn254_pairing() {
    let (h, p) = (kona_preimage::BidirectionalChannel::new().unwrap(),
                  kona_preimage::BidirectionalChannel::new().unwrap());
    let osaka = OpFpvmPrecompiles::new_with_spec(
        OpSpecId::OSAKA, kona_preimage::HintWriter::new(h.client),
        kona_preimage::OracleReader::new(p.client));
    // The Jovian-limited accelerated fn must be installed for OSAKA.
    let f = osaka.accelerated_precompiles.get(&bn254::pair::ADDRESS).unwrap();
    let jovian_fn = super::super::bn128_pair::fpvm_bn128_pair_jovian::<_, _> as usize;
    assert_eq!(*f as usize, jovian_fn, "OSAKA uses Isthmus (Granite-limit) bn254 pairing");
}
```

```bash
git worktree add /tmp/kona-01-03 44beaad6cb^
cd /tmp/kona-01-03/rust && cargo test -p kona-client test_post_jovian_specs_use_jovian_precompiles
# parent: FAIL ("INTEROP should use Jovian accelerated precompiles"); fix: PASS
```

(Comparing function pointers can be flaky across codegen units. The fix's address-set and `ptr::eq` assertions are the reliable check.)

Executed: no.

## Recommendation

The fix is correct. Replace the hand-maintained match arms with a derivation from `op_revm::OpPrecompiles::new_with_spec(spec)` plus an override table keyed by address. Add a test that iterates every `OpSpecId` and checks that each accelerated function's input-limit behaviour matches op-revm's precompile at that spec, so a new spec variant cannot silently fall into an older group.

## References

- Fix commit: 44beaad6cb7a1b4100f4c6248eb6274a29154497
- Pull request: https://github.com/ethereum-optimism/optimism/pull/20003
- Relevant files: `rust/kona/bin/client/src/fpvm_evm/precompiles/provider.rs`, `rust/kona/bin/client/src/fpvm_evm/precompiles/bn128_pair.rs`, `rust/op-revm/src/precompiles.rs`, `rust/kona/crates/protocol/genesis/src/rollup.rs`
- Specs: https://specs.optimism.io/protocol/jovian/exec-engine.html (precompile input limits); `docs/public-docs/op-stack/protocol/hardforks/karst.mdx`
