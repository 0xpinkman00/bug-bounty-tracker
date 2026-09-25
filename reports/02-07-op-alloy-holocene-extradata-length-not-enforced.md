# op-alloy Holocene extraData decoder accepts headers longer than 9 bytes, so Rust clients can disagree with op-geth/op-node on block validity

| Field | Value |
|---|---|
| **Target** | `op-alloy-consensus` `decode_holocene_extra_data` (today `rust/op-alloy/crates/consensus/src/eip1559.rs`). Consumers: op-reth base-fee validation (`chainspec/src/basefee.rs`), kona-node attribute consolidation (`crates/node/engine/src/attributes.rs`), kona-protocol `to_system_config`, kona executor |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | "Unintended chain split (network partition)". Downgraded: only the sequencer can produce such a block, and the only divergent pairing found is kona-node (pre-production at the time) on op-reth |
| **Fix commit(s)** | 44c20e4451b13d39b5ac200e815ddb0e8a21d0bb (alloy-rs/op-alloy#596), 2025-09-12 |
| **Vulnerable since** | 2d00b4e0db "feat: upstream decode extradata fn" (alloy-rs/op-alloy#340), 2024-12-12. The lenient `< 9` check dates from the Holocene extraData work in reth (c4263f11a6, paradigmxyz/reth#11887, 2024-10-30). Live about 9 months, all of it after Holocene activation on mainnet. |

## Brief / Intro

Since the Holocene upgrade, every OP Stack L2 block header carries its EIP-1559 fee parameters in the `extraData` field. The field is a version byte `0x00` followed by 8 bytes of parameters. The spec requires it to be **exactly 9 bytes**. op-geth and op-node enforce that length. The shared Rust decoder in op-alloy only rejected headers *shorter* than 9 bytes. It read the first 9 bytes of a longer field and ignored the rest. Rust clients (op-reth, kona) could therefore accept a block that Go clients reject. Only the sequencer signs and gossips unsafe blocks, so only a malicious or buggy sequencer could produce such a block.

## Vulnerability Details

Parent of fix, `crates/consensus/src/eip1559.rs:51-62`:

```rust
pub fn decode_holocene_extra_data(extra_data: &[u8]) -> Result<(u32, u32), EIP1559ParamError> {
    if extra_data.len() < 9 {                       // <-- only a lower bound
        return Err(EIP1559ParamError::NoEIP1559Params);
    }
    if extra_data[0] != HOLOCENE_EXTRA_DATA_VERSION_BYTE {
        return Err(EIP1559ParamError::InvalidVersion(extra_data[0]));
    }
    // skip the first version byte
    Ok(decode_eip_1559_params(B64::from_slice(&extra_data[1..9])))   // trailing bytes ignored
}
```

The Go side, which op-geth uses in header verification and op-node uses in consolidation (`op-core/eip1559/eip1559.go:119-126`, extracted verbatim from op-geth), is strict:

```go
func ValidateHoloceneExtraData(extra []byte) error {
    if len(extra) != 9 {
        return fmt.Errorf("holocene extraData should be 9 bytes, got %d", len(extra))
    }
    ...
```

Where the lenient decoder mattered at the time:

1. **op-reth** does not check the format of a block's *own* `extraData` in header validation. It only checks the generic 32-byte maximum (`validate_header_extra_data`). It decodes the **parent's** `extraData` to check the child's base fee (`decode_holocene_base_fee`). op-reth therefore imports a 10-byte-extraData block B and, before the fix, also every child of B.
2. **kona-node consolidation** (`crates/node/engine/src/attributes.rs:209`, at aae831824b, the version current when the fix landed) decides whether an unsafe block matches the derived attributes by decoding the block's `extraData` with this function. If the first 9 bytes match the attributes, it declares the unsafe block matching and promotes it to safe. op-node instead calls `eip1559.ValidateOptimismExtraData` (`op-node/rollup/attributes/engine_consolidate.go:124`). op-node rejects the block and reorgs it out in favour of a freshly built block with a 9-byte `extraData`.

The fix makes the length check exact:

```diff
-    if extra_data.len() < 9 {
-        return Err(EIP1559ParamError::NoEIP1559Params);
+    // Holocene extra data is always 9 _exactly_ bytes
+    if extra_data.len() != 9 {
+        return Err(EIP1559ParamError::InvalidExtraDataLength);
     }
```

Note on the triage claim: the triage said the old code "let Jovian-format (17-byte) extraData decode as Holocene". That is **not** the case for real Jovian headers. They start with version byte `0x01` and were already rejected by the version check. The PoC below confirms this. Only a 17-byte header with version `0x00` would have slipped through.

### Attack scenario

1. A malicious or buggy sequencer builds block B whose header `extraData` is the correct 9 bytes plus one or more trailing bytes. It signs B and gossips it. The block hash covers `extraData`, so B is a distinct block.
2. op-geth nodes reject B at header verification. op-reth nodes import B as their unsafe head, and before the fix they also import its children.
3. When the batch for B's height is derived from L1, the derived attributes produce a 9-byte `extraData`. op-node (on either EL) sees a mismatch and reorgs B out. kona-node's consolidation on op-reth sees a match on the first 9 bytes and keeps B as **safe**. From that point kona-node/op-reth has a safe chain that differs from op-node's.

## Impact Details

- **Who is affected:** kona-node running on op-reth. In September 2025 kona-node was still pre-production. op-node + op-reth only shows a transient unsafe-head difference, which derivation corrects. The fault-proof programs are not affected: kona-client builds the block itself from derived attributes, so the `extraData` is always 9 bytes.
- **Who can trigger it:** only the sequencer. Blocks with a bad `extraData` never come out of derivation, and only the sequencer's key signs gossip.
- **Residual gap:** even after this fix, op-reth does not check the format of a block's own Holocene `extraData` at import. It fails only when it validates a *child* of that block. That is still one block later than op-geth. Worth a follow-up; see Recommendation.
- **Severity:** a sequencer-only trigger and a pre-production consumer reduce this from the nominal "Unintended chain split" (High) to **Low**.

## Proof of Concept

The fix commit added `test_encode_holocene_invalid_length`, which truncates to 8 bytes. That case was already rejected before the fix, so it does not show the bug. The PoC below tests the *longer-than-9* case directly. It compiles the parent and fixed versions of `eip1559.rs` side by side in a scratch crate. The file only depends on `alloy-eips`, `alloy-primitives` and `thiserror`, so no repo changes are needed.

```bash
S=$(mktemp -d); mkdir -p $S/src
cd /home/trevor/workspace/audits/optimism
git show 44c20e4451^:crates/consensus/src/eip1559.rs > $S/src/parent.rs
git show 44c20e4451:crates/consensus/src/eip1559.rs  > $S/src/fixed.rs
cat > $S/Cargo.toml <<'EOF'
[package]
name = "poc0207"
version = "0.1.0"
edition = "2021"
[features]
fixed = []
[dependencies]
alloy-eips = { version = "1", default-features = false }
alloy-primitives = { version = "1", default-features = false }
thiserror = { version = "2", default-features = false }
EOF
cat > $S/src/lib.rs <<'EOF'
#[cfg(not(feature = "fixed"))] #[path = "parent.rs"] pub mod eip1559;
#[cfg(feature = "fixed")]      #[path = "fixed.rs"]  pub mod eip1559;

#[cfg(test)]
mod poc {
    use super::eip1559::*;
    use alloy_eips::eip1559::BaseFeeParams;
    use alloy_primitives::B64;

    /// Holocene spec: extraData MUST be exactly 9 bytes. A 10-byte header must be rejected.
    #[test]
    fn poc_holocene_extra_data_longer_than_9_bytes_is_rejected() {
        let mut extra = encode_holocene_extra_data(B64::ZERO, BaseFeeParams::new(250, 6))
            .unwrap().to_vec();
        extra.push(0xff); // 10 bytes: invalid per spec, rejected by op-geth / op-node
        let res = decode_holocene_extra_data(&extra);
        assert!(res.is_err(), "10-byte Holocene extraData was accepted: {:?}", res);
    }

    /// Real Jovian extraData (version 0x01) must not decode as Holocene.
    #[test]
    fn poc_jovian_extra_data_does_not_decode_as_holocene() {
        let extra = encode_jovian_extra_data(B64::ZERO, BaseFeeParams::new(250, 6), 1_000).unwrap();
        assert!(decode_holocene_extra_data(&extra).is_err());
    }
}
EOF
cd $S
cargo test                     # parent code: poc_holocene_... FAILS
cargo test --features fixed    # fixed code: all pass
```

Executed: **yes** (offline, against cached crates).
- Parent: `poc_holocene_extra_data_longer_than_9_bytes_is_rejected ... FAILED` with `10-byte Holocene extraData was accepted: Ok((6, 250))`. The Jovian test passes, which confirms that real Jovian headers were already rejected by the version byte.
- Fix: `test result: ok. 10 passed; 0 failed`.

## Recommendation

The fix is correct and minimal: it enforces `len == 9` exactly, matching the spec and op-geth. Defense in depth:

- Make op-reth validate the format of a block's *own* Holocene/Jovian `extraData` during header validation, as op-geth does (`ValidateOptimismExtraData`). Today a malformed header is only caught when its child is validated.
- Keep differential tests between `op-core/eip1559` (Go) and `op-alloy-consensus` (Rust) over randomized `extraData` lengths and versions.

## References

- Fix commit: 44c20e4451b13d39b5ac200e815ddb0e8a21d0bb
- Pull request: https://github.com/alloy-rs/op-alloy/pull/596 (imported into this monorepo's history)
- Relevant files: `rust/op-alloy/crates/consensus/src/eip1559.rs`, `rust/op-reth/crates/chainspec/src/basefee.rs`, `rust/op-reth/crates/consensus/src/lib.rs`, `rust/kona/crates/node/engine/src/attributes.rs`, `op-core/eip1559/eip1559.go`, `op-node/rollup/attributes/engine_consolidate.go`
- Spec: https://github.com/ethereum-optimism/specs/blob/main/specs/protocol/holocene/exec-engine.md#eip-1559-parameters-in-block-header
