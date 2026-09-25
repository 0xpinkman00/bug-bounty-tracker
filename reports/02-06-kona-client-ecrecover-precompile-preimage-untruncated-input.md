# kona-client (FPVM): accelerated ecrecover built its precompile preimage from the full, unbounded calldata instead of the 128 bytes ecrecover reads

| Field | Value |
|---|---|
| **Target** | kona `bin/client/src/fpvm_evm/precompiles/ecrecover.rs` (`fpvm_ec_recover`), used by the kona fault-proof program (cannon-kona / kona-based proving). Now under `rust/kona/` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (pre-production: CANNON_KONA was not yet a live game type) |
| **Impact category** | Fault-proof liveness/robustness: a precompile preimage the challenger may be unable to post onchain. The closest in-scope category is "Causing network processing nodes to process transactions from the mempool beyond set parameters" / griefing of the proof system. Not directly a loss of funds |
| **Fix commit(s)** | 40f622c8698ca84450308fffc90d183ab8191f5d (op-rs/kona#3002), 2025-11-04 |
| **Vulnerable since** | At least d20b8ae17f "feat: Use `alloy-evm` for stateless block building" (op-rs/kona#1400), 2025-04-15 |

## Brief / Intro

Fault-proof programs such as op-program and kona-client re-execute L2 blocks inside a MIPS emulator (Cannon). Signature recovery (the `ecrecover` precompile) is too expensive to run in there. The program therefore asks an external "preimage oracle" for the result. The key it asks for is a hash of the precompile address, the gas and the input bytes. If a dispute ever reaches exactly that instruction, someone has to load the same input onto the L1 `PreimageOracle` contract so the step can be checked onchain. `ecrecover` reads only the first 128 bytes of its input and costs a flat 3,000 gas however long the input is. op-program therefore truncates the input to 128 bytes before building the key. kona-client used the *entire* calldata. An L2 user can call `ecrecover` with a very large input: the only cost is memory expansion on L2, while the precompile charge stays at 3,000 gas. That forces kona's preimage to be arbitrarily large. A preimage much larger than what fits in an L1 transaction cannot be loaded onchain, so the step that depends on it cannot be proven.

## Vulnerability Details

`bin/client/src/fpvm_evm/precompiles/ecrecover.rs:13-38` (parent of fix)
```rust
pub(crate) fn fpvm_ec_recover<H, O>(input: &[u8], gas_limit: u64, hint_writer: &H, oracle_reader: &O)
    -> PrecompileResult
{
    const ECRECOVER_BASE: u64 = 3_000;
    if ECRECOVER_BASE > gas_limit { return Err(PrecompileError::OutOfGas); }

    let result_data = kona_proof::block_on(precompile_run! {
        hint_writer,
        oracle_reader,
        &[ECRECOVER_ADDR.as_slice(), &ECRECOVER_BASE.to_be_bytes(), input]   // full calldata
    })
    .map_err(|e| PrecompileError::Other(e.to_string()))
    .unwrap_or_default();
    Ok(PrecompileOutput::new(ECRECOVER_BASE, result_data.into()))
}
```

`precompile_run!` (`bin/client/src/fpvm_evm/precompiles/utils.rs`) sends the whole concatenation as an `L1Precompile` hint. The preimage key is `keccak256(addr ‖ gas ‖ input)` with type byte 6. Onchain, `PreimageOracle.loadPrecompilePreimagePart(_partOffset, _precompile, _requiredGas, bytes calldata _input)` (`packages/contracts-bedrock/src/cannon/PreimageOracle.sol:403-448`) recomputes that key from `_input` as calldata and runs the precompile on it. To prove a step that reads the preimage, a challenger must therefore submit the *entire* original input to L1.

op-program (`op-program/client/l2/engineapi/precompiles.go`, `ecrecoverOracle.Run`) truncates first:

```go
const ecRecoverInputLength = 128
if len(input) > ecRecoverInputLength {
    input = input[:ecRecoverInputLength]
}
input = common.RightPadBytes(input, ecRecoverInputLength)
...
result, ok := c.Oracle.Precompile(ecrecoverPrecompileAddress, input, c.RequiredGas(input))
```

Its preimage input is therefore always exactly 128 bytes, however large the L2 calldata.

The *result* was never wrong. The host computes ecrecover natively, and native ecrecover ignores bytes past 128. So kona-client produced correct output roots offchain, and the fix's new test `test_accelerated_ecrecover_with_extra_bytes` passes on both versions. The defect is the size of the preimage and whether it can be posted onchain.

A note on the triage framing: kona's keys differing from op-program's is not a problem in itself. cannon-kona is a separate game type with its own prestate, and the challenger uploads whatever preimage the kona trace needs. The real risk is that the key covers unbounded, attacker-sized data.

**Fix:**
```diff
+    let truncated_input = &input[..input.len().min(128)];
     let result_data = kona_proof::block_on(precompile_run! {
         hint_writer,
         oracle_reader,
-        &[ECRECOVER_ADDR.as_slice(), &ECRECOVER_BASE.to_be_bytes(), input]
+        &[ECRECOVER_ADDR.as_slice(), &ECRECOVER_BASE.to_be_bytes(), truncated_input]
     })
```

Truncating does not change the result, because ecrecover ignores bytes past 128. Unlike op-program, kona does not right-pad short inputs. That is harmless: the host pads natively, and the onchain `staticcall` pads implicitly.

### Attack scenario

1. On an L2 whose proofs use cannon-kona, an attacker sends a transaction that calls `ecrecover` (address `0x01`) with, say, 1–3 MiB of calldata or memory. On L2 this costs roughly calldata/memory gas plus 3,000. For example, 1 MiB of memory is about 2.2M gas.
2. The kona-client trace for any output root covering that block contains a preimage read whose key commits to about 1–3 MiB of input.
3. The attacker disputes (or proposes) so that the bisection ends on that instruction. The party who must step has to call `loadPrecompilePreimagePart` with the full input. That is far above the ~128 KiB public-mempool transaction size limit and near or above what fits in an L1 block's gas at post-Pectra calldata prices. If the preimage cannot be loaded, the step cannot be executed, and that party times out.

Step 3 needs the bisection to land on that exact preimage read. An honest challenger chooses its own moves, so an attacker cannot force this easily. The realistic outcome is a griefing / liveness risk rather than a reliable theft path.

## Impact Details

- **Scope and maturity:** kona-client with Cannon ("cannon-kona") was not a production dispute game at fix time. The commit says it was fixed "in preparation for adding Kona + Cannon to OP Stack fault proofs", and the CANNON_KONA game type was dev-feature gated in OPContractsManager. No live game could be affected.
- **Worst case if shipped:** some execution steps could not be proven onchain. That could let a dishonest party win a subgame by forcing a timeout, or at least make honest defence very expensive (huge L1 calldata posted privately to a builder). Offchain, the host must also serve and hash arbitrarily large hints, which is a resource concern for challengers.
- **Severity:** Low, because the component was pre-production. The same issue in a live fault-proof program would deserve at least Medium, given the potential for an unprovable step in a dispute game.

## Proof of Concept

The fix's regression test (`test_accelerated_ecrecover_with_extra_bytes`) checks only the *result*, which was correct before the fix too. It does not distinguish the versions. The PoC below instead checks the size of the hint/preimage input that the client emits. It wraps the hint channel of the existing test harness, so it needs a small helper that records the last hint. Sketch:

```rust
// bin/client/src/fpvm_evm/precompiles/ecrecover.rs, inside `mod test`
#[tokio::test(flavor = "multi_thread")]
async fn poc_ecrecover_preimage_input_is_bounded() {
    test_accelerated_precompile(|hint_writer, oracle_reader| {
        // Valid 128-byte signature input followed by 1 MiB of junk.
        let mut input = TEST_INPUT.to_vec();
        input.extend(core::iter::repeat(0xFF).take(1 << 20));

        // The key committed to by the client is keccak(addr || gas || <preimage input>).
        // Recompute what the client *should* request (128-byte input) and check that the
        // oracle was asked for exactly that key.
        let bounded_key = alloy_primitives::keccak256(
            [ECRECOVER_ADDR.as_slice(), &3_000u64.to_be_bytes(), &input[..128]].concat(),
        );
        let res = fpvm_ec_recover(&input, u64::MAX, hint_writer, oracle_reader).unwrap();
        assert_eq!(res.bytes.as_ref(), EXPECTED_RESULT.as_ref());
        // With a recording oracle wrapper (test_utils) assert:
        //   last_requested_key == PreimageKey::new(*bounded_key, PreimageKeyType::Precompile)
        // Parent commit: the requested key is keccak over 20+8+128+1_048_576 bytes -> assertion fails.
        // Fix commit:    the requested key is keccak over 20+8+128 bytes            -> passes.
    }).await;
}
```

A simpler check that needs no harness change is to read the hint length. `precompile_run!` sends `HintType::L1Precompile.with_data(&[addr, gas, input])`. On the parent the hint payload is `28 + input.len()` bytes (1,048,732 bytes here). On the fix it is `28 + min(input.len(), 128)` = 156 bytes. The host's `route_hint` in `test_utils.rs` receives this hint string and can log or assert its length.

Run (kona workspace from `git archive <rev>`): `cargo test -p kona-client poc_ecrecover_preimage_input_is_bounded`.

**Executed: no.** The kona-client build was not run in this session. The behaviour follows directly from the one-line diff and the `precompile_run!` macro, which hashes and hints exactly the slice it is given.

## Recommendation

The fix is correct and matches op-program. Further suggestions:

- Audit every accelerated precompile in kona-client for the same property: the preimage input must be bounded by what the precompile actually reads, or by its gas cost. For example, check the bn254 pairing input (bounded by gas per pair) and KZG point evaluation (fixed 192 bytes).
- `fpvm_ec_recover` calls `.unwrap_or_default()` on oracle errors, which turns a failed preimage fetch into an empty (failed-recovery) result instead of aborting. In an FPVM that can silently change execution. Consider propagating the error.
- Add a differential test between op-program and kona-client precompile hint sizes for oversized inputs.

## References

- Fix commit: 40f622c8698ca84450308fffc90d183ab8191f5d (https://github.com/op-rs/kona/pull/3002)
- Relevant files: `bin/client/src/fpvm_evm/precompiles/ecrecover.rs`, `bin/client/src/fpvm_evm/precompiles/utils.rs`; op-program reference `op-program/client/l2/engineapi/precompiles.go`; `packages/contracts-bedrock/src/cannon/PreimageOracle.sol` (`loadPrecompilePreimagePart`)
- Specs: https://specs.optimism.io/fault-proof/index.html#pre-image-oracle (precompile preimage key type 6)
