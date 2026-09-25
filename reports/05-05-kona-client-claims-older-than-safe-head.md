# kona fault-proof client: claims about blocks older than the agreed safe head were checked against the agreed output root, so kona could declare an invalid claim valid

| Field | Value |
|---|---|
| **Target** | kona fault-proof program: `bin/client/src/lib.rs` (`run`) and `crates/proof-sdk/proof/src/sync.rs` (`new_pipeline_cursor`). Today this is `rust/kona/bin/client/src/single.rs` and `rust/kona/crates/proof/...` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (pre-production kona; the same bug in a live proof program would be rated High) |
| **Impact category** | Class: fault-proof unsoundness, "Direct loss of funds" (dispute bonds) / invalid state-transition proof. Downgraded because at the time kona did not back any production dispute game |
| **Fix commit(s)** | `52096e93b44ca8ec0b0bcad474b4f6bdf0b5cae4` (op-rs/kona#852), 2024-11-27 |
| **Vulnerable since** | Unknown. The client special-cased only `claimed_l2_block_number == 0` from the start of the `Driver`-based client |

## Brief / Intro

A fault-proof program answers one question inside an on-chain dispute game: "starting from this *agreed* L2 output root, is the *claimed* output root correct for L2 block N?" kona is the Rust implementation of that program. Before this fix, if the claimed block N was *older* than the block committed to by the agreed output root, kona did no derivation at all. It simply compared the claim with the agreed output root. A claim of the form "block N has output root R", where R is really the output root of a *later* block M > N, was therefore reported as **valid**. The Go reference (op-program) reports it as **invalid**, because it computes the true output root of block N. In a fault-proof VM game that runs kona, the step would have proved an invalid claim correct.

## Vulnerability Details

The agreed output root commits (in its preimage) to the hash of the agreed "safe head" block. kona builds its derivation cursor from that block.

`52096e9^:bin/client/src/lib.rs:71-96`: the only early-exit check was for genesis:
```rust
if boot.claimed_l2_block_number == 0 {
    if boot.agreed_l2_output_root == boot.claimed_l2_output_root { return Ok(()); }
    else { return Err(FaultProofProgramError::InvalidClaim(..)); }
}
```
Then (`:103-137`):
```rust
let cursor = new_pipeline_cursor(oracle.clone(), &boot, ...).await?;   // tip = agreed safe head M
...
let (number, output_root) =
    driver.advance_to_target(&boot.rollup_config, Some(boot.claimed_l2_block_number)).await?;
if output_root != boot.claimed_l2_output_root { return Err(InvalidClaim(..)); }
Ok(())
```
`Driver::advance_to_target` (`52096e9^:crates/driver/src/core.rs:72-81`) returns immediately when the cursor is already at or past the target:
```rust
if let Some(tb) = target {
    if self.cursor.l2_safe_head().block_info.number >= tb {
        return Ok((self.cursor.l2_safe_head().block_info.number,
                   *self.cursor.l2_safe_head_output_root()));   // = agreed output root (block M)
    }
}
```
So for `claimed_l2_block_number = N < M`, kona compares `claimed_output_root` with the **agreed** root of block M:
- claim == agreed root (a later block's root claimed for block N): kona says **valid**. That is wrong.
- claim == true root of block N: kona says **invalid**. That is also wrong, but it errs on the conservative side.

At the time, op-program (`op-program/client/claim/validate.go`, e.g. at `afe849ea0b`) computed `L2OutputRoot(min(l2ClaimBlockNum, safeHead))`, the true historical root of block N, and compared it with the claim. Before the fix, kona disagreed with op-program in both cases above.

**Triage correction:** the triage note says "op-program treats such claims as invalid". op-program in fact validated them against the real root of block N. The fix makes kona reject *every* claim with `N < agreed safe head`. That is stricter than op-program, but it is sound: it can no longer call an invalid claim valid.

Fix (`52096e9`):
```rust
+    let safe_head = fetch_safe_head(oracle.as_ref(), boot.as_ref(), &mut l2_provider).await?;
+    if boot.claimed_l2_block_number < safe_head.number {
+        return Err(FaultProofProgramError::InvalidClaim(boot.agreed_l2_output_root, boot.claimed_l2_output_root));
+    }
+    if boot.agreed_l2_output_root == boot.claimed_l2_output_root {
+        info!(target: "client", "Trace extension detected. State transition is already agreed upon.");
+        return Ok(());
+    }
```

### Regression introduced by this fix (fixed much later)

The new "trace extension" shortcut returns `Ok(())` whenever `agreed_root == claimed_root`, **without checking that the claimed block number equals the safe-head number**. A claim "block M+1 has root R_M" (the agreed root repeated one block later) was therefore accepted without deriving M+1. That is again an invalid claim reported as valid, and it is the easier one to reach in a game (post a leaf equal to its pre-state). It was fixed in `b08e543ddf` (PR #19775, 2026-03-26, "kona-client: fix trace-extension short-circuit at capped leaves ... enabling trivial wins in dispute games"), which now requires `claimed_l2_block_number == safe_head.number` for the shortcut. That regression deserves its own report if it is not already covered elsewhere.

### Attack scenario

This assumes a dispute game that uses a kona absolute prestate (as later Asterisc-kona / Cannon-kona games did).
1. In the output-bisection phase, the attacker arranges for the execution-trace subgame's pre-state (agreed) claim to be a real output root `R_M` of a block M beyond the disputed block. For example, it posts `R_M` at a position in the trace-extension region, whose block number the game caps at the proposal's `l2BlockNumber` N < M.
2. The disputed (claimed) value at the leaf is also `R_M`. The local context gives the program `claimed_l2_block_number = N` and `agreed_output_root = R_M`.
3. kona sees N < M, skips derivation, finds `claimed == agreed`, and exits "valid". A counter-step by the honest party against the attacker's leaf claim would fail on-chain.

Reaching step 1 needs an adversarial pre-state that the honest challenger would itself dispute at the output level. So the practical exploitability, even in production, depends on the game DAG and is uncertain.

## Impact Details

- **Class:** fault-proof unsoundness, where the program accepts a false statement about L2 state. In production this could cost honest challengers their bonds and, in the worst case, help an invalid output root survive.
- **Mitigating factors:**
  - In November 2024 kona ran only in testnet Asterisc games. Production games used op-program with Cannon.
  - Reaching the vulnerable input (agreed safe head newer than the claimed block) needs a pre-state claim that honest challengers would contest at the output-bisection level.
  - The bug lived only in kona's pre-1.0 client.
- **Severity:** Low as deployed, noting that the same class in a live proof program would be High.

## Proof of Concept

kona's native mode runs the same client code with a host that fetches preimages from live RPCs. Use any L2 chain (e.g. OP Sepolia) and two consecutive-ish blocks M and N < M:

```bash
# At the parent commit 52096e9^ of the kona tree (bin/client/justfile "run-client-native" style invocation)
M=<recent safe block>; N=$((M-5))
AGREED_HASH=$(cast block $M -r $L2_RPC --field hash)
AGREED_ROOT=$(cast rpc optimism_outputAtBlock $(printf '0x%x' $M) -r $OP_NODE_RPC | jq -r .outputRoot)
L1_HEAD=$(cast block latest -r $L1_RPC --field hash)
# The claim is block M's (later) output root, claimed for the older block N.

cargo run --bin kona-host --release -- \
  --l1-head $L1_HEAD \
  --agreed-l2-head-hash $AGREED_HASH \
  --agreed-l2-output-root $AGREED_ROOT \
  --claimed-l2-output-root $AGREED_ROOT \
  --claimed-l2-block-number $N \
  --l2-chain-id 11155420 \
  --l1-node-address $L1_RPC --l1-beacon-address $L1_BEACON --l2-node-address $L2_RPC \
  --native --data-dir ./data -v
echo "exit=$?"
# Parent commit: exit=0 ("Derivation complete, reached L2 safe head." then "Successfully validated L2 block #M")
#                -> invalid claim accepted.
# Fix commit:    exit=1 ("Claimed L2 block number N is less than the safe head M").
# op-program with the same inputs: exits 1 (claim != real output root of block N).
```

Executed: no. It needs L1/L2 archive RPC endpoints and a historical kona build. The control flow was verified by reading `52096e9^:bin/client/src/lib.rs` and `52096e9^:crates/driver/src/core.rs`.

## Recommendation

The fix closes the "older claim" case by rejecting outright, which is sound. Recommendations:
- Keep kona's claim semantics exactly aligned with op-program and the spec, including trace extension, and cover each edge case with shared test vectors run against both programs (claimed < agreed, claimed == agreed, claimed > agreed with equal roots, and L1 data exhausted).
- The shortcut this fix added (`agreed == claimed` implies valid) was itself unsound, and it was only corrected in `b08e543ddf`. Early exits in proof programs should always check the block number as well as the root.

## References

- Fix commit: `52096e93b44ca8ec0b0bcad474b4f6bdf0b5cae4`
- Pull request: https://github.com/op-rs/kona/pull/852
- Follow-up fix for the regression: `b08e543ddfb2c49be51a351c10135bdedcb8152d` (https://github.com/ethereum-optimism/optimism/pull/19775)
- Relevant files: `bin/client/src/lib.rs`, `crates/proof-sdk/proof/src/sync.rs`, `crates/driver/src/core.rs` (now `rust/kona/bin/client/src/single.rs`, `rust/kona/crates/proof/`)
- Reference implementation: `op-program/client/claim/validate.go` (at `afe849ea0b`), `packages/contracts-bedrock/src/dispute/FaultDisputeGame.sol` (`addLocalData`, block-number capping)
