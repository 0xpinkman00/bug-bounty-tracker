# kona-proof: the pipeline cursor was seeded with a zero output root, so a claim of `0x00…00` for any block beyond the L1-head safe head was proven "valid"

| Field | Value |
|---|---|
| **Target** | kona fault-proof program: `rust/kona/crates/proof/proof/src/sync.rs` (`new_oracle_pipeline_cursor`) together with `rust/kona/crates/proof/driver/src/core.rs` (`advance_to_target`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | High (it would be Critical once `CANNON_KONA` is the respected game type) |
| **Impact category** | "Direct loss of funds": theft of honest challengers' bonds in `CANNON_KONA` games, which would become invalid output-root finalization under a respected game type |
| **Fix commit(s)** | b08e543ddfb2c49be51a351c10135bdedcb8152d (PR #19775, private fix optimism-private #454), 2026-03-26 |
| **Vulnerable since** | 40e4ea65c2 `feat(client): Interop binary (op-rs/kona#903)`, 2025-01-14, which introduced `TipCursor::new(.., B256::ZERO)`. The bug is present in every kona-client release before `kona-client/v1.2.13` |

## Brief / Intro

A dispute game fixes an L1 block (the "L1 head"). Only L2 blocks whose batch data had reached L1 by then can be derived. If a claim is about a later L2 block, the spec says the fault-proof program stops at the last derivable block and returns *that* block's output root. kona tracked the "current safe head output root" in a cursor. When a proof started, it filled that field with zero instead of the real starting root. If derivation ran out of L1 data before producing even one new block, kona reported the output root as `0x00…00`. Anyone could then post zero claims for blocks past the L1-head safe head and have kona prove them valid. That was enough to defend an arbitrary invalid proposal in a `CANNON_KONA` game.

## Vulnerability Details

Parent of the fix, `rust/kona/crates/proof/proof/src/sync.rs:38-42`:

```rust
// Construct the cursor.
let mut cursor = PipelineCursor::new(channel_timeout, origin);
let tip = TipCursor::new(safe_head_info, safe_header, B256::ZERO);   // line 41: output root = 0
cursor.advance(origin, tip);
```

The driver's `advance_to_target` (`rust/kona/crates/proof/driver/src/core.rs:222-247` at the parent) handles `EndOfSource` like this. It lowers the target to the current tip and, on the next loop iteration, returns the tip's stored output root:

```rust
Err(PipelineErrorKind::Critical(PipelineError::EndOfSource)) => {
    if target.is_some() { target = Some(tip_cursor.l2_safe_head.block_info.number); }
    ...
    continue;               // next iteration: target reached ->
}
...
return Ok((tip_cursor.l2_safe_head, tip_cursor.l2_safe_head_output_root));  // line 226: B256::ZERO
```

If no block was derived before `EndOfSource`, the tip is still the initial one, so the program's final output root is `B256::ZERO`. `single.rs` then compares it with the claim (`if output_root != boot.claimed_l2_output_root`). A claimed root of zero matches, and the program exits 0 (VALID).

The correct answer is the agreed starting output root. op-program and the spec return the safe-head output root in this case, and op-challenger's `OutputTraceProvider` clamps every claim beyond the L1-head safe head to that same root (`op-challenger/game/fault/trace/outputs/provider.go:79-86`).

Fix: the agreed root is threaded into the cursor (`sync.rs`, `single.rs`, `interop/transition.rs`):

```rust
 pub async fn new_oracle_pipeline_cursor<L1, L2>(
     rollup_config: &RollupConfig,
     safe_header: Sealed<Header>,
+    agreed_l2_output_root: B256,
 ...
-    let tip = TipCursor::new(safe_head_info, safe_header, B256::ZERO);
+    let tip = TipCursor::new(safe_head_info, safe_header, agreed_l2_output_root);
```

Interaction with 01-01a: in single-chain mode the *honest* claim here equals the agreed root, and the (also buggy) trace-extension shortcut returned VALID for it before derivation ever ran. So on mainnet single-chain games this bug showed up as "zero claims accepted" and not "honest claims rejected". The interop entry point (`interop/transition.rs`) had the same zero seed, but interop was not active on any production chain.

### Attack scenario

1. Let `S` be the L2 safe head as of the L1 head the game will use. The attacker creates a `CANNON_KONA` game proposing a fabricated root `R'` for an L2 block `B > S`. The factory only requires `B` to be above the anchor.
2. The honest challenger disputes `R'`. For positions `≤ S` its claims are true output roots. For positions `> S` they are clamped to `root(S)`.
3. The attacker posts true roots at positions `≤ S`, so the honest challenger agrees with those and leaves them alone. It posts `0x00…00` at every position `> S`. Bisection converges on a leaf whose pre-state the honest challenger agrees with (block `N ≥ S`, root `root(S)`) and whose disputed claim is the attacker's `0` at block `N+1`.
4. kona starts from `S`, finds no more batch data before the L1 head (`EndOfSource`), and returns the seeded `B256::ZERO`. That matches the claim, so it exits VALID. The honest challenger's own kona trace says the same, so it cannot counter.
5. The attacker's leaf stands, every honest claim above it is countered, and `R'` resolves DEFENDER_WINS. The attacker takes the challengers' bonds.

## Impact Details

- **Trigger:** anyone, with no privileged role and no special L1 or L2 conditions. Proposing a block past the current safe head is always possible.
- **At the time of the fix:** `CANNON_KONA` was deployed but not the respected game type (Upgrade 18). The realized impact was bond theft in `CANNON_KONA` games, with the same mitigations as 01-01a: the `DelayedWETH` delay, Guardian blacklisting leading to REFUND mode, and op-dispute-mon alerting.
- **Worst case avoided:** after Karst (Upgrade 19, 2026-07-08) made `CANNON_KONA` respected, this would have let an attacker finalize an arbitrary output root and forge withdrawals. That is Critical.
- **Severity rationale:** High. The bug is a permissionless break of fault-proof soundness with a direct monetary loss (bonds). The respected-game-type caveat keeps it out of Critical.

## Proof of Concept

The fix added the op-e2e action test `Test_ProgramAction_EndOfSourceOutputRoot` (`op-e2e/actions/proofs/end_of_source_test.go` at `b08e543ddf`). It builds one L2 block, batches it, and then proves block `safe+1`, for which no batch data exists at the L1 head. The `ZeroClaim` case expects `ErrClaimNotValid`. On the parent, kona returns `0x0` and exits 0, so the case fails.

```go
// excerpt, op-e2e/actions/proofs/end_of_source_test.go (fix commit)
params := []helpers.FixtureInputParam{
    func(f *helpers.FixtureInputs) { f.L2OutputRoot = safeHeadOutputRoot },
    func(f *helpers.FixtureInputs) { f.L2Head = safeHeadHash },
    helpers.WithL2BlockNumber(safeHeadNum + 1),   // block not derivable from L1 at l1Head
    helpers.WithL2Claim(safeHeadOutputRoot),
}
...
matrix.AddTestCase("ZeroClaim", nil, helpers.LatestForkOnly, runEndOfSourceOutputRootTest,
    helpers.ExpectError(claim.ErrClaimNotValid),
    helpers.WithL2Claim(common.Hash{}))            // attacker's zero claim
```

Steps:

```bash
# 1. kona-host built from the vulnerable parent
git worktree add /tmp/kona-01-01b-parent b08e543ddf^
(cd /tmp/kona-01-01b-parent/rust && cargo build --release -p kona-host)
# 2. run the fix commit's action test against it (the test file only exists at the fix commit)
git worktree add /tmp/kona-01-01b-fix b08e543ddf
cd /tmp/kona-01-01b-fix
KONA_HOST_PATH=/tmp/kona-01-01b-parent/rust/target/release/kona-host \
  go test ./op-e2e/actions/proofs -run 'Test_ProgramAction_EndOfSourceOutputRoot/ZeroClaim' -v
# parent kona-host: FAIL (kona exits 0 / claim accepted)
# rebuild kona-host from /tmp/kona-01-01b-fix: PASS
```

The `HonestClaim` case passes on both commits in single-chain mode, because of the 01-01a shortcut. The `JunkClaim` case (`0xdeadbeef`) is rejected on both.

Executed: no. The action test needs a kona-host build and the op-e2e harness, which were not run for this write-up.

## Recommendation

The fix is right: seed the cursor with the agreed output root. Also:

- Avoid sentinel defaults such as `B256::ZERO` for consensus values. Make the constructor take the value, as the fix does, so a missing value is a compile error.
- Add an explicit "claimed root must be non-zero" sanity check. The spec never produces a zero output root, so this is cheap defence in depth.
- The kona-host re-execution path (`bin/host/src/interop/handler.rs`) now passes `B256::ZERO` deliberately, with a comment that the value is unused. Keep that path strictly out of anything that feeds a claim comparison.

## References

- Fix commit: b08e543ddfb2c49be51a351c10135bdedcb8152d
- Pull request: https://github.com/ethereum-optimism/optimism/pull/19775
- Relevant files: `rust/kona/crates/proof/proof/src/sync.rs`, `rust/kona/crates/proof/driver/src/core.rs`, `rust/kona/bin/client/src/single.rs`, `rust/kona/bin/client/src/interop/transition.rs`, `op-challenger/game/fault/trace/outputs/provider.go`
- Related: 01-01a (trace-extension shortcut, same PR)
- Specs: https://specs.optimism.io/fault-proof/index.html (program epilogue / L1 head semantics)
