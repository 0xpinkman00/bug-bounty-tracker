# kona-client: trace-extension short-circuit accepted any claim equal to the agreed output root, whatever its block number, so invalid output roots could win CANNON_KONA games

| Field | Value |
|---|---|
| **Target** | kona fault-proof program (kona-client), `rust/kona/bin/client/src/single.rs` (`run`). The program behind the `CANNON_KONA` (game type 8) dispute game |
| **Asset type** | Blockchain/DLT (off-chain fault-proof program whose execution is the on-chain source of truth for `FaultDisputeGame` step resolution) |
| **Severity** | High (it would be Critical once `CANNON_KONA` is the respected game type) |
| **Impact category** | "Direct loss of funds": theft of honest challengers' bonds in `CANNON_KONA` games. It would also have meant "invalid output roots finalized / invalid withdrawals" had `CANNON_KONA` been respected |
| **Fix commit(s)** | b08e543ddfb2c49be51a351c10135bdedcb8152d (PR #19775, bundling private fixes optimism-private #454/#455/#456), 2026-03-26 |
| **Vulnerable since** | 963afdbd46 `fix(client): Trace extension support (op-rs/kona#778)`, 2024-11-04. The bug is present in every kona-client release before `kona-client/v1.2.13` (2026-03-27), including `kona-client/v1.2.7`, the prestate named in the Upgrade 18 notice that deployed `CANNON_KONA` |

## Brief / Intro

In an OP Stack fault dispute game, participants bisect a disagreement about L2 output roots (commitments to L2 state) down to a single L2 block. They then run the fault-proof program (FPP) inside the on-chain MIPS emulator to decide whether the claimed output root for that one block is correct. kona-client is the Rust FPP behind the `CANNON_KONA` game type. kona had a shortcut for "trace extension": if the claimed output root equals the agreed starting output root, it declared the claim valid immediately and did no work. It never checked that the claim was for the *same block*. An attacker can therefore claim "block N+1 has the same output root as block N". That claim is always false, but kona accepted it. So any permissionless player could defend an arbitrary invalid output root in a `CANNON_KONA` game and take the honest challengers' bonds.

## Vulnerability Details

The FPP receives the agreed (trusted) output root and its L2 block (the "safe head"), a claimed output root, and the claimed L2 block number. Vulnerable code, parent of the fix, `rust/kona/bin/client/src/single.rs:71-93`:

```rust
// If the claimed L2 block number is less than the safe head of the L2 chain, the claim is invalid.
if boot.claimed_l2_block_number < safe_head.number { ... return Err(InvalidClaim) }

// In the case where the agreed upon L2 output root is the same as the claimed L2 output root,
// trace extension is detected and we can skip the derivation and execution steps.
if boot.agreed_l2_output_root == boot.claimed_l2_output_root {        // line 87
    info!(target: "client", "Trace extension detected. State transition is already agreed upon.");
    return Ok(());                                                     // exit 0 => VM status VALID
}
```

Trace extension exists because the output bisection tree has a fixed depth. Leaves beyond the proposal's L2 block number are "capped" at that block number, so the pre-state and the claim describe the same block, and the only correct claim is the agreed root itself. The shortcut is correct only when `claimed_l2_block_number == safe_head.number`. For any `claimed_l2_block_number > safe_head.number`, the correct output root is different: every output root commits to its block hash, so two different blocks never share one. The shortcut still returned success on root equality alone.

The program's exit code becomes the VM status byte that `FaultDisputeGame.step` checks. Exit code 0 (VALID) means the disputed output claim is proven correct. The honest challenger runs the same kona-client binary to build its execution trace. It therefore also sees VALID and cannot post a counter. `FaultDisputeGame._verifyExecBisectionRoot` requires an INVALID or PANIC status to attack an opponent's output claim.

Fix (`single.rs`), which keys the shortcut on the block number and enforces equality there:

```rust
-    if boot.agreed_l2_output_root == boot.claimed_l2_output_root {
+    if boot.claimed_l2_block_number == safe_head.number {
+        if boot.claimed_l2_output_root != boot.agreed_l2_output_root {
+            return Err(FaultProofProgramError::InvalidClaim(
+                boot.agreed_l2_output_root,
+                boot.claimed_l2_output_root,
+            ));
+        }
         info!(target: "client", "Trace extension detected. State transition is already agreed upon.");
         return Ok(());
     }
```

With the fix, a claim for a later block always goes through derivation and execution, and a mismatching claim at the capped leaf is rejected.

### Attack scenario

1. The attacker creates a `CANNON_KONA` game whose root claim is a fabricated output root `R'` for some L2 block `B`. The root claim can be anything, for example a root that commits to a forged `L2ToL1MessagePasser` storage entry.
2. An honest `op-challenger` (which runs `cannon-kona` by default) disputes `R'` and bisects. At every output-bisection position where the attacker has to post a claim, the attacker posts the agreed output root of the block just before it. The simplest strategy is to always attack leftwards with the anchor root `A`. Bisection then converges to the leftmost leaf: pre-state `A` at the anchor block `S` (agreed) and an attacker claim `A` at block `S+1`.
3. At that leaf the FPP input is `agreed = A`, `claimed = A`, `claimed_block = S+1`. kona hits the shortcut and exits 0 (VALID). The honest challenger's own kona trace agrees, so it cannot make the required INVALID-status execution root claim. The attacker's leaf is never countered.
4. When the game resolves, each honest claim above the leaf is countered by an uncountered attacker claim. The root `R'` resolves DEFENDER_WINS, and the attacker collects every bond the honest challenger posted.

## Impact Details

- **Who can trigger:** anyone. Creating a game and making moves is permissionless. No batcher, sequencer or other privileged role is involved.
- **At the time of the fix:** `CANNON_KONA` was a live, permissionless but **non-respected** game type (Upgrade 18, `op-contracts/v6.0.0`). Withdrawals were proven only against the respected `CANNON` game type, so a winning invalid root could not be used to withdraw. The concrete loss was the honest challengers' bonds, which increase with every level of the game. That is theft of funds from whoever runs the honest challenger.
- **Mitigating factors:** bonds are paid through `DelayedWETH` with a delay. The Guardian can blacklist a game in `AnchorStateRegistry`, which moves bond distribution to REFUND mode. op-dispute-mon would flag the game as having a wrong result (its op-node disagrees with the root). Recovery therefore needs privileged intervention, but it is possible.
- **Why not Critical:** Critical would need direct theft of user funds or finalization of invalid withdrawals. That only follows if `CANNON_KONA` is the respected game type. Karst / Upgrade 19 (mainnet 2026-07-08) made it respected. Had the bug survived until then, an attacker could have finalized arbitrary output roots and drained the bridge. The fix landed about 3.5 months earlier.
- **Duration:** the bug was present from Nov 2024 in kona. It was exposed on-chain from the moment `CANNON_KONA` games could be created on a chain until that chain's prestate was upgraded past `kona-client/v1.2.13`.

## Proof of Concept

The fix added a Rust regression test that drives `kona_client::single::run` with an in-memory oracle. `does_not_short_circuit_on_root_match_at_different_block` is the exploit case: agreed root = claimed root, claimed block = safe head + 1. On the parent commit `run` returns `Ok(())`, so the assertion fails. On the fix, `run` tries to derive and errors, so the test passes. `Cargo.toml` is unchanged by the fix, so the file compiles as-is on the parent.

`rust/kona/bin/client/tests/trace_extension.rs` (abridged from the fix commit; the full file is at `git show b08e543ddf:rust/kona/bin/client/tests/trace_extension.rs`):

```rust
use alloy_consensus::Header;
use alloy_primitives::B256;
use async_trait::async_trait;
use kona_client::single::{FaultProofProgramError, run};
use kona_preimage::{HintWriterClient, PreimageKey, PreimageOracleClient,
    errors::{PreimageOracleError, PreimageOracleResult}};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone, Debug, Default)]
struct MockOracle { preimages: Arc<Mutex<HashMap<PreimageKey, Vec<u8>>>> }
#[async_trait]
impl PreimageOracleClient for MockOracle {
    async fn get(&self, key: PreimageKey) -> PreimageOracleResult<Vec<u8>> {
        self.preimages.lock().await.get(&key).cloned().ok_or(PreimageOracleError::KeyNotFound)
    }
    async fn get_exact(&self, key: PreimageKey, buf: &mut [u8]) -> PreimageOracleResult<()> {
        let d = self.get(key).await?;
        if d.len() != buf.len() { return Err(PreimageOracleError::BufferLengthMismatch(buf.len(), d.len())); }
        buf.copy_from_slice(&d); Ok(())
    }
}
#[derive(Clone, Debug, Default)]
struct MockHintWriter;
#[async_trait]
impl HintWriterClient for MockHintWriter {
    async fn write(&self, _: &str) -> PreimageOracleResult<()> { Ok(()) }
}

fn b256(f: u8) -> B256 { B256::from([f; 32]) }

fn preimages(agreed: B256, claimed: B256, claimed_block: u64, safe_hash: B256, safe_num: u64)
    -> HashMap<PreimageKey, Vec<u8>> {
    let mut p = HashMap::new();
    p.insert(PreimageKey::new_local(1), b256(0x11).to_vec());          // L1 head
    p.insert(PreimageKey::new_local(2), agreed.to_vec());              // agreed output root
    p.insert(PreimageKey::new_local(3), claimed.to_vec());             // claimed output root
    p.insert(PreimageKey::new_local(4), claimed_block.to_be_bytes().to_vec());
    p.insert(PreimageKey::new_local(5), 10u64.to_be_bytes().to_vec()); // chain id (OP Mainnet)
    let mut out = [0u8; 128];
    out[96..].copy_from_slice(safe_hash.as_slice());                   // output root preimage
    p.insert(PreimageKey::new_keccak256(*agreed), out.to_vec());
    let h = Header { number: safe_num, ..Default::default() };
    p.insert(PreimageKey::new_keccak256(*safe_hash), alloy_rlp::encode(&h));
    p
}

/// Exploit: claim "block N+1 has the same output root as block N".
#[tokio::test(flavor = "multi_thread")]
async fn does_not_short_circuit_on_root_match_at_different_block() {
    let (safe_num, safe_hash, agreed) = (3, b256(0x22), b256(0xAA));
    let oracle = MockOracle { preimages: Arc::new(Mutex::new(
        preimages(agreed, agreed, safe_num + 1, safe_hash, safe_num))) };
    // Parent commit: Ok(()) -> claim judged VALID -> assertion fails.
    // Fix: derivation is attempted (and fails on the mock oracle) -> Err.
    assert!(run(oracle, MockHintWriter).await.is_err());
}
```

Run it (read-only for the repo; uses a throwaway worktree):

```bash
git worktree add /tmp/kona-01-01a b08e543ddf^
cp <this test> /tmp/kona-01-01a/rust/kona/bin/client/tests/trace_extension.rs
cd /tmp/kona-01-01a/rust && cargo test -p kona-client --test trace_extension
# expected on parent: does_not_short_circuit_on_root_match_at_different_block ... FAILED
# repeat with `git worktree add /tmp/kona-fix b08e543ddf` -> passes
```

End-to-end variant: the fix also added `runTraceExtensionRepeatedRootAtNextBlockTest` to `op-e2e/actions/proofs/trace_extension_test.go`. Build `kona-host` from the parent, then run `KONA_HOST_PATH=<kona-host> go test ./op-e2e/actions/proofs -run TraceExtension` at `b08e543ddf`. The test proves the 1→2 transition with the claim set to block 1's output root. kona accepts it on the parent and rejects it on the fix.

Executed: no. A full kona-client build was not run for this write-up. The result above follows from reading the parent code: the shortcut returns before any oracle access beyond the boot info and the safe-head header, both of which the mock supplies.

## Recommendation

The fix is correct: trace extension is decided by `claimed_l2_block_number == safe_head.number`, and at that point the claim must equal the agreed root. Further suggestions:

- Keep a differential test that runs op-program and kona-client over the same boot inputs, including adversarial ones such as a repeated root at N+1, a zero root, or an out-of-range block number. The op-e2e matrix now does this for this case.
- The interop entry point (`bin/client/src/interop/*`) has its own trace-extension logic. Audit it for the same "compare roots only" pattern before interop activation.

## References

- Fix commit: b08e543ddfb2c49be51a351c10135bdedcb8152d
- Pull request: https://github.com/ethereum-optimism/optimism/pull/19775
- Introduced: 963afdbd46 (op-rs/kona#778)
- Relevant files: `rust/kona/bin/client/src/single.rs`, `rust/kona/bin/client/tests/trace_extension.rs`, `op-e2e/actions/proofs/trace_extension_test.go`, `packages/contracts-bedrock/src/dispute/FaultDisputeGame.sol` (`_verifyExecBisectionRoot`)
- Specs: https://specs.optimism.io/fault-proof/index.html (trace extension, fault-proof program epilogue); `docs/public-docs/notices/archive/upgrade-18.mdx`, `upgrade-19.mdx`
