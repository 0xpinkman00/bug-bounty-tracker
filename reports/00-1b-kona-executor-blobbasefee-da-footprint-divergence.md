# kona-executor derives BLOBBASEFEE from the post-Jovian DA footprint, so the fault-proof program computes different state from op-geth/op-reth

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/proof/executor/src/builder/env.rs` (kona-client fault-proof program, stateless block executor) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Medium |
| **Impact category** | Theft of bonds in non-respected `CANNON_KONA` dispute games. In the respected game this would be Critical (direct loss of funds, since an invalid output root can win), but the fix shipped before kona became respected. |
| **Fix commit(s)** | 17a5c8bdfbc9d0ec5f9a530c37f077f885691027 (PR #21328, prepared in optimism-private), 2026-06-10 |
| **Vulnerable since** | The blob-env code dates from op-rs/kona `46f51e56215` (2025-07). It became exploitable when Jovian activated (Sepolia 2025-11-19, Mainnet 2025-12-02), because Jovian repurposed the header `blobGasUsed` field. |

## Brief / Intro

On OP Stack chains, the `BLOBBASEFEE` opcode always returns 1. L2 blocks carry no blobs, and op-geth and op-reth hard-code the value. The Jovian upgrade reused the block header's `blobGasUsed` field to hold a different number, the block's "DA footprint", which is used for the L2 base-fee calculation. kona's fault-proof executor still fed that field into the Ethereum L1 blob-fee formula. So after any block with a large DA footprint, kona computed `BLOBBASEFEE` as 2, 6, 370 and so on instead of 1. Any user can deploy a contract that reads `BLOBBASEFEE` and stores it or branches on it. Then kona's re-execution of that block gives a different state root from the real chain, and the dispute game settles on the wrong answer.

## Vulnerability Details

The parent code is at `rust/kona/crates/proof/executor/src/builder/env.rs:103-114` (`17a5c8bdfb^`):

```rust
let (params, fraction) = if spec_id.is_enabled_in(OpSpecId::ISTHMUS) {
    (Some(BlobParams::prague()), BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE)
} else if spec_id.is_enabled_in(OpSpecId::ECOTONE) {
    (Some(BlobParams::cancun()), BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN)
} else { (None, 0) };

let blob_excess_gas_and_price = parent_header
    .maybe_next_block_excess_blob_gas(params)          // uses parent.blob_gas_used
    .or_else(|| spec_id.is_enabled_in(OpSpecId::ECOTONE).then_some(0))
    .map(|excess| BlobExcessGasAndPrice::new(excess, fraction));
```

`maybe_next_block_excess_blob_gas` applies the EIP-4844 rule `excess' = max(0, excess + blob_gas_used - target)`. For Prague parameters the target is 6 × 131072 = 786,432. After Jovian, `parent.blob_gas_used` is the parent block's DA footprint, which is often in the millions on busy chains. The fix's unit test uses 30,406,400, taken from op-mainnet block 152635937. `blob_gasprice = fake_exponential(1, excess', 5_007_716)` goes above 1 once the footprint is more than about 4.26M.

op-reth's `evm_env_for_op` and op-geth both pin the blob env to `{excess_blob_gas: 0, blob_gasprice: 1}`. The fix does the same:

```rust
let blob_excess_gas_and_price = spec_id
    .is_enabled_in(OpSpecId::ECOTONE)
    .then_some(BlobExcessGasAndPrice { excess_blob_gas: 0, blob_gasprice: 1 });
```

The value only matters for execution through the `BLOBBASEFEE` opcode (`0x4a`). Nothing else in L2 execution reads it. So the divergence happens exactly when a transaction in block N+1 reads `BLOBBASEFEE` and block N had a DA footprint above about 4.26M. The footprint can come from ordinary busy traffic or from the attacker's own large-calldata transactions.

### Was kona the respected proof program while this was live?

No. It was a non-respected game type.
- Upgrade 18 (`docs/public-docs/notices/archive/upgrade-18.mdx`) added the `CANNON_KONA` (8) game type "alongside `CANNON` (0)" and states that "This upgrade does not change the respected game type". Withdrawals were proven against op-program `CANNON` games. Honest `op-challenger`s were told to run `--trace-type=cannon,cannon-kona,...` and so played `CANNON_KONA` games with bonds. The repo does not record the exact date U18 was executed on each chain. The notice is archived, and U19 refers to chains "already configured for `cannon-kona` as part of Upgrade 18", so `CANNON_KONA` games existed on Mainnet and Sepolia before Karst.
- Upgrade 19 / Karst made `CANNON_KONA` respected, with a prestate built from `kona-client/v1.6.0-rc.2`. `git merge-base --is-ancestor 17a5c8bdfb kona-client/v1.6.0-rc.2` is **true**, so the respected prestate already had the fix.

So the bug was live on Sepolia and Mainnet from Jovian (Nov/Dec 2025) until the U19 prestate replaced the U18-era `cannon64-kona` prestate (June/July 2026). During that time it affected only the bonded, non-respected `CANNON_KONA` games.

### Attack scenario

1. The attacker deploys `BLOBBASEFEE PUSH0 SSTORE STOP` (`0x4a5f5500`) on L2.
2. The attacker waits for, or creates by sending high-entropy calldata transactions, a block N with DA footprint above about 4.26M. In block N+1 the attacker calls the probe. Canonically, slot 0 = 1. kona computes slot 0 = 2 or more.
3. Bond theft against honest challengers: the attacker creates a `CANNON_KONA` game whose root claim is kona's (wrong) output root for a block at or after N+1. Honest `op-challenger`s dispute it with op-node's canonical output root. At the single-block execution leaf, Cannon runs kona, which reproduces the attacker's root. The honest challengers lose every bonded claim on that path, and the attacker collects them.
4. Or the attacker counters an honest proposal of the canonical root in a `CANNON_KONA` game, and kona "proves" it invalid.

## Impact Details

- **Actual impact:** loss of dispute-game bonds for honest challengers and proposers in `CANNON_KONA` games before Karst. Withdrawals were not affected, because the `OptimismPortal` only accepted respected `CANNON` games in that period, and op-program was not affected by this bug.
- **Potential impact if it had shipped in the respected prestate:** an invalid output root that any user can trigger. The attacker would build a contract whose behaviour depends on `BLOBBASEFEE`, for example one that sends an L2→L1 withdrawal only when `BLOBBASEFEE > 1`. Kona's state would then include a withdrawal that never happened canonically, which is a Critical double spend. The fix landing before the Karst prestate was cut prevented this.
- **Who can trigger it:** any L2 user. No privileged role is needed.
- **Mitigating factors:** non-respected game type; op-dispute-mon alerts on game results that disagree with op-node; operators could stop playing `CANNON_KONA` games.
- **Severity:** **Medium**. Theft of dispute bonds that any user can trigger, in a live but non-respected fault-proof game type.

## Proof of Concept

**1. Fault-proof action test added by the fix.** It fails on `17a5c8bdfb^` and passes on the fix. `rust/kona/tests/proofs/jovian_blobbasefee_test.go` (`TestJovianBlobBaseFeeMatchesCanonical`):
- seeds the probe contract `0x4a5f5500` into genesis;
- fills one block with incompressible 5 kB calldata txs until the DA footprint exceeds 10M, and asserts `BlobGasUsed > 4_258_349`;
- calls the probe in the next block and asserts that canonical storage is 1;
- runs `RunFaultProofProgramFromGenesis` with kona-host on both the honest-claim and junk-claim matrices.

```bash
# fixed tree
cd rust/kona/tests && just action-tests-single TestJovianBlobBaseFeeMatchesCanonical
# parent (separate worktree): copy the test file into rust/kona/tests/proofs/ then run the same command
git worktree add /tmp/kona-parent 17a5c8bdfb^
cp rust/kona/tests/proofs/jovian_blobbasefee_test.go /tmp/kona-parent/rust/kona/tests/proofs/
cd /tmp/kona-parent/rust/kona/tests && just action-tests-single TestJovianBlobBaseFeeMatchesCanonical
# parent: HonestClaim case fails (kona computes a different output root); fix: passes
```

Unit test from the fix: `cd rust && cargo test -p kona-executor --lib builder::env::tests::prepare_block_env_pins_blob_gasprice_to_one`.

**2. Standalone arithmetic model (executed).** This reproduces the parent's blob-fee formula with the alloy-eips Prague constants:

```rust
// blobfee_poc.rs — rustc -O blobfee_poc.rs && ./blobfee_poc
const DATA_GAS_PER_BLOB: u64 = 131_072; const TARGET_BLOBS_PRAGUE: u64 = 6;
const UPDATE_FRACTION_PRAGUE: u128 = 5_007_716;
fn fake_exponential(f: u128, n: u128, d: u128) -> u128 {
    let (mut i, mut out, mut acc) = (1u128, 0u128, f * d);
    while acc > 0 { out += acc; acc = (acc * n) / (d * i); i += 1; } out / d }
fn next_excess(pe: u64, used: u64) -> u64 { (pe + used).saturating_sub(TARGET_BLOBS_PRAGUE * DATA_GAS_PER_BLOB) }
fn main() {
    for fp in [1_000_000u64, 4_257_000, 4_258_000, 10_000_000, 30_406_400] {
        println!("parent DA footprint {fp:>10}: kona(old) BLOBBASEFEE = {:>4}, canonical = 1",
                 fake_exponential(1, next_excess(0, fp) as u128, UPDATE_FRACTION_PRAGUE));
    }
}
```

Output:
```
parent DA footprint    1000000: kona(old) BLOBBASEFEE =    1, canonical = 1
parent DA footprint    4257000: kona(old) BLOBBASEFEE =    1, canonical = 1
parent DA footprint    4258000: kona(old) BLOBBASEFEE =    2, canonical = 1
parent DA footprint   10000000: kona(old) BLOBBASEFEE =    6, canonical = 1
parent DA footprint   30406400: kona(old) BLOBBASEFEE =  370, canonical = 1
```

A real op-mainnet footprint (block 152635937) would have given `BLOBBASEFEE = 370` in kona for the following block.

Executed: yes for the standalone model. No for the action test and unit test, which need kona-host and crate builds.

## Recommendation

The fix pins the blob env to `excess_blob_gas = 0, blob_gasprice = 1` from Ecotone onward, which matches op-reth and op-geth. The Jovian base-fee path, which correctly uses the DA footprint, is unchanged.

Further suggestions:
- Keep kona's executor environment derivation (`prepare_block_env`) on a code path shared with op-reth (`evm_env_for_op`), so that header-field reinterpretations in future forks cannot drift. A later commit (`3ce7fc28c0`, "op-reth: reuse shared payload EVM environment builder") moves in that direction.
- Add a differential test that runs the kona executor and op-reth on real post-fork blocks and compares every opcode-visible block-env field.

## References

- Fix commit: 17a5c8bdfbc9d0ec5f9a530c37f077f885691027
- Pull request: https://github.com/ethereum-optimism/optimism/pull/21328
- Relevant files: `rust/kona/crates/proof/executor/src/builder/env.rs`, `rust/kona/tests/proofs/jovian_blobbasefee_test.go`
- Respected-game-type evidence: `docs/public-docs/notices/archive/upgrade-18.mdx`, `docs/public-docs/notices/upgrade-19.mdx` (archived by `798b46044e`), tag `kona-client/v1.6.0-rc.2`
- Jovian DA footprint spec: https://specs.optimism.io/protocol/jovian/exec-engine.html
