# op-reth — `BLOBBASEFEE` opcode returns 0 instead of 1 on post-Ecotone blocks — consensus divergence from op-geth (shipped in reth v1.5.0)

| Field | Value |
|---|---|
| **Target** | op-reth, `reth-optimism-evm` (`crates/optimism/evm/src/lib.rs` upstream; imported here as `evm/src/lib.rs`, now `rust/alloy-op-evm/src/env.rs`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | High |
| **Impact category** | "Unintended chain split (network partition)" |
| **Fix commit(s)** | ff2a5dd6d0a18c92e1ed94d1ebfdf5136ad1ffbd (paradigmxyz/reth#17272, upstream merge `78bad34091ce6825d78525d68504b4d1ccbe3d65`), 2025-07-08 |
| **Vulnerable since** | 753d3d7d06dfc992e975cc00419805012b3112a0 ("feat: bump revm v26", paradigmxyz/reth#16969, upstream merge `88edd5264937c8cc1f14c05cd0a92e9495d0b5aa`), 2025-06-23. **Shipped in reth/op-reth release v1.5.0** (published 2025-06-26). Fixed in v1.5.1 (published 2025-07-08) |

## Brief / Intro

Every OP Stack block after the Ecotone upgrade supports the `BLOBBASEFEE` opcode (EIP-7516), which returns the current blob gas price. OP L2 blocks carry no blobs and always have `excess_blob_gas = 0`, so the protocol-defined answer is the EIP-4844 minimum price, **1 wei**. op-geth and kona both return 1. A dependency upgrade in op-reth hard-coded the blob price to **0**. Any user could deploy a contract whose behaviour depends on `BLOBBASEFEE`, send one ordinary transaction, and op-reth v1.5.0 nodes would compute a different state root and receipts root from every other client. Those nodes then either halt (as verifiers) or produce blocks the rest of the network rejects (as sequencers or builders).

## Vulnerability Details

Before the revm v26 bump, op-reth derived the blob fee from the block header. With `excess_blob_gas = 0`, `BlobExcessGasAndPrice::new(0, ..)` yields `blob_gasprice = 1`, which matches op-geth (`eip4844.CalcBlobFee` with zero excess gas returns `minBlobGasPrice = 1`).

The revm v26 migration (753d3d7d06) replaced that computation with a hard-coded literal, in both `evm_env` (used to validate and import blocks) and `next_evm_env` (used to build blocks):

```rust
// evm/src/lib.rs @ 753d3d7d06 (lines ~135-138 and ~177-180)
let blob_excess_gas_and_price = spec
    .into_eth_spec()
    .is_enabled_in(SpecId::CANCUN)
    .then_some(BlobExcessGasAndPrice { excess_blob_gas: 0, blob_gasprice: 0 });
```

revm's `BLOBBASEFEE` instruction pushes `block.blob_gasprice()` directly, so on op-reth the opcode evaluated to 0 on every Ecotone-or-later block, while op-geth evaluated it to 1. OP chains reject blob transactions, so the opcode is the only thing that consumes this value. That is also why the existing test suite did not catch the change.

The fix changes the literal to 1 in both places:

```diff
-            .then_some(BlobExcessGasAndPrice { excess_blob_gas: 0, blob_gasprice: 0 });
+            .then_some(BlobExcessGasAndPrice { excess_blob_gas: 0, blob_gasprice: 1 });
```

The upstream commit title was "chore: check blob fee" and the PR title was "chore: use new blob function". The single commit in the PR is "fix: correctly set blob gas price for OP". Neither title flags the consensus impact. The current tree pins this with a regression test, `evm_env_for_op_next_block_pins_blob_gasprice_to_one`, in `rust/alloy-op-evm/src/env.rs:319`, with the comment "The `BLOBBASEFEE` opcode must always be 1 on the OP Stack from Ecotone onward".

### Did a release ship it?

Yes. Checked against upstream `paradigmxyz/reth` via the GitHub compare API and raw sources:

- `v1.5.0` (2025-06-26) contains the regression merge `88edd526` and does **not** contain the fix `78bad340`. `crates/optimism/evm/src/lib.rs@v1.5.0` lines 138 and 180 read `blob_gasprice: 0`.
- `v1.5.1` (2025-07-08) contains the fix (`blob_gasprice: 1`).
- The v1.5.1 release notes say: *"This release includes a fix for historical sync issue on base mainnet, op-reth operators are advised to update their nodes"*, with update priority **"Op-reth: high"**. `chore: check blob fee (#17272)` is listed among its changes. Between v1.5.0 and the fix, it is the only execution-affecting change in the imported optimism crates. The others are RPC, txpool, logging and typo changes.
- reth issue #17214, "v1.5.0 op-reth Base fresh sync fails: root mismatch during execution" (receipt root mismatch at Base block 30323680, milestone v1.5.1), matches the failure this bug produces on historical Base transactions that use `BLOBBASEFEE`. I could not see a root-cause comment on the issue page, so this link is strongly suggested rather than confirmed.

### Attack scenario

1. The attacker deploys a contract on any OP Stack chain past Ecotone, for example runtime code `4a 5f 55 00` (`BLOBBASEFEE; PUSH0; SSTORE; STOP`), or anything that branches on `block.blobbasefee`.
2. The attacker sends one normal L2 transaction calling it.
3. op-geth and kona store 1. op-reth v1.5.0 stores 0. The state root, and usually gas used and the receipts root, differ.
4. Verifier op-reth v1.5.0 nodes reject the canonical block as invalid and stall. A sequencer or block builder running op-reth v1.5.0 produces blocks whose state root every op-geth or kona node rejects, so the unsafe chain splits.

## Impact Details

- Anyone can trigger it for the cost of one L2 transaction. No privileges are needed.
- Affected: every node running op-reth v1.5.0 (and main-branch builds from 2025-06-23 to 2025-07-08) on any OP Stack chain. Verifiers stall or fall out of sync. The issue report shows fresh historical syncs of Base failing, because historical transactions already used the opcode. An op-reth sequencer would fork the chain away from op-geth and kona verifiers. Proposers reading state from such a node could post output roots that differ from the fault-proof program (kona or op-program) result.
- Limiting factors: the release was live for about 12 days. op-geth was still the majority client for most OP chains, so the canonical chain as derived by op-geth was not affected. The fix is a one-line change that requires no state migration.
- Severity: "Unintended chain split (network partition)" is rated High, and the shipped release plus confirmed user-visible sync failures justify keeping it there.

## Proof of Concept

A Rust test for the upstream reth tree. Add it to the `tests` module in `crates/optimism/evm/src/lib.rs` (that module already has `test_evm_config()` built from `BASE_MAINNET`, and the imports `CacheDB`, `EmptyDBTyped`, `ProviderError`, `AccountInfo`, `Header`, `Address`, `bytes`).

```rust
#[test]
fn poc_blobbasefee_is_one_post_ecotone() {
    use alloy_evm::Evm;
    use alloy_primitives::{address, Bytes, TxKind};
    use revm::{context::TxEnv, state::Bytecode};

    let evm_config = test_evm_config(); // Base mainnet, Ecotone active at 1710374401

    // A post-Ecotone OP header: blob fields present and zero, as on every OP block.
    let header = Header {
        number: 30_000_000,
        timestamp: 1_720_000_000,
        base_fee_per_gas: Some(0),
        excess_blob_gas: Some(0),
        blob_gas_used: Some(0),
        gas_limit: 30_000_000,
        ..Default::default()
    };

    // 1. Environment-level check.
    let env = evm_config.evm_env(&header);
    let blob = env.block_env.blob_excess_gas_and_price.expect("cancun rules active");
    assert_eq!(blob.blob_gasprice, 1, "OP BLOBBASEFEE must be 1 (op-geth parity)");

    // 2. Execution-level check: BLOBBASEFEE; PUSH0; SSTORE; STOP
    let contract = address!("0x000000000000000000000000000000000000c0de");
    let code = Bytecode::new_raw(bytes!("4a5f5500"));
    let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
    db.insert_account_info(
        contract,
        AccountInfo { balance: U256::ZERO, nonce: 1, code_hash: code.hash_slow(), code: Some(code) },
    );
    let mut evm = evm_config.evm_with_env(db, env);
    let mut tx = OpTransaction::new(TxEnv {
        caller: Address::repeat_byte(0x11),
        kind: TxKind::Call(contract),
        gas_limit: 100_000,
        gas_price: 0,
        chain_id: Some(8453),
        ..Default::default()
    });
    tx.enveloped_tx = Some(Bytes::new()); // non-deposit txs need an envelope for the L1 fee
    let res = evm.transact(tx).unwrap();
    let slot0 = res.state[&contract]
        .storage
        .get(&U256::ZERO)
        .map(|s| s.present_value)
        .unwrap_or_default();
    assert_eq!(slot0, U256::from(1), "op-geth stores 1 here");
}
```

Run:

```
git clone https://github.com/paradigmxyz/reth && cd reth
git checkout v1.5.0   # expected: FAIL (blob_gasprice == 0, slot0 == 0)
cargo test -p reth-optimism-evm poc_blobbasefee_is_one_post_ecotone
git checkout v1.5.1   # expected: PASS
cargo test -p reth-optimism-evm poc_blobbasefee_is_one_post_ecotone
```

In this monorepo, the equivalent regression test that now guards the behaviour is:

```
cd rust && cargo test -p alloy-op-evm evm_env_for_op_next_block_pins_blob_gasprice_to_one
```

Executed: no. The release and version facts above were verified against GitHub (tags, compare API, raw sources at `v1.5.0` and `v1.5.1`, release notes). The test was not compiled, so small API adjustments may be needed.

## Recommendation

The fix restores `blob_gasprice: 1`. Further hardening:
- Keep a test that pins `BLOBBASEFEE == 1` for every fork from Ecotone onward. The current tree has one (`rust/alloy-op-evm/src/env.rs`).
- Add a differential execution test (op-reth vs op-geth or kona) over a contract that reads every block-context opcode, and run it on every revm or reth bump. This bug came from a dependency migration that silently replaced derived values with literals.
- Label consensus-affecting fixes as such in commit and PR titles and in release notes. "chore: check blob fee" hides the severity from downstream operators.

## References

- Fix commit: ff2a5dd6d0a18c92e1ed94d1ebfdf5136ad1ffbd (upstream 78bad34091ce6825d78525d68504b4d1ccbe3d65)
- Pull request: https://github.com/paradigmxyz/reth/pull/17272 (regression: https://github.com/paradigmxyz/reth/pull/16969)
- Release notes: https://github.com/paradigmxyz/reth/releases/tag/v1.5.1
- Related user report: https://github.com/paradigmxyz/reth/issues/17214
- Relevant files: `evm/src/lib.rs` (imported history), `rust/alloy-op-evm/src/env.rs` (current)
- Specs: EIP-7516 (BLOBBASEFEE), EIP-4844 (`MIN_BASE_FEE_PER_BLOB_GAS = 1`), OP Ecotone spec https://specs.optimism.io/protocol/ecotone/overview.html
