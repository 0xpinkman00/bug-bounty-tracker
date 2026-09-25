# kona-client FPVM precompiles: lookup keyed on `target_address`, so DELEGATECALL/CALLCODE into a precompile silently returned empty success

| Field | Value |
|---|---|
| **Target** | kona fault-proof program EVM, `bin/client/src/fpvm_evm/precompiles/provider.rs` (`OpFpvmPrecompiles::run`); in the monorepo today at `rust/kona/bin/client/src/fpvm_evm/precompiles/provider.rs` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Medium |
| **Impact category** | Fault-proof unsoundness in `CANNON_KONA` games. Kona's state transition diverges from op-geth/op-reth on attacker-chosen transactions, which would allow "Direct loss of funds" (bond theft; with a respected game type, invalid withdrawals) if shipped in a deployed prestate |
| **Fix commit(s)** | 440d2ca7d584fe4f5e0f9ed7d0485f79b6504b3a (op-rs/kona#3117, fixes op-rs/kona#3108), 2025-12-04 |
| **Vulnerable since** | e0b86ed25d `feat(jovian/da-footprint): integrate the DA footprint block limit in kona (op-rs/kona#2934)`, 2025-10-14. That commit moved to revm's new `PrecompileProvider::run(&CallInputs)` API and picked the wrong field. The window was about 7 weeks on kona `main` |

## Brief / Intro

EVM contracts can call precompiles (built-in functions such as `ecrecover` or `sha256`) with `CALL`, `STATICCALL`, `DELEGATECALL` or `CALLCODE`. With `DELEGATECALL` and `CALLCODE` the *code* comes from the precompile address, but the call runs in the *caller's* context. After a revm API change, kona's fault-proof EVM looked precompiles up by the context address (`target_address`) instead of the code address (`bytecode_address`). A delegate-call to a precompile therefore found nothing. kona treated the precompile address as an empty account and returned success with empty output. op-geth and op-reth run the precompile. Any L2 user could make kona's result differ from the real chain with one transaction, which breaks fault-proof soundness for kona-based games.

## Vulnerability Details

In revm's `CallInputs`, `target_address` is the account whose storage and balance are used, and `bytecode_address` is the account whose code runs. For `CALL` and `STATICCALL` the two are equal. For `DELEGATECALL` and `CALLCODE`, `target_address` is the caller.

Parent of the fix, `bin/client/src/fpvm_evm/precompiles/provider.rs:119-129`:

```rust
let output =
    if let Some(accelerated) = self.accelerated_precompiles.get(&inputs.target_address) {
        (accelerated)(&input, inputs.gas_limit, &self.hint_writer, &self.oracle_reader)
    } else if let Some(precompile) = self.inner.precompiles.get(&inputs.target_address) {
        precompile.execute(&input, inputs.gas_limit)
    } else {
        return Ok(None);      // "not a precompile": revm falls back to loading code at
    };                        // bytecode_address, which is empty => STOP, success, no output
```

Upstream revm's own `EthPrecompiles::run` (bluealloy/revm@827d572, "provide `&CallInputs` to `PrecompileProvider::run`") uses `inputs.bytecode_address`. op-reth, through `op-revm`'s `OpPrecompiles`, therefore ran the precompile correctly. Before e0b86ed25d, kona received the code address directly as `address: &Address`. The port swapped it for the wrong field.

Fix:

```rust
-            if let Some(accelerated) = self.accelerated_precompiles.get(&inputs.target_address) {
+            if let Some(accelerated) = self.accelerated_precompiles.get(&inputs.bytecode_address) {
 ...
-            } else if let Some(precompile) = self.inner.precompiles.get(&inputs.target_address) {
+            } else if let Some(precompile) = self.inner.precompiles.get(&inputs.bytecode_address) {
```

### Attack scenario

1. The attacker deploys a contract `X` whose behaviour branches on the result of `DELEGATECALL(sha256 precompile 0x02, data)`. If the returned data is empty, `X` calls `L2ToL1MessagePasser.initiateWithdrawal{value: v}` (or any other state change). Otherwise it does nothing.
2. On the real chain (op-geth/op-reth), sha256 returns 32 bytes, so no withdrawal happens and `X` keeps `v`.
3. In kona's re-execution, the delegate-call returns empty, so the withdrawal *is* recorded and the resulting state and output root differ.
4. In a `CANNON_KONA` game, the attacker proposes kona's root for a block after that transaction. The honest challenger (using op-node's canonical roots) disputes it. At the single-block leaf, kona-client reproduces the attacker's root and exits VALID, and the honest challenger's kona trace agrees. The attacker wins the game and the challengers' bonds. The attacker can also challenge an honest proposal covering that block and win: kona says the canonical root is INVALID.
5. If `CANNON_KONA` were the respected game type, the forged `initiateWithdrawal` could be proven and finalized on L1 while the attacker still holds `v` on L2: a double spend.

## Impact Details

- **Trigger:** any L2 user, for the cost of one transaction. No privileged role is needed.
- **Affected software:** only the kona FPP (kona-client). kona-node executes through op-reth/revm and was not affected. op-program and `CANNON` games were not affected.
- **Deployment state (the main mitigating factor):** the bug existed on kona `main` from 2025-10-14 to 2025-12-04. `CANNON_KONA` was first deployed on chains by Upgrade 18 (`op-contracts/v6.0.0`, released 2026-01-14 / 2026-03-16), using the `kona-client/v1.2.7` prestate built in the separate op-rs/kona repo. I could not check out that tag here, so I cannot confirm whether any deployed prestate contained the bug. Given the dates it most likely did not. Even if it did, `CANNON_KONA` was non-respected until Karst (2026-07-08), so the worst realistic impact was bond theft.
- **Severity:** Medium. On its own the bug is a permissionless soundness break, which would be High, or Critical under a respected game type. It is downgraded because it was very likely fixed before any production `CANNON_KONA` prestate and the game type was never respected while it was live.

## Proof of Concept

The fix added unit tests in `provider.rs` that construct `CallInputs` with `bytecode_address = precompile` and `target_address = Address::ZERO`, which is exactly the delegate-call shape. On the parent, `test_run_accelerated_precompile` and `test_run_default_precompile_sha256` fail because `run` returns `Ok(None)`. A more explicit delegate-call version:

```rust
// add to `mod test` in bin/client/src/fpvm_evm/precompiles/provider.rs at 440d2ca7d5^
// (the fix commit's test module supplies create_test_context / imports; copy it over first)
#[test]
fn poc_delegatecall_into_sha256_is_executed() {
    let (hint_chan, preimage_chan) = (
        kona_preimage::BidirectionalChannel::new().unwrap(),
        kona_preimage::BidirectionalChannel::new().unwrap(),
    );
    let mut precompiles = OpFpvmPrecompiles::new_with_spec(
        OpSpecId::ISTHMUS,
        kona_preimage::HintWriter::new(hint_chan.client),
        kona_preimage::OracleReader::new(preimage_chan.client),
    );
    let sha256 = revm::precompile::u64_to_address(2);
    let caller_contract = Address::repeat_byte(0x42);
    let inputs = CallInputs {
        input: CallInput::Bytes(Bytes::from_static(b"hello world")),
        gas_limit: 100_000,
        bytecode_address: sha256,        // code being run
        target_address: caller_contract, // DELEGATECALL context
        caller: caller_contract,
        value: revm::interpreter::CallValue::Apparent(alloy_primitives::U256::ZERO),
        scheme: revm::interpreter::CallScheme::DelegateCall,
        is_static: false,
        return_memory_offset: 0..0,
        known_bytecode: None,
    };
    let res = precompiles.run(&mut create_test_context(), &inputs).unwrap();
    // Parent: None  -> revm treats 0x02 as an empty account -> success, empty returndata.
    // Fix:    Some(Return, 32-byte digest) -> matches op-geth / op-reth.
    let out = res.expect("precompile must be executed for DELEGATECALL");
    assert_eq!(out.output.len(), 32);
}
```

```bash
# the parent commit is in the imported op-rs/kona history (kona repo layout at the tree root)
git worktree add /tmp/kona-01-02 440d2ca7d584fe4f5e0f9ed7d0485f79b6504b3a^
cd /tmp/kona-01-02 && cargo test -p kona-client poc_delegatecall_into_sha256_is_executed
# parent: panics "precompile must be executed for DELEGATECALL"; fix commit: passes
```

Executed: no.

## Recommendation

The fix is correct. Also:

- Differential-test kona's `OpFpvmPrecompiles` against `op_revm::OpPrecompiles` for every `CallScheme` and every precompile address on each spec. This would also have caught entry 01-03.
- When upgrading revm, audit every custom `PrecompileProvider` against upstream's implementation of the same trait method. This class is covered by `docs/ai/reth-update-review.md` ("silent overrides").

## References

- Fix commit: 440d2ca7d584fe4f5e0f9ed7d0485f79b6504b3a (op-rs/kona#3117, issue op-rs/kona#3108)
- Introduced: e0b86ed25dd7ad2b9e12e4e9c2ad90bdb844c3dd (op-rs/kona#2934)
- Upstream reference: https://github.com/bluealloy/revm/commit/827d57285890509cffa2bdf98af15da5e2b35a04
- Relevant files: `rust/kona/bin/client/src/fpvm_evm/precompiles/provider.rs`
- Docs: `docs/public-docs/notices/archive/upgrade-18.mdx`, `upgrade-19.mdx`
