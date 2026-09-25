# kona-hardforks — wrong `setEcotone()` selector in the Ecotone upgrade deposit — kona derives a different Ecotone activation block from op-node

| Field | Value |
|---|---|
| **Target** | kona `crates/protocol/hardforks/src/ecotone.rs` (`Ecotone::ENABLE_ECOTONE_INPUT`), used by kona-derive attribute building → kona-node and kona-client (fault/ZK proof program) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | "Unintended chain split (network partition)" (kona-derived chains only, at the Ecotone activation block); incorrect fault-proof program output for that block |
| **Fix commit(s)** | d2a621cc61efeb418dea7ce4aef7efb865b98eb5 (op-rs/kona#2263), 2025-06-24 |
| **Vulnerable since** | The first kona Ecotone attribute builder, 4bcd2339f7 (op-rs/kona#92, 2024-04-14). The constant was carried through op-alloy (c781573335, 2024-08-29; 037cc2e831) and back into kona-hardforks (e9f844d76c, 2025-02-21). Every kona-client release up to and including `kona-client/v1.0.2` (2025-06-04) has it |

## Brief / Intro

At each hard fork, OP Stack nodes inject a few fixed "upgrade" deposit transactions into the first block of the fork. These deploy new system contracts and switch them on. For Ecotone, the fifth upgrade transaction (index 4) calls `GasPriceOracle.setEcotone()`. kona encoded that call with the 4-byte selector `0x22b908b3` instead of the correct `0x22b90ab3`. When kona derived the Ecotone activation block, it therefore produced a different transaction from op-node. That transaction also *reverts*, because GasPriceOracle has no function with that selector and no fallback. The result is a different transaction hash, receipt, state and block hash, so kona disagreed with the canonical chain at that one block and everything after it.

## Vulnerability Details

```rust
// crates/protocol/hardforks/src/ecotone.rs:24-25 (parent of d2a621cc)
/// The Enable Ecotone Input Method 4Byte Signature
pub const ENABLE_ECOTONE_INPUT: [u8; 4] = hex!("22b908b3");
...
// ecotone.rs:163-173 — upgrade deposit #4
TxDeposit {
    source_hash: Self::enable_ecotone_source(),
    from: Self::DEPOSITOR_ACCOUNT,
    to: TxKind::Call(Predeploys::GAS_PRICE_ORACLE),
    gas_limit: 80_000,
    input: Self::ENABLE_ECOTONE_INPUT.into(),   // wrong selector
    ..
},
```

`cast sig "setEcotone()"` gives `0x22b90ab3`, which is the value in the Ecotone spec and in op-node (`op-node/rollup/derive/ecotone_upgrade_transactions.go`). The existing golden-vector test did not catch the mistake because the golden file `bytecode/ecotone_tx_4.hex` had been generated from kona's own output and contained the same wrong selector (`...808422b908b3`).

kona-derive emits these transactions when `is_ecotone_active(next_l2_time) && !is_ecotone_active(parent.timestamp)` (`crates/protocol/derive/src/attributes/stateful.rs:131-134`). That is the same activation-block rule as op-node's `IsEcotoneActivationBlock`, so the upgrade transactions only appear on chains that activated Ecotone *after* genesis.

Fix: correct the constant and the golden vector, and add selector tests derived from `keccak256` for every hard-fork selector:

```diff
-    pub const ENABLE_ECOTONE_INPUT: [u8; 4] = hex!("22b908b3");
+    pub const ENABLE_ECOTONE_INPUT: [u8; 4] = hex!("22b90ab3");
```
```diff
-7ef857...8083013880808422b908b3
+7ef857...8083013880808422b90ab3
```
```rust
#[test]
fn test_ecotone_selector_is_valid() {
    let expected_selector = &keccak256("setEcotone()")[..4];
    assert_eq!(Ecotone::ENABLE_ECOTONE_INPUT, expected_selector);
}
```

### Consequences at the activation block (kona vs op-node)

1. Deposit #4 has different calldata, so it has a different tx hash and a different transactions root.
2. The call reverts in kona's execution (unknown selector, no fallback), so `GasPriceOracle.isEcotone` stays `false`, and the receipt status and gas used differ.
3. The state root, receipts root and block hash all differ, and every later kona-derived block has a different parent.

### Trigger scenario (no attacker needed)

1. Take a chain whose Ecotone activation is after genesis (OP Mainnet, Base, and most chains launched before March 2024), or a devnet or testnet that schedules Ecotone later.
2. A kona-node that derives through the activation block (for example, syncing from genesis via derivation) builds a non-canonical block. Its EL then diverges from op-geth and op-node peers from that point on.
3. kona-client, asked to prove a claim whose L2 range includes the activation block, computes a wrong output root.

## Impact Details

- **Would-be impact:** a deterministic divergence between kona and op-node, which could affect any kona-derived node (chain split) and any kona-based proof (the kona + Cannon/Asterisc fault proofs, and ZK systems built on kona such as OP Succinct) that covers the activation block.
- **Why Low:**
  - Only one block per chain is affected, and it is one that already happened (OP Mainnet and Base activated Ecotone in March 2024). Chains that launched with Ecotone at genesis have no activation block and no upgrade transactions.
  - Dispute games and ZK proofs cover recent output roots. A game covering a 2024 activation block would be long past its window, and new chains with a post-genesis Ecotone were rare by mid-2025.
  - kona-node was pre-release during the whole window. kona-node syncs usually start from a recent checkpoint or EL sync, not from derivation through 2024 blocks.
  - An attacker cannot influence it. It is a deterministic encoding bug.
- The bug was nonetheless long-lived (about 14 months) and present in every kona-client release through v1.0.2. A new chain or devnet that scheduled Ecotone after genesis and used kona for derivation or proofs would have been exposed.

## Proof of Concept

1. Selector check (executed):

```
$ cast sig "setEcotone()"
0x22b90ab3        # kona used 0x22b908b3
```

2. Regression test added by the fix, runnable in this monorepo:

```
cd rust && cargo test -p kona-hardforks test_ecotone_selector_is_valid
```

It fails if the constant is reverted to `22b908b3`.

3. Cross-client equivalence test (suggested, kona repo at `d2a621cc61^`). The expected bytes come from the spec and op-node, not from kona:

```rust
#[test]
fn poc_ecotone_tx4_matches_op_node() {
    // op-node: op-node/rollup/derive/ecotone_upgrade_transactions.go, enableEcotoneInput = crypto.Keccak256([]byte("setEcotone()"))[:4]
    let expected = alloy_primitives::keccak256("setEcotone()");
    let txs = Ecotone::deposits().collect::<Vec<_>>();
    assert_eq!(txs[4].input.as_ref(), &expected[..4]);  // FAILS before the fix (0x22b908b3)
}
```

```
git checkout d2a621cc61^ && cargo test -p kona-hardforks poc_ecotone_tx4_matches_op_node   # FAIL
git checkout d2a621cc61  && cargo test -p kona-hardforks poc_ecotone_tx4_matches_op_node   # PASS
```

Executed: partially. The `cast sig` check was executed. The Rust tests were not run.

## Recommendation

The fix corrects the selector and derives test expectations from `keccak256(signature)` rather than from self-generated golden files. Further hardening:
- Generate upgrade-transaction golden vectors from op-node, or from the spec's published transaction hashes and source hashes, and compare kona against them in CI for every fork (Ecotone, Fjord, Isthmus, Jovian and later).
- Add an action test that derives *through* each fork's activation block with a post-genesis activation time and compares block hashes against op-node.

## References

- Fix commit: d2a621cc61efeb418dea7ce4aef7efb865b98eb5
- Pull request: https://github.com/op-rs/kona/pull/2263
- Relevant files: `crates/protocol/hardforks/src/ecotone.rs`, `crates/protocol/hardforks/src/bytecode/ecotone_tx_4.hex`, `crates/protocol/hardforks/src/utils.rs`, `crates/protocol/derive/src/attributes/stateful.rs`
- Specs: https://specs.optimism.io/protocol/ecotone/derivation.html#gaspriceoracle-enable-ecotone
