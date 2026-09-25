# op-alloy / kona-derive: Ecotone and Fjord network-upgrade deposits built wrong (kona diverges at the activation blocks)

| Field | Value |
|---|---|
| **Target** | `op-alloy-consensus` hardfork upgrade-transaction builders (`crates/consensus/src/hardforks/{ecotone,fjord}.rs`), used by `kona-derive`'s `StatefulAttributesBuilder` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Informational (would be Medium for a production client syncing from genesis) |
| **Impact category** | "Unintended chain split (network partition)" (limited to kona re-deriving historical Ecotone/Fjord activation blocks) |
| **Fix commit(s)** | 5a08235ee388994bf76791753659fdc0354bfad0 (alloy-rs/op-alloy#408), 2025-02-03 (bytecode loading); d81f39491b940915522a3113ec7929cd39ffc241 (alloy-rs/op-alloy#412), 2025-02-03 (addresses) |
| **Vulnerable since** | Wrong addresses: present from kona's original implementation (`crates/derive/src/types/ecotone.rs`, seen at ba2de1d290, Aug 2024), carried into op-alloy by c781573335 (op-alloy#55, 2024-08-29). Undecoded hex bytecode: 147b320fef (op-alloy#288, 2024-11-19). |

## Brief / Intro

At a hard-fork activation block, every OP Stack node must insert a fixed set of "upgrade" deposit transactions into the block. These deploy new predeploy code and point the predeploy proxies at it. They must be byte-for-byte identical across clients, or the block hash differs. The Rust implementation used by kona built the Ecotone and Fjord upgrade transactions with the wrong target addresses and the wrong sender. For a period it also used the hex *text* of the contract bytecode instead of the decoded bytes. Any kona node or kona proof that re-derives the Ecotone or Fjord activation block would produce a different block from op-node and op-geth. Both forks activated in 2024, before kona was used in production. So this only affected kona syncing from genesis.

## Vulnerability Details

The spec (Ecotone derivation, "L1Block Proxy Update", "GasPriceOracle Proxy Update", "GasPriceOracle Enable Ecotone"; Fjord equivalents) requires:

| Tx | from | to |
|---|---|---|
| Ecotone #2 L1Block `upgradeTo` | `0x0` | L1Block proxy `0x4200…0015` |
| Ecotone #3 GPO `upgradeTo` | `0x0` | GPO proxy `0x4200…000F` |
| Ecotone #4 `setEcotone()` | depositor `0xDeaD…0001` | GPO proxy `0x4200…000F` |
| Fjord #1 GPO `upgradeTo` | `0x0` | GPO proxy `0x4200…000F` |
| Fjord #2 `setFjord()` | depositor `0xDeaD…0001` | GPO proxy `0x4200…000F` |

The parent of d81f39491b instead had:

`crates/consensus/src/hardforks/ecotone.rs:121-150` (parent)
```rust
TxDeposit { source_hash: Self::update_l1_block_source(),
    from: Address::default(), to: TxKind::Call(Self::L1_BLOCK_DEPLOYER), ... },   // 0x4210…0000
TxDeposit { source_hash: Self::update_gas_price_oracle_source(),
    from: Address::default(), to: TxKind::Call(Self::GAS_PRICE_ORACLE_DEPLOYER), ... },
TxDeposit { source_hash: Self::enable_ecotone_source(),
    from: Self::L1_BLOCK_DEPLOYER, to: TxKind::Call(Self::GAS_PRICE_ORACLE), ... }, // impl, not proxy
```
`crates/consensus/src/hardforks/fjord.rs:74-89` (parent): both the proxy update and `setFjord` target `GAS_PRICE_ORACLE` (the Ecotone GPO *implementation* `0xb528…da7a`) instead of the proxy.

Second bug (fixed by 5a08235ee3): after op-alloy#288 the deployment bytecode was loaded with `include_bytes!("./bytecode/l1_block_ecotone.hex").into()`. That embeds the ASCII hex characters (`0x36 0x30 0x38 …`) as the init code rather than the decoded bytecode. The Ecotone L1Block, Ecotone GPO, EIP-4788 and Fjord GPO deployment transactions therefore carried garbage input.

The unit tests compared the output against `.hex` fixtures that had been generated from this same code, so they passed. Both fixes change the fixtures (`ecotone_tx_{0..5}.hex`, `fjord_tx_{0,1,2}.hex`), which confirms that the encoded transactions changed.

The fix replaces the targets with `L1_BLOCK_PROXY` / `GAS_PRICE_ORACLE_PROXY`, sets `from: DEPOSITOR_ACCOUNT` for `setEcotone`, and decodes the hex with `hex::decode(include_str!(...))`.

`kona-derive` consumed these builders directly (`crates/derive/src/attributes/stateful.rs:138-143` at e4f126ac72: `Hardforks::ECOTONE.txs()`, `Hardforks::FJORD.txs()`).

### Attack scenario

No attacker is needed. The divergence is deterministic:
1. A kona-node syncs a chain (OP Mainnet, Base, …) from before Ecotone, or a kona fault-proof run covers the Ecotone/Fjord activation block.
2. kona builds payload attributes whose upgrade deposits differ from op-node's.
3. The execution result and block hash differ from the canonical chain. A kona-node stalls or forks at that block, and a kona proof of that range computes a wrong output root.

## Impact Details

- Affected only kona (kona-node and the kona fault-proof client), and only for the historical Ecotone (Mar 2024) and Fjord (Jul 2024) activation blocks. Any new chain whose genesis enables these forks at time 0 skips the upgrade transactions (they are not inserted at genesis), so it is unaffected as well.
- kona-node was pre-production in this period, and kona-based dispute games (if deployed anywhere) start from recent anchor states, so they never re-execute 2024 activation blocks.
- No funds at risk, and no production node affected. I rate it Informational. A production client with this bug would be Medium ("unintended chain split" for nodes syncing from genesis).

## Proof of Concept

Executed: **yes**. Fails on `d81f39491b^`, passes on `d81f39491b`.

`crates/consensus/tests/poc_upgrade_txs.rs` (in the op-alloy tree as imported in the monorepo history):
```rust
use alloy_primitives::{address, Address, TxKind};
use op_alloy_consensus::{Ecotone, Fjord};

const L1_BLOCK_PROXY: Address = address!("4200000000000000000000000000000000000015");
const GPO_PROXY: Address = address!("420000000000000000000000000000000000000F");
const DEPOSITOR: Address = address!("DeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001");

#[test]
fn ecotone_upgrade_deposits_match_spec() {
    let d: Vec<_> = Ecotone::deposits().collect();
    assert_eq!(d[2].from, Address::ZERO);
    assert_eq!(d[2].to, TxKind::Call(L1_BLOCK_PROXY), "L1Block proxy update targets wrong address");
    assert_eq!(d[3].to, TxKind::Call(GPO_PROXY), "GPO proxy update targets wrong address");
    assert_eq!(d[4].from, DEPOSITOR, "setEcotone sent from wrong account");
    assert_eq!(d[4].to, TxKind::Call(GPO_PROXY), "setEcotone targets wrong address");
}

#[test]
fn fjord_upgrade_deposits_match_spec() {
    let d: Vec<_> = Fjord::deposits().collect();
    assert_eq!(d[1].to, TxKind::Call(GPO_PROXY), "Fjord GPO proxy update targets wrong address");
    assert_eq!(d[2].to, TxKind::Call(GPO_PROXY), "setFjord targets wrong address");
}
```

Run:
```bash
for rev in d81f39491b^ d81f39491b; do
  d=$(mktemp -d); git archive $rev | tar -x -C $d
  mkdir -p $d/crates/consensus/tests && cp poc_upgrade_txs.rs $d/crates/consensus/tests/
  (cd $d && cargo test -p op-alloy-consensus --test poc_upgrade_txs)
done
```

Observed on the parent:
```
assertion `left == right` failed: L1Block proxy update targets wrong address
  left: Call(0x4210000000000000000000000000000000000000)
 right: Call(0x4200000000000000000000000000000000000015)
assertion `left == right` failed: Fjord GPO proxy update targets wrong address
  left: Call(0xb528d11cc114e026f138fe568744c6d45ce6da7a)
 right: Call(0x420000000000000000000000000000000000000f)
test result: FAILED. 0 passed; 2 failed
```
On the fix: `test result: ok. 2 passed`.

## Recommendation

The fixes correct the addresses, the sender and the bytecode decoding, and add source-hash tests. Further hardening:
- Generate the expected upgrade-transaction fixtures from op-node (`op-node/rollup/derive/ecotone_upgrade_transactions.go`, `fjord_upgrade_transactions.go`) rather than from the code under test.
- Add a kona action or regression test that derives real Ecotone/Fjord activation blocks from a public chain and compares block hashes.

## References

- Fix commits: 5a08235ee388994bf76791753659fdc0354bfad0, d81f39491b940915522a3113ec7929cd39ffc241
- PRs: https://github.com/alloy-rs/op-alloy/pull/408, https://github.com/alloy-rs/op-alloy/pull/412
- Relevant files: `crates/consensus/src/hardforks/ecotone.rs`, `crates/consensus/src/hardforks/fjord.rs`, `crates/consensus/src/hardforks/bytecode/*.hex` (op-alloy); `crates/derive/src/attributes/stateful.rs` (kona)
- Specs: https://specs.optimism.io/protocol/ecotone/derivation.html#network-upgrade-automation-transactions, https://specs.optimism.io/protocol/fjord/derivation.html#network-upgrade-automation-transactions
