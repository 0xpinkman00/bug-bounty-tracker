# op-reth tx-pool admits transactions that can never be included (L1-info gas reservation and Isthmus operator fee not enforced)

| Field | Value |
|---|---|
| **Target** | `rust/op-reth/crates/txpool/src/validator.rs` (`OpTransactionValidator`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | Mempool resource griefing: "Causing network processing nodes to process transactions from the mempool beyond set parameters". Downgraded from that category's usual rating because the pool's per-sender and global caps bound the effect |
| **Fix commit(s)** | d3a0391a3d229b6cd0af8c565f90b34be49fc702 (PR #21548), 2026-07-25; 91977fbfc513528df108053304e397d53ddf39d0 (PR #21609), 2026-07-25 |
| **Vulnerable since** | Unknown exactly. Neither check appears anywhere in op-reth's txpool history before these fixes. The operator-fee gap has existed since Isthmus (operator fee) support was added |

## Brief / Intro

A node's transaction pool (mempool) is supposed to accept only transactions that could actually be included in a block. It stores and gossips each one to peers, so the pool's resources are only well spent on includable transactions. op-reth, the Rust OP Stack execution client, admitted two kinds of transactions that op-geth rejects and that the block builder will never include:

- (1) transactions whose gas limit only fits in a block that has no L1-info deposit. Every OP block has that deposit, so they can never fit.
- (2) transactions from senders who can pay for L2 gas and the L1 data fee but not the Isthmus *operator fee*.

These transactions stay in the pool and propagate until they expire. Because they are never included, the sender never pays for them.

## Vulnerability Details

### (1) No L1-info gas reservation

Every OP block starts with the L1-attributes deposit, which uses gas. op-geth therefore caps pool transactions at `blockGasLimit - l1InfoGasOverhead` (70,000) in `core/txpool/validation.go`. op-reth used the inner Ethereum validator's cap, which is the full block gas limit. Transactions with `gas_limit` in `(block_gas_limit - 70_000, block_gas_limit]` were admitted but can never be packed.

Fix (`validator.rs`, `d3a0391a3d`):
```rust
pub(crate) const L1_INFO_GAS_OVERHEAD: u64 = 70_000;
...
let gas_limit = transaction.gas_limit();
let effective_gas_limit = self.inner.block_gas_limit().saturating_sub(L1_INFO_GAS_OVERHEAD);
if gas_limit > effective_gas_limit {
    return TransactionValidationOutcome::Invalid(
        transaction,
        InvalidPoolTransactionError::ExceedsGasLimit(gas_limit, effective_gas_limit),
    );
}
```
The check runs *before* the potentially slow interop `is_valid_cross_tx` access-list check, which can take up to 7,200 s. That also removes an admission path that is cheap for the sender and expensive for the node.

### (2) Operator fee not reserved in the balance check

The Isthmus exec-engine spec says: "the transaction pool must reject transactions that do not have enough balance to cover the worst-case cost of the transaction fee. This worst-case cost of a transaction now includes the worst-case operator fee."

`validator.rs:240-262` (parent `91977fbfc5^`)
```rust
let cost_addition = match l1_block_info.l1_tx_data_fee(
    self.chain_spec(), self.block_timestamp(), &encoded, false) { ... };
let cost = valid_tx.transaction().cost().saturating_add(cost_addition);
// Checks for max cost
if cost > balance {
    return TransactionValidationOutcome::Invalid(.., InvalidTransactionError::InsufficientFunds(..).into());
}
```
Only the L1 data fee was added. Fix:
```rust
let spec_id = revm_spec_by_timestamp_after_bedrock(self.chain_spec(), self.block_timestamp());
cost_addition = cost_addition.saturating_add(operator_fee_addition(
    &l1_block_info, spec_id, &encoded, valid_tx.transaction().gas_limit()));
```
`operator_fee_addition` calls `L1BlockInfo::operator_fee_charge` with the transaction's gas limit, which is the worst case. It uses the Isthmus formula (`gas × scalar / 1e6 + constant`) or the Jovian formula (`gas × scalar × 100 + constant`), and returns 0 before Isthmus or when the parameters are unset.

### Attack scenario

1. The attacker funds `N` accounts. For (2), each needs just enough ETH for `value + gas_limit × max_fee + L1 data fee` and not enough for the operator fee. On a chain whose operator fee is non-zero, the Jovian `×100` scalar makes this gap easy to hit.
2. The attacker submits transactions to an op-reth node. For (1), use `gas_limit = block_gas_limit`. For (2), use the underfunded senders.
3. op-reth accepts and gossips them. When the builder reaches them it rejects them: (1) never fits and (2) fails the balance check at execution. They are skipped without charge and stay pending, taking pool slots and gossip bandwidth, until eviction or expiry.
4. The attacker can fill and refill pending slots across op-reth nodes at no cost in fees. op-geth peers reject these transactions, so the effect is limited to op-reth nodes.

## Impact Details

- **Effect:** wasted pool memory and slots, gossip bandwidth, and builder CPU (repeated attempts to execute the transactions) on op-reth nodes, including op-reth-based sequencers. In the worst case, honest transactions are evicted from a full pool.
- **Mitigating factors:**
  - reth's pool limits pending and queued transactions per sender and in total, and evicts by price, so the spam is bounded.
  - Variant (2) only matters on chains with a non-zero operator fee.
  - No consensus or funds impact: the builder never includes these transactions.
- **Severity:** **Low**.

## Proof of Concept

Both fixes include regression tests.

(1) `rejects_tx_exceeding_l1_info_reserved_gas_limit` (`rust/op-reth/crates/txpool/src/transaction.rs`, `d3a0391a3d`):
```rust
let block_gas_limit = validator.block_gas_limit();
let effective_limit = block_gas_limit - L1_INFO_GAS_OVERHEAD;
let outcome = validator.validate_one(TransactionOrigin::External, make_tx(block_gas_limit)).await;
assert!(matches!(outcome,
    TransactionValidationOutcome::Invalid(_, InvalidPoolTransactionError::ExceedsGasLimit(..))));
let outcome = validator.validate_one(TransactionOrigin::External, make_tx(effective_limit)).await;
assert!(outcome.is_valid());
```
On the parent, the first `validate_one` returns `Valid`: a transaction at the full block gas limit is accepted.

(2) The `operator_fee_addition` unit tests (`operator_fee_added_when_isthmus_and_params_present`, `operator_fee_uses_jovian_formula_in_jovian`, and others) in `validator.rs`. The following end-to-end variant fails on the parent. It uses the `(1)` test harness, with a sender balance equal to `tx.cost() + l1_data_fee`, and operator-fee parameters set in the validator's `OpL1BlockInfo`:
```rust
// expected on fix:   TransactionValidationOutcome::Invalid(_, /* Consensus(InsufficientFunds{..}) */ ..)
// observed on parent: TransactionValidationOutcome::Valid{..}
```

Run:
```bash
cd rust
cargo test -p reth-optimism-txpool rejects_tx_exceeding_l1_info_reserved_gas_limit
cargo test -p reth-optimism-txpool operator_fee
```
To reproduce the failure, cherry-pick only the test hunk onto `d3a0391a3d^` in a scratch clone (it needs the `L1_INFO_GAS_OVERHEAD` constant and the `block_gas_limit()` accessor, so define both in the test) and observe the `Valid` outcome.

Executed: no. The op-reth crate graph is too heavy to build for this review.

## Recommendation

The fixes bring op-reth in line with op-geth and the Isthmus spec. More generally, add a differential test that runs the same set of admission-edge transactions through op-geth's `ValidateTransaction` and op-reth's `OpTransactionValidator`. Candidates: gas-limit edges, fee-component balance edges, deposit and post-exec types, and interop access lists. That would catch future parity drift.

## References

- Fix commits: d3a0391a3d229b6cd0af8c565f90b34be49fc702, 91977fbfc513528df108053304e397d53ddf39d0
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/21548, https://github.com/ethereum-optimism/optimism/pull/21609
- Relevant files: `rust/op-reth/crates/txpool/src/validator.rs`, `rust/op-reth/crates/txpool/src/transaction.rs`
- Specs: https://specs.optimism.io/protocol/isthmus/exec-engine.html#operator-fee, https://specs.optimism.io/protocol/jovian/exec-engine.html#operator-fee; op-geth `core/txpool/validation.go` (`EffectiveGasLimit`)
