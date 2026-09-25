# op-alloy / op-reth / kona: lenient EIP-2718 decoding of consensus transaction bytes let a batcher smuggle in a forged deposit and split the op-reth chain from the kona fault proof

| Field | Value |
|---|---|
| **Target** | `rust/op-alloy/crates/consensus` (`OpTxEnvelope` / `TxDeposit` / `TxPostExec` untyped decoding), `rust/op-reth/crates/payload/src/payload.rs` (payload-builder attributes), `rust/op-alloy/crates/rpc-types-engine` (attribute and flashblock decoding, used by the kona-client executor), `rust/kona/crates/node/engine/src/attributes.rs` (kona-node consolidation) |
| **Asset type** | Blockchain/DLT |
| **Severity** | High (Critical impact, downgraded because only the authorized batcher can trigger it) |
| **Impact category** | "Direct loss of funds" / "Unintended chain split (network partition)". An unbacked ETH mint on op-reth nodes, and a block-hash split between op-reth and the respected kona fault-proof program |
| **Fix commit(s)** | 85f7c13d7470a66254081f0177fc297201c07459 (PR #22778), 2026-09-04 |
| **Vulnerable since** | The lenient decoders (`TxDeposit::fallback_decode`, `decode_2718_exact` on attribute bytes, the raw-bytes tx root in kona) date back to the monorepo import (48a7a09bfc, 2026-02-10). The clean forged-deposit path needs the envelope's fallback to try each variant on a fresh copy of the buffer. That arrived with `alloy-tx-macros` 2.1.1 in 4f21ce6b95 (2026-07-15), so it affects op-reth `v2.4.1-rc.2` through `v2.4.2` and `kona-client/v1.7.0-rc.1`/`rc.2`. Fixed in op-reth `v2.4.3` and `kona-client/v1.7.0` |

## Brief / Intro

A rollup node turns batches from L1 into "payload attributes": the raw transaction bytes that make up the next L2 block. It hands them to the execution client (op-reth) to build that block. For batches in the *singular* batch format, those bytes are copied straight from the batcher's data. op-node's only type check is that the **first byte** is not `0x7E`, the deposit type, because batches must never contain deposits. The shared Rust decoder was too lenient: given a deposit's RLP body *without* its `0x7E` tag, it tried every transaction type in turn and decoded the body as a deposit. Such a body starts with `0xF8`, so it passes the "no deposits" check. The batcher could therefore insert a deposit with any sender and any `mint` amount into a block, and op-reth would create that ETH out of nothing. The same lenient decoding caused two more problems. op-reth rebuilt non-canonical bytes into canonical ones, while kona-client hashed the original bytes, so the two computed different block hashes. kona-node also compared decoded transactions instead of bytes. Only the chain's authorized batcher can post these bytes.

## Vulnerability Details

### 1. The untyped fallback resurrects a deposit from an untagged body

`OpTxEnvelope` is derived with alloy's `TransactionEnvelope` macro (`rust/op-alloy/crates/consensus/src/transaction/envelope.rs:25-50`, parent commit). The variant order is Legacy, Eip2930, Eip1559, Eip7702, **Deposit**, PostExec. For input whose first byte is `>= 0xC0` (an RLP list, i.e. "untyped"), `alloy-tx-macros` 2.1.1 generates:

```rust
fn fallback_decode(buf: &mut &[u8]) -> Eip2718Result<Self> {
    let mut candidate = *buf;
    if let Ok(tx) = Decodable2718::fallback_decode(&mut candidate) { *buf = candidate; return Ok(Self::Legacy(tx)) }
    let mut candidate = *buf;
    if let Ok(tx) = Decodable2718::fallback_decode(&mut candidate) { ...; return Ok(Self::Eip2930(tx)) }
    ...
    let mut candidate = *buf;
    if let Ok(tx) = Decodable2718::fallback_decode(&mut candidate) { ...; return Ok(Self::Deposit(tx)) }
    ...
}
```

`Sealed<TxDeposit>::fallback_decode` forwards to `TxDeposit::fallback_decode`, which was (`rust/op-alloy/crates/consensus/src/transaction/deposit.rs:303`, parent):

```rust
fn fallback_decode(data: &mut &[u8]) -> Eip2718Result<Self> {
    let tx = Self::decode(data)?;      // plain RLP body, no 0x7E required
    Ok(tx)
}
```

For a deposit body, the Legacy and typed arms all fail on the first field: a 32-byte `source_hash` cannot decode as a `u64` nonce or chain id. The Deposit arm then succeeds, and `TxPostExec::fallback_decode` behaved the same way. Every consumer that decoded consensus bytes through `OpTxEnvelope::decode_2718[_exact]` was affected:

- **op-reth payload builder** (`rust/op-reth/crates/payload/src/payload.rs:311,345`, parent). `OpTransactionSigned` is `pub type OpTransactionSigned = OpTxEnvelope` (`rust/op-reth/crates/primitives/src/transaction/mod.rs:15`).
  ```rust
  .map(|data| Decodable2718::decode_2718_exact(data.as_ref()).map(|tx| WithEncoded::new(data, tx)))
  ```
- **kona-client executor** (`rust/kona/crates/proof/executor/src/builder/core.rs:299`, via `OpPayloadAttributes::recovered_transactions_with_encoded` → `decoded_transactions` → `OpTxEnvelope::decode_2718`).

The batch-validity checks only look at the first byte. op-node `checkSequencerTxData` (`op-node/rollup/derive/batches.go:186-207`, parent) and kona `SingleBatch::check_batch` (`rust/kona/crates/protocol/protocol/src/batch/single.rs:170-187`, parent) both do this:

```go
switch txBytes[0] {
case optypes.DepositTxType:   // 0x7E
    return BatchDrop
...
}
return BatchAccept               // 0xF8... passes
```

### 2. Non-canonical bytes give different block hashes in op-reth and kona

With `alloy-consensus` 2.1.1, `Signed<T>::fallback_decode` simply calls `T::rlp_decode_signed`, so it also accepts a *typed* transaction body with the type byte stripped (e.g. EIP-1559 without `0x02`). Legacy transactions with a `0x00` prefix and untagged deposits are accepted too. op-reth then builds the block from the decoded transaction, and its transactions root uses the **canonical re-encoding**. kona-client computes the transactions root from the **raw attribute bytes** (`rust/kona/crates/proof/executor/src/builder/assemble.rs:43-49`, parent):

```rust
let transactions_root = ordered_trie_with_encoder(
    attrs.transactions.as_ref().expect(...),
    |tx, buf| buf.put_slice(tx.as_ref()),      // raw, possibly non-canonical bytes
).root();
```

Both execute the same transaction, so the state roots match. The header's `transactions_root`, and so the block hash, is different, and the output root commits to the block hash. op-geth, which reached end of support on 2026-05-31, rejected these bytes outright.

### 3. kona-node consolidation compared decoded transactions

`AttributesMatch::check` (`rust/kona/crates/node/engine/src/attributes.rs:150-166`, parent) decoded the attribute bytes and compared them with `==` against the block's transactions. op-node compares raw bytes. An unsafe block could therefore be consolidated as safe in kona-node while op-node would reorg it.

### The fix

- `TxDeposit::fallback_decode` and `TxPostExec::fallback_decode` now always return an error: "Deposits have no untyped form" (`deposit.rs`, `post_exec.rs`).
- A new `decode_2718_canonical` (`rust/op-alloy/crates/consensus/src/transaction/canonical.rs`) decodes the bytes, then re-encodes the result and requires a byte-for-byte match:
  ```rust
  pub fn decode_2718_canonical<T: Decodable2718 + Encodable2718>(bytes: &[u8]) -> Eip2718Result<T> {
      let tx = T::decode_2718_exact(bytes)?;
      if tx.encode_2718_len() != bytes.len() || tx.encoded_2718() != bytes {
          return Err(Eip2718Error::RlpError(alloy_rlp::Error::Custom("non-canonical transaction encoding")));
      }
      Ok(tx)
  }
  ```
  It is used for op-reth payload-builder attributes, for `OpPayloadAttributes::decoded_transactions` (and so for the kona-client executor), and for flashblock payload decoding.
- kona-node `AttributesMatch` now compares raw bytes first, like op-node, and treats non-canonical attribute bytes as `MalformedAttributesTransaction`.

With the fix, op-reth rejects the attributes and kona-client fails to execute them. In both, the Holocene invalid-payload rule then replaces the block with a deposits-only block, just as op-geth did.

### Attack scenario (forged deposit)

1. The batcher key posts a *singular* batch whose first user transaction is `rlp(TxDeposit{ source_hash: any, from: attacker, to: attacker, mint: 10^24 wei, value: 0, gas_limit: 50_000, is_system_tx: false, data: "" })`, **without** the `0x7E` prefix. The bytes start with `0xF8`/`0xF9`.
2. op-node's batch checks accept it, because the first byte is not `0x7E`, and send it to op-reth in the payload attributes right after the L1-info and user deposits.
3. op-reth decodes it as `OpTxEnvelope::Deposit` and runs it as a deposit, crediting `mint` to `attacker`. The built payload lists it as a normal `0x7E` transaction. It sits next to the other deposits, so op-node's `sanityCheckPayload` ("deposits first") passes and the block becomes safe.
4. Every op-reth node that derives from L1 now shows `attacker` holding the unbacked ETH. The attacker can sell it or bridge it out through third-party bridges and exchanges straight away.
5. For the native bridge: kona-client runs the same deposit, so its state root agrees on the mint. Its block hash does not match op-reth's (section 2). Honest challengers take their output roots from op-node / op-reth, while the respected `CANNON_KONA` VM decides at the step. So the attacker can permissionlessly propose kona-consistent roots and win disputes against honest challengers, then prove and finalize a withdrawal of the minted ETH from `OptimismPortal`. The Guardian can stop this during the proof maturity and airgap delays.

## Impact Details

- **Worst case:** unlimited creation of unbacked ETH on the L2 as op-reth nodes see it. That means direct theft from liquidity providers, exchanges and bridges that accept L2 ETH, and possibly from the L1 bridge through the fault-proof path described above. Separately, any non-canonical encoding (sub-issue 2) makes op-reth's chain and the respected fault-proof program disagree on every later output root. Honest proposers and challengers lose bonds, and withdrawals stall until the Guardian steps in.
- **Exposure window:** op-geth, which rejected all these encodings, reached end of support on 2026-05-31, so op-reth is the production execution client. The fallback that retries on a fresh buffer copy, which makes the deposit forgery clean, came with the `alloy-consensus` / `alloy-tx-macros` 2.1.1 bump (4f21ce6b95, 2026-07-15). It is in op-reth `v2.4.1-rc.2`…`v2.4.2` and `kona-client/v1.7.0-rc.1`/`rc.2`, and fixed in op-reth `v2.4.3` / `kona-client/v1.7.0` (2026-09-04/05). Earlier builds (e.g. op-reth `v2.3.3` with macros 2.0.5, and the Karst prestate `kona-client/v1.6.0`) passed the *same* `buf` to each arm in turn, so a failed Legacy attempt left the cursor part-way into the input. Whether a deposit could still be smuggled through there, with a crafted `source_hash` prefix, was not established. The raw-bytes vs canonical block-hash split (sub-issue 2) and the kona-node consolidation mismatch (sub-issue 3) apply to the whole range.
- **Who can trigger it:** only the batcher key authorized in `SystemConfig`. No user-controlled path reaches payload attributes with non-canonical bytes: span-batch transactions are re-encoded canonically by the derivation code, and txpool transactions are canonical. The sequencer key can put such bytes in *unsafe* gossip blocks, but derivation replaces those.
- **Severity reasoning:** the impact class is Critical, because funds can be minted and stolen. The OP Stack security model says a compromised batcher can only censor or delay the chain, and cannot alter state or steal funds. This bug breaks that promise, and batcher keys are hot keys. Requiring that privileged key is a real mitigating factor, so the report is rated **High**, not Critical. It is not rated Medium, as the original triage suggested, because the consequence is fund creation and not just a split.

## Proof of Concept

A unit test against the parent commit shows the core flaw: an untagged deposit body decodes as a deposit. Add it to `rust/op-alloy/crates/consensus/src/transaction/envelope.rs` at `85f7c13d74^`:

```rust
#[cfg(test)]
mod poc_non_canonical {
    use super::*;
    use alloy_eips::eip2718::{Decodable2718, Encodable2718};
    use alloy_primitives::{Address, B256, Bytes, TxKind, U256};

    #[test]
    fn poc_bare_deposit_body_decodes_as_deposit() {
        let canonical = TxDeposit {
            source_hash: B256::with_last_byte(2),
            from: Address::repeat_byte(0x42),
            to: TxKind::Call(Address::repeat_byte(0x43)),
            mint: u128::MAX,
            value: U256::from(1u64),
            gas_limit: 50_000,
            is_system_transaction: false,
            input: Bytes::new(),
        }
        .encoded_2718();
        let bare = &canonical[1..];
        assert_eq!(bare[0], 0xF8); // passes op-node/kona "txBytes[0] != 0x7E" batch check
        let decoded = OpTxEnvelope::decode_2718_exact(bare)
            .expect("VULNERABLE: bare deposit body accepted");
        let dep = decoded.as_deposit().expect("decoded as a deposit");
        assert_eq!(dep.mint, u128::MAX);
        // Canonical re-encoding (0x7E-prefixed) differs from the consensus bytes -> op-reth's
        // tx root != kona-client's raw-bytes tx root.
        assert_ne!(decoded.encoded_2718(), bare.to_vec());
    }
}
```

```
cd rust && cargo test -p op-alloy-consensus --lib poc_bare_deposit_body_decodes_as_deposit
```

Expected: the test **passes** on `85f7c13d74^`, which demonstrates the flaw. On `85f7c13d74` it fails at the `expect`, and the fix's own regression test `bare_deposit_body_is_rejected` (`cargo test -p op-alloy-consensus --lib bare_deposit_body_is_rejected`) passes. For the op-reth builder path, the fix adds `try_new_rejects_non_canonical_transaction_encoding` (`cargo test -p reth-optimism-payload-builder --lib try_new_rejects_non_canonical`), and for kona-node `test_attributes_mismatch_non_canonical_transaction_encoding` (`cargo test -p kona-engine --lib test_attributes_mismatch_non_canonical`).

A full end-to-end reproduction would be an op-e2e action test with a batcher that posts a singular batch holding the bare deposit body, followed by checking the attacker's balance on the op-reth verifier. It follows directly from the steps above but was not written.

Executed: yes. The test was run on a `git archive` snapshot of `85f7c13d74^` (the repo checkout was not changed), and it passes there:

```
test transaction::envelope::poc_non_canonical::poc_bare_deposit_body_decodes_as_deposit ... ok
test result: ok. 1 passed; 0 failed
```

The op-reth / op-node end-to-end steps (attributes → built block → balance) were not executed. They rest on reading the code listed above.

## Recommendation

The fix covers the root cause from both sides: untyped fallbacks can no longer produce deposit or post-exec transactions, and consensus bytes must round-trip exactly. Further suggestions:

- Make op-node's and kona's batch validation reject any transaction bytes that are not a canonical EIP-2718 encoding of an allowed type, instead of checking only the first byte. The execution layer would then no longer be the only line of defence.
- Build kona-client's transactions root from the canonical encoding of the decoded transactions, or assert that it equals the raw bytes, so the fault-proof program cannot drift from the execution client on encoding.
- Every alloy / alloy-tx-macros bump changes fallback-decoding semantics (candidate-copy in 2.1.1, a `ty() != 0` check in `Signed::fallback_decode` in 2.5.0). Add a conformance test that pins decoder behaviour on consensus-critical inputs (untagged deposit, untagged typed tx, `0x00`-tagged legacy, trailing bytes) to the reth-update review checklist (`docs/ai/reth-update-review.md`).

## References

- Fix commit: 85f7c13d7470a66254081f0177fc297201c07459
- Pull request: https://github.com/ethereum-optimism/optimism/pull/22778
- Enabling dependency bump: 4f21ce6b95 (`alloy-tx-macros` / `alloy-consensus` 2.1.1, 2026-07-15)
- Relevant files: `rust/op-alloy/crates/consensus/src/transaction/{deposit.rs,envelope.rs,canonical.rs}`, `rust/op-alloy/crates/consensus/src/post_exec.rs`, `rust/op-alloy/crates/rpc-types-engine/src/attributes.rs`, `rust/op-reth/crates/payload/src/payload.rs`, `rust/kona/crates/proof/executor/src/builder/assemble.rs`, `rust/kona/crates/node/engine/src/attributes.rs`, `op-node/rollup/derive/batches.go`
- op-geth end of support / Karst: `docs/public-docs/notices/archive/op-geth-deprecation.mdx`, `docs/public-docs/notices/archive/upgrade-19.mdx`
