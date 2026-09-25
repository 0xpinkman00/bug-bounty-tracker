# op-reth payload builder — per-transaction DA size estimate left scaled by 1e6 — op-reth sequencers under default batcher throttling exclude every user transaction (shipped in reth v1.4.1–v1.4.7)

| Field | Value |
|---|---|
| **Target** | op-reth txpool / payload builder: `txpool/src/transaction.rs` (`OpPooledTransaction::estimated_compressed_size`), consumed by `payload/src/builder.rs` (`ExecutionInfo::is_tx_over_limits`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Medium |
| **Impact category** | "Network not being able to confirm new transactions (total network shutdown)" (for user transactions on chains sequenced by affected op-reth). Rated below the category's default because no attacker is involved, deposits still go through, and the effect requires a specific setup and is obvious to operators |
| **Fix commit(s)** | a22fd4ab0688946735a2f112be49de91d3bfaa87 (paradigmxyz/reth#16558, upstream merge `f2d1863485545a344205c81deae3b54418ebdbc6`), 2025-06-03 |
| **Vulnerable since** | 33c42e1eec67d759f659e9ead312e23885e18c5a (paradigmxyz/reth#16153, "perf: use estimated_compressed_size for DA limiter", upstream `96bc7b345d0a`), 2025-05-12. **Shipped in reth/op-reth v1.4.1 (2025-05-16), v1.4.3 (2025-05-20) and v1.4.7 (2025-06-02)**. Fixed in v1.4.8 (2025-06-04) |

## Brief / Intro

OP Stack sequencers can be told to limit how much L1 data availability (DA) space each block uses. The batcher does this by calling the execution client's `miner_setMaxDASize(maxTxSize, maxBlockSize)` RPC, with sizes in bytes. A performance change in op-reth replaced the transaction's byte length with the Fjord "estimated compressed size". That helper, however, returns its result **multiplied by 1,000,000**, a fixed-point format used inside L1-fee maths. The payload builder compared this inflated number against byte limits, so even the smallest transaction (at least 100 bytes, which became 100,000,000) exceeded any realistic limit. The default op-batcher always sets a block DA limit of 130,000 bytes, so an op-reth sequencer running the affected versions built blocks containing only L1 deposits and no user transactions.

## Vulnerability Details

Before 33c42e1eec, the builder used the encoded length:

```rust
if tx_data_limit.is_some_and(|da_limit| tx.length() as u64 > da_limit) { return true; }
if block_data_limit.is_some_and(|da_limit| self.cumulative_da_bytes_used + (tx.length() as u64) > da_limit) { return true; }
```

33c42e1eec switched the builder to `tx.estimated_da_size()`, which the txpool implements as:

```rust
// txpool/src/transaction.rs:72-80 (parent of a22fd4ab)
/// Returns the estimated compressed size of a transaction in bytes scaled by 1e6.
/// `max(minTransactionSize, intercept + fastlzCoef*fastlzSize)`
pub fn estimated_compressed_size(&self) -> u64 {
    *self.estimated_tx_compressed_size
        .get_or_init(|| op_alloy_flz::tx_estimated_size_fjord(self.encoded_2718()))
}
impl DataAvailabilitySized for OpPooledTransaction<..> {
    fn estimated_da_size(&self) -> u64 { self.estimated_compressed_size() }
}
```

```rust
// payload/src/builder.rs (after 33c42e1eec)
let tx_da_size = tx.estimated_da_size();                    // e.g. >= 100_000_000
if info.is_tx_over_limits(tx_da_size, block_gas_limit, tx_da_limit, block_da_limit, tx.gas_limit()) {
    best_txs.mark_invalid(tx.signer(), tx.nonce());          // skipped for this block
    continue;
}
...
info.cumulative_da_bytes_used += tx_da_size;
```

`is_tx_over_limits` returns true when `cumulative_da_bytes_used + tx_da_size > block_data_limit`. With `tx_da_size ≥ 100 × 10⁶` and a block limit of 130,000, this holds for every transaction. `mark_invalid` removes the transaction and its dependants from this block's iterator only, so they stay in the pool and are skipped again in every later block.

The fix uses the unscaled byte estimate, matching op-geth (`core/types/rollup_cost.go`, which divides by 1e6):

```diff
-    /// Returns the estimated compressed size of a transaction in bytes scaled by 1e6.
+    /// Returns the estimated compressed size of a transaction in bytes.
-            .get_or_init(|| op_alloy_flz::tx_estimated_size_fjord(self.encoded_2718()))
+            .get_or_init(|| op_alloy_flz::tx_estimated_size_fjord_bytes(self.encoded_2718()))
```

The PR description quotes the real batcher call that exposed the bug: `"method":"miner_setMaxDASize","params":["0x0","0x1fbd0"]`, which is a 130,000-byte block limit.

### Why default deployments hit it

The op-batcher defaults at the time (`op-batcher/flags/flags.go` @ 2025-06-03) were `throttle-threshold = 1_000_000` (non-zero, so throttling is enabled), `throttle-tx-size = 5000`, `throttle-block-size = 21_000` and `throttle-always-block-size = 130_000`. The throttle loop (`op-batcher/batcher/driver.go`) *always* sends `maxBlockSize = ThrottleAlwaysBlockSize` (130,000) to every `--l2-eth-rpc` endpoint, and a tighter limit when the backlog exceeds the threshold. So the block limit was active at all times on a default setup, not just under backlog.

### Trigger scenario (no attacker required)

1. A chain runs op-reth v1.4.1, v1.4.3 or v1.4.7 as the sequencer's execution client, with op-batcher on default throttling flags (the batcher refuses to run if `miner_setMaxDASize` is unavailable, so the miner API is enabled).
2. The batcher sets `maxDASize(0, 130000)`.
3. Every block the sequencer builds contains only the L1-info deposit and user deposits. No L2-submitted transaction is ever included.

## Impact Details

- **Effect:** the chain keeps producing blocks, but users cannot get L2 transactions confirmed. Only L1→L2 deposits, the forced-inclusion path, still work. This is effectively a liveness outage for normal users while the affected version is deployed.
- **Scope:** chains whose *sequencer* used op-reth v1.4.1 to v1.4.7 with batcher DA throttling enabled (the default). op-reth verifiers, and chains sequenced by op-geth, were not affected, because this code path only runs when building blocks. The major OP chains' sequencers ran op-geth in this period as far as I know. I have not verified which chains ran op-reth sequencers.
- **Mitigating factors:** there is no attacker; this is a deterministic functional regression. It is obvious immediately (empty blocks), and operators could work around it by disabling throttling (`--throttle-threshold=0`) or rolling back. Deposits keep the chain censorship-resistant. Exposure lasted about 19 days across three releases.
- **Severity:** Medium. The impact category is the most severe liveness class, but the lack of attacker control, the configuration dependency and the easy detection justify downgrading. With throttling off the bug is dormant.

## Proof of Concept

A unit test in upstream reth `crates/optimism/payload/src/builder.rs` (or `crates/optimism/txpool/src/transaction.rs`) showing that a minimal transaction's DA size fails the default 130,000-byte block limit:

```rust
#[test]
fn poc_min_tx_exceeds_default_block_da_limit() {
    use alloy_consensus::{SignableTransaction, TxEip1559};
    use alloy_primitives::{Signature, TxKind, U256, Address};
    use op_alloy_consensus::OpTxEnvelope;
    use reth_optimism_txpool::{estimated_da_size::DataAvailabilitySized, OpPooledTransaction};
    use reth_primitives_traits::Recovered;

    // Smallest realistic user tx: an empty-calldata EIP-1559 transfer.
    let tx = TxEip1559 { chain_id: 10, nonce: 0, gas_limit: 21_000, max_fee_per_gas: 1,
                         max_priority_fee_per_gas: 1, to: TxKind::Call(Address::ZERO),
                         value: U256::from(1), ..Default::default() };
    let signed = OpTxEnvelope::Eip1559(tx.into_signed(Signature::test_signature()));
    let len = signed.eip2718_encoded_length();
    let pooled = OpPooledTransaction::new(Recovered::new_unchecked(signed, Address::ZERO), len);

    let da = pooled.estimated_da_size();
    let info = ExecutionInfo::new();
    // op-batcher default: miner_setMaxDASize(0, 130_000)
    assert!(
        !info.is_tx_over_limits(da, 30_000_000, None, Some(130_000), 21_000),
        "a ~100-byte tx must fit a 130 kB DA block limit (got da_size = {da})"
    );
}
```

```
git clone https://github.com/paradigmxyz/reth && cd reth
git checkout v1.4.7   # expected FAIL: da_size = 100_000_000 (min size 100 * 1e6)
cargo test -p reth-optimism-payload-builder poc_min_tx_exceeds_default_block_da_limit
git checkout v1.4.8   # expected PASS: da_size = 100
cargo test -p reth-optimism-payload-builder poc_min_tx_exceeds_default_block_da_limit
```

An end-to-end reproduction uses an op-reth v1.4.7 sequencer with a default op-batcher, or simply `cast rpc miner_setMaxDASize 0x0 0x1fbd0` against the sequencer EL, then sends any L2 transaction. It is never included, while deposits are.

Executed: no. The release facts (compare API: v1.4.1, v1.4.3 and v1.4.7 contain upstream `96bc7b34` but not `f2d18634`; v1.4.8 contains both) and the vulnerable source at `v1.4.1` (`tx_estimated_size_fjord` used for `estimated_da_size`) were verified against GitHub.

## Recommendation

The fix switches to `tx_estimated_size_fjord_bytes`. Further hardening:
- Encode the unit in the type (for example a `DaBytes(u64)` newtype versus a `ScaledDa(u64)`) so scaled and unscaled estimates cannot be mixed up silently.
- Add a builder test that fills a block under the batcher's default `miner_setMaxDASize` values and asserts that ordinary transactions are included.
- Consider a sanity guard in `is_tx_over_limits` or at the RPC. A single transaction whose DA size exceeds the whole block limit indicates a units error and should be logged loudly rather than skipped silently.

## References

- Fix commit: a22fd4ab0688946735a2f112be49de91d3bfaa87 (upstream f2d1863485545a344205c81deae3b54418ebdbc6)
- Pull request: https://github.com/paradigmxyz/reth/pull/16558 (regression: https://github.com/paradigmxyz/reth/pull/16153, issue https://github.com/paradigmxyz/reth/issues/16110)
- Releases: https://github.com/paradigmxyz/reth/releases/tag/v1.4.8
- Relevant files: `txpool/src/transaction.rs`, `txpool/src/estimated_da_size.rs`, `payload/src/builder.rs` (imported op-reth history); `op-batcher/flags/flags.go`, `op-batcher/batcher/driver.go`
- Related: op-geth `core/types/rollup_cost.go` (`EstimatedDASize`, divides by 1e6)
