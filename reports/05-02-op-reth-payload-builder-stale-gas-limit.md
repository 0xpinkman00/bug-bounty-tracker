# op-reth: the payload builder's EVM used the parent's gas limit instead of the gas limit in the payload attributes, so blocks built right after a gas-limit change diverge

| Field | Value |
|---|---|
| **Target** | op-reth: `evm/src/lib.rs` (`OpEvmConfig::next_cfg_and_block_env`) and `payload/src/builder.rs` (`OpPayloadBuilder::cfg_and_block_env`). Today these live at `rust/op-reth/crates/{evm,payload}` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | "Unintended chain split (network partition)", limited to op-reth nodes that *build* the affected block, and only for one block per gas-limit change. Downgraded from High for the reasons in Impact Details |
| **Fix commit(s)** | `fbcd1026b9b1d7d9aeaafffdc9ae20048e4a089c` (paradigmxyz/reth#13351), 2024-12-12 |
| **Vulnerable since** | Unknown. The OP builder's `next_cfg_and_block_env` took the gas limit from the parent for as long as the attributes-provided gas limit existed (it was never plumbed into `NextBlockEnvAttributes`) |

## Brief / Intro

On OP Stack chains the block gas limit is not voted on by block producers as on Ethereum L1. The chain operator sets it in the L1 `SystemConfig` contract, and op-node passes it to the execution client in every "build this block" request (the payload attributes' `gasLimit`). op-reth's block builder wrote the new gas limit into the block header, but ran the transactions in an EVM whose block gas limit was still the *previous* block's value. After a gas-limit change, the first block built by op-reth could run transactions differently from op-geth: the `GASLIMIT` opcode returns a different value, and transactions whose gas lies between the old and new limits are dropped. The result is a block with a different state root and hash from the canonical one.

## Vulnerability Details

`fbcd1026^:evm/src/lib.rs:152-164`:
```rust
let block_env = BlockEnv {
    number: U256::from(parent.number + 1),
    coinbase: attributes.suggested_fee_recipient,
    timestamp: U256::from(attributes.timestamp),
    ...
    gas_limit: U256::from(parent.gas_limit),          // <-- stale
    basefee: self.chain_spec.next_block_base_fee(parent, attributes.timestamp)?,
    ...
};
```
`NextBlockEnvAttributes` (`fbcd1026^:payload/src/builder.rs:171-178`) carried only `timestamp`, `suggested_fee_recipient` and `prev_randao`. The OP attributes' `gas_limit` never reached the EVM environment.

Elsewhere in the builder the attributes value *was* used, so the code disagreed with itself:
- `OpPayloadBuilderCtx::block_gas_limit()` (`:583`) returns `attributes.gas_limit`. It is used for the header (`gas_limit: ctx.block_gas_limit()`, `:410`) and for the pool-packing cap (`:847-859`).
- `initialized_block_env.gas_limit`, the value revm sees, is `parent.gas_limit`.

What diverges in the one block where `attributes.gas_limit != parent.gas_limit`:
1. **`GASLIMIT` opcode (0x45):** it returns the old limit. Any transaction that branches on or stores `block.gaslimit` produces different state from op-geth.
2. **revm's transaction validation:** revm rejects a non-deposit transaction with `tx.gas_limit > block_env.gas_limit` (`CallerGasLimitMoreThanBlock`). When the limit is **raised**, a transaction with gas between the old and new limits is valid for op-geth but invalid for op-reth's EVM. In `execute_sequencer_transactions` (`fbcd1026^:payload/src/builder.rs:790-800`) any `EVMError::Transaction` is logged and the transaction silently skipped:
   ```rust
   Err(err) => match err {
       EVMError::Transaction(err) => {
           trace!(target: "payload_builder", %err, ?sequencer_tx, "Error in sequencer transaction, skipping.");
           continue
       }
   ```
   When op-node derives a block from L1 batch data, the batch transactions arrive as `attributes.transactions`. op-reth builds a block *without* one of the canonical transactions, while op-geth includes it.

From the next block on, `parent.gas_limit` equals the new limit, so the window is exactly one block per change.

Fix (`fbcd1026`):
```rust
-            gas_limit: U256::from(parent.gas_limit),
+            gas_limit: U256::from(attributes.gas_limit),
```
```rust
             prev_randao: attributes.prev_randao(),
+            gas_limit: attributes.gas_limit.unwrap_or(parent.gas_limit),
         };
         self.evm_config.next_cfg_and_block_env(parent, next_attributes)
```

The block-import path (`engine_newPayload` of a block built elsewhere) was unaffected. It fills the block environment from the received header, which carries the new limit.

### Attack scenario

1. The chain operator raises or lowers the gas limit with `SystemConfig.setGasLimit`. During this period Base did this frequently, as part of its ongoing gas-target increases.
2. The attacker watches L1 for the `ConfigUpdate` event. The new limit applies from the first L2 block whose L1 origin includes that event. The attacker sends a few cheap transactions around that time to a contract that does `sstore(0, gaslimit())`.
3. An op-reth node that builds that block computes a different storage value and state root from op-geth. This means an op-reth sequencer, or an op-reth verifier whose op-node derives the block from L1 through FCU+attributes instead of importing the gossiped block.
   - op-reth verifier deriving from L1: its local chain permanently diverges from the canonical chain (different state root, and every later block builds on it).
   - op-reth sequencer: the block it gossips does not match what op-geth nodes derive from the batch. Verifiers reject it or later reorg it out as an unsafe block.

## Impact Details

- **Affected nodes:** only op-reth, and only in the *building* role. The common verifier configuration imports gossiped unsafe blocks through `newPayload`, and op-node then consolidates the safe chain against those blocks without asking the EL to build. That configuration is unaffected.
- **Trigger:** a gas-limit change by the `SystemConfig` owner. This is a trusted role, but the action is routine. Divergence also needs a transaction in that single block that observes `GASLIMIT` or has gas between the old and new limits. An attacker can arrange that cheaply, but there is no profit motive beyond disruption.
- **Duration:** one block per gas-limit change, but the consequence for a deriving op-reth node is permanent until an operator resyncs it.
- **Why Low:** trusted-role trigger, one-block window, only non-default op-reth roles affected, and no fund loss. It is still a consensus-relevant bug, because op-reth and op-geth disagree about the post-state of a valid block.

## Proof of Concept

The fix commit added no regression test. The test below targets `OpEvmConfig::next_cfg_and_block_env` directly. Put it in upstream `paradigmxyz/reth` `crates/optimism/evm/src/lib.rs` (`tests` module), at the revision before PR #13351. Note that `NextBlockEnvAttributes` has no `gas_limit` field on the parent commit. The pre-fix variant therefore shows the bug by asserting that the returned `block_env.gas_limit` equals the *parent's* limit, even though the payload attributes request a different one:

```rust
#[test]
fn poc_block_env_gas_limit_ignores_attributes() {
    use reth_evm::NextBlockEnvAttributes;
    let evm_config = OpEvmConfig::new(Arc::new(OpChainSpec { inner: ChainSpec::default() }));
    let parent = Header { gas_limit: 30_000_000, base_fee_per_gas: Some(1), ..Default::default() };

    // Parent commit: there is no way to pass the attributes' gas limit.
    let attrs = NextBlockEnvAttributes {
        timestamp: 1,
        suggested_fee_recipient: Default::default(),
        prev_randao: Default::default(),
        // fixed commit: gas_limit: 60_000_000,
    };
    let (_cfg, block_env) = evm_config.next_cfg_and_block_env(&parent, attrs).unwrap();

    // Parent commit: block_env.gas_limit == 30_000_000 while the header built by the
    // OP payload builder uses attributes.gas_limit (60_000_000). GASLIMIT inside the EVM
    // and the revm per-tx cap therefore use the stale value.
    // Fixed commit (with gas_limit: 60_000_000 above): assert_eq!(block_env.gas_limit, U256::from(60_000_000));
    assert_eq!(block_env.gas_limit, U256::from(parent.gas_limit));
}
```

End-to-end reproduction on a devnet with an op-reth sequencer (or an op-reth verifier with `--syncmode=consensus-layer` on op-node):
1. Deploy `contract G { uint public g; fallback() external { g = block.gaslimit; } }`.
2. Call `SystemConfig.setGasLimit(old + 1_000_000)` on L1.
3. Call `G` in every L2 block until the gas limit changes.
4. Compare `G.g()` and the block hash at the first new-limit block between the op-reth node and an op-geth node. On the parent commit the values differ (old limit against new limit), and so do the state roots.

```
cargo test -p reth-optimism-evm --features optimism poc_block_env_gas_limit_ignores_attributes
```

Executed: no. The historical op-reth crates in this monorepo are not a standalone buildable workspace. The behaviour was confirmed by reading the parent-commit code.

## Recommendation

The fix plumbs `attributes.gas_limit` into `NextBlockEnvAttributes` and the EVM `BlockEnv`, which is correct. Defense in depth:
- Derive every block-level field (header and EVM env) from one source. The bug existed because `block_gas_limit()` and `initialized_block_env.gas_limit` were computed separately.
- Add a builder sanity check that `header.gas_limit == block_env.gas_limit` before sealing.
- Add a differential test that changes the `SystemConfig` gas limit on a devnet and compares op-reth and op-geth block hashes.

## References

- Fix commit: `fbcd1026b9b1d7d9aeaafffdc9ae20048e4a089c`
- Pull request: https://github.com/paradigmxyz/reth/pull/13351
- Relevant files: `evm/src/lib.rs`, `payload/src/builder.rs` (now `rust/op-reth/crates/{evm,payload}`)
- Spec: https://github.com/ethereum-optimism/specs/blob/main/specs/protocol/system-config.md (gas limit), https://github.com/ethereum-optimism/specs/blob/main/specs/protocol/exec-engine.md (payload attributes `gasLimit`)
