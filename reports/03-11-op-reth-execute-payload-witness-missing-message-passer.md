# op-reth `debug_executePayload`: post-Isthmus execution witness omits the L2ToL1MessagePasser account, so stateless re-execution fails

| Field | Value |
|---|---|
| **Target** | op-reth, `payload/src/builder.rs` (`OpBuilder::witness`), served by `rpc/src/witness.rs` (`debug_executePayload`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Informational |
| **Impact category** | No direct Immunefi impact. Liveness of off-chain proof generation for provers that source witnesses only from op-reth ("Griefing" at most, and nobody controls the trigger) |
| **Fix commit(s)** | f42ad618e04fd0984a24ff871f7b250dea853309 (paradigmxyz/reth#16062) — 2025-05-05 |
| **Vulnerable since** | Isthmus support in the op-reth payload builder (the witness helper dates from 4a195d810a, paradigmxyz/reth#12573, 2024-11-15; the bug only shows once Isthmus is active). Isthmus activated on OP Mainnet on 2025-05-09, four days after the fix landed on reth `main`. |

## Brief / Intro

Fault-proof and ZK-proof systems re-run an L2 block "statelessly". They do not have a full database; they are given only the pieces of state the block touches (an *execution witness*). op-reth offers the `debug_executePayload` RPC, which builds a block from given attributes and returns that witness. Proof hosts such as kona-host call it. From the Isthmus hard fork on, every L2 block header also commits to the storage root of the `L2ToL1MessagePasser` contract, the contract that records L2-to-L1 withdrawals. Checking that header field therefore needs the contract's account entry. op-reth only included that account in the witness when the block actually contained a withdrawal. In the common case of a block with no withdrawals, the witness was incomplete and stateless re-execution could not finish. No attacker is involved. This is a correctness gap in a debug RPC.

## Vulnerability Details

The witness is built from whatever accounts the executed block loaded into the `State` cache (parent of the fix, `payload/src/builder.rs:363-391`):

```rust
let mut builder = ctx.block_builder(&mut db)?;
builder.apply_pre_execution_changes()?;
ctx.execute_sequencer_transactions(&mut builder)?;
builder.into_executor().apply_post_execution_changes()?;

let ExecutionWitnessRecord { hashed_state, codes, keys, lowest_block_number: _ } =
    ExecutionWitnessRecord::from_executed_state(&db);           // only accounts in db cache
let state = state_provider.witness(Default::default(), hashed_state)?;
```

Isthmus places `L2ToL1MessagePasser.storageRoot` in the header's `withdrawalsRoot`. The normal block builder reads that storage root from the state provider after execution, *outside* the executor's `State` cache. As a result, `0x4200…0016` is only in `db` if some transaction in the block touched it, i.e. only if the block had a withdrawal. For every other Isthmus block, the account leaf and the trie nodes on its path are missing from `state`/`keys`. A stateless client (kona's `StatelessL2Builder`, the op-program executor) that computes the header then fails with a missing-preimage/trie-node error.

The fix forces the account into the cache before recording the witness:

```rust
 builder.into_executor().apply_post_execution_changes()?;
+
+if ctx.chain_spec.is_isthmus_active_at_timestamp(ctx.attributes().timestamp()) {
+    // force load `L2ToL1MessagePasser.sol` so l2 withdrawals root can be computed even if
+    // no l2 withdrawals in block
+    _ = db.load_cache_account(ADDRESS_L2_TO_L1_MESSAGE_PASSER)?;
+}
```

### Scenario

1. An Isthmus chain has a proof host (kona-host, or a ZK prover built on kona) whose L2 RPC is op-reth.
2. The host asks for a witness via `debug_executePayload` for a block without withdrawals, which is most blocks.
3. The client cannot get the MessagePasser account from the witness preimages. kona-host then falls back to per-node `L2StateNode` hints served by `debug_dbGet` (`rust/kona/bin/host/src/single/handler.rs:285-299`). If that fallback is unavailable on the L2 node, proof generation for the block fails.

## Impact Details

- **No attacker control**: the defect shows up for honest inputs. An adversary cannot cause it or make it worse, beyond it already existing for most blocks.
- **Consequence**: an honest proposer or challenger that depends only on op-reth witnesses cannot produce the proof, or the bottom-level preimages, for affected blocks. In a dispute game this could in principle cost a challenger the ability to `step`. That needs an unusual deployment where every honest actor uses kona-host with op-reth and no working fallback. OP Mainnet's production fault proofs at the time used op-program with op-geth.
- **Exposure**: the fix landed on 2025-05-05, before OP Mainnet Isthmus activation (2025-05-09). Sepolia-family testnets activated Isthmus earlier (April 2025) and could have been affected for anyone proving them with op-reth witnesses.
- Given no attacker, the host-side fallback, and the short or no mainnet exposure, the rating is **Informational**.

## Proof of Concept

Reproduce against a local Isthmus-at-genesis devnet running op-reth built at the parent commit (`f42ad618e0^`) and then at the fix. Pick any block `N` that contains no withdrawal (for example an empty block containing only the L1-info deposit):

```bash
RPC=http://127.0.0.1:8545           # op-reth L2 RPC with --http.api debug,eth
N=$(cast block-number --rpc-url $RPC)
PARENT=$(cast block $((N-1)) --json --rpc-url $RPC | jq -r .hash)
BLK=$(cast block $N --json --rpc-url $RPC)
TXS=$(echo "$BLK" | jq -r '.transactions[]' | while read h; do cast rpc debug_getRawTransaction $h --rpc-url $RPC | jq -r .; done | jq -R . | jq -s .)
ATTRS=$(jq -n --argjson b "$BLK" --argjson txs "$TXS" '{
  timestamp: $b.timestamp, prevRandao: $b.mixHash, suggestedFeeRecipient: $b.miner,
  withdrawals: [], parentBeaconBlockRoot: $b.parentBeaconBlockRoot,
  transactions: $txs, noTxPool: true, gasLimit: $b.gasLimit,
  eip1559Params: ("0x" + ($b.extraData[4:20]))}')

cast rpc debug_executePayload "$PARENT" "$ATTRS" --rpc-url $RPC \
  | jq '.keys | map(ascii_downcase) | index("0x4200000000000000000000000000000000000016")'
# parent commit : null   (MessagePasser address not in witness keys)
# fix commit    : <n>    (present)
```

End-to-end effect: point `kona-host --l2-node-address $RPC` at the vulnerable op-reth for block `N`. The run prints `` `debug_executePayload` failed to return a complete witness `` and must fall back to `debug_dbGet` for the missing nodes.

Executed: no (requires building op-reth and running a devnet).

## Recommendation

The fix loads the MessagePasser account unconditionally after Isthmus. More generally, any state that the header computation reads outside the executor (here the withdrawals-root storage trie) should be recorded into the witness. A regression test is recommended that re-executes `payload_witness` output statelessly (for example with kona's `StatelessL2Builder`) for an Isthmus block without withdrawals.

## References

- Fix commit: f42ad618e04fd0984a24ff871f7b250dea853309
- Pull request: https://github.com/paradigmxyz/reth/pull/16062
- Relevant files: `payload/src/builder.rs` (op-reth, now under `rust/op-reth/`), `rpc/src/witness.rs`, `rust/kona/bin/host/src/single/handler.rs`
- Spec: https://specs.optimism.io/protocol/isthmus/exec-engine.html (L2ToL1MessagePasser storage root in header)
