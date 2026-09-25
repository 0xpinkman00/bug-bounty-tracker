# kona-node RPC: admin namespace always enabled on the public listener, ignoring `--rpc.enable-admin`

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/node/service` and `rust/kona/crates/node/rpc` (kona-node JSON-RPC server) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Medium |
| **Impact category** | Shutdown of greater than 10% or equal to but less than 30% of network processing nodes without brute force actions, but does not shut down the network (Medium). For a kona-node sequencer, this is unauthenticated sequencer halting. |
| **Fix commit(s)** | 649ae01634231ad2f4a008f6ddcff42072fb5ea1 (PR #21753), 2026-07-15 |
| **Vulnerable since** | Before kona was imported into the monorepo (`48a7a09bfc`, 2026-02-10; there `AdminRpc` was merged unconditionally in `actors/rpc/actor.rs`). The registration was moved into `node.rs` by `7295d14094` (2026-05-26) without change. |

## Brief / Intro

Like op-node, kona-node has a privileged "admin" RPC API. It can stop and start the sequencer, override conductor leadership, reset derivation, and push an arbitrary block into the node as its new unsafe head. In op-node this API is off by default and needs `--rpc.enable-admin`. kona-node parsed the same flag but never read it: the admin API was always on, served without authentication, and by default listened on `0.0.0.0` (every network interface). Anyone who could reach a kona-node's RPC port could halt it as a sequencer or feed it forged blocks.

## Vulnerability Details

The flag was parsed into `RpcBuilder.enable_admin` (`rust/kona/bin/node/src/flags/rpc.rs:27-29,58`), and the listener defaulted to all interfaces:

```rust
#[arg(long = "rpc.addr", default_value = "0.0.0.0", env = "KONA_NODE_RPC_ADDR")]
pub listen_addr: IpAddr,
...
#[arg(long = "rpc.enable-admin", env = "KONA_NODE_RPC_ENABLE_ADMIN")]
pub enable_admin: bool,
```

The RPC setup never consulted it. See `rust/kona/crates/node/service/src/service/node.rs:387-399` at `649ae01634^`:

```rust
let mut modules = RpcModule::new(());
modules.merge(HealthzApiServer::into_rpc(HealthzRpc {}))...;
modules.merge(P2pRpc::new(p2p_rpc_tx).into_rpc())...;
modules
    .merge(AdminRpc::new(sequencer_admin_client, network_admin_tx).into_rpc())   // always
    .map_err(|e| format!("Failed to register admin module: {e:?}"))?;
modules.merge(RollupRpc::new(engine_rpc_client.clone(), l1_watcher_queries_tx).into_rpc())...;
```

No authentication middleware sits in front of this server. The admin namespace (`rust/kona/crates/node/rpc/src/admin.rs`) exposes:

| Method | Effect |
|---|---|
| `admin_stopSequencer` / `admin_startSequencer` | Stops or starts block production on a sequencer node |
| `admin_overrideLeader`, `admin_setRecoverMode` | Change conductor and leader state on a sequencer |
| `admin_resetDerivationPipeline` | Forces a derivation reset |
| `admin_postUnsafePayload` | Sends an arbitrary `OpExecutionPayloadEnvelope` to the engine as a new unsafe block, with **no sequencer-signature check** (`admin.rs:62-71` → `NetworkAdminQuery::PostUnsafePayload` → `actors/network/actor.rs:191-196` → `unsafe_block_tx` → `engine_client.send_unsafe_block`). This works on every node, not only sequencers. |

**The fix** gates the merge on the flag:

```rust
merge_admin_module(&mut modules, config.enable_admin(), sequencer_admin_client, network_admin_tx)?;

fn merge_admin_module(modules: &mut RpcModule<()>, enable_admin: bool, ...) -> Result<(), String> {
    if enable_admin {
        modules.merge(AdminRpc::new(sequencer_admin_client, network_admin_tx).into_rpc())...;
    }
    Ok(())
}
```

It also adds the `RpcBuilder::enable_admin()` accessor, and sets `KONA_NODE_RPC_ENABLE_ADMIN=true` in the devstack, which relied on the accidental exposure. An intermediate change of the default bind address to `127.0.0.1` was reverted, because the node ships as a Docker image. Protection now comes from the opt-in flag alone.

### Attack scenario

1. The attacker scans for kona-node RPC endpoints (default port 9545, bound to `0.0.0.0`). Operators often expose the rollup RPC because proposers, indexers and challengers use `optimism_outputAtBlock`, `optimism_syncStatus` and similar methods.
2. Against a kona-node **sequencer**, the attacker calls `admin_stopSequencer`. Unsafe block production stops until an operator steps in. The attacker can repeat the call right after any restart, and can also call `admin_overrideLeader` to disturb conductor-managed HA sets.
3. Against any kona-node **verifier or RPC node**, the attacker builds a valid execution payload on top of the node's unsafe head, for example one with a fabricated deposit transaction that mints ETH to the attacker, and submits it with `admin_postUnsafePayload`. The node's EL accepts it as the new unsafe head, because a deposit only needs to be valid for the EL. Downstream users of that node's `latest`/unsafe view (wallets, exchanges, bridges that credit on unsafe) see the forged state until derivation reorgs it out.

## Impact Details

- **Sequencer halt:** unauthenticated remote stop of block production on any kona-node sequencer with an exposed RPC port. On a production sequencer this would be High or Critical ("Network not being able to confirm new transactions").
- **Unsafe-head forgery:** remote injection of unsigned blocks as the unsafe head of any exposed kona-node. The safe and finalized chains are not affected, because derivation replaces the forged blocks. So the harm is limited to parties that rely on the unsafe head of that particular node.
- **Preconditions:** the RPC port must be reachable by the attacker. No credentials are needed.
- **Mitigating factors:** kona-node is documented as experimental and "not production ready". OP Stack production sequencers run op-node, which gates the admin API correctly. Many deployments firewall the RPC port.

Given the pre-production status of the component, and the need for a reachable RPC port, this is rated **Medium**.

## Proof of Concept

**Runtime reproduction on the parent commit.** Start a kona-node without `--rpc.enable-admin`:

```bash
git worktree add /tmp/kona-parent 649ae01634^
cd /tmp/kona-parent/rust && cargo build --release --bin kona-node
./target/release/kona-node node --l1-eth-rpc $L1 --l1-beacon $BEACON --l2-engine-rpc $ENGINE \
   --l2-engine-jwt-secret jwt.hex --chain 11155420 --mode sequencer   # flags abbreviated, see `kona-node node --help`; note: no --rpc.enable-admin

# From another host:
curl -s -X POST http://<node-ip>:9545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"admin_sequencerActive","params":[]}'
# parent:  {"jsonrpc":"2.0","id":1,"result":true}
curl -s -X POST http://<node-ip>:9545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"admin_stopSequencer","params":[]}'
# parent:  {"result":"0x<unsafe head hash>"}  -> sequencer stopped
# fixed:   {"error":{"code":-32601,"message":"Method not found"}}
```

**Unit-level regression test from the fix.** It fails to compile or fails on the parent, and passes on the fix:

```rust
// rust/kona/crates/node/service/src/service/node.rs
#[test]
fn admin_module_registered_only_when_enabled() {
    assert!(admin_method_names(false).is_empty(), "admin namespace must not be registered when disabled");
    let enabled = admin_method_names(true);
    for method in ["admin_postUnsafePayload", "admin_startSequencer", "admin_stopSequencer"] {
        assert!(enabled.iter().any(|m| m == method), "missing {method}");
    }
}
```

```bash
cd rust && cargo test -p kona-node-service --lib service::node::tests::admin_module_registered_only_when_enabled
```

Executed: no.

## Recommendation

The fix registers the admin namespace only when `--rpc.enable-admin` is set, which matches op-node.

Defence-in-depth suggestions:
- Serve admin methods on a separate, localhost-bound or JWT-authenticated listener, as op-geth does with its authenticated engine port.
- Log a startup warning when admin is enabled on a non-loopback address.
- Add a test at the CLI level that parses the flags and asserts the RPC module's method list, so the flag cannot become dead again.

## References

- Fix commit: 649ae01634231ad2f4a008f6ddcff42072fb5ea1
- Pull request: https://github.com/ethereum-optimism/optimism/pull/21753
- Relevant files: `rust/kona/crates/node/service/src/service/node.rs`, `rust/kona/crates/node/rpc/src/{admin.rs,config.rs}`, `rust/kona/bin/node/src/flags/rpc.rs`, `rust/kona/crates/node/service/src/actors/network/actor.rs`
- Related discussion: ethereum-optimism/optimism#16487 (bind address default)
