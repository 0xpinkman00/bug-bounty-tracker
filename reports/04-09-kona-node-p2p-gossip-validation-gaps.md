# kona-node P2P gossip: incomplete unsafe-block validation and wrong or static unsafe-block signer (pre-release)

| Field | Value |
|---|---|
| **Target** | kona-node P2P (`crates/node/p2p/src/gossip/block_validity.rs`, `bin/node/src/flags/*`, `bin/node/src/runtime/loader.rs`; today under `rust/kona/`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Informational (kona-node was pre-release, and no production network relied on it) |
| **Impact category** | "Causing network processing nodes to process transactions from the mempool beyond set parameters" (closest fit: kona-node accepting unsafe blocks that the P2P spec says to reject) |
| **Fix commit(s)** | 444bef7aa05d38f1764c3804a367b9c2e0f3799e (op-rs/kona#1322) 2025-03-27; 7a53411205dd7ce7ca46032e0d1999516295ebb4 (#1339) 2025-03-28; db363c0208f8247988eb6d6be8a00b5eb1045451 (#1453) 2025-04-17; 25023272678f76e2da44c54abbb4f830ae5365f0 (#1454) 2025-04-17; 430b77219678ce28e7c4ad5e81deadb6c6197ee3 (#1455) 2025-04-17; 2f80b7bbeac4deb8e557ffac92607c0b52bec675 (#1505) 2025-04-24; acae017bc204a7bd62d7cfca7cdb7148a34d56dd (#1523) 2025-04-25; 200c20bc5bcf136573f361899048cf428c287745 (#1604) 2025-04-30 |
| **Vulnerable since** | From the first kona-node gossip handler (early 2025) until the commits above |

## Brief / Intro

Before blocks are posted to L1, the sequencer broadcasts new L2 blocks over a peer-to-peer gossip network. Nodes treat these as the "unsafe" chain. The OP Stack P2P spec lists checks that every node must make before accepting and relaying such a block. The block must be signed by the chain's current *unsafe block signer*, its hash must match its contents, it must not be a replay, there may be at most 5 blocks per height, and version-specific fields must be well formed. In early 2025, kona-node, the Rust rollup node that was still in development, skipped most of these checks. It also used the wrong key as the expected signer, or a fixed one. None of this affected production networks, because kona-node was not yet deployed. The fixes brought kona-node in line with the spec and with op-node.

## Vulnerability Details

Before db363c0208, `BlockHandler::block_valid` (`crates/node/p2p/src/gossip/block_validity.rs:36-71`) checked only the timestamp window and the signature:

```rust
// CHECK: The timestamp is not too far in the future or past.
if is_future || is_past { return Err(BlockInvalidError::Timestamp { .. }); }

// CHECK: The signature is valid.
let msg = envelope.payload_hash.signature_message(self.chain_id);
let block_signer = *self.signer_recv.borrow();
let Ok(msg_signer) = envelope.signature.recover_address_from_prehash(&msg) else { .. };
if msg_signer != block_signer { return Err(BlockInvalidError::Signer { .. }); }
Ok(())
```

The gaps, and the commits that closed them:

### (a) Expected signer was wrong or static (444bef7aa0, 7a53411205, 2f80b7bbea, acae017bc2)
- Before 444bef7aa0, the node passed `Address::default()` as the signer (`crates/node/service/src/service/standard/mod.rs:113-115`, "TODO: grab the unsafe block signer from the config"). kona-node therefore rejected every real block.
- 444bef7aa0 replaced that with `genesis.system_config.batcher_address`, which is the **batcher** key, not the unsafe block signer. For about one day, kona-node accepted gossip blocks signed by the batcher key and rejected the sequencer's. 7a53411205 fixed this by using `roles.unsafe_block_signer` from the superchain registry.
- That value was still a static registry snapshot. If the chain rotated `SystemConfig.unsafeBlockSigner`, for example after a key compromise, kona-node kept trusting the old key. 2f80b7bbea added a `RuntimeLoader` that reads the signer slot (`keccak256("systemconfig.unsafeblocksigner") - 1`) from L1 at startup, and acae017bc2 made that work for chains not in the registry. At that point the signer was still read only once at startup, not continuously.

### (b) No block-hash check (db363c0208)
The handler did not recompute the header hash from the payload. The signed payload hash covers the payload bytes, so a relaying peer cannot tamper with the contents. The authorized signer, however, could gossip payloads whose `block_hash` field does not match their contents. kona-node would then relay them, and the spec says to reject them. The execution client would still reject such a payload in `engine_newPayload`, so the main effect was on gossip hygiene.

### (c) No version-specific checks (2502327267)
Nothing checked that V3/V4 topics carry `parent_beacon_block_root` and zero blob gas fields, that V4 carries the Isthmus `withdrawals_root`, and so on.

### (d) No replay or equivocation limits (430b772196)
The spec says to ignore already-seen block hashes and to reject a block if more than 5 different blocks have been seen for its height. Without these limits, a misbehaving or compromised signer could equivocate without bound, and kona-node would forward every version.

Note: the first version of (d) recorded the block hash in `seen_hashes` *before* verifying the signature. Any peer could therefore spend a height's 5-block allowance with unsigned blocks that had valid hashes, and the real block would then be rejected. This was fixed later in cd8e786aed ("Fix invalid blocks marked as seen", op-rs/kona#2391, 2025-07-21). Today, `rust/kona/crates/node/gossip/src/handler.rs:81` verifies the signature before `block_valid`.

### (e) Isthmus hash check (200c20bc5b)
After (b), the hash check did not account for the implied Isthmus `requests_hash`, so kona-node would have rejected every valid Isthmus gossip block (liveness only). 200c20bc5b sets the empty requests hash when Isthmus is active. It also takes the signature-domain chain ID from the rollup config instead of a separately plumbed value.

### Attack scenario (for (a), the most serious case)
1. A chain rotates its unsafe block signer because the old key leaked.
2. The holder of the old key gossips alternative unsafe blocks.
3. kona-node, still trusting the old key, accepts them and inserts them as its unsafe head. It diverges from op-node peers until derivation from L1 reorgs it back.

## Impact Details

- Only kona-node was affected. op-node already made every one of these checks (`op-node/p2p/gossip.go`).
- kona-node was not production software in this period. No mainnet or testnet operator relied on it for the unsafe chain.
- Unsafe blocks are always re-checked against L1 derivation. Wrongly accepted gossip blocks cause temporary unsafe-head divergence and reorgs, not safe-chain or fund impact.
- Items (b), (c) and (d) need a malicious or compromised authorized signer, except the ordering flaw in the first (d) fix noted above.

For these reasons I rate this **Informational**.

## Proof of Concept

Executed: **no**. Building the historical kona workspace takes a long time. The fix commits added unit tests that fail on the pre-fix handler. Each commit also changes the handler's API, so the tests serve as regression tests rather than drop-in tests for the parent:

- `test_block_invalid_hash`, `test_block_invalid_base_fee` (db363c0208): a V1 payload with `block_hash = 0` must return `BlockInvalidError::BlockHash`. Before the fix the handler returns `Ok(())`, because the signature matches the configured signer.
- `test_cannot_validate_same_block_twice`, `test_cannot_have_too_many_blocks_for_the_same_height` (430b772196): the second copy returns `BlockSeen`, and the 7th distinct block at one height returns `TooManyBlocks`. Before the fix both are accepted.
- `test_genesis_signer` (7a53411205): for chain 10 the signer must be `0xAAAA45d9549EDA09E70937013520214382Ffc4A2` (the OP Mainnet unsafe block signer), not the batcher address that 444bef7aa0 returned.

```bash
d=$(mktemp -d); git archive 430b77219678ce28e7c4ad5e81deadb6c6197ee3 | tar -x -C $d
(cd $d && cargo test -p kona-p2p block_validity)
d=$(mktemp -d); git archive 7a53411205dd7ce7ca46032e0d1999516295ebb4 | tar -x -C $d
(cd $d && cargo test -p kona-node test_genesis_signer)
```

To show the gap on a parent, put the body of `test_block_invalid_hash` into the parent's `block_validity.rs` test module and assert `handler.block_valid(&envelope).is_ok()`. It passes on `db363c0208^`, meaning the mismatched hash is accepted. The same assertion fails on `db363c0208`.

## Recommendation

The fixes implement the spec's checks. Further hardening:
- Refresh the unsafe block signer from L1 continuously, not only at startup, as op-node does through `SystemConfig` updates.
- Verify signatures before touching any per-height state (done later in cd8e786aed).
- Run op-node's gossip validation test vectors against kona-node for differential testing.

## References

- Fix commits: listed in the table above
- PRs: https://github.com/op-rs/kona/pull/1322, /1339, /1453, /1454, /1455, /1505, /1523, /1604
- Follow-up: cd8e786aed (op-rs/kona#2391)
- Relevant files: `crates/node/p2p/src/gossip/block_validity.rs`, `crates/node/p2p/src/gossip/handler.rs`, `bin/node/src/flags/globals.rs`, `bin/node/src/flags/p2p.rs`, `bin/node/src/runtime/loader.rs`
- Spec: https://specs.optimism.io/protocol/rollup-node-p2p.html#block-validation
