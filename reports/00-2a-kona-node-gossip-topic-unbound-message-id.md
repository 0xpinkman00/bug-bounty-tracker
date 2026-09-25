# kona-node gossip — message-id not bound to topic — cross-topic replay suppresses real unsafe blocks

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/node/gossip` (kona-node P2P block gossip) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | Shutdown of greater than 10% or equal to but less than 30% of network processing nodes without brute force actions, but does not shut down the network (closest fit: the unsafe-block feed of affected kona-nodes stalls; the chain keeps going) |
| **Fix commit(s)** | d18b32eeef8ebe5a4f1341516be7e6f043b13735 (PR #21804), 2026-07-20 |
| **Vulnerable since** | 01ad4b154a (op-rs/kona#1032, 2025-02-13), when the networking crate was imported. About 17 months. |

## Brief / Intro

OP Stack nodes share new L2 blocks from the sequencer over libp2p gossipsub. Blocks go out on several block-version topics (`/optimism/<chain>/0..3/blocks`). Gossipsub drops any message whose *message-id* it has already seen. kona-node, the experimental Rust consensus client, computed that id from the payload alone and left out the topic. An unauthenticated peer could therefore resend a real block's bytes on the wrong topic. kona-node rejected that copy, but it still stored the copy's id in its duplicate cache, so when the genuine block arrived on the correct topic it was dropped as a duplicate. The block was hidden for up to 120 seconds. op-node binds the topic into the id and was never affected.

## Vulnerability Details

Parent-commit code, `rust/kona/crates/node/gossip/src/config.rs:124-149`:

```rust
fn compute_message_id(msg: &Message) -> MessageId {
    let id = if snappy_decompressed_len_within_bound(&msg.data).is_some() {
        let mut decoder = Decoder::new();
        decoder.decompress_vec(&msg.data).map_or_else(
            |_| { /* sha256(0x00000000 || raw)[..20] */ },
            |data| {
                let domain_valid_snappy: Vec<u8> = vec![0x1, 0x0, 0x0, 0x0];
                sha256([domain_valid_snappy.as_slice(), data.as_slice()].concat().as_slice())[..20]
                    .to_vec()
            },
        )
    } else { /* sha256(0x00000000 || raw)[..20] */ };
    MessageId(id)
}
```

The id is `sha256(domain || payload)`. `msg.topic` is never used. The config sets `duplicate_cache_time(120s)` and `validate_messages()` (`config.rs:90-93`). In rust-libp2p gossipsub the duplicate cache is keyed only by `MessageId` and is shared across all topics. An id is inserted when a message is received, before application validation, and it is not removed when the application later returns `Reject`.

kona subscribes to all four block topics (`handler.rs` `topics()`), and it decodes each message according to the topic it arrived on (`handler.rs:59-67`). Here is what happens when the same bytes arrive on the wrong topic:

1. The id is identical to the id of the genuine message.
2. `BlockHandler` decodes the bytes with the wrong version (for example `decode_v3` applied to V4 bytes), fails, and returns `Reject`.
3. The id stays in the duplicate cache. When the genuine message then arrives on the correct topic, gossipsub drops it as already seen and never passes it to the handler.

op-node's `BuildMsgIdFn` (`op-node/p2p/gossip.go:116`) hashes `domain || uint64_le(len(topic)) || topic || payload`, so the two copies get different ids.

The fix (`config.rs`) now matches op-node:

```rust
let topic = msg.topic.as_str().as_bytes();
let topic_len = (topic.len() as u64).to_le_bytes();
let digest =
    sha256([domain.as_slice(), topic_len.as_slice(), topic, payload].concat().as_slice());
MessageId(digest[..20].to_vec())
```

The same commit also changes several `warn!` calls on unauthenticated-input paths (invalid snappy, decode error, invalid block) to `debug!` plus metrics, so an invalid peer can no longer spam warnings into the logs.

### Attack scenario

1. The attacker runs one or more libp2p peers connected to target kona-nodes, and to well-connected op-nodes or the sequencer's gossip peers so it learns new blocks early.
2. When block N arrives on `/optimism/<chain>/3/blocks`, the attacker immediately republishes the same compressed bytes on `/optimism/<chain>/2/blocks` to every kona-node it is connected to.
3. Each kona-node that receives the wrong-topic copy before the real one caches the id, rejects the copy, and then discards the genuine block N from every honest peer for up to 120s.
4. The attacker repeats this for every block. The victims' unsafe head stalls and only moves forward through L1 derivation (safe head). RPC consumers of those nodes see stale "latest" state.

## Impact Details

- **Affected**: kona-node only, as a verifier or RPC node following unsafe blocks. Sequencers build their own blocks and are not affected. op-node is not affected.
- **Effect**: liveness and staleness of unsafe-head data on the victim node. No funds are at risk and there is no consensus fault. Safe and finalized progress through L1 derivation continues.
- **Preconditions**: the attacker must win a propagation race against honest peers for each block, which is easier with good connectivity. Each rejected message lowers the attacker peer's gossipsub score, so sustaining the attack needs fresh peer identities (a Sybil attack).
- **Severity rationale**: an unauthenticated, cheap block-propagation DoS would normally rank higher. It is rated Low because kona-node is documented as "not production ready" (`docs/public-docs/releases/kona-node.mdx:23`), because the effect is limited to delayed unsafe blocks on that client, and because the attack depends on racing honest peers.

## Proof of Concept

The fix adds `compute_message_id_binds_topic`. Placed in the `tests` module of `rust/kona/crates/node/gossip/src/config.rs` at the parent commit, the following assertion fails there, because both ids are `sha256(0x00000000 || payload)`, and passes on the fix:

```rust
#[test]
fn poc_message_id_must_depend_on_topic() {
    let payload = vec![1u8, 2, 3, 4, 5];
    let make = |topic: &str| Message {
        source: None,
        data: payload.clone(),
        sequence_number: None,
        topic: libp2p::gossipsub::TopicHash::from_raw(topic),
    };
    let id_v3 = compute_message_id(&make("/optimism/10/2/blocks"));
    let id_v4 = compute_message_id(&make("/optimism/10/3/blocks"));
    // Parent: equal -> a replay on the wrong topic poisons the duplicate cache.
    assert_ne!(id_v3.0, id_v4.0, "message id must depend on the topic");
}
```

Run it with:

```
cd rust && cargo test -p kona-gossip --lib poc_message_id_must_depend_on_topic
```

The fix commit also pins byte-for-byte parity with op-node through golden vectors (`compute_message_id_matches_op_node_golden_vectors`).

Executed: no. No Rust build cache was available, and a full kona build was out of scope.

## Recommendation

The fix is correct and complete for the id: it matches op-node's construction exactly and the tests pin it. Further defence in depth:

- Add a fast pre-validation that rejects a block when its topic does not match the block-version expected for its timestamp, before it can affect scoring or caching.
- Keep id-construction parity with op-node under a shared test vector file so the two clients cannot drift apart again.

## References

- Fix commit: d18b32eeef8ebe5a4f1341516be7e6f043b13735
- Pull request: https://github.com/ethereum-optimism/optimism/pull/21804 (follow-up to #21753)
- Relevant files: `rust/kona/crates/node/gossip/src/config.rs`, `rust/kona/crates/node/gossip/src/handler.rs`, `op-node/p2p/gossip.go`
