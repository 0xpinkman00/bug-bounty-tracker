# kona-node P2P — gossip blocks with bad signatures are recorded as "seen" before signature checks — unauthenticated censorship of unsafe blocks

| Field | Value |
|---|---|
| **Target** | kona-node / kona-p2p, `crates/node/p2p/src/gossip/block_validity.rs` (`BlockHandler::block_valid`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (the defect class is Medium; kona-node had no release while it was live) |
| **Impact category** | "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network" (would-be, for kona-node unsafe-block processing); griefing of honest peers |
| **Fix commit(s)** | cd8e786aedbba46d569e6a1d19ad84b6c721bf4b (op-rs/kona#2391, closes op-rs/kona#2361), 2025-07-21 |
| **Vulnerable since** | 430b772196 (op-rs/kona#1455, "add remaining block checks (replays + maximum block number per height)"), 2025-04-17. Fixed before the first kona-node release (`kona-node/v1.0.0-rc.1`, 2025-07-31) |

## Brief / Intro

When an OP node receives a new block over P2P gossip, it runs a checklist before accepting it. Two of the checks guard against spam and replays: remember which block hashes have already been seen, and accept at most five different blocks per block height. The last check, the one that proves the sequencer actually produced the block, is the signature check. kona-node recorded a block as "seen" *before* it verified the signature. An anonymous peer could therefore fill each upcoming height's quota with junk blocks, or pre-register the hash of a real block with a fake signature. When the sequencer's genuine block then arrived, kona-node threw it away as a duplicate or as "too many blocks".

## Vulnerability Details

Parent of the fix, `block_valid` (`crates/node/p2p/src/gossip/block_validity.rs:146-184`):

```rust
if let Some(seen_hashes_at_height) = self.seen_hashes.get_mut(&envelope.payload.block_number()) {
    if seen_hashes_at_height.len() > Self::MAX_BLOCKS_TO_KEEP {          // MAX_BLOCKS_TO_KEEP = 5
        return Err(BlockInvalidError::TooManyBlocks { .. });
    }
    if seen_hashes_at_height.contains(&envelope.payload.block_hash()) {
        return Err(BlockInvalidError::BlockSeen { .. });                 // -> MessageAcceptance::Ignore
    }
    seen_hashes_at_height.insert(envelope.payload.block_hash());          // <-- recorded here
} else {
    self.seen_hashes.insert(envelope.payload.block_number(),
                            HashSet::from([envelope.payload.block_hash()]));  // <-- or here
}

// CHECK: The signature is valid.                                        // <-- only now
let Ok(msg_signer) = envelope.signature.recover_address_from_prehash(&msg) else {
    return Err(BlockInvalidError::Signature);
};
if msg_signer != block_signer {
    return Err(BlockInvalidError::Signer { .. });
}
```

The checks that run before the insert (timestamp within `[now-60s, now+5s]`, header hash matching the payload, version-specific fields) are all satisfiable by anyone. An attacker can build a syntactically valid payload for any block number with a matching block hash. Nothing ties the block number to the timestamp. `seen_hashes` is a `BTreeMap<u64, HashSet<B256>>` capped at 1,000 heights with lowest-first eviction, so an attacker can pre-fill hundreds of *future* heights.

The fix moves the insert after both signature checks:

```diff
-            seen_hashes_at_height.insert(envelope.payload.block_hash());
-        } else {
-            self.seen_hashes.insert(envelope.payload.block_number(),
-                HashSet::from([envelope.payload.block_hash()]));
         }
         // CHECK: The signature is valid.
         ...
         if msg_signer != block_signer { return Err(BlockInvalidError::Signer { .. }); }
+        self.seen_hashes
+            .entry(envelope.payload.block_number())
+            .or_default()
+            .insert(envelope.payload.block_hash());
```

The regression test `test_invalid_signature` now also asserts `handler.seen_hashes.is_empty()` before validating an invalid-signature block.

### Attack scenario

**Variant A (height flooding):**
1. The attacker connects to kona-nodes as an ordinary gossip peer and learns the current unsafe height `N`.
2. For each height `h` in `N+1 .. N+k`, the attacker gossips 6 distinct well-formed payloads with the current timestamp, `block_number = h`, correct block hashes and any signature (garbage, or signed by the attacker's own key).
3. Each is rejected (`Signature` or `Signer`), but its hash is first stored, so after 6 blocks `seen_hashes[h].len() == 6 > 5`.
4. When the sequencer's real block for `h` arrives, kona-node returns `TooManyBlocks` and `Reject`s it. The honest relaying peer is also down-scored for sending an "invalid" message.

**Variant B (targeted replay):** an attacker who receives a genuine block first (for example, by being better connected to the sequencer) re-gossips the same payload with a corrupted signature to a victim. The hash is recorded, and the genuine copy arriving later is `Ignore`d as `BlockSeen`.

Either way, kona-nodes stop importing unsafe blocks from gossip. They fall back to L1 derivation, where the safe head lags by minutes, or to req/resp sync if available.

## Impact Details

- **Attacker requirements:** only a P2P connection. No keys and no stake. Each junk message costs the attacker some gossipsub score for `Reject`s, but cheap sybil peer IDs avoid bans. Variant A needs only 6 messages per height and can be pre-computed for hundreds of future heights.
- **Effect:** unsafe-head stall or censorship on every targeted kona-node, plus reputation damage to honest peers that relay the genuine block. Safety and the safe and finalized chain are unaffected.
- **Mitigating factors:** kona-node was pre-release. The first release (`v1.0.0-rc.1`, 2025-07-31) includes the fix. op-node's validator orders these checks correctly (signature before seen-cache), so op-node was not affected.
- **Severity:** a remote, unauthenticated liveness attack on a node's unsafe-block pipeline would be Medium for a production client. It is downgraded to **Low** because no kona-node release carried it.

## Proof of Concept

Add to the `tests` module of `crates/node/p2p/src/gossip/block_validity.rs`. It reuses the existing helpers `v1_valid_block`, `BlockHandler::new` and `MAX_BLOCKS_TO_KEEP`.

```rust
fn env_for(block: &Block<OpTxEnvelope>) -> OpNetworkPayloadEnvelope {
    OpNetworkPayloadEnvelope {
        payload: OpExecutionPayload::V1(ExecutionPayloadV1::from_block_slow(block)),
        signature: Signature::test_signature(),
        payload_hash: PayloadHash(B256::ZERO),
        parent_beacon_block_root: None,
    }
}
fn corrupt(mut e: OpNetworkPayloadEnvelope) -> OpNetworkPayloadEnvelope {
    let mut sig = e.signature.as_bytes();
    sig[0] = !sig[0];
    e.signature = Signature::from_raw_array(&sig).unwrap();
    e
}

/// Variant A: junk blocks fill a height; the genuine block is then refused.
#[test]
fn poc_bad_sig_blocks_censor_genuine_block() {
    let genuine_block = v1_valid_block();
    let genuine = env_for(&genuine_block);
    let msg = genuine.payload_hash.signature_message(10);
    let sequencer = genuine.signature.recover_address_from_prehash(&msg).unwrap();
    let (_, rx) = tokio::sync::watch::channel(sequencer);
    let mut handler = BlockHandler::new(RollupConfig { l2_chain_id: 10, ..Default::default() }, rx);

    for _ in 0..=BlockHandler::MAX_BLOCKS_TO_KEEP {
        let mut junk = v1_valid_block();
        junk.header.number = genuine_block.header.number;
        assert!(handler.block_valid(&corrupt(env_for(&junk))).is_err());
    }
    // Parent commit: Err(TooManyBlocks). Fixed commit: Ok(()).
    assert!(handler.block_valid(&genuine).is_ok());
}

/// Variant B: the genuine hash is pre-registered with a forged signature.
#[test]
fn poc_bad_sig_replay_marks_genuine_seen() {
    let block = v1_valid_block();
    let genuine = env_for(&block);
    let msg = genuine.payload_hash.signature_message(10);
    let sequencer = genuine.signature.recover_address_from_prehash(&msg).unwrap();
    let (_, rx) = tokio::sync::watch::channel(sequencer);
    let mut handler = BlockHandler::new(RollupConfig { l2_chain_id: 10, ..Default::default() }, rx);

    assert!(handler.block_valid(&corrupt(genuine.clone())).is_err());
    // Parent commit: Err(BlockSeen). Fixed commit: Ok(()).
    assert!(handler.block_valid(&genuine).is_ok());
}
```

Run (kona repo, now `rust/kona` in this monorepo; upstream op-rs/kona at the commits below):

```
git checkout cd8e786aedbb^   # expected: both tests FAIL
cargo test -p kona-p2p poc_bad_sig
git checkout cd8e786aedbb    # expected: both tests PASS
cargo test -p kona-p2p poc_bad_sig
```

Executed: no.

## Recommendation

The fix, recording the hash only after successful signature and signer verification, matches the spec's ordering and op-node. Further hardening:
- Do the cheap signature check before the more expensive block-hash recomputation, which also reduces CPU cost per junk message.
- Keep a separate short-lived cache of *rejected* message IDs, so repeated junk is dropped cheaply without affecting accounting for genuine blocks.
- Add a test that no rejected message mutates `seen_hashes` (a property test over all `BlockInvalidError` paths).

## References

- Fix commit: cd8e786aedbba46d569e6a1d19ad84b6c721bf4b
- Pull request: https://github.com/op-rs/kona/pull/2391 (issue https://github.com/op-rs/kona/issues/2361; introduced by https://github.com/op-rs/kona/pull/1455)
- Relevant files: `crates/node/p2p/src/gossip/block_validity.rs`, `crates/node/p2p/src/gossip/handler.rs`
- Specs: https://specs.optimism.io/protocol/rollup-node-p2p.html#block-validation
