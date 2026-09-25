# kona-node gossip: unbounded snappy pre-allocation before validation (memory-exhaustion DoS)

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/node/gossip` (kona-node P2P block gossip) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours (Low); node crash only on memory-constrained or strict-overcommit hosts |
| **Fix commit(s)** | 649ae01634231ad2f4a008f6ddcff42072fb5ea1 (PR #21753), 2026-07-15 |
| **Vulnerable since** | Before kona was imported into the monorepo (`48a7a09bfc`, 2026-02-10). Present in every kona-node release up to the fix. |

## Brief / Intro

kona-node is the experimental Rust consensus client for the OP Stack. It receives new L2 blocks from other nodes over a libp2p gossip network, and every gossip message is snappy-compressed. Before the fix, kona-node trusted the "decompressed size" field that the sender writes at the start of each compressed message. It allocated a buffer of that size before it checked the message in any way. Any peer, with no authentication, could make each kona-node it reached allocate and fill large buffers, or ask for a 4 GiB buffer from a 7-byte message. This wastes memory and CPU and can crash nodes that run with little memory or with strict memory-overcommit settings.

## Vulnerability Details

A snappy frame starts with a varint giving the decompressed length. `snap::raw::Decoder::decompress_vec` allocates `vec![0; declared_len]` and only then decodes. kona-node called it in two places, both on unauthenticated input.

**1. The gossipsub message-id function.** Gossipsub runs this function on every inbound PUBLISH, before any signature or application validation. See `rust/kona/crates/node/gossip/src/config.rs:103-122` at `649ae01634^`:

```rust
fn compute_message_id(msg: &Message) -> MessageId {
    let mut decoder = Decoder::new();
    let id = decoder.decompress_vec(&msg.data).map_or_else(   // allocates declared_len bytes
        |_| { /* invalid-snappy domain */ ... },
        |data| { /* valid-snappy domain */ ... },
    );
    MessageId(id)
}
```

**2. The block handler.** It decodes the payload envelope, and `decode_v1..v4` in `rust/op-alloy/crates/rpc-types-engine/src/envelope.rs` also call `decompress_vec` with no bound. See `rust/kona/crates/node/gossip/src/handler.rs:48-56`:

```rust
fn handle(&mut self, msg: Message) -> (MessageAcceptance, Option<OpNetworkPayloadEnvelope>) {
    let decoded = if msg.topic == self.blocks_v1_topic.hash() {
        OpNetworkPayloadEnvelope::decode_v1(&msg.data)       // decompress_vec, unbounded
    } else if ...
```

The gossipsub transport limit (`max_transmit_size(MAX_GOSSIP_SIZE)`, 10 MiB) applies only to the **compressed** bytes on the wire. Nothing limited the **decompressed** size. op-node rejects a frame whose `snappy.DecodedLen(data) > maxGossipSize` in both its `BuildMsgIdFn` and its topic validator (`op-node/p2p/gossip.go`). kona had no equivalent check.

In practice this gives two attack shapes:

- **Declared-length bomb.** A 7-byte frame `ff ff ff ff 0f 00 41` declares `u32::MAX` bytes. kona then requests a zeroed allocation of about 4 GiB twice per message, once in the message-id function and once in the handler. On Linux with default heuristic overcommit, a zeroed allocation this large is served lazily with `mmap`/`calloc`. It succeeds on a host with enough RAM and swap, and the decode then fails straight away, so few pages are touched. The fix's own commit body says so: the first regression test "passed even against unbounded code (`vec![0; u32::MAX]` is a lazily-committed calloc under overcommit)". On hosts with `vm.overcommit_memory=2`, or with less than about 4 GiB of RAM plus swap available, the allocation fails and Rust aborts the process through `handle_alloc_error`.
- **Valid high-ratio frame.** A frame up to 10 MiB that really decompresses to many times its size (snappy copy elements) makes kona allocate **and fill** hundreds of MiB per message, twice. Each message is rejected afterwards, but the memory and CPU are spent every time. New peer IDs cost nothing, so peer scoring does not stop it.

**The fix.** It adds `snappy_decompressed_len_within_bound`, which reads only the varint header, and applies it at both sites:

```rust
pub(crate) fn snappy_decompressed_len_within_bound(data: &[u8]) -> Option<usize> {
    snap::raw::decompress_len(data).ok().filter(|&n| n <= MAX_GOSSIP_SIZE)
}

fn compute_message_id(msg: &Message) -> MessageId {
    let id = if snappy_decompressed_len_within_bound(&msg.data).is_some() {
        /* decompress as before */
    } else {
        /* invalid-snappy domain over raw bytes, no allocation */
    };
    ...
}

// handler.rs
if snappy_decompressed_len_within_bound(&msg.data).is_none() {
    return (MessageAcceptance::Reject, None);
}
```

Every allocation is now at most 10 MiB, which matches op-node.

### Attack scenario

1. The attacker finds kona-node peers through discv5 and joins the block topic mesh with a fresh peer ID.
2. The attacker publishes a stream of frames on the `blocks/v*` topics. These are either the 7-byte `u32::MAX` bomb or 10 MiB frames that decompress to hundreds of MiB.
3. Each receiving kona-node allocates the declared or decompressed size twice per message before rejecting it. Constrained or strict-overcommit nodes abort. Other nodes see large memory and CPU spikes. The attacker reconnects under new peer IDs and repeats.

## Impact Details

- **Who is affected:** operators running kona-node with P2P enabled. op-node is not affected.
- **Attacker cost:** none. No authentication, stake or valid signature is needed, because the allocation happens before signature checks.
- **Mitigating factors:**
  - kona-node is documented as "not production ready" (`docs/public-docs/releases/kona-node.mdx`: "Production deployments should prefer op-node"). Production OP Stack sequencers and most verifiers run op-node.
  - A reliable one-shot crash needs a host that refuses a 4 GiB zeroed allocation. On a typical 16+ GiB host with default overcommit, the bomb frame does not crash the node. The valid high-ratio frame gives real resource consumption, but not certainly a crash.
  - Rejected messages are not forwarded (`validate_messages()` is set), so each attacker message only hits the peers it is sent to directly.
- **Severity:** a crash-on-demand of a production consensus client would be High ("Shutdown of greater than or equal to 30% of network processing nodes"). Because the client is experimental and a crash only happens under some memory configurations, this is rated **Low**: resource consumption on a pre-production node.

## Proof of Concept

The fix added tests that separate the bounded and unbounded code. `compute_message_id_rejects_oversize_frame_via_invalid_snappy` fails on the parent commit. The parent decompresses the oversize frame and returns the valid-snappy id, which shows that it allocated and filled more than `MAX_GOSSIP_SIZE`.

Run it against the parent code in a separate checkout (do not modify your main worktree):

```bash
git worktree add /tmp/kona-parent 649ae01634^
cd /tmp/kona-parent/rust
# append the test below to kona/crates/node/gossip/src/config.rs `mod tests`
cargo test -p kona-gossip --lib config::tests::poc_unbounded_decompression -- --nocapture
# expected on parent: assertion fails (the node decompressed > MAX_GOSSIP_SIZE)
# expected on 649ae01634: passes
```

```rust
#[test]
fn poc_unbounded_decompression() {
    // A frame that validly decompresses to MAX_GOSSIP_SIZE + 1 bytes but is tiny on the wire.
    let over = snap::raw::Encoder::new().compress_vec(&vec![0u8; MAX_GOSSIP_SIZE + 1]).unwrap();
    assert!(over.len() < 1024, "compressed frame is only {} bytes", over.len());

    let msg = Message {
        source: None,
        data: over.clone(),
        sequence_number: None,
        topic: libp2p::gossipsub::TopicHash::from_raw("/optimism/10/2/blocks"),
    };
    let id = compute_message_id(&msg);

    // Bounded behaviour (fix): invalid-snappy domain over the raw bytes, no decompression.
    let bounded = sha256(&[[0u8, 0, 0, 0].as_slice(), over.as_slice()].concat());
    assert_eq!(id.0, bounded[..20].to_vec(), "node decompressed an over-limit frame");

    // Declared-length bomb: header claims u32::MAX bytes.
    let bomb = vec![0xFFu8, 0xFF, 0xFF, 0xFF, 0x0F, 0x00, 0x41];
    assert_eq!(snap::raw::decompress_len(&bomb).unwrap(), u32::MAX as usize);
}
```

To see the process abort from the declared-length bomb on the parent, run the node or the test under a hard address-space limit. This makes the 4 GiB request fail the way it does on a strict-overcommit host:

```bash
(ulimit -v 2000000; cargo test -p kona-gossip --lib config::tests::compute_message_id_rejects_declared_oversize_bomb)
# parent: "memory allocation of 4294967295 bytes failed" + abort; fix: passes
```

Executed: no. Building the kona crates was out of scope for this review. The claims rest on the diff, the fix's regression tests and the commit body.

## Recommendation

The fix bounds the declared decompressed length by `MAX_GOSSIP_SIZE` before any decompression, in both the message-id function and the block handler. This matches op-node. The follow-up in the same PR also removed the warn-level logs on these reject paths, so unauthenticated peers cannot spam logs.

Further hardening to consider:
- Put the same bound inside `OpNetworkPayloadEnvelope::decode_v*` in op-alloy, so any other caller that decodes gossip bytes is safe by construction.
- Apply peer-score penalties for oversize frames, so repeat offenders are pruned quickly.

## References

- Fix commit: 649ae01634231ad2f4a008f6ddcff42072fb5ea1
- Pull request: https://github.com/ethereum-optimism/optimism/pull/21753
- Relevant files: `rust/kona/crates/node/gossip/src/config.rs`, `rust/kona/crates/node/gossip/src/handler.rs`, `rust/op-alloy/crates/rpc-types-engine/src/envelope.rs`
- op-node reference: `op-node/p2p/gossip.go` (`BuildMsgIdFn`, topic validator `DecodedLen` check)
- Related: 00-1a2 (admin RPC) and 00-1a3 (span-batch bitlist) were fixed in the same PR.
