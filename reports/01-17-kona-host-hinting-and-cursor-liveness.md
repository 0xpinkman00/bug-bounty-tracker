# kona host / proof driver — wrong or missing preimage hints and an unevicted cursor map — fault-proof program stalls or grows memory

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/proof/{proof,proof-interop,executor,mpt,driver}`, `rust/kona/bin/host/src/{single,interop}/handler.rs` |
| **Asset type** | Blockchain/DLT (fault-proof off-chain tooling) |
| **Severity** | Low (overall). 17a is Low; 17b, 17c and 17d are Informational |
| **Impact category** | Fault-proof liveness: the honest challenger cannot produce a kona trace in time. Closest Immunefi class: Low, node-level disruption. There is no direct loss of funds, because every preimage is checked against its hash |
| **Fix commit(s)** | see the table below (4 commits, 2026-04-02 to 2026-04-22) |
| **Vulnerable since** | 17a, 17b and 17d predate kona's import into the monorepo (`48a7a09bfc`, 2026-02-10). For 17c, the origin was not determined |

| ID | Fix commit | PR | Defect | Scope | Rating |
|---|---|---|---|---|---|
| 17a | `8e0c70ed2138b479a55be60bfe103e60b792ee82` (2026-04-21) | #20163 (optimism-private#492) | `L2AccountProof` / `L2AccountStorageProof` hints sent a **block number** instead of a block hash | single-chain and interop kona FPP | Low |
| 17b | `ef4820a704cd062f291b7c6d78fda83b0ebf06bd` (2026-04-22) | #20164 | Interop trie hints could be sent **without `chain_id`** | interop FPP (not activated) | Informational |
| 17c | `8ff9e2b70a9652aec121759fd49641cf0003b2ac` (2026-04-02) | #19850 | No `L2Transactions` hint before walking the transaction trie during deposit-only re-execution | interop FPP (not activated) | Informational |
| 17d | `1cb676bd17efd30d5ddc71e44cdb40fc86ba8e6e` (2026-04-21) | #20165 (optimism-private#480) | `PipelineCursor::origin_infos` never evicted | kona driver (FPP and SP1 range programs) | Informational |

## Brief / Intro

The kona fault-proof program (FPP) runs as a client with no direct access to chain data. It asks a "host" for every piece of data by hash. Before each request it sends a "hint" that tells the host what to prefetch from an L1 or L2 RPC. A preimage the host returns cannot be forged, because the client checks it against its hash. But if a hint sends the host to the wrong data, or no hint is sent, the host never obtains the correct preimage and the client waits forever. The honest challenger then cannot finish its kona trace, and cannot respond in a dispute game before its clock runs out. A separate bug let a lookup table inside the proof driver grow without limit.

## Vulnerability Details

### 17a — Account and storage proof hints keyed by block number

Parent `rust/kona/crates/proof/executor/src/db/mod.rs` (`get_trie_account`, `storage`):

```rust
pub fn get_trie_account(&mut self, address: &Address, block_number: u64) -> ... {
    ...
        .hint_account_proof(*address, block_number)          // 8-byte number
...
        .hint_storage_proof(address, index, self.parent_block_header.number)
```

Parent single-chain host `rust/kona/bin/host/src/single/handler.rs:316-330`:

```rust
ensure!(hint.data.len() == 8 + 20, "Invalid hint data length");
let block_number = u64::from_be_bytes(hint.data.as_ref()[..8].try_into()?);
...
providers.l2.get_proof(address, Default::default()).block_id(block_number.into()).await?;
```

The commit message and PR (#20163) say these hints should carry a 32-byte block hash. A block number is resolved against whatever block the host's L2 node holds at that height right now. Sometimes that block is not the parent header the FPP is executing on: the node may be reorging, lagging, or on a different fork from the agreed pre-state. In that case `eth_getProof` returns trie nodes for the wrong state root, and the client asks for nodes that were never stored. The online host backend (`bin/host/src/backend/online.rs:142-180`) retries the last hint inside an unbounded `while preimage.is_none()` loop, so the program hangs.

The fix sends `parent_block_header.hash()` instead. Both hosts accept either the legacy 8-byte number or the 32-byte hash, so older prestates keep working:

```diff
-            .hint_account_proof(*address, block_number)
+            .hint_account_proof(*address, self.parent_block_header.hash())
```

Why this is Low rather than higher: the block executor first sends an `L2PayloadWitness` hint keyed by the parent **hash** (`executor/src/builder/core.rs:281`). That hint prefetches the whole execution witness. Account and storage proof hints are only a fallback, for trie nodes the witness does not contain. Also, in a dispute the agreed pre-state block is one the honest challenger's node treats as canonical, so the number and the hash normally point to the same block.

### 17b — Interop trie hints without `chain_id`

Parent `proof-interop/src/provider.rs`: `chain_id` was held in an `Arc<RwLock<Option<u64>>>` and was set only inside `header_by_number`. If `header_by_hash` ran first, trie hints were sent with no chain ID, and the multi-chain interop host could not tell which L2 to query. The fix removes that shared mutable field. It adds a `ChainScopedHinter { oracle, chain_id }` that each call site constructs explicitly.

### 17c — Missing `L2Transactions` hint during deposit-only re-execution

Parent `proof-interop/src/consolidation.rs:130-140`: `re_execute_deposit_only` walked the transaction trie of the invalidated block with `OrderedListWalker::try_new_hydrated(header.transactions_root, ...)` and never hinted the host first. `trie_node_by_hash`, called synchronously through `block_on`, therefore blocked forever. The fix calls `interop_provider.hint_transactions(chain_id, header.hash())` before the walk.

### 17d — `origin_infos` never evicted

Parent `proof/driver/src/cursor.rs:164-172`:

```rust
if self.tips.len() >= self.capacity {
    let key = self.origins.pop_front().unwrap();
    self.tips.remove(&key);
    // origin_infos.remove(&key) missing
}
...
self.origin_infos.insert(origin.number, origin);
```

`origin_infos` grows by one `BlockInfo` (about 80 bytes plus map overhead) each time the driver advances. A fault-proof run derives only a handful of blocks, so the growth there is negligible. It only adds up in programs that reuse the driver over long ranges, such as the kona-sp1 range programs (`rust/kona/sp1/crates/client`). The fix adds `self.origin_infos.remove(&key);`.

### Attack scenario (17a, the only one reachable on activated chains)

1. A kona-backed dispute game (for example a Cannon-kona game) reaches execution-trace bisection. The honest challenger has to run kona-host and kona-client to produce a trace or a step proof.
2. At the queried height, the challenger's L2 execution client does not have the agreed pre-state block (for example because it is mid-reorg or has fallen behind). At the same time, the execution witness is missing a trie node that the client later needs.
3. Because of the account-proof hint, the host stores proof nodes for the wrong state root. The client's request for the correct node is never answered, and the host keeps retrying.
4. The challenger's kona trace provider times out. If this lasts past the game clock, the challenger cannot counter or step, and an invalid claim at that position may go unchallenged.

## Impact Details

- **17a:** affects liveness of kona-based fault proofs only. Soundness is untouched, because preimages are checked against their hashes. To hit it you need a gap in the witness and a host-side L2 node whose number-to-hash mapping differs from the agreed chain. The challenger can recover by pointing kona-host at a synced node. Rated Low.
- **17b / 17c:** reachable only in the interop proof (super-root game types). Interop is not activated on any production chain. Rated Informational.
- **17d:** memory grows by kilobytes to megabytes over very long derivation ranges. There is no practical DoS inside the FPP. Rated Informational.
- None of these lets an attacker take funds. The worst case is that the honest kona challenger cannot act in time. Other game types and other challenger implementations running in parallel reduce that risk.

## Proof of Concept

**17d.** The fix added this regression test. On `1cb676bd^` it fails, because `origin_infos.len()` equals `total_advances + 1`:

```rust
#[test]
fn advance_evicts_origin_infos_when_full() {
    let channel_timeout = 2;
    let origin = mock_block_info(0);
    let mut cursor = PipelineCursor::new(channel_timeout, origin);
    let capacity = cursor.capacity; // channel_timeout + 5 = 7
    let total_advances = capacity * 3;
    for i in 1..=total_advances {
        cursor.advance(mock_block_info(i as u64), mock_tip());
    }
    assert!(cursor.origin_infos.len() <= capacity + 1);
    assert!(!cursor.origin_infos.contains_key(&1));
}
```

```bash
cd rust && cargo test -p kona-driver --lib cursor::tests::advance_evicts_origin_infos_when_full
```

**17a.** A check on the hint format, sketched below. Record what `TrieDB` passes to its hinter:

```rust
// rust/kona/crates/proof/executor/src/db/mod.rs, #[cfg(test)] — sketch
struct RecordingHinter(core::cell::RefCell<Vec<B256>>);
impl TrieHinter for RecordingHinter {
    type Error = TrieNodeError;
    fn hint_trie_node(&self, _: B256) -> Result<(), Self::Error> { Ok(()) }
    fn hint_account_proof(&self, _: Address, block_hash: B256) -> Result<(), Self::Error> {
        self.0.borrow_mut().push(block_hash); Ok(())
    }
    fn hint_storage_proof(&self, _: Address, _: U256, block_hash: B256) -> Result<(), Self::Error> {
        self.0.borrow_mut().push(block_hash); Ok(())
    }
    fn hint_execution_witness(&self, _: B256, _: &OpPayloadAttributes) -> Result<(), Self::Error> { Ok(()) }
}
// Build a TrieDB with a blinded state root and parent header P, call db.get_trie_account(&addr),
// and assert the recorded value == P.hash_slow(). On 8e0c70ed^ the trait takes a u64 and the
// value passed is P.number, which the host resolves against its *current* canonical block.
```

To see the host-side behaviour by hand: run `kona-host single` against an L2 RPC whose block at height `N` is not the agreed block, with the witness endpoint disabled. The host log shows the `L2AccountProof` hint being retried indefinitely.

**17b / 17c:** the interop acceptance test `TestInteropFaultProofs_InvalidBlock` (`op-acceptance-tests/tests/interop/proofs/serial/`) exercises the deposit-only re-execution path. #19850 was one of the fixes it depended on; the test is still skipped at #19894 pending other work.

Executed: no. I verified these by reading the code, to avoid a cold build of the kona workspace. The 17a test is a sketch and has not been compiled.

## Recommendation

The fixes do four things: switch these hints to hash keys (with a backwards-compatible host), bind the chain ID to the hinter explicitly, add the missing transactions hint, and evict `origin_infos`. Two further suggestions:
- Give the online host backend a retry limit, or a hard error for hints it cannot satisfy, so a wrong hint fails fast and visibly instead of silently hanging the challenger.
- Add a native host/client test that runs with the witness endpoint disabled, so the fallback hint paths get exercised.

## References

- Fix commits: 8e0c70ed2138b479a55be60bfe103e60b792ee82, ef4820a704cd062f291b7c6d78fda83b0ebf06bd, 8ff9e2b70a9652aec121759fd49641cf0003b2ac, 1cb676bd17efd30d5ddc71e44cdb40fc86ba8e6e
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/20163, https://github.com/ethereum-optimism/optimism/pull/20164, https://github.com/ethereum-optimism/optimism/pull/19850, https://github.com/ethereum-optimism/optimism/pull/20165
- Relevant files: `rust/kona/crates/proof/executor/src/db/mod.rs`, `rust/kona/crates/proof/mpt/src/traits.rs`, `rust/kona/crates/proof/proof/src/l2/chain_provider.rs`, `rust/kona/crates/proof/proof-interop/src/{provider.rs,consolidation.rs}`, `rust/kona/crates/proof/driver/src/cursor.rs`, `rust/kona/bin/host/src/{single,interop}/handler.rs`, `rust/kona/bin/host/src/backend/online.rs`
- Spec: https://specs.optimism.io/fault-proof/index.html
