# kona-mpt: an emptied storage trie has no root commitment, so kona's fault-proof program rejects valid blocks

| Field | Value |
|---|---|
| **Target** | kona fault-proof program: `kona-mpt` (`crates/mpt/src/node.rs`, `crates/mpt/src/db/mod.rs`), used by `kona-executor` / `kona-client` |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (pre-production). The same bug in a production fault-proof program would be High to Critical. |
| **Impact category** | "Unintended chain split (network partition)", here in the form of a fault-proof divergence: kona computes no state root for valid blocks that op-geth and op-program accept. Discounted because kona did not secure any production dispute game. |
| **Fix commit(s)** | `06365fd942d028951fcc818895f97ff9796d6604` (op-rs/kona#705), 2024-10-18 |
| **Vulnerable since** | The TrieDB storage-root path existed in this form at least since 2024-09 (it predates `3a6890fc66`, op-rs/kona#541, 2024-09-21). It was most likely present from the introduction of the kona `TrieDB`. |

## Brief / Intro

kona is a Rust implementation of the OP Stack fault-proof program. It re-executes L2 blocks inside a proof VM and recomputes the Ethereum state root from a Merkle-Patricia trie (MPT). Each contract's storage has its own trie. When a transaction set a contract's last non-zero storage slot to zero, that storage trie became empty. kona's MPT code then refused to produce a root hash for it (`RootNotBlinded`) instead of returning the well-known empty-trie root. The executor aborted, and the program exited with the "claim invalid" status. Any user could trigger this with an ordinary transaction. A kona-backed dispute game would then treat every honest output root covering that block as invalid.

## Vulnerability Details

`TrieDB` keeps a `TrieNode` for each touched account's storage. After it applies a block's storage changes, it "blinds" the node (hashes it) and reads the resulting commitment:

`crates/mpt/src/db/mod.rs` (parent `06365fd942^`), lines ~255-266:

```rust
bundle_account.storage.iter().try_for_each(|(index, value)| {
    Self::change_storage(acc_storage_root, *index, value, &self.fetcher, &self.hinter)
})?;

// Recompute the account storage root.
acc_storage_root.blind();

let commitment =
    acc_storage_root.blinded_commitment().ok_or(TrieDBError::RootNotBlinded)?;
trie_account.storage_root = commitment;
```

`change_storage` deletes a slot from the trie when its new value is zero (`db/mod.rs:307-309`). Deleting the only remaining leaf turns the root into `TrieNode::Empty` (`node.rs:331-334`):

```rust
Self::Leaf { prefix, .. } => {
    if path == prefix {
        *self = Self::Empty;
```

`blind()` only hashes nodes whose RLP encoding is at least 32 bytes (`node.rs:127-133`). `Empty` encodes to the single byte `0x80`, so it stays `Empty`. Then `blinded_commitment()` handled only the `Blinded` variant (`node.rs:117-122`):

```rust
pub const fn blinded_commitment(&self) -> Option<B256> {
    match self {
        Self::Blinded { commitment } => Some(*commitment),
        _ => None,
    }
}
```

The result is `None`, which becomes `TrieDBError::RootNotBlinded`. The error propagates out of `execute_payload`, then out of `DerivationDriver::produce_output`, then out of `main`. The `client_entry` macro turns any `Err` into `kona_common::io::exit(1)` (`crates/common-proc/src/lib.rs:38-40`). Exit status 1 is the fault-proof VM's "invalid claim" result.

`compute_output_root` (`crates/executor/src/lib.rs:389`) had the same `blinded_commitment().ok_or(...)` pattern for the `L2ToL1MessagePasser` storage root. `TrieDB::state_root` did too, for the account trie, although in practice the account trie is never empty.

### The fix

```diff
 pub const fn blinded_commitment(&self) -> Option<B256> {
     match self {
         Self::Blinded { commitment } => Some(*commitment),
+        Self::Empty => Some(EMPTY_ROOT_HASH),
         _ => None,
     }
 }
```

An empty trie now reports the canonical empty root `0x56e81f…b421`, which is what op-geth and op-program write into the account's `storageRoot`.

### Attack scenario

1. An attacker deploys a contract that has exactly one non-zero storage slot. Alternatively, they pick any existing contract whose last non-zero slot they can clear.
2. In L2 block `B` they send a transaction that sets that slot to zero. op-geth accepts it and computes a normal state root, and the honest proposer posts a correct output root for a range that includes `B`.
3. The attacker challenges that honest output root in a kona-backed game and bisects down to block `B`.
4. At the leaf, the kona program runs `B`, hits `RootNotBlinded`, and exits with status 1. The on-chain VM step therefore resolves in the challenger's favour, and the honest claim is countered.

## Impact Details

- **What breaks:** kona cannot produce the correct post-state for any block in which a contract's storage becomes fully empty. The program declares the claim invalid instead of computing it. That is a disagreement with op-program and op-geth on valid chain data.
- **Who can trigger it:** any L2 user, for the cost of one ordinary transaction. It can also happen by accident, because clearing a contract's only storage slot is routine.
- **Consequence if kona had secured a game:** an honest output root covering such a block could be countered at the VM step. The honest proposer's and defenders' bonds would be lost ("Direct loss of funds"), and withdrawals proven against that root would be blocked. An honest kona-based challenger also could not defend. This is the High/Critical fault-proof unsoundness class.
- **Mitigating factors (why Low):** in October 2024 kona ran only in experimental or testnet (asterisc-kona) configurations and did not back any production dispute game. The fix landed before any mainnet use. Chains that used op-program or Cannon were unaffected.

## Proof of Concept

This is a node-level unit test for `crates/mpt/src/node.rs` (`mod test`). It uses only APIs that exist at the parent commit. It inserts one storage slot, deletes it (a storage slot being zeroed), blinds the node, and asks for the root. On the parent it fails with `None`. On the fix it returns `EMPTY_ROOT_HASH`. The fix's own regression test (`test_empty_blinded`) checks the same final step directly.

```rust
#[test]
fn poc_cleared_storage_trie_has_root() {
    use alloy_consensus::EMPTY_ROOT_HASH;
    // Hashed storage key of slot 0, as TrieDB::change_storage computes it.
    let slot_key = Nibbles::unpack(keccak256(U256::ZERO.to_be_bytes::<32>()));

    // Storage trie with a single non-zero slot.
    let mut root = TrieNode::Empty;
    root.insert(&slot_key, bytes!("01"), &NoopTrieProvider).unwrap();
    root.blind();
    assert!(root.blinded_commitment().is_some());

    // Re-open it unblinded (as change_storage would via the fetcher), then zero the slot.
    let mut root = TrieNode::Empty;
    root.insert(&slot_key, bytes!("01"), &NoopTrieProvider).unwrap();
    root.delete(&slot_key, &NoopTrieProvider, &NoopTrieHinter).unwrap();
    assert_eq!(root, TrieNode::Empty);

    // TrieDB::update_accounts then does exactly this:
    root.blind();
    // Parent: None -> TrieDBError::RootNotBlinded -> client exit(1).
    assert_eq!(root.blinded_commitment(), Some(EMPTY_ROOT_HASH));
}
```

(If `U256` is not in scope in the test module, add `use alloy_primitives::U256;`.)

To run it against the parent and against the fix without touching the working tree:

```bash
cd /home/trevor/workspace/audits/optimism
for c in 06365fd942^ 06365fd942; do
  d=/tmp/kona-$(git rev-parse --short $c); mkdir -p $d
  git archive $c | tar -x -C $d
  # paste the test above into $d/crates/mpt/src/node.rs inside `mod test`
  (cd $d && cargo test -p kona-mpt poc_cleared_storage_trie_has_root)
done
# expected: parent -> assertion failed (left: None, right: Some(0x56e8…b421)); fix -> ok
```

An end-to-end reproduction would do the same through `TrieDB::state_root(&bundle)`, using a `BundleState` in which an account's only storage slot goes from `1` to `0`. At the parent that returns `Err(TrieDBError::RootNotBlinded)`.

Executed: no. The test was derived from the code and the fix's regression test; building the old kona workspace was skipped to avoid a long build.

## Recommendation

The fix is correct and minimal: `Empty` now maps to `EMPTY_ROOT_HASH`. Defense in depth:

- Make `blind()` (or a dedicated `root()` helper) always return a commitment for any node. For a root node, hash the RLP even when it is shorter than 32 bytes, because the "inline if < 32 bytes" rule applies only to child references. That removes the whole `RootNotBlinded` error class.
- Add differential tests that run the kona executor against op-geth or op-program on blocks that empty storage, destroy accounts, and create-then-clear storage.

## References

- Fix commit: `06365fd942d028951fcc818895f97ff9796d6604`
- Pull request: https://github.com/op-rs/kona/pull/705
- Relevant files (at fix time): `crates/mpt/src/node.rs`, `crates/mpt/src/db/mod.rs`, `crates/executor/src/lib.rs`, `crates/common-proc/src/lib.rs`. The current location is `rust/kona/crates/proof/mpt/`.
- Ethereum Yellow Paper, Appendix D (empty trie root `keccak256(rlp(""))`)
