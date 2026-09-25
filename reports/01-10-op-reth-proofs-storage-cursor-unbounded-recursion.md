# op-reth proofs-history trie — `MdbxStorageCursor::next` recursed once per deleted storage slot — possible stack-overflow crash of proof-serving nodes

| Field | Value |
|---|---|
| **Target** | `rust/op-reth/crates/trie/src/db/cursor.rs` (`reth-optimism-trie`, proofs-history storage used by the op-reth proofs ExEx) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | Causes network processing nodes to crash (op-reth nodes running the proofs-history ExEx). Exploitability in optimized release builds is unconfirmed |
| **Fix commit(s)** | `af58c70d72eeddd3c038bfa139a5fdd2032f796b` (op-rs/op-reth#402, resolves op-rs/op-reth#401 and #394) — 2025-11-25 |
| **Vulnerable since** | `17b3a33b65` "Add crate `reth-optimism-exex` and `reth-optimism-trie`" (op-rs/op-reth#204) |

## Brief / Intro

op-reth has an optional "proofs history" extension. It keeps a versioned copy of the state so the node can quickly serve Merkle proofs (`eth_getProof`, execution witnesses) for recent historical blocks. Fault-proof challengers and proposers use it. In this store, deleting a storage slot is recorded as the value zero. The cursor that walks an account's storage skipped zero values by calling itself recursively, once per zero entry. Anyone can create a contract with a long run of deleted slots, so walking that storage could need thousands of nested calls and crash the node with a stack overflow. The fix replaces the recursion with a loop. My testing suggests an optimized build may already have turned the recursion into a loop, so real-world exploitability is uncertain.

## Vulnerability Details

Storage deletions are persisted as a live zero value, not as a tombstone. Parent `rust/op-reth/crates/trie/src/db/store.rs:338-345`:

```rust
storage.storage_slots_ref().iter()
    .map(|(key, val)| (hashed_address, *key, Some(StorageValue(*val)))),   // val == 0 for deleted slots
```

Parent `rust/op-reth/crates/trie/src/db/cursor.rs:310-327`, `impl HashedCursor for MdbxStorageCursor`:

```rust
fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
    let result = self.inner.next().map(|opt| {
        opt.and_then(|(k, v)| {
            (k.hashed_address == self.hashed_address).then_some((k.hashed_storage_key, v.0))
        })
    })?;

    // hashed storage values can be zero, which means the storage slot is deleted, so we should
    // skip those
    if let Some((_, v)) = result &&
        v.is_zero()
    {
        return self.next();          // one extra stack frame per consecutive zero slot
    }

    Ok(result)
}
```

`seek()` (line 289-307) also falls through to `self.next()` when the first entry is zero. The recursion depth therefore equals the length of the longest run of consecutive (in hashed-key order) zero-valued slots of the account being walked.

Fix:

```diff
-        let result = self.inner.next()...?;
-        if let Some((_, v)) = result && v.is_zero() {
-            return self.next();
-        }
-        Ok(result)
+        loop {
+            let result = self.inner.next()...?;
+            if let Some((_, v)) = result && v.is_zero() {
+                continue;
+            }
+            return Ok(result);
+        }
```

### Attack scenario

1. The attacker deploys a contract. In block `k` it writes `N` distinct storage slots (for example `N = 100_000`); in block `k+1` it zeroes all of them. Writing and clearing in the same transaction would leave no net change, so two blocks are needed. The contract has no other storage, so all `N` zero entries are consecutive in the account's hashed-key order.
2. Something later makes the proofs-history store walk that account's storage at a block ≥ `k+1`. Examples: `eth_getProof` / witness generation served from proofs history, or a storage wipe during ExEx ingestion, which iterates the previous storage with `ro.next()` (`store.rs:331-333`).
3. `next()` recurses `N` times. If the compiler has not turned this into a loop, the thread's stack (2 MiB for Tokio workers) overflows and the process aborts.

Cost: about `N × (22.1k + ~5k)` gas across a few L2 blocks, which is cheap on OP chains. The attacker may also be able to trigger the walk repeatedly through RPC.

## Impact Details

- **Affected nodes:** only op-reth nodes with the proofs-history ExEx enabled. These are typically infrastructure for op-challenger / op-proposer / kona-host witness generation. A crash-loop there hurts fault-proof liveness, although other nodes can serve the data.
- **Exploitability caveat (important):** `return self.next();` is a self tail call. LLVM's tail-recursion elimination often turns this into a loop in optimized builds. I built a simplified model with the same shape (`Result<Option<(B256-like, U256-like)>, Err>`, self-recursive on zero values; scratch file `t.rs`) with rustc 1.95:
  - the `-O` build handled 1,000,000 consecutive zero entries on a 2 MiB thread without crashing;
  - the debug build overflowed the stack.

  I did not check whether the real `reth-optimism-trie` release binary eliminates the recursion; the extra `?` error conversions and cursor calls could stop it. Debug builds are definitely vulnerable.
- **Maturity:** in November 2025 the proofs-history ExEx was a new, opt-in component.
- **Severity:** Low. It is a permissionless node crash in principle, but only on an opt-in component, and it may not be reachable in production builds.

## Proof of Concept

**Executed: partially.** I ran the simplified model described above; the op-reth test below was **not** executed, because it needs a full reth build.

Add to `mod tests` in `rust/op-reth/crates/trie/src/db/cursor.rs`. It uses the existing `setup_db`, `append_hashed_storage` and `storage_cursor` helpers and compiles on both the parent and the fix:

```rust
#[test]
fn poc_many_zero_storage_slots_do_not_overflow_stack() {
    let db = setup_db();
    let addr = B256::from([0xAB; 32]);
    const N: u64 = 200_000;
    {
        let wtx = db.tx_mut().expect("rw tx");
        // N consecutive deleted slots (value 0), then one live slot at the end.
        for i in 0..N {
            let mut slot = [0u8; 32];
            slot[24..].copy_from_slice(&i.to_be_bytes());
            append_hashed_storage(&wtx, addr, B256::from(slot), 1, Some(U256::ZERO));
        }
        append_hashed_storage(&wtx, addr, B256::from([0xFF; 32]), 1, Some(U256::from(7)));
        wtx.commit().expect("commit");
    }
    // Run on a small stack so the recursion depth, not the platform default, decides the outcome.
    let handle = std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let tx = db.tx().expect("ro tx");
            let mut cur = storage_cursor(&tx, 10, addr);
            cur.seek(B256::ZERO).expect("seek")
        })
        .unwrap();
    let res = handle.join().expect("thread must not overflow its stack");
    assert_eq!(res, Some((B256::from([0xFF; 32]), U256::from(7))));
}
```

Run from `rust/` (the default `cargo test` profile is unoptimized, which matches the debug-build behaviour):

```sh
cargo test -p reth-optimism-trie --lib poc_many_zero_storage_slots_do_not_overflow_stack
```

Expected results:
- **Parent (`af58c70d72^`):** the process aborts with `thread '<unknown>' has overflowed its stack`.
- **Fix:** the test passes.

To assess production risk, run the same test with `--release`, or check the generated assembly of `MdbxStorageCursor::next` for a self-`call`.

## Recommendation

The fix, an explicit loop, is correct and removes any dependence on compiler optimizations. Further suggestions:

- `seek()` still delegates to `next()`. That is fine now that `next()` loops, but the pattern should stay non-recursive.
- Consider recording storage deletions as `MaybeDeleted(None)` tombstones, like accounts and trie nodes. The generic `BlockNumberVersionedCursor` already skips tombstones iteratively.
- Audit the other op-reth ExEx/trie cursors for self-recursion on attacker-sized data.

## References

- Fix commit: `af58c70d72eeddd3c038bfa139a5fdd2032f796b`
- Pull request: https://github.com/op-rs/op-reth/pull/402 (issues op-rs/op-reth#401, op-rs/op-reth#394)
- Relevant files: `rust/op-reth/crates/trie/src/db/cursor.rs`, `rust/op-reth/crates/trie/src/db/store.rs`
