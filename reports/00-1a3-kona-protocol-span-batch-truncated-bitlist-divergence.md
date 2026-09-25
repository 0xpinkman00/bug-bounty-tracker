# kona span-batch decoder zero-pads a truncated `protected_bits` bitlist, so kona derives a different chain from op-node (fault-proof divergence)

| Field | Value |
|---|---|
| **Target** | `rust/kona/crates/protocol/protocol/src/batch/bits.rs` (shared by kona-client FPP and kona-node derivation) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Medium |
| **Impact category** | Unintended chain split (network partition) between kona and op-node derivation. It also breaks the fault-proof guarantee that a malicious batcher cannot get an invalid output root accepted. |
| **Fix commit(s)** | 649ae01634231ad2f4a008f6ddcff42072fb5ea1 (PR #21753), 2026-07-15 |
| **Vulnerable since** | `c4e89037712` (op-rs/kona, 2025-02-19). Present in the production `cannon64-kona` prestate built from `kona-client/v1.6.0-rc.2`. The first tagged kona-client release with the fix is `kona-client/v1.7.0-rc.1` (2026-08-21). |

## Brief / Intro

OP Stack chains post L2 transactions to Ethereum in compressed "span batches". Each node re-derives the L2 chain from those batches. The fault-proof program (FPP) does the same derivation inside the on-chain MIPS emulator when an output root is disputed. A span batch stores, among other fields, one bit per legacy transaction. The bit says whether that transaction is EIP-155 "replay-protected", meaning its signature commits to the chain ID. If a batch was cut short so this last bitlist was missing bytes, op-node rejected the whole batch. kona filled the missing bits with zeros and accepted it, so it treated those transactions as unprotected. The two implementations therefore derive different L2 chains from the same L1 data. Since the Karst upgrade (June/July 2026), kona is the program that decides dispute games, so kona's divergent result is what the chain's withdrawal bridge enforces.

## Vulnerability Details

The span-batch transaction section is decoded in a fixed order. `protected_bits` is the **last** field (`rust/kona/crates/protocol/protocol/src/batch/transactions.rs:124-131`):

```rust
pub fn decode(&mut self, r: &mut &[u8]) -> Result<(), SpanBatchError> {
    self.decode_contract_creation_bits(r)?;
    self.decode_tx_sigs(r)?;
    self.decode_tx_tos(r)?;
    self.decode_tx_data(r)?;
    self.decode_tx_nonces(r)?;
    self.decode_tx_gases(r)?;
    self.decode_protected_bits(r)?;      // bit_length = legacy_tx_count
```

The vulnerable decoder is at `rust/kona/crates/protocol/protocol/src/batch/bits.rs:28-47`, at `649ae01634^` and in `kona-client/v1.6.0-rc.2`:

```rust
pub fn decode(b: &mut &[u8], bit_length: usize) -> Result<Self, SpanBatchError> {
    let buffer_len = bit_length / 8 + if bit_length.is_multiple_of(8) { 0 } else { 1 };
    let bits = if b.len() < buffer_len {
        let mut bits = vec![0; buffer_len];      // <-- silently zero-pad
        bits[..b.len()].copy_from_slice(b);
        b.advance(b.len());
        bits
    } else { ... };
```

The consumer at `transactions.rs:345-348` turns a 0 bit into an unprotected legacy transaction:

```rust
let is_protected = if tx.tx_type() == OpTxType::Legacy {
    protected_bit_idx += 1;
    self.protected_bits.get_bit(protected_bit_idx - 1).unwrap_or_default() == 1
} else { true };
txs.push(tx.to_full_tx_bytes(*nonce, *gas, to, chain_id, sig, is_protected)?);
```

op-node's decoder (`op-node/rollup/derive/span_batch_util.go:13-24`) uses `io.ReadFull`, which returns `io.ErrUnexpectedEOF` on short input. The span batch fails to decode and is dropped.

The consequence for the same L1 bytes:
- **op-node / op-reth (canonical chain):** the batch is dropped. Those L2 blocks come from later batches, or, if none arrive, become deposit-only blocks at the sequencing-window deadline.
- **kona (FPP and kona-node):** the batch is accepted. Every legacy transaction whose bit fell in the missing bytes is rebuilt as a pre-EIP-155 transaction, with `v = 27/28` and a signing hash without the chain ID. That gives a different transaction hash and, from the same `(r, s)` values, a different recovered sender. So the transaction set and the post-state differ.

The fix rejects short input:

```rust
if b.len() < buffer_len {
    return Err(SpanBatchError::BitfieldTooShort);
}
let v = b[..buffer_len].to_vec();
```

### Was kona the respected proof program while this was live?

Yes. From the repository:
- `docs/public-docs/notices/upgrade-19.mdx` (at `798b46044e^`) says Upgrade 19 / Karst "**promotes `CANNON_KONA` to the respected game type** making the Rust-based `kona-client` the primary fault proof program used for withdrawals". The respected-game-type change was part of the L1 contract upgrade, "expected to happen the week prior to activation". Activation was Sepolia on 2026-06-17 and Mainnet on 2026-07-08. Commit `b40d2ce097` ("post karst activation cleanup", 2026-07-09) confirms the mainnet activation.
- The U19 `cannon64-kona` absolute prestate was built from `kona-client/v1.6.0-rc.2` (commit `d7cea91bc2`, 2026-06-10). `git merge-base --is-ancestor 649ae01634 kona-client/v1.6.0-rc.2` is **false**, so the production respected prestate contains this bug. The bug stays live on-chain until a new prestate built from `kona-client/v1.7.0*` or later is adopted.

### Attack scenario

1. An actor who controls the chain's batcher key (a compromised key or a buggy batcher) posts a span batch whose `protected_bits` field is cut short.
2. op-node drops the batch, so the canonical chain (what users, exchanges and op-challenger's output-root source see) does not contain those transactions.
3. The attacker designs the batch so that a legacy transaction, re-read without EIP-155, recovers to an address with funds, and that transaction calls `L2ToL1MessagePasser.initiateWithdrawal`. In kona's view of L2 this withdrawal exists. On the canonical chain it does not, and the funds stay spendable.
4. The attacker proposes the output root that kona computes. Honest challengers dispute it using op-node's canonical output roots. At the single-block leaf, kona-in-Cannon re-derives the attacker's version and the attacker wins the step.
5. After the game resolves and the air-gap passes, the attacker proves and finalizes the withdrawal against the `OptimismPortal`. That spends L1-locked ETH that is still owned on L2: a double spend.

## Impact Details

- **What breaks:** the protocol's guarantee that a malicious batcher can censor or reorder but cannot steal. With this bug the batcher can create a divergence that the fault-proof system settles in favour of the non-canonical chain.
- **Who can trigger it:** only the batcher. On standard chains this is a single key registered in `SystemConfig`. There is no permissionless path: an ordinary user cannot get a truncated batch accepted from an unauthorized sender.
- **Other mitigations:** op-dispute-mon would flag the disagreement between op-node-derived roots and the game result. The Guardian can blacklist a game or pause withdrawals during the 3.5-day finality air-gap.
- **Duration:** live in the respected program from the U19 contract upgrade (about 2026-06-10 on Sepolia, about 2026-07-01 on Mainnet) until a prestate with the fix is adopted. Code fixed on 2026-07-15.
- **Severity:** fund-theft impact, but it needs a trusted role (the batcher) to act maliciously or to malfunction in this specific way. Under Immunefi, attacks that need a privileged key are normally out of scope or heavily downgraded. It is kept at **Medium** rather than Low because it turns a liveness-only role into a theft-capable one in the live, respected proof program. kona-node derivation is affected too, but kona-node is not production ready.

## Proof of Concept

**1. Regression test added by the fix.** It fails on `649ae01634^` (the old decoder returns `Ok`) and passes on the fix:

```rust
// rust/kona/crates/protocol/protocol/src/batch/bits.rs, mod test
#[test]
fn decode_rejects_truncated_input() {
    let mut empty: &[u8] = &[];
    assert!(matches!(SpanBatchBits::decode(&mut empty, 1), Err(SpanBatchError::BitfieldTooShort)));
    let mut short: &[u8] = &[0xFF];
    assert!(matches!(SpanBatchBits::decode(&mut short, 16), Err(SpanBatchError::BitfieldTooShort)));
}
```

On the parent, `BitfieldTooShort` does not exist yet. Use this parent-compatible variant, which shows the zero-padding directly:

```rust
#[test]
fn poc_truncated_protected_bits_zero_padded() {
    // One legacy tx whose protected bit (0x01) was cut off the end of the batch.
    let mut empty: &[u8] = &[];
    let bits = SpanBatchBits::decode(&mut empty, 1).expect("parent accepts truncated bitlist");
    assert_eq!(bits.get_bit(0), Some(0)); // legacy tx #0 now treated as NOT EIP-155 protected
}
```

```bash
git worktree add /tmp/kona-parent 649ae01634^
cd /tmp/kona-parent/rust && cargo test -p kona-protocol --lib batch::bits::test::poc_truncated_protected_bits_zero_padded
# parent: passes (bug present). On 649ae01634 the same call returns Err(BitfieldTooShort).
cd <repo>/rust && cargo test -p kona-protocol --lib batch::bits::test::decode_rejects_truncated_input   # fix: passes
```

**2. Standalone model (executed).** The parent and fixed `decode` bodies were copied verbatim into a dependency-free Rust file:

```rust
// bits_poc.rs — rustc -O bits_poc.rs && ./bits_poc
// decode_old = bits.rs:28-47 at 649ae01634^ ; decode_new = bits.rs at 649ae01634
fn main() {
    let legacy_tx_count = 1;
    let mut r: &[u8] = &[];                       // protected_bits byte missing
    let bits = decode_old(&mut r, legacy_tx_count).unwrap();
    assert_eq!(get_bit(&bits, 0), Some(0));        // tx treated as pre-EIP-155
    let mut r: &[u8] = &[];
    assert_eq!(decode_new(&mut r, legacy_tx_count), Err(SpanBatchError::BitfieldTooShort));
}
```

Output:
```
old decode: Ok([0])
old: protected bit for legacy tx #0 = Some(0) (0 => treated as pre-EIP-155 tx)
new decode: Err(BitfieldTooShort)   (op-node: io.ErrUnexpectedEOF -> batch dropped)
old decode(16 bits, 1 byte) = [ff, 00]: txs 0..7 read as unprotected
OK: parent accepts truncated bitlists, fix rejects them
```

Executed: yes for the standalone model. No for the in-crate tests.

## Recommendation

The fix returns `SpanBatchError::BitfieldTooShort` when fewer than `ceil(bit_length/8)` bytes remain. This matches op-node's `io.ReadFull` semantics.

Further suggestions:
- Ship a new `cannon64-kona` absolute prestate that contains this fix, and update the on-chain `CANNON_KONA` game args. Until that happens, the respected program still has the old behaviour.
- Add differential fuzzing between op-node's `spanBatchTxs.decode` and kona's `SpanBatchTransactions::decode` over truncated and mutated inputs. Related kona/op-node span-batch divergences were fixed around the same time (40191ea14e, 1cff94d9ba, 54ee88feb2), which suggests this bug class is systemic.

## References

- Fix commit: 649ae01634231ad2f4a008f6ddcff42072fb5ea1
- Pull request: https://github.com/ethereum-optimism/optimism/pull/21753
- Relevant files: `rust/kona/crates/protocol/protocol/src/batch/{bits.rs,errors.rs,transactions.rs}`, `op-node/rollup/derive/span_batch_util.go`
- Respected-game-type evidence: `docs/public-docs/notices/upgrade-19.mdx` (history: `4fe941d232`, `2b829de28c`, `b40d2ce097`, archived by `798b46044e`); tag `kona-client/v1.6.0-rc.2`
- Spec: https://specs.optimism.io/protocol/delta/span-batches.html
