# op-node — span-batch validation did not drop SetCode (EIP-7702) transactions before Isthmus — derivation divergence from spec and kona

| Field | Value |
|---|---|
| **Target** | `op-node/rollup/derive/batches.go` (`checkSpanBatch`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Informational |
| **Impact category** | Unintended chain split (network partition). Latent only: it needs the trusted batcher and a chain that had not yet activated Isthmus |
| **Fix commit(s)** | `34b4ec03c590e93bbc0fa4aeb92fda461978753d` (PR #19150) — 2026-03-19 |
| **Vulnerable since** | `d509f44f48` (2025-03-14, "implement SetCodeTx span batches"). The follow-up `b6b9371e21` (2025-03-15) added the pre-Isthmus drop only to the singular-batch path |

## Brief / Intro

The batcher posts L2 transactions to L1 in "batches". A span batch is a compact encoding that covers many L2 blocks at once. Before the Isthmus upgrade, EIP-7702 "SetCode" transactions (type 4) are not valid on OP Stack L2s, so the spec says any batch containing one must be dropped. op-node enforced this for singular batches but not for span batches, while kona enforced it for both. A span batch containing a type-4 transaction before Isthmus was therefore handled differently by op-node (and op-program, the production Cannon fault-proof program built from the same code) than by kona-node and the kona fault-proof program.

## Vulnerability Details

Parent `op-node/rollup/derive/batches.go:384-393`, per block in `checkSpanBatch`:

```go
for i, txBytes := range batch.GetBlockTransactions(i) {
    if len(txBytes) == 0 { ... return BatchDrop }
    if txBytes[0] == types.DepositTxType { ... return BatchDrop }
    // no SetCodeTxType check
}
```

The singular path in the same file (`checkSingularBatch`, lines 185-188 at the parent) already had:

```go
if !isIsthmus && txBytes[0] == types.SetCodeTxType {
    log.Warn("sequencers may not embed any SetCode transactions before Isthmus", "tx_index", i)
    return BatchDrop
}
```

kona's `SpanBatch::check_batch` (`rust/kona/crates/protocol/protocol/src/batch/span.rs:510-516` at the parent) also drops with `BatchDropReason::Eip7702PreIsthmus`. Span-batch decoding accepts `SetCodeTxType` whatever the fork (`span_batch_txs.go:274,393`), so a type-4 transaction survives decoding and reaches validation.

Fix:

```diff
+		isIsthmus := cfg.IsIsthmus(blockTimestamp)
 		for i, txBytes := range batch.GetBlockTransactions(i) {
 ...
+			if !isIsthmus && txBytes[0] == types.SetCodeTxType {
+				log.Warn("sequencers may not embed any SetCode transactions before Isthmus", "tx_index", i)
+				return BatchDrop
+			}
```

**Where the chains diverge.** On the parent code, op-node accepts the span batch and turns the type-4 transaction into payload attributes. The pre-Prague/pre-Isthmus EL then rejects the payload:
- Post-Holocene, op-node replaces the block with a deposit-only block and flushes the channel.
- Pre-Holocene, op-node drops those attributes, but any earlier elements of the same span batch have already been applied.

kona (and the spec) drop the entire span batch at validation time and wait for another batch for that slot, or for the sequencing window to expire. The resulting L2 safe chains differ.

### Attack scenario

1. The chain is not yet on Isthmus.
2. The batcher (trusted, or compromised) posts a span batch in which one block contains a type-4 transaction. The honest sequencer's EL could never have built such a block, so an honest batcher never posts one.
3. op-node and op-program accept the batch and produce a deposit-only block, or a partial span. kona-node and kona-client drop the batch. After that, the batcher can post a different valid batch for the same slot, which only kona will adopt.
4. Outcome: op-node and kona-node follow different safe chains. Cannon (op-program) and Cannon-kona games disagree about the same output root.

## Impact Details

- **Preconditions:** control of the batcher key, and a chain with Isthmus inactive. OP Mainnet and the rest of the Superchain activated Isthmus in May 2025, about 2 months after the singular-only fix. When this fix landed (March 2026), no Superchain chain was pre-Isthmus, and new chains start with Isthmus at genesis. No such batch is known to have been posted, so historical replays are unaffected.
- **Consequence if triggered:** a chain split between op-node and kona-node, and conflicting fault-proof results between the op-program-backed and kona-backed game types. On a chain running both game types, this breaks the "both proof systems agree" assumption.
- **Severity:** Informational. The bug class would be a chain split (High), but it could not be reached on any live chain when it was fixed, and it needs a trusted role.

## Proof of Concept

The fix commit added no test. The PoC below adds one span-batch case to the existing table-driven `TestValidBatch`, copied from the existing singular "setCode tx included pre-Isthmus" and span "deposit tx included" cases. Insert it into `spanBatchTestCases` in `op-node/rollup/derive/batches_test.go`, directly after the span "deposit tx included" case:

```go
{
    Name:       "PoC 01-15: setCode tx included pre-Isthmus in span batch",
    L1Blocks:   []eth.L1BlockRef{l1A, l1B},
    L2SafeHead: l2A0,
    Batch: BatchWithL1InclusionBlock{
        L1InclusionBlock: l1B,
        Batch: initializedSpanBatch([]*SingularBatch{
            {
                ParentHash: l2A1.ParentHash,
                EpochNum:   rollup.Epoch(l2A1.L1Origin.Number),
                EpochHash:  l2A1.L1Origin.Hash,
                Timestamp:  l2A1.Time,
                Transactions: []hexutil.Bytes{
                    []byte{types.SetCodeTxType, 0}, // piece of data alike to a SetCodeTx
                },
            },
        }, uint64(0), big.NewInt(0)),
    },
    Expected:    BatchDrop,
    ExpectedLog: "sequencers may not embed any SetCode transactions before Isthmus",
    ConfigMod:   deltaAtGenesis,   // default config: Isthmus not scheduled
},
```

I ran it without modifying the tree by using `go test -overlay`. Overlay 1 replaces only `batches_test.go`, which gives the fixed code. Overlay 2 also replaces `batches.go` with a copy where the span path's `isIsthmus := cfg.IsIsthmus(blockTimestamp)` is changed to `isIsthmus := true`. That reproduces the parent behaviour on the current (refactored) code.

```bash
go test -overlay overlay15_fixed.json ./op-node/rollup/derive/ -run 'TestValidBatch/span_PoC' -count=1 -v
# --- PASS: TestValidBatch/span_PoC_01-15:_setCode_tx_included_pre-Isthmus_in_span_batch

go test -overlay overlay15_vuln.json  ./op-node/rollup/derive/ -run 'TestValidBatch/span_PoC' -count=1 -v
#   Error: Not equal: expected: 0x0  actual: 0x1   (BatchDrop expected, BatchAccept returned)
# --- FAIL: TestValidBatch/span_PoC_01-15:_setCode_tx_included_pre-Isthmus_in_span_batch
```

On the actual parent commit (`34b4ec03c5^`), the same case should also return `BatchAccept`, because the span loop has no SetCode check at all (shown by reading the code, not run).

Executed: yes. I ran it on the current `develop` tree, with the fix re-introduced in an overlay and with it removed.

## Recommendation

The fix adds the per-block Isthmus check to the span path. Current `develop` goes further: it factors both paths through one `checkSequencerTxData` helper (`batches.go:187`), so singular and span validation cannot drift apart again. Any future per-transaction rule should be added only through that shared helper. A differential test that runs identical batches through op-node's and kona's validators would have caught this year-long gap.

## References

- Fix commit: 34b4ec03c590e93bbc0fa4aeb92fda461978753d
- Pull request: https://github.com/ethereum-optimism/optimism/pull/19150
- Related: d509f44f48 (#14197, SetCode span-batch encoding), b6b9371e21 (#14877, singular-only pre-Isthmus drop)
- Relevant files: `op-node/rollup/derive/batches.go`, `op-node/rollup/derive/span_batch_txs.go`, `rust/kona/crates/protocol/protocol/src/batch/span.rs`
- Spec: https://specs.optimism.io/protocol/isthmus/derivation.html
