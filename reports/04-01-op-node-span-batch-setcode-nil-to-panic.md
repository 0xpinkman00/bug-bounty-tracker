# op-node span batch decoder: nil-pointer panic on a SetCode tx flagged as contract creation

| Field | Value |
|---|---|
| **Target** | `op-node/rollup/derive` (span batch transaction decoding) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low (would be Medium if it had shipped in a release) |
| **Impact category** | "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network" (trigger requires the batcher key) |
| **Fix commit(s)** | 6c849df4c1344b5640751bb736bbee96226e7f5d (PR #14882), 2025-03-14. Follow-up e2e test: 83b08b5e3fa844694f86f8ca84c391defa5009fe (PR #15159), 2025-04-01 |
| **Vulnerable since** | d509f44f48 "op-node/rollup/derive: implement SetCodeTx span batches" (PR #14197), 2025-03-14 05:11 PDT. Fixed about 9.5 hours later, at 14:42 PDT the same day. No release tag contains the bug. |

## Brief / Intro

The op-node reads L2 transactions back from L1. The batcher posts them there in a compact format called a *span batch*. In that format each transaction's destination (`to`) address is stored in a separate list, and a bitmap flags which transactions are contract creations and so have no `to`. When Isthmus support for EIP-7702 "SetCode" (type 4) transactions was added, the decoder assumed a SetCode transaction always has a `to` address and dereferenced it without checking. A span batch that flags a SetCode transaction as a contract creation therefore makes every op-node that derives it crash with a nil-pointer panic. The node hits the same batch after a restart and crashes again. Only the chain's authorized batcher key can post batch data that derivation reads. The bug lived on `develop` for a few hours and was never in a release.

## Vulnerability Details

In a span batch, `to` addresses are stored only for transactions whose bit in `contractCreationBits` is 0. When the batch is rebuilt into full transactions, `to` is left `nil` for transactions whose bit is 1:

`op-node/rollup/derive/span_batch_txs.go:340-362` (parent of fix)
```go
var to *common.Address = nil
bit := btx.contractCreationBits.Bit(idx)
if bit == 0 {
    ...
    to = &btx.txTos[toIdx]
    toIdx++
}
...
tx, err := stx.convertToFullTx(nonce, gas, to, chainID, v, r, s)
```

For legacy, 2930 and 1559 transactions, `To` is itself a `*common.Address`, so passing `nil` is fine. `types.SetCodeTx.To` is a plain `common.Address` value, because EIP-7702 forbids SetCode contract creation. The new case dereferenced the pointer without a check:

`op-node/rollup/derive/span_batch_tx.go:190-198` (parent of fix)
```go
case types.SetCodeTxType:
    setCodeTxInner := tx.inner.(*spanBatchSetCodeTxData)
    inner = &types.SetCodeTx{
        ...
        To:         *to,          // <- nil dereference when contract-creation bit is set
```

The call path is `ChannelInReader.NextBatch` → `DeriveSpanBatch` → `RawSpanBatch.derive` → `spanBatchTxs.fullTxs` → `convertToFullTx`. Nothing on this path recovers from a panic (the only `recover()` calls in op-node are in the P2P code). The span-batch decoder does not check the transaction type against the active hardfork before this point: decoding runs first, and fork checks happen later in batch validation. So the panic can be reached on any chain running this code, whether or not Isthmus is active.

Fix:
```diff
 	case types.SetCodeTxType:
+		if to == nil {
+			return nil, fmt.Errorf("to address is required for SetCodeTx")
+		}
+
 		setCodeTxInner := tx.inner.(*spanBatchSetCodeTxData)
```
The decode now fails with an ordinary error. Derivation already handles that case: the malformed batch is dropped, like any other undecodable batch, and derivation continues. The follow-up PR #15159 added an action test (`Test_ProgramAction_SetCodeTxWithContractCreationBitSet`) that checks op-node and the fault-proof program both drop such a batch.

### Attack scenario

1. An attacker holds the batcher key, either as a malicious or buggy batcher or through a leaked hot key. They build a span batch holding one SetCode transaction, set that transaction's contract-creation bit, and leave out its `to` entry.
2. They post the channel to the batch inbox on L1. Every verifier op-node, and the sequencer's own op-node, reaches this L1 block during derivation and calls `fullTxs`.
3. Each op-node panics. On restart it reaches the same L1 data and panics again. The safe head stops everywhere, and verifier nodes stop following the unsafe chain too because the process is down. Recovery needs a patched binary.

## Impact Details

- **Effect:** a deterministic crash loop on every op-node running the vulnerable code, caused by one L1 transaction.
- **Precondition:** the data must be signed by the batcher address in the chain's SystemConfig. Derivation throws away batch data from any other sender before decoding it. The batcher is trusted for liveness, since it can always stop posting, but it is not meant to be able to crash verifiers. This bug gave a batcher, or anyone who compromised its hot key, a network-wide crash that is worse than simply not posting.
- **Exposure:** the vulnerable code existed only on `develop` for about 9.5 hours (d509f44f48 → 6c849df4c1). No release tag contains it, and no production network ran it.

With a trusted-key precondition and no deployment, this is **Low**. Had it shipped, it would be Medium: a crash of most network nodes, gated by a privileged key.

## Proof of Concept

The test below goes through the same encode → decode → `recoverV` → `fullTxs` path that `RawSpanBatch.derive` uses. On the parent commit it panics, and on the fix it returns the new error.

Executed: **yes**. On the parent tree the test failed with `derivation panicked on malformed span batch: runtime error: invalid memory address or nil pointer dereference`. After swapping in the fixed `span_batch_tx.go` it passed (`ok`).

Save as `op-node/rollup/derive/poc_setcode_nil_to_test.go` in a tree at `6c849df4c1344b5640751bb736bbee96226e7f5d^`:

```go
package derive

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	"github.com/ethereum-optimism/optimism/op-service/testutils"
)

func TestPoC_SetCodeTxContractCreationBitPanics(t *testing.T) {
	chainID := big.NewInt(901)
	rng := rand.New(rand.NewSource(0))
	tx := testutils.RandomSetCodeTx(rng, types.NewIsthmusSigner(chainID))
	raw, err := tx.MarshalBinary()
	require.NoError(t, err)

	sbt, err := newSpanBatchTxs([][]byte{raw}, chainID)
	require.NoError(t, err)

	// Malicious batcher: mark tx 0 as contract creation and drop its `to`.
	sbt.contractCreationBits.SetBit(sbt.contractCreationBits, 0, 1)
	sbt.txTos = []common.Address{}

	var buf bytes.Buffer
	require.NoError(t, sbt.encode(&buf))

	// Verifier side (mirrors RawSpanBatch.decode + derive).
	var decoded spanBatchTxs
	decoded.totalBlockTxCount = 1
	require.NoError(t, decoded.decode(bytes.NewReader(buf.Bytes())))
	require.NoError(t, decoded.recoverV(chainID))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("derivation panicked on malformed span batch: %v", r)
		}
	}()
	_, err = decoded.fullTxs(chainID)
	require.ErrorContains(t, err, "to address is required for SetCodeTx")
}
```

Run it without changing the repo checkout:

```bash
P=6c849df4c1344b5640751bb736bbee96226e7f5d
D=$(mktemp -d)
git archive $P^ go.mod go.sum op-node op-service op-alt-da op-supervisor | tar -x -C $D
cp poc_setcode_nil_to_test.go $D/op-node/rollup/derive/
(cd $D && go test ./op-node/rollup/derive/ -run TestPoC_SetCodeTxContractCreationBitPanics -count=1)   # FAIL (panic)
git show $P:op-node/rollup/derive/span_batch_tx.go > $D/op-node/rollup/derive/span_batch_tx.go
(cd $D && go test ./op-node/rollup/derive/ -run TestPoC_SetCodeTxContractCreationBitPanics -count=1)   # ok
```

The fix commit also includes a smaller unit regression test, `TestSpanBatchTxSetCodeInvalidTo` in `op-node/rollup/derive/span_batch_tx_test.go`. PR #15159 adds the full action test `Test_ProgramAction_SetCodeTxWithContractCreationBitSet` in `op-e2e/actions/proofs/isthmus_setcode_tx_test.go`.

## Recommendation

The fix returns an error instead of dereferencing, which is correct: the batch is then dropped as invalid, as the spec requires. As defense in depth:
- Fuzz span-batch decoding for every transaction type whenever a new type is added. `FuzzSpanBatchTxs`-style fuzzers would have found this in seconds.
- Consider a top-level `recover()` around single-batch decoding that turns a panic into "drop this batch". This must be done carefully so that op-node and the fault-proof program stay consistent.
- Check that kona's span-batch decoder rejects the same input the same way. It must, or kona and op-node would disagree about the safe chain.

## References

- Fix commit: 6c849df4c1344b5640751bb736bbee96226e7f5d
- Pull request: https://github.com/ethereum-optimism/optimism/pull/14882
- Introducing commit: d509f44f48 (https://github.com/ethereum-optimism/optimism/pull/14197)
- Follow-up e2e test: https://github.com/ethereum-optimism/optimism/pull/15159
- Relevant files: `op-node/rollup/derive/span_batch_tx.go`, `op-node/rollup/derive/span_batch_txs.go`, `op-node/rollup/derive/span_batch.go`
- Spec: https://specs.optimism.io/protocol/delta/span-batches.html, https://specs.optimism.io/protocol/isthmus/derivation.html
