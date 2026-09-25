# op-node safe-chain consolidation ignored Holocene EIP-1559 parameters (kona-node also skipped transaction and EIP-1559 checks)

| Field | Value |
|---|---|
| **Target** | `op-node/rollup/attributes/engine_consolidate.go` (`AttributesMatchBlock`); kona-node `crates/node/engine/src/attributes.rs` (`AttributesMatch::check`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | op-node: Medium (requires the sequencer / unsafe-block-signer key). kona-node part: Informational (pre-production) |
| **Impact category** | "Unintended chain split (network partition)" |
| **Fix commit(s)** | op-node: 4dcaec464f52558165d5787c7c3d99062d9c20ed (PR #14179), 2025-02-07, first released in `op-node/v1.11.0` (2025-02-10). kona-node: a6ee73e903864624c030c9b5d9b48506d9b39066 (op-rs/kona#1412, transaction checks) and 273043cf9ecf6ecb76d2db0e4de5a0f345a00a3d (op-rs/kona#1419, EIP-1559 checks), 2025-04-14 |
| **Vulnerable since** | e7fbaeca08 "Holocene: initial op-node support for configurable eip-1559 params" (PR #12497), 2024-10-21. Live on Sepolia from Holocene (Nov 2024) and on OP Mainnet/Superchain from Holocene activation on 2025-01-09 until nodes upgraded to v1.11.0 |

## Brief / Intro

An OP Stack node learns about new L2 blocks in two ways. It receives them quickly from the sequencer over P2P gossip ("unsafe" blocks), and it later re-derives them from data posted on L1 ("safe" blocks). When the re-derived version of a block arrives and the node already has an unsafe block at that height, op-node does not rebuild the block. It *consolidates*: it compares the derived "payload attributes" with the existing block field by field and, if they match, marks the existing block as safe. The Holocene upgrade added a new consensus field, the EIP-1559 fee parameters (denominator and elasticity) stored in the block's `extraData`. The comparison was never updated to check it. A gossiped block with the wrong fee parameters was therefore accepted as the safe, and later finalized, version of the block. Nodes that synced from L1 built a different block, so the network's safe chain split.

## Vulnerability Details

Since Holocene, the derivation pipeline puts the SystemConfig's EIP-1559 parameters into `PayloadAttributes.EIP1559Params`. The execution engine writes them into the header's `extraData` (`0x00 ‖ denominator(4) ‖ elasticity(4)`). The engine uses the parent's `extraData` to compute the next block's base fee, so the field affects both the block hash and every later block.

Parent of the fix, `op-node/rollup/attributes/engine_consolidate.go`, `AttributesMatchBlock` (lines about 29-78) compares: parent hash, timestamp, prevRandao, transactions, gas limit, withdrawals, parent beacon root and fee recipient. **It never looks at `attrs.EIP1559Params` or `block.ExtraData`**:
```go
	if attrs.SuggestedFeeRecipient != block.FeeRecipient {
		return fmt.Errorf("fee recipient data does not match, ...")
	}
	return nil          // <- EIP1559Params / extraData never compared
}
```

The execution layer cannot catch this on import. It checks that Holocene `extraData` is well-formed, but it does not know which values the L1 SystemConfig prescribes. P2P gossip validation does not check the values either. As the fix's own comment puts it: "The extraData field of blocks from sequencer gossip isn't currently checked during import."

Fix, added at the end of `AttributesMatchBlock`:
```go
	if err := checkEIP1559ParamsMatch(rollupCfg.ChainOpConfig, attrs.EIP1559Params, block.ExtraData); err != nil {
		return err
	}
```
`checkEIP1559ParamsMatch` validates both encodings. It translates the attributes value `(0,0)` to the chain's pre-Holocene constants (`EIP1559DenominatorCanyon`, `EIP1559Elasticity`), exactly as the engine does, and requires the result to equal the values decoded from `extraData`. It also rejects non-empty `extraData` before Holocene. The node now loads `ChainOpConfig` at startup, from the superchain registry or `debug_chainConfig`, so that it can perform the translation. On a mismatch, consolidation fails and op-node replaces the unsafe block with the derived one, which is a reorg to the canonical block.

### Attack scenario

1. The holder of the unsafe-block signer key, meaning a compromised or buggy sequencer, gossips block *N* whose `extraData` encodes, for example, `(50, 2)`, while the L1 SystemConfig prescribes `(250, 6)`. All other fields match what the batcher later posts.
2. Every verifier that received block *N* over gossip later derives it from L1. The comparison passes, so block *N*, with the wrong fee parameters, becomes **safe** and then **finalized** on those nodes.
3. Nodes that were syncing from L1 at the time, restarted nodes, and the fault-proof program (op-program) build block *N* with `(250, 6)`. It has a different hash, and later blocks have different base fees and state roots.
4. The network now has two safe/finalized chains. RPC providers, bridges and exchanges on different sides disagree about finalized blocks. A proposer running an affected node posts output roots that the fault-proof system proves wrong, and the proposer loses its bond. Fixing the affected nodes requires manual intervention.

## Impact Details

- **Consequence:** the safe and finalized L2 chain splits between nodes. The split carries forward, because every later base fee depends on the parent's parameters. The safe chain is meant to depend only on L1 data, and this bug let the sequencer key break that property.
- **Precondition:** blocks must be signed with the unsafe-block signer key, which is a trusted role. The same symptom could also come from an ordinary bug in a sequencer's execution client, with no malicious intent.
- **Limits:** withdrawal safety is not directly at risk. The fault-proof program derives from L1 and would reject output roots from the divergent chain, so the loss falls on operators such as proposers and on infrastructure consistency.
- **Exposure:** production chains were exposed from Holocene activation (2025-01-09 on mainnet) until upgrade to op-node v1.11.0 (released 2025-02-10), and Sepolia from November 2024.

The Immunefi impact "unintended chain split" is High. Because only a trusted key can trigger it, the rating here is **Medium**.

### kona-node (Informational)

Before 2025-04-14, `AttributesMatch::check` in kona-node carried literal `// TODO: check transactions` and `// TODO: Check EIP-1559 parameters` markers. It compared only header-level fields. A sequencer-signed unsafe block with *different transactions*, but the same parent, timestamp, randao, gas limit, withdrawals, beacon root and fee recipient, would therefore have been promoted to safe. That is a much stronger version of the op-node bug. a6ee73e903 added transaction-by-transaction comparison and 273043cf9e added the EIP-1559 check. kona-node was pre-production at the time, so this part is Informational.

## Proof of Concept

A Go unit test that calls `AttributesMatchBlock` with Holocene attributes `(250, 6)` and a block whose `extraData` encodes `(50, 2)`.

Executed: **yes**. On a tree exported at `4dcaec464f^`, the test **FAILED** with `An error is expected but got nil`, meaning the mismatching block was accepted. After swapping in the fixed `engine_consolidate.go` and `types.go` from `4dcaec464f`, it **PASSED**.

`op-node/rollup/attributes/poc_eip1559_consolidate_test.go`:
```go
package attributes

import (
	"testing"

	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/log"
	"github.com/stretchr/testify/require"

	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
)

func TestPoC_ConsolidationIgnoresEIP1559Params(t *testing.T) {
	a := ecotoneArgs() // existing helper in engine_consolidate_test.go
	var attrParams eth.Bytes8
	copy(attrParams[:], eip1559.EncodeHolocene1559Params(250, 6))       // what derivation says
	a.attrs.EIP1559Params = &attrParams
	a.envelope.ExecutionPayload.ExtraData =
		eth.BytesMax32(eip1559.EncodeHoloceneExtraData(50, 2))           // what the gossiped block has

	err := AttributesMatchBlock(&rollup.Config{}, a.attrs, a.parentHash, a.envelope, testlog.Logger(t, log.LevelInfo))
	require.Error(t, err, "unsafe block with foreign EIP-1559 params was accepted as matching derived attributes")
}
```

Run without touching the checkout:
```bash
P=4dcaec464f52558165d5787c7c3d99062d9c20ed
D=$(mktemp -d)
git archive $P^ go.mod go.sum op-node op-service op-alt-da op-supervisor | tar -x -C $D
cp poc_eip1559_consolidate_test.go $D/op-node/rollup/attributes/
(cd $D && go test ./op-node/rollup/attributes/ -run TestPoC_ConsolidationIgnoresEIP1559Params -count=1)  # FAIL
for f in op-node/rollup/attributes/engine_consolidate.go op-node/rollup/types.go; do git show $P:$f > $D/$f; done
(cd $D && go test ./op-node/rollup/attributes/ -run TestPoC_ConsolidationIgnoresEIP1559Params -count=1)  # ok
```

The fix itself adds `TestCheckEIP1559ParamsMatch` and a `createMismatchedEIP1559Params` case to `TestAttributesMatch` in `engine_consolidate_test.go`.

## Recommendation

The fix closes the gap. Suggested follow-ups:
- Make consolidation fail closed. Instead of listing the fields to check, compare the *whole* header implied by the attributes. For example, build the expected header fields generically, or require an exact match on `extraData` and any header field that a fork adds. Each new fork (Isthmus `requestsHash`/`withdrawalsRoot`, Jovian min-base-fee in `extraData`) otherwise risks repeating this bug.
- Keep one shared test vector between op-node and kona-node for consolidation, and fail CI if either side has an unimplemented `TODO` in a consensus check.

## References

- Fix commit (op-node): 4dcaec464f52558165d5787c7c3d99062d9c20ed (https://github.com/ethereum-optimism/optimism/pull/14179)
- Introducing change: e7fbaeca08 (https://github.com/ethereum-optimism/optimism/pull/12497)
- kona-node fixes: a6ee73e903864624c030c9b5d9b48506d9b39066 (https://github.com/op-rs/kona/pull/1412), 273043cf9ecf6ecb76d2db0e4de5a0f345a00a3d (https://github.com/op-rs/kona/pull/1419)
- Relevant files: `op-node/rollup/attributes/engine_consolidate.go`, `op-node/rollup/types.go`, `op-node/node/node.go`, `crates/node/engine/src/attributes.rs` (kona, now `rust/kona/...`)
- Specs: https://specs.optimism.io/protocol/holocene/exec-engine.html#eip-1559-parameters-in-block-header , https://specs.optimism.io/protocol/derivation.html#l2-execution-engine
