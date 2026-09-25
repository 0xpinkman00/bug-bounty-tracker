# op-dispute-mon: games that claim an L2 block number above 2^63-1 fail enrichment instead of being flagged as invalid proposals

| Field | Value |
|---|---|
| **Target** | `op-dispute-mon/mon/extract/output_agreement_enricher.go` |
| **Asset type** | Blockchain/DLT (off-chain monitoring tooling) |
| **Severity** | Informational |
| **Impact category** | No direct Immunefi impact. Degraded monitoring and alerting fidelity for an invalid proposal |
| **Fix commit(s)** | d0b1f1b087c4741017e51ef6081e8770cc7dff10 (PR #16643) — 2025-07-09 |
| **Vulnerable since** | unknown / since the enricher first called `OutputAtBlock` without a range check |

## Brief / Intro

op-dispute-mon watches every fault dispute game created on L1. For each game it asks a trusted op-node whether the proposed output root is correct. It then raises alerts when an incorrect proposal looks set to win, or a correct one looks set to lose. Anyone can create a permissionless game, and the L2 block number is a free `uint64` parameter. When a game named a block number above 2^63-1, the op-node/EL lookup failed with a generic error, because Ethereum JSON-RPC block numbers are `int64`. dispute-mon then recorded the game as "failed to monitor" instead of marking it as a proposal it *disagrees* with. That removes the game from the agreement and forecast metrics that the main alerts use.

## Vulnerability Details

Parent of the fix, `output_agreement_enricher.go:47-62`:

```go
func (o *OutputAgreementEnricher) Enrich(ctx context.Context, block rpcblock.Block, caller GameCaller, game *monTypes.EnrichedGameData) error {
    ...
    output, err := o.client.OutputAtBlock(ctx, game.L2BlockNumber)
    if err != nil {
        // string match as the error comes from the remote server so we can't use Errors.Is sadly.
        if strings.Contains(err.Error(), "not found") {
            game.AgreeWithClaim = false
            return nil
        }
        return fmt.Errorf("failed to get output at block: %w", err)
    }
```

The path for a huge block number:

1. `RollupClient.OutputAtBlock` sends `optimism_outputAtBlock(hexutil.Uint64(n))`. op-node accepts it and calls `L2.L2BlockRefByNumber(n)`, which issues `eth_getBlockByNumber("0x8000…")` (`op-service/sources/eth_client.go:208`).
2. op-geth's `rpc.BlockNumber.UnmarshalJSON` rejects the value with `"block number larger than int64"` (go-ethereum `rpc/types.go:108`). That is not a "not found" error.
3. `Enrich` returns an error. `Extractor.enrichGames` increments `failed` and `continue`s (`extract/extractor.go:96-99`). A newly created game has no cached data, so it is **left out** of the enriched set. It does not appear in `games_agreement`, the forecast of expected outcomes, or the "honest actor losing / invalid proposal winning" signals. The only trace is the aggregate `failed_games` gauge and an error log.

The fix short-circuits the case:

```go
+   if game.L2BlockNumber > math.MaxInt64 {
+       // The BlockNumber type used by RPCs is an int64 so anything bigger than that can't be a valid block.
+       game.AgreeWithClaim = false
+       return nil
+   }
    output, err := o.client.OutputAtBlock(ctx, game.L2BlockNumber)
```

Such a block cannot exist for centuries at any realistic block time, so disagreeing is always correct.

### Attack scenario

1. The attacker calls `DisputeGameFactory.create(CANNON, rootClaim, abi.encode(2**63))`, posting the normal proposal bond.
2. op-dispute-mon fails to enrich the game on every cycle. The game is counted only in `failed_games`, and the per-game agreement and forecast alerts never fire for it.
3. If the honest challengers also failed to counter it (a separate precondition that this bug does not cause), the monitoring layer, which exists to catch exactly that, would give a weaker and non-specific signal.

## Impact Details

- **No direct loss**: dispute-mon is an observer. Whether the game is resolved correctly depends on op-challenger and on-chain logic, not on this code.
- **Mitigations**: the `failed_games` metric still goes non-zero and an error is logged each cycle. Operators who alert on that metric would still notice. The attacker also risks the full proposal bond, since honest challengers should defeat the claim.
- The effect is reduced precision of a defense-in-depth monitor, so the rating is **Informational**.

## Proof of Concept

The fix added a regression subtest. On the parent commit the stub rollup client returns `outputErr`, `Enrich` returns an error, and `require.NoError` fails. On the fix it passes without making any RPC call.

```go
// op-dispute-mon/mon/extract/output_agreement_enricher_test.go  (inside TestDetector_CheckOutputRootAgreement)
t.Run("BlockNumberLargerThanInt64", func(t *testing.T) {
    validator, rollup, metrics := setupOutputValidatorTest(t)
    rollup.outputErr = errors.New("should not have even requested the output root")
    game := &types.EnrichedGameData{
        L1HeadNum:     100,
        L2BlockNumber: uint64(math.MaxInt64) + 1,
        RootClaim:     mockRootClaim,
    }
    err := validator.Enrich(context.Background(), rpcblock.Latest, nil, game)
    require.NoError(t, err)                 // parent: fails, "failed to get output at block: should not have even requested..."
    require.False(t, game.AgreeWithClaim)
    require.Zero(t, metrics.fetchTime)
})
```

Run:

```
# at the fix commit (test name at that time)
go test ./op-dispute-mon/mon/extract -run 'TestDetector_CheckOutputRootAgreement/BlockNumberLargerThanInt64' -v
# at current develop (the test was renamed/moved; field is now L2SequenceNumber)
go test ./op-dispute-mon/mon/extract -run '/BlockNumberLargerThanInt64' -v
```

Executed: yes, on current `develop`. `TestOutputAgreementEnricher/BlockNumberLargerThanInt64` PASS. Not executed on the parent commit, because no checkout was allowed. The failure there follows directly from the code shown above.

## Recommendation

The fix is correct. For defense in depth: (1) treat any RPC-side "invalid block number" or "larger than int64" error as disagreement, instead of relying on string matching for "not found"; (2) when enrichment fails, still emit a per-game "unmonitored game" alert with the game address, so a single adversarial game cannot hide inside an aggregate counter; (3) consider a sanity bound (e.g. block number greater than the safe head plus some margin relative to L1 time) that flags games which can never be valid.

## References

- Fix commit: d0b1f1b087c4741017e51ef6081e8770cc7dff10
- Pull request: https://github.com/ethereum-optimism/optimism/pull/16643
- Relevant files: `op-dispute-mon/mon/extract/output_agreement_enricher.go`, `op-dispute-mon/mon/extract/extractor.go`, `op-service/sources/rollupclient.go`, `op-service/sources/eth_client.go`
