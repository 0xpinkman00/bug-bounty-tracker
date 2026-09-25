# L2ContractsManager / NUT upgrade path: CGT chains could not be upgraded, an unguarded factory initializer, and silent no-ops (audit/FMA findings)

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/L2/L2ContractsManager.sol`, `src/L2/LiquidityController.sol`, `src/universal/OptimismMintableERC20Factory.sol`, `src/L2/L2ProxyAdmin.sol`, `src/libraries/L2ContractsManagerUtils.sol`, `src/libraries/NetworkUpgradeTxns.sol`, `op-node/rollup/derive/upgrade_transaction.go` |
| **Asset type** | Smart Contract (L2 predeploys and the hardfork upgrade path) |
| **Severity** | Low (A); Informational (B–E) |
| **Impact category** | A: "Contract fails to deliver promised returns, but doesn't lose value" (a scheduled predeploy upgrade fails on affected chains). B–E: none directly; defence in depth |
| **Fix commit(s)** | 6556d9d4fcb2346987193826e51552cd948ecfdf (PR #20095, 2026-04-16); 86dbbdc754c871211da428abf76affb16b7d908b (PR #20108, 2026-04-17); ff889b053b46d93f10e82b2f7415bc3557ea18ea (PR #20007, 2026-04-13); ebfebdc7785f45a0876bcdf2db6fb91632a0f9c4 (PR #19798, 2026-03-30); 8f8adda34cb6ca27a1f1a9b267eb20c6e52c1af9 (PR #19783, 2026-03-27); 0cbad332c8b09263ebda8799101f9ac7e08c48b3 (PR #19785, 2026-03-26) |
| **Vulnerable since** | L2CM added in a7369cf1a1 (PR #19111, 2026-02-25). The unconditional `setFeature(CUSTOM_GAS_TOKEN)` was added in e7a1f70331 (PR #19668, 2026-03-27). All of this code was behind the `L2CM` dev feature and the not-yet-activated Karst NUT bundle |

## Brief / Intro

On OP Stack chains, L2 system contracts ("predeploys", such as the bridge, the fee vaults and `L1Block`) are upgraded at a hardfork by **Network Upgrade Transactions (NUTs)**. These are special deposit transactions that op-node injects into the first block of the fork. The new mechanism for this is the `L2ContractsManager` (L2CM). The L2 `ProxyAdmin` delegatecalls it once, and it upgrades and re-initializes every predeploy in a single atomic transaction. Audit and failure-mode-analysis (FMA) reviews found several ways that upgrade could revert, and so leave a chain's predeploys un-upgraded at the fork. They also found places where the upgrade path silently accepted bad input. None of these issues could lead to theft. All of them were in pre-release, dev-flag-gated code, fixed before Karst activated.

## Vulnerability Details

### A. The upgrade reverts on custom-gas-token (CGT) chains (Low) — PR #20095

**A1. `setFeature` is not idempotent.** In the parent commit, L2CM enabled the CGT feature unconditionally:

`L2ContractsManager.sol:430-432` (parent `6556d9d4fc^`)
```solidity
if (_config.isCustomGasToken) {
    IL1Block(Predeploys.L1_BLOCK_ATTRIBUTES).setFeature(Features.CUSTOM_GAS_TOKEN);
}
```
`L1Block._setFeature` reverts on a second enable:

`L1Block.sol:240-241`
```solidity
function _setFeature(bytes32 _feature) internal {
    if (isFeatureEnabled[_feature]) revert L1Block_FeatureAlreadyEnabled();
```
This affects any CGT chain whose `L1Block` already has the feature set. That includes chains created from the new genesis (which writes the feature mapping directly) and any chain that already ran one L2CM upgrade. On such a chain, `L2ContractsManager.upgrade()` reverts. Because L2CM is designed to be reused by later forks, every later L2CM-based NUT would also fail on every CGT chain after the first successful one.

**A2. `LiquidityController.initialize` rejects `owner == address(0)`.** L2CM reads the current config of each predeploy and replays it into `initialize`, including `owner: liquidityController.owner()` (`L2ContractsManager.sol:235`). A CGT chain whose operator called `renounceOwnership()` on the LiquidityController therefore replays `address(0)`:

`LiquidityController.sol:66-76` (parent)
```solidity
function initialize(address _owner, ...) external initializer {
    _assertOnlyProxyAdminOrProxyAdminOwner();
    __Ownable_init();
    transferOwnership(_owner);   // OZ: "Ownable: new owner is the zero address"
```

When either A1 or A2 applies, the revert bubbles up through `L2ProxyAdmin.upgradePredeploys` (`L2ProxyAdmin__UpgradeFailed`). The NUT deposit is still included in the block but fails, so **none** of the predeploys are upgraded, while the node-side fork logic does activate.

Fix:
```diff
-        if (_config.isCustomGasToken) {
+        if (
+            _config.isCustomGasToken
+                && !IL1Block(Predeploys.L1_BLOCK_ATTRIBUTES).isFeatureEnabled(Features.CUSTOM_GAS_TOKEN)
+        ) {
             IL1Block(Predeploys.L1_BLOCK_ATTRIBUTES).setFeature(Features.CUSTOM_GAS_TOKEN);
         }
```
```diff
         __Ownable_init();
-        transferOwnership(_owner);
+        _transferOwnership(_owner);   // preserves a renounced owner across upgrades
```

### B. `OptimismMintableERC20Factory.initialize` had no access control (Informational) — PR #20108

`OptimismMintableERC20Factory.sol:64` (parent `86dbbdc754^`)
```solidity
function initialize(address _bridge) external initializer {
    bridge = _bridge;
}
```
L2CM re-initializes predeploys in three steps: it upgrades to a `StorageSetter`, zeroes the `_initialized` byte, and then calls `upgradeToAndCall(impl, initialize(...))`. If those steps were ever split across transactions, anyone could call `initialize` in between and set `bridge` to an attacker contract. The factory would then deploy "bridge-mintable" tokens that the attacker's bridge could mint. In the NUT flow the steps happen atomically inside one delegatecall from `L2ProxyAdmin`, so the gap cannot be reached. The fix adds `ProxyAdminOwnedBase` and `_assertOnlyProxyAdminOrProxyAdminOwner()`, the same guard every other re-initializable predeploy already had.

### C. Silent no-ops in the upgrade helpers (Informational) — PRs #19798, #20007, #19783, #19785

- `L2ContractsManagerUtils.upgradeTo/upgradeToAndCall` returned early (`if (!Predeploys.isUpgradeable(_proxy)) return;`) instead of reverting. A misrouted or conditional predeploy was therefore skipped silently (#19798). They now revert with `L2ContractsManager_NotUpgradeable`.
- An implementation or `StorageSetter` address with **no code** was accepted. Upgrading a proxy to an empty implementation turns the predeploy into a no-op contract, so calls "succeed" and return empty data. The helpers now revert with `L2ContractsManager_EmptyImplementation` (#20007).
- `L2ProxyAdmin.upgradePredeploys` would `delegatecall` an L2CM address with no code, which is a successful no-op. It now reverts with `L2ProxyAdmin__L2ContractsManagerNotDeployed` (#19783).
- `upgradeToAndCall` now also reverts if the OZ v4 `_initializing` byte is set, matching the existing v5 check (#19783).
- `NativeAssetLiquidity` (non-initializable) was moved to the non-initializable section. `ConditionalDeployer` was added to the implementation list and count used by the NUT bundle generator (#20007, #19785).

### D. The NUT bundle schema version was not enforced (Informational) — PR #20007

`op-node/rollup/derive/upgrade_transaction.go` and `NetworkUpgradeTxns.readArtifact` parsed any bundle whatever its `metadata.version`. The bundle is embedded in the binary at build time and is not attacker-supplied, so the only risk is a build-time schema mismatch being decoded wrongly. Both readers now require `"1.0.0"`.

### E. Genesis flag consistency (Informational) — PR #20007

`L2Genesis.run` now requires `useInterop == isDevFeatureEnabled(devFeatureBitmap, OPTIMISM_PORTAL_INTEROP)`. This prevents a genesis where the two sources of truth for interop disagree.

### Attack scenario (A, the only item with a direct impact)

1. A CGT chain has `CUSTOM_GAS_TOKEN` already set in `L1Block` (new genesis, or an earlier L2CM run), or its operator has renounced ownership of the `LiquidityController`.
2. The Karst (or a later) fork activates, and op-node injects the NUT that calls `L2ProxyAdmin.upgradePredeploys(l2cm)`.
3. `L2CM.upgrade()` reverts. The deposit is recorded as failed and every predeploy keeps its old implementation. The chain now runs fork-N node logic against fork-(N-1) predeploys, which needs another coordinated hardfork to repair.

No one outside the trusted roles can trigger this. It is a latent defect that fires automatically on affected configurations.

## Impact Details

- **A:** A failed predeploy upgrade at a hardfork, limited to CGT chains in the conditions above. No funds are lost directly. The severity depends on how much the new fork's node logic relies on the new predeploy code. In the worst case, a feature that the fork promises (for example, a new `L1Block` interface) is missing until a follow-up upgrade. Rated **Low**: it is pre-activation (Karst had not activated on production chains, to our knowledge), dev-flag gated (`DevFeatures.L2CM`), limited to CGT chains, and only failure/liveness, with no value at risk.
- **B:** Only reachable if the re-initialization were non-atomic, which it is not in the NUT path. **Informational.**
- **C–E:** Robustness improvements that turn silent misconfiguration into a hard failure. **Informational.**

## Proof of Concept

This PoC is based on the regression test added in PR #20095 (`test_upgrade_whenLiquidityControllerOwnerIsZero_succeeds`), plus a new A1 case. Add it to `L2ContractsManager_Upgrade_CGT_Test` in `packages/contracts-bedrock/test/L2/L2ContractsManager.t.sol`:

```solidity
    /// A2: renounced LiquidityController owner must not brick the upgrade.
    function test_poc_upgrade_lcOwnerZero() public {
        skipIfSysFeatureDisabled(Features.CUSTOM_GAS_TOKEN);
        vm.mockCall(
            Predeploys.LIQUIDITY_CONTROLLER, abi.encodeCall(ILiquidityController.owner, ()), abi.encode(address(0))
        );
        _executeUpgrade(); // parent: reverts "L2ContractsManager: Upgrade failed" (Ownable zero-address)
        assertEq(ILiquidityController(Predeploys.LIQUIDITY_CONTROLLER).owner(), address(0));
    }

    /// A1: running the L2CM upgrade on a CGT chain whose L1Block already has the feature set.
    function test_poc_upgrade_cgtFeatureAlreadySet() public {
        skipIfSysFeatureDisabled(Features.CUSTOM_GAS_TOKEN);
        _executeUpgrade();  // first run sets CUSTOM_GAS_TOKEN (or genesis already did)
        assertTrue(IL1Block(Predeploys.L1_BLOCK_ATTRIBUTES).isFeatureEnabled(Features.CUSTOM_GAS_TOKEN));
        _executeUpgrade();  // parent: setFeature -> L1Block_FeatureAlreadyEnabled -> upgrade fails
    }
```

For B, a unit test with no deployment context:

```solidity
    function test_poc_factoryInitializeUnguarded() public {
        // Simulate the reset window: clear the initialized slot, then call from a random EOA.
        vm.store(Predeploys.OPTIMISM_MINTABLE_ERC20_FACTORY, bytes32(0), bytes32(0));
        vm.prank(makeAddr("attacker"));
        // parent: succeeds and sets bridge; fix: reverts ProxyAdminOwnedBase_NotProxyAdminOrProxyAdminOwner
        IOptimismMintableERC20Factory(Predeploys.OPTIMISM_MINTABLE_ERC20_FACTORY).initialize(makeAddr("evilBridge"));
    }
```

Run it:

```bash
cd packages/contracts-bedrock
DEV_FEATURE__L2CM=true SYS_FEATURE__CUSTOM_GAS_TOKEN=true \
  forge test --match-test 'test_poc_upgrade_|test_upgrade_whenLiquidityControllerOwnerIsZero_succeeds' -vv
```

On the parent commit, the two `test_poc_upgrade_*` tests fail with `L2ContractsManager: Upgrade failed`. On `6556d9d4fc` they pass.

Executed: no. A full contracts-bedrock build is required, and testing the parent commit would need a checkout. The revert conditions follow directly from the quoted `L1Block._setFeature` and OZ `transferOwnership` code.

## Recommendation

The fixes cover the findings. Further suggestions:

- Treat every "replay current config into `initialize`" path as needing to accept **every** state reachable on a live chain: zero owners, features already set, and unset optional fields. A fork test that runs the L2CM upgrade **twice** on each supported configuration (standard, CGT, interop) would have caught A1 and A2.
- Consider making `L1Block.setFeature` idempotent when called by the depositor/L2CM path, rather than relying on each caller to guard it.
- Keep the new `EmptyImplementation` and `NotUpgradeable` hard failures. They turn silent partial upgrades into visible failures before activation.

## References

- Fix commits: 6556d9d4fc, 86dbbdc754, ff889b053b, ebfebdc778, 8f8adda34c, 0cbad332c8
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/20095, https://github.com/ethereum-optimism/optimism/pull/20108, https://github.com/ethereum-optimism/optimism/pull/20007, https://github.com/ethereum-optimism/optimism/pull/19798, https://github.com/ethereum-optimism/optimism/pull/19783, https://github.com/ethereum-optimism/optimism/pull/19785
- Relevant files: `packages/contracts-bedrock/src/L2/L2ContractsManager.sol`, `src/L2/LiquidityController.sol`, `src/L2/L1Block.sol`, `src/L2/L2ProxyAdmin.sol`, `src/universal/OptimismMintableERC20Factory.sol`, `src/libraries/L2ContractsManagerUtils.sol`, `src/libraries/NetworkUpgradeTxns.sol`, `scripts/L2Genesis.s.sol`, `op-node/rollup/derive/upgrade_transaction.go`
