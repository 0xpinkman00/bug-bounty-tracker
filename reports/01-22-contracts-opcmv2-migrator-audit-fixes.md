# OPContractsManagerV2 / Migrator: CREATE2 front-running of chain deployments, plus hardening of privileged upgrade and migrate paths (audit findings)

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/src/L1/opcm/OPContractsManagerV2.sol`, `OPContractsManagerUtils.sol`, `OPContractsManagerMigrator.sol` |
| **Asset type** | Smart Contract (L1 deployment and upgrade tooling) |
| **Severity** | Low (A); Informational (B–F) |
| **Impact category** | A: "Griefing (e.g. no profit motive for an attacker, but damage to the users or the protocol)". B–F: none directly; defence in depth or misconfiguration prevention for trusted callers |
| **Fix commit(s)** | 56ee47e5f515425dfcb9e42c4f08b7b4d15e1469 (PR #19272, 2026-03-05); d1293a59c1e0e5b9c3d1ffc3f2b62b7d2e561abd (PR #19286, 2026-03-05, "Finding 22"); a6310c80fec05050a764a8848b43fa4dd47a03a8 (PR #19285, 2026-03-03, "Finding 21"); cadb73d9bd46102bb4f54180dc3769e8cfc14707 (PR #19281, 2026-03-05); 61c07664bb13c58e8aac71dc5421f6049c2bf3e4 (PR #19077, 2026-02-05) |
| **Vulnerable since** | OPCMv2 introduced in ec8ce8753d (PR #18079, 2025-11-24). It was gated behind the `OPCM_V2` dev feature for the whole period |

## Brief / Intro

The OP Contracts Manager (OPCM) is the L1 "factory and upgrader" for OP Stack chains. Anyone can call `deploy()` to create a new chain's full set of L1 contracts. A chain's owner Safe **delegatecalls** `upgrade()` or `migrate()` to upgrade existing contracts in place. OPCMv2 is the redesigned version. An external audit of it produced a batch of findings. Only one of them is reachable by an unprivileged party. `deploy()` derived CREATE2 addresses only from values the caller chooses, so a watcher of the public mempool could copy a pending deployment and take the victim's contract addresses first. That makes the victim's deploy revert, and the "expected" addresses then hold contracts the attacker configured. The other findings are safety rails on functions that only the chain's `ProxyAdmin` owner can use.

## Vulnerability Details

### A. `deploy()` CREATE2 salt did not bind the caller, allowing front-run griefing (Low) — PR #19272 (audit #17)

Proxy addresses for a new chain were derived only from caller-supplied config:

`OPContractsManagerUtils.sol:89-98` (parent `56ee47e5f5^`)
```solidity
function computeSalt(uint256 _l2ChainId, string memory _saltMixer, string memory _contractName)
    public pure returns (bytes32)
{
    return keccak256(abi.encode(_l2ChainId, _saltMixer, _contractName));
}
```

`OPContractsManagerV2.sol:199-213` (parent)
```solidity
function deploy(FullConfig memory _cfg) external returns (ChainContracts memory) {
    ...
    ChainContracts memory cts =
        _loadChainContracts(ISystemConfig(address(0)), _cfg.l2ChainId, _cfg.saltMixer, instructions);
    return _apply(_cfg, cts, true);
}
```

`deploy()` is permissionless, and the salt contains neither `msg.sender` nor any role address. As a result:

1. An attacker who sees Alice's pending `deploy(cfg)` can submit `deploy(cfg')` first, where `cfg'` has the same `l2ChainId` and `saltMixer` but different `proxyAdminOwner`, batcher, guardian and so on.
2. The attacker's call deploys proxies at exactly the addresses Alice's call would have used. Alice's transaction then reverts on the CREATE2 collision.
3. Addresses Alice may have precomputed and shared (in registry PRs, genesis files, off-chain configs, or funding transfers) now point at a chain whose owner is the attacker.

Fix: the caller is mixed into the salt.
```diff
 function deploy(FullConfig memory _cfg) external returns (ChainContracts memory) {
+    // Include msg.sender in the salt mixer to prevent cross-caller CREATE2 collisions.
+    string memory saltMixer = string(bytes.concat(bytes20(msg.sender), bytes(_cfg.saltMixer)));
     ...
-        _loadChainContracts(ISystemConfig(address(0)), _cfg.l2ChainId, _cfg.saltMixer, instructions);
+        _loadChainContracts(ISystemConfig(address(0)), _cfg.l2ChainId, saltMixer, instructions);
```

Note: at the parent commit, OPCMv1 (`src/L1/OPContractsManager.sol:1077-1111`) derives salts the same way, as `computeSalt(_input.l2ChainId, _input.saltMixer, ...)`, and this commit did not change it. OPCMv1 was later removed entirely (cb3b286dce, 2026-04-03), and the `OPCM_V2` dev flag was retired with it.

### B. `upgrade`, `upgradeSuperchain` and `migrate` were callable directly (Informational) — PR #19272 (audit #17)

These functions are meant to run only under `DELEGATECALL` from the chain owner's Safe. A direct call already failed further down, because `ProxyAdmin` checks `msg.sender == owner` and the OPCM itself is not the owner. The fix adds an explicit `_onlyDelegateCall()` (`address(this) != address(opcmV2)`) so the failure is clear and does not depend on downstream checks.

### C. Input-validation gaps on the privileged upgrade path (Informational) — PR #19272 (audit #9, #10, #18, #11)

- **Duplicate instruction keys (#9).** `_assertValidUpgradeInstructions` did not reject repeated `ExtraInstruction` keys, which made it ambiguous which override took effect. Duplicates now revert, except for `PermittedProxyDeployment`.
- **`startingRespectedGameType` (#10).** It could name a game type that was not in `disputeGameConfigs` or was disabled. The portal would then respect a game type the factory cannot create, which halts new proposals and withdrawals until the owner fixes it. It is now validated. The override `overrides.cfg.startingRespectedGameType` is permitted so that upgrades can still switch it.
- **`loadBytes` on an EOA (#18).** A `staticcall` to an address with no code "succeeds" with empty data. It now reverts with `ConfigLoadFailed`.
- **Migrator proxy args (#11).** The migrator passed `IAddressManager(address(0))` to the proxy deploy args. It now passes the real `AddressManager`.

### D. OZ v5 `Initializable` slot was not reset on upgrade (Informational) — PR #19286 (Finding 22)

`OPContractsManagerUtils.upgrade()` cleared only the OZ v4 `_initialized` byte before re-initializing. If a future implementation adopted OZ v5 (ERC-7201 slot `0xf0c57e16…6a00`), its `initializer` would revert and the upgrade would fail. The fix also zeroes the v5 `_initialized` uint64 and reverts if the v5 `_initializing` flag is set. This is forward compatibility only: no OZ v5 L1 contracts were upgraded through this path at the time.

### E. Migrator safety (Informational) — PRs #19285 (Finding 21) and #19281 (#14)

- `migrate()` (interop migration to a shared lockbox, ASR and DGF) could be called without the `OPTIMISM_PORTAL_INTEROP` dev feature enabled. It now reverts with `OPContractsManagerMigrator_InteropNotEnabled`.
- The migrator deployed a **new** `DelayedWETH` for the shared dispute games, while `SystemConfig` still pointed to the old one. Later upgrades, which read `DelayedWETH` from `SystemConfig`, would have configured games against a different bond vault than the shared DGF's live games. The migrator now reuses `chainSystemConfigs[0].delayedWETH()`.
- Comment-only items #6, #8, #13 and #19 document intentional behaviour: hard-coded game-type lists, no SuperchainConfig version floor in `migrate`, minimal migration game validation, and ASR non-atomic replacement.

### F. Initial deploys could enable permissionless games with no prestate (Informational) — PR #19077

`_assertValidFullConfig` allowed `CANNON`/`CANNON_KONA` to be enabled on the first deploy, before any absolute prestate existed. The deployer would have had to pass such a config on purpose. Initial deploys now allow only `PERMISSIONED_CANNON`.

### Attack scenario (A)

1. Alice broadcasts `OPContractsManagerV2.deploy(cfg)` with `l2ChainId = 12345` and `saltMixer = "alice-mainnet"`.
2. Mallory copies `cfg`, sets herself as `proxyAdminOwner` and guardian, and front-runs with a higher priority fee.
3. Mallory's chain contracts now sit at the addresses derived from `(12345, "alice-mainnet", name)`. Alice's transaction reverts, and she has to redeploy with a new `saltMixer`, losing gas and any off-chain setup tied to the precomputed addresses.

## Impact Details

- **A:** Griefing only. The attacker pays gas to deploy a whole chain's worth of proxies, gains nothing, and cannot touch Alice's funds or an existing chain. Alice recovers by choosing a new `saltMixer`. The worst secondary effect is that someone relies on the precomputed addresses before checking that the deploy actually landed. Also, OPCMv2 was behind the `OPCM_V2` dev feature and not yet the production deployer. **Low.**
- **B–F:** Every path needs the chain's `ProxyAdmin` owner (via delegatecall) or a deployer supplying its own config. These are guard rails against operator mistakes, not attacker-reachable bugs. **Informational.**

## Proof of Concept

This PoC is based on the fix's regression test `test_deploy_differentSendersDifferentAddresses_succeeds`. Add it to `OPContractsManagerV2_Deploy_Test` in `packages/contracts-bedrock/test/L1/opcm/OPContractsManagerV2.t.sol`:

```solidity
    /// Front-run griefing: same l2ChainId/saltMixer, attacker-chosen owner.
    function test_poc_deploy_frontRunCollision() public {
        address victim   = makeAddr("victim");
        address attacker = makeAddr("attacker");

        IOPContractsManagerV2.FullConfig memory evil = deployConfig;
        evil.proxyAdminOwner = attacker;

        // Attacker lands first.
        vm.prank(attacker);
        IOPContractsManagerV2.ChainContracts memory a = opcmV2.deploy(evil);

        // Parent commit: victim's identical-salt deploy reverts (CREATE2 collision).
        // Fix commit: succeeds at different addresses.
        vm.prank(victim);
        IOPContractsManagerV2.ChainContracts memory v = opcmV2.deploy(deployConfig);
        assertNotEq(address(a.systemConfig), address(v.systemConfig));
    }
```

Upstream tests for B, C and E were added in the same PRs: `test_upgrade_notDelegateCalled_reverts`, `test_upgradeSuperchain_notDelegateCalled_reverts`, `test_migrate_notDelegateCalled_reverts`, `test_upgrade_duplicateInstructionKeys_reverts`, `test_deploy_startingGameTypeNotInConfigs_reverts`, `test_deploy_startingGameTypeDisabled_reverts`, plus the OZ v5 cases in `test/L1/opcm/OPContractsManagerUtils.t.sol`.

Run them:

```bash
cd packages/contracts-bedrock
DEV_FEATURE__OPCM_V2=true forge test --match-contract OPContractsManagerV2_Deploy_Test --match-test test_poc_deploy_frontRunCollision -vv
```

On the parent commit, the victim's `deploy` reverts, so the test fails. On `56ee47e5f5` it passes.

Executed: no. It needs the full contracts-bedrock build and deploy fixtures, and running it on the parent would need a checkout. `deployConfig` is a storage variable in the test contract, so `evil = deployConfig` makes an independent memory copy and mutating `evil` does not affect the victim's config.

## Recommendation

- The `msg.sender` salt binding is the right fix. Consider also binding the `proxyAdminOwner`, so that one deployer cannot accidentally reuse a salt across chains with different owners. OPCMv1's `deploy` used the same salt pattern at the parent commit. It was removed a month later (cb3b286dce, PR #19795, 2026-04-03), which made OPCMv2, with the fix, the only deployer.
- The other changes are appropriate hardening. Keep the new negative tests: duplicate keys, respected-game validation, and direct-call rejection.

## References

- Fix commits: 56ee47e5f5, d1293a59c1, a6310c80fe, cadb73d9bd, 61c07664bb
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/19272, https://github.com/ethereum-optimism/optimism/pull/19286, https://github.com/ethereum-optimism/optimism/pull/19285, https://github.com/ethereum-optimism/optimism/pull/19281, https://github.com/ethereum-optimism/optimism/pull/19077
- Relevant files: `packages/contracts-bedrock/src/L1/opcm/OPContractsManagerV2.sol`, `src/L1/opcm/OPContractsManagerUtils.sol`, `src/L1/opcm/OPContractsManagerMigrator.sol`, `src/L1/OPContractsManager.sol`, `test/L1/opcm/OPContractsManagerV2.t.sol`, `test/L1/opcm/OPContractsManagerUtils.t.sol`
