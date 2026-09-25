# VerifyOPCM governance verification script skipped the ContractsContainer and OPCM immutables, so a malicious OPCM could pass verification

| Field | Value |
|---|---|
| **Target** | `packages/contracts-bedrock/scripts/deploy/VerifyOPCM.s.sol` (off-chain verification tooling run before governance approves an OPCM) |
| **Asset type** | Smart Contract (verification tooling for on-chain upgrade contracts) |
| **Severity** | Low |
| **Impact category** | No direct Immunefi category. Governance-verification bypass that could lead to installing malicious implementations. Requires a malicious OPCM deployer, and governance relying on this script |
| **Fix commit(s)** | 0ea9f6cd2dde475fa6ef15b6ed2ad131fc53bb36 (PR #16795, Spearbit 5.2.1) 2025-07-29; 1bfc93f7c1fe1846217795a1f6051e1b0260f597 (PR #16733, Spearbit 5.1.1) 2025-07-30; 281f29e3332b21bbcd35c29e4254b6316a75a619 (PR #17008) 2025-08-12 |
| **Vulnerable since** | Since `VerifyOPCM` was introduced and the OPCM was split into components that share an `OPContractsManagerContractsContainer` (both before this chunk; exact commit not pinned). Findings from the Spearbit review of the script. |

## Brief / Intro

`OPContractsManager` (OPCM) is the on-chain contract that governance uses to deploy and upgrade OP Stack chains. Before governance signs an upgrade, reviewers run `VerifyOPCM.s.sol` against the deployed OPCM. The script checks that the on-chain bytecode matches the audited source, so the deployer does not have to be trusted. The OPCM is really several contracts: a Deployer, an Upgrader, a GameTypeAdder and an InteropMigrator. Each of them reads the list of implementation addresses from a *ContractsContainer*. The script compared bytecode with *immutable* values masked out, and several security-critical addresses are immutables. So it never checked which container each component points to, never checked the container's own code, and never checked the OPCM's `superchainConfig`, `protocolVersions`, `superchainProxyAdmin` or `upgradeController` addresses. A malicious OPCM built from genuine code but wired to attacker-chosen addresses would have passed verification.

## Vulnerability Details

**How verification worked (parent of 0ea9f6cd2d, `VerifyOPCM.s.sol:183-233`).** `_collectOpcmContractRefs` gathers:
- the OPCM itself,
- every `opcm*()` component (`_getOpcmPropertyRefs`),
- every address returned by `opcm.implementations()` and `opcm.blueprints()`.

Each address is checked with `_compareBytecode(actual, expected, ..., artifact)`, which *skips immutable-reference ranges*. The constructor-args check (`_isValidConstructorArgs`) only verifies that the args ABI-decode and re-encode cleanly, not what values they hold.

**Gap 1: components can point at different containers (fixed by #16733).** `OPContractsManager.implementations()` delegates to the **Deployer** (`OPContractsManager.sol:1985-1987` at 1bfc93f7c1^):

```solidity
function implementations() public view returns (Implementations memory) {
    return opcmDeployer.implementations();          // Deployer's container
}
```

The **Upgrader** reads its *own* immutable container (`OPContractsManagerBase`, lines 68, 91-93):

```solidity
OPContractsManagerContractsContainer public immutable contractsContainer;
function implementations() public view returns (OPContractsManager.Implementations memory) {
    return contractsContainer.implementations();
}
```

`contractsContainer` is an immutable, so the bytecode comparison masks it. A deployer can give the Deployer an honest container and the Upgrader an attacker container with malicious `systemConfigImpl`, `optimismPortalImpl` and so on. The script only ever verified the honest list. `OPContractsManager.upgrade()` delegatecalls `opcmUpgrader`, which would install the malicious implementations on every chain being upgraded. The container's own bytecode was not verified either, so a container whose getters return different values depending on context would also go unnoticed.

**Gap 2: OPCM immutables unchecked (fixed by #16795).** `superchainConfig`, `protocolVersions`, `superchainProxyAdmin` and `upgradeController` are OPCM immutables (lines 1790-1801). `upgrade()` passes `superchainConfig` and `superchainProxyAdmin` straight into the Upgrader, and `upgradeController` controls `setRC` and the RC flow. None of them was compared to an expected value.

**Fixes.**
- #16733 adds `_verifyContractsContainerConsistency`. It calls `contractsContainer()` on every OPCM component (except `opcmStandardValidator`), reverts with `VerifyOPCM_ContractsContainerMismatch` if they differ or are zero, and adds the container itself to the bytecode-verified references:

  ```solidity
  refs[1] = OpcmContractRef({
      field: "contractsContainer",
      name: "OPContractsManagerContractsContainer",
      addr: contractsContainerAddr,
      blueprint: false
  });
  ```
- #16795 adds `_verifyOpcmImmutableVariables`. It enumerates every zero-arg `view` getter in the OPCM ABI, requires each to be listed in `expectedGetters`, and compares the address getters to `EXPECTED_SUPERCHAIN_CONFIG`, `EXPECTED_PROTOCOL_VERSIONS`, `EXPECTED_SUPERCHAIN_PROXY_ADMIN` and `EXPECTED_UPGRADE_CONTROLLER`. `_validateAllGettersAccounted` makes the run fail if a new getter appears that has not been classified.
- #17008 fixes a fail-fast path: an unaccounted getter used to `return false` from inside the loop and skip the rest of the checks. The fix uses `success = false; continue;`, so every failure is reported.

### Attack scenario

1. A malicious or compromised OPCM deployer deploys genuine component bytecode, but the Upgrader gets `OPContractsManagerContractsContainer(evilBlueprints, evilImpls)`. The Deployer gets the honest container.
2. Reviewers run `VerifyOPCM.run(opcm)`. Every bytecode matches with immutables masked, and every address in `opcm.implementations()` (the honest list) matches its artifact. Result: `Overall Verification Status: SUCCESS`.
3. Governance approves, and the upgrade Safe delegatecalls `opcm.upgrade(...)`. The Upgrader installs `evilImpls` as the proxy implementations for SystemConfig, OptimismPortal and the rest. The attacker now controls bridge funds.

## Impact Details

- If exploited, the outcome would be critical: arbitrary implementations behind the portal and bridges. The **preconditions** are strong, though. The OPCM deployer, in practice OP Labs, must be malicious or compromised, and governance must rely on this script as its main defence. Other review layers exist, such as the `OPContractsManagerStandardValidator` run after the upgrade and superchain-ops simulations, and they could catch the resulting addresses.
- The script is off-chain tooling and is not itself deployed.
- **Low** as a verification-tooling gap that removes one defence-in-depth layer against a trusted-party compromise.

## Proof of Concept

The fix added `test_verifyContractsContainerConsistency_mismatch_reverts` and `test_verifyContractsContainerConsistency_eachComponent_reverts` in `test/scripts/VerifyOPCM.t.sol`. Those tests call the new internal helper directly, so they cannot run on the parent. The end-to-end version below runs against the public `run()` entry point. It builds an OPCM whose Upgrader uses a different container, then checks that verification rejects it. It fails on 1bfc93f7c1^ (`run` succeeds) and passes on 1bfc93f7c1 (`run` reverts):

```solidity
// Add to VerifyOPCM_Run_Test in test/scripts/VerifyOPCM.t.sol
// imports: OPContractsManager, OPContractsManagerUpgrader, OPContractsManagerContractsContainer,
//          OPContractsManagerGameTypeAdder, OPContractsManagerDeployer,
//          OPContractsManagerInteropMigrator, OPContractsManagerStandardValidator
//          from "src/L1/OPContractsManager.sol" / "src/L1/OPContractsManagerStandardValidator.sol"
function test_poc_run_upgraderWithDifferentContainer_reverts() public {
    skipIfCoverage();

    // Evil container: same blueprints, one implementation swapped for an attacker contract.
    // (Its bytecode must still pass the per-implementation check, so reuse a real
    //  implementation address in a different slot, e.g. swap two impls.)
    // (`opcm` is typed IOPContractsManager in the test base; convert the structs to the concrete types)
    OPContractsManager.Implementations memory impls =
        abi.decode(abi.encode(opcm.implementations()), (OPContractsManager.Implementations));
    OPContractsManager.Blueprints memory bps =
        abi.decode(abi.encode(opcm.blueprints()), (OPContractsManager.Blueprints));
    (impls.systemConfigImpl, impls.l1StandardBridgeImpl) = (impls.l1StandardBridgeImpl, impls.systemConfigImpl);
    OPContractsManagerContractsContainer evilContainer = new OPContractsManagerContractsContainer(bps, impls);

    // Genuine Upgrader bytecode, attacker container.
    OPContractsManagerUpgrader evilUpgrader = new OPContractsManagerUpgrader(evilContainer);

    // Same OPCM, but with the evil Upgrader.
    OPContractsManager evilOpcm = new OPContractsManager(
        OPContractsManagerGameTypeAdder(address(opcm.opcmGameTypeAdder())),
        OPContractsManagerDeployer(address(opcm.opcmDeployer())),
        evilUpgrader,
        OPContractsManagerInteropMigrator(address(opcm.opcmInteropMigrator())),
        OPContractsManagerStandardValidator(address(opcm.opcmStandardValidator())),
        opcm.superchainConfig(),
        opcm.protocolVersions(),
        opcm.superchainProxyAdmin(),
        opcm.l1ContractsRelease(),
        opcm.upgradeController()
    );

    vm.setEnv("EXPECTED_SUPERCHAIN_CONFIG", vm.toString(address(opcm.superchainConfig())));
    vm.setEnv("EXPECTED_PROTOCOL_VERSIONS", vm.toString(address(opcm.protocolVersions())));
    vm.setEnv("EXPECTED_SUPERCHAIN_PROXY_ADMIN", vm.toString(address(opcm.superchainProxyAdmin())));
    vm.setEnv("EXPECTED_UPGRADE_CONTROLLER", vm.toString(opcm.upgradeController()));

    // Parent: passes verification (no revert) even though upgrade() would install the swapped
    //         implementations. Fix: VerifyOPCM_ContractsContainerMismatch.
    vm.expectRevert(VerifyOPCM.VerifyOPCM_ContractsContainerMismatch.selector);
    harness.run(address(evilOpcm), true);
}
```

A matching PoC for Gap 2 is to deploy `evilOpcm` with `upgradeController = address(0xBAD)` and keep the honest env value. The parent passes and 0ea9f6cd2d fails with `upgradeController mismatch`.

Run:

```bash
cd packages/contracts-bedrock
just build-go-ffi
forge test --match-contract VerifyOPCM_Run_Test --match-test test_poc_ -vvv
```

Executed: **no**. It needs a full contracts build and `forge-artifacts`, and a checkout of the parent commits is not allowed in this review. Types and getters were checked against the parent source: OPCM constructor at `OPContractsManager.sol:1857-1868`, Upgrader constructor at line 596, container constructor at lines 37-50.

## Recommendation

The three fixes close the reported gaps. Further hardening:

- Treat *every* immutable in every verified contract as either verified against an expected value or explicitly allow-listed, not only the OPCM's own immutables. The component `contractsContainer` immutable was the root of Gap 1.
- Verify the StandardValidator's immutables as well. It is excluded from the container check.
- Pair the script with a post-upgrade on-chain check (StandardValidator) that compares every installed implementation to the verified list.

## References

- Fix commits: 0ea9f6cd2dde475fa6ef15b6ed2ad131fc53bb36, 1bfc93f7c1fe1846217795a1f6051e1b0260f597, 281f29e3332b21bbcd35c29e4254b6316a75a619
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/16795, https://github.com/ethereum-optimism/optimism/pull/16733, https://github.com/ethereum-optimism/optimism/pull/17008
- Relevant files: `packages/contracts-bedrock/scripts/deploy/VerifyOPCM.s.sol`, `packages/contracts-bedrock/src/L1/OPContractsManager.sol`, `packages/contracts-bedrock/test/scripts/VerifyOPCM.t.sol`
- Source of findings: Spearbit review of VerifyOPCM (findings 5.1.1, 5.2.1)
