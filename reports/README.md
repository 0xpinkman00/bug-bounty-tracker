# Optimism monorepo — retrospective security-fix reports

These reports cover security fixes found in the `develop` history from **2024-09-24 to 2026-09-24** (8,712 non-merge commits). Each report uses the Immunefi template: Brief/Intro, Vulnerability Details, Impact Details, Proof of Concept, Recommendation and References.

## Method

1. **Keyword filter.** A broad filter (fix/security/panic/DoS/validate/bond/…) cut the history to 2,459 candidate commits.
2. **Triage.** Six parallel triage agents read every candidate subject and inspected about 450 diffs, producing about 95 candidate entries (related commits grouped).
3. **Verification and writing.** Sixteen writer agents re-checked each entry against the parent-commit code and rewrote severity to Immunefi's classification. The main mitigating factors were trusted-role-only triggers, pre-activation or dev-flag-gated code, and pre-production components such as kona-node and kona proofs before Karst. Entries that did not hold up were rejected.
4. **PoCs.** Where cheap, PoCs were run against `git archive` snapshots or Go `-overlay` builds, so the repo was never modified. Each report states `Executed: yes/no`. Most Rust/Foundry PoCs were **not** executed, because of historical build cost.

**Severity note:** "Severity" is the rating for the bug *as it actually existed*: its deployment status and who could trigger it. Many reports also give a "would be X if live" defect-class rating.

## Summary

| Severity | Reports |
|---|---|
| Critical | 0 |
| High | 4 |
| Medium | 13 |
| Low | 51 |
| Informational | 24 |
| **Total** | **92** |

## Highlights

- **[00-1i](00-1i-op-alloy-op-reth-kona-non-canonical-tx-encoding.md), High:** lenient tx decoding let a batcher smuggle a forged deposit that mints unbacked ETH on op-reth v2.4.1-rc.2 to v2.4.2.
- **[01-01a](01-01a-kona-client-trace-extension-short-circuit.md) / [01-01b](01-01b-kona-proof-zero-output-root-cursor.md), High:** kona fault-proof soundness bugs (trivial game wins) in CANNON_KONA games before they became respected. The unsound shortcut in 01-01a was introduced by the fix in [05-05](05-05-kona-client-claims-older-than-safe-head.md).
- **[03-01](03-01-op-reth-blobbasefee-zero-chain-split.md), High:** op-reth `BLOBBASEFEE` returned 0 (op-geth returns 1). It shipped in reth v1.5.0 and any user could split the chain with it.
- **[00-1a3](00-1a3-kona-protocol-span-batch-truncated-bitlist-divergence.md), Medium:** the only divergence found in the *live respected* kona prestate (v1.6.0-rc.2).
- **[04-08](04-08-op-batcher-span-channel-exceeds-max-rlp-bytes.md), Medium:** ordinary users could force an over-limit batcher channel and stall the safe head. Live for about 10 months.
- **[04-06](04-06-op-node-consolidation-missing-eip1559-params-check.md) / [02-01](02-01-op-node-holocene-span-batch-too-old-epoch-critical-halt.md) / [03-07](03-07-op-reth-da-size-estimate-scaled-1e6-empty-blocks.md) / [05-01](05-01-op-reth-holocene-base-fee-params-divergence.md), Medium:** production op-node/op-reth consensus and liveness bugs.

## High

| ID | Title | Severity notes |
|---|---|---|
| [00-1i](00-1i-op-alloy-op-reth-kona-non-canonical-tx-encoding.md) | op-alloy / op-reth / kona: lenient EIP-2718 decoding of consensus transaction bytes let a batcher smuggle in a forged deposit and split the op-reth chain from the kona fault proof | Critical impact, downgraded because only the authorized batcher can trigger it |
| [01-01a](01-01a-kona-client-trace-extension-short-circuit.md) | kona-client: trace-extension short-circuit accepted any claim equal to the agreed output root, whatever its block number, so invalid output roots could win CANNON_KONA games | it would be Critical once `CANNON_KONA` is the respected game type |
| [01-01b](01-01b-kona-proof-zero-output-root-cursor.md) | kona-proof: the pipeline cursor was seeded with a zero output root, so a claim of `0x00…00` for any block beyond the L1-head safe head was proven "valid" | it would be Critical once `CANNON_KONA` is the respected game type |
| [03-01](03-01-op-reth-blobbasefee-zero-chain-split.md) | op-reth — `BLOBBASEFEE` opcode returns 0 instead of 1 on post-Ecotone blocks — consensus divergence from op-geth (shipped in reth v1.5.0) |  |

## Medium

| ID | Title | Severity notes |
|---|---|---|
| [00-1a2](00-1a2-kona-node-admin-rpc-exposed-without-opt-in.md) | kona-node RPC: admin namespace always enabled on the public listener, ignoring `--rpc.enable-admin` |  |
| [00-1a3](00-1a3-kona-protocol-span-batch-truncated-bitlist-divergence.md) | kona span-batch decoder zero-pads a truncated `protected_bits` bitlist, so kona derives a different chain from op-node (fault-proof divergence) |  |
| [00-1b](00-1b-kona-executor-blobbasefee-da-footprint-divergence.md) | kona-executor derives BLOBBASEFEE from the post-Jovian DA footprint, so the fault-proof program computes different state from op-geth/op-reth |  |
| [00-1c](00-1c-kona-executor-destroyed-changed-account-dropped.md) | kona-executor TrieDB drops re-created (`DestroyedChanged`) accounts and aborts on in-block create+destroy, giving wrong or unprovable state roots in the fault-proof program |  |
| [00-1f](00-1f-kona-span-batch-leading-zero-type-byte-divergence.md) | kona span-batch decoding: a leading `0x00` type byte was stripped, so kona accepted batches that op-node drops (derivation / fault-proof divergence) |  |
| [01-02](01-02-kona-client-precompile-lookup-target-address.md) | kona-client FPVM precompiles: lookup keyed on `target_address`, so DELEGATECALL/CALLCODE into a precompile silently returned empty success |  |
| [01-11](01-11-op-batcher-shadow-brotli-oversized-block-stall.md) | op-batcher — shadow compressor with Brotli mistakes the version byte for data — an oversized L2 block is never batched and the batcher spams empty channels | config-dependent |
| [02-01](02-01-op-node-holocene-span-batch-too-old-epoch-critical-halt.md) | op-node Holocene batch stage: overlapping span batch with a too-old L1 origin raises a critical error and halts derivation | High if the batcher key were not a trusted role |
| [03-03](03-03-kona-node-unauthenticated-unsafe-block-signer-update.md) | kona-node — L1 watcher accepts `ConfigUpdate(UnsafeBlockSigner)` logs from any L1 contract — anyone can replace the P2P block signer and hijack the unsafe chain | the defect class is High; downgraded because kona-node had no release while the bug was live |
| [03-07](03-07-op-reth-da-size-estimate-scaled-1e6-empty-blocks.md) | op-reth payload builder — per-transaction DA size estimate left scaled by 1e6 — op-reth sequencers under default batcher throttling exclude every user transaction (shipped in reth v1.4.1–v1.4.7) |  |
| [04-06](04-06-op-node-consolidation-missing-eip1559-params-check.md) | op-node safe-chain consolidation ignored Holocene EIP-1559 parameters (kona-node also skipped transaction and EIP-1559 checks) | op-node: Medium (requires the sequencer / unsafe-block-signer key). kona-node part: Informational (pre-production) |
| [04-08](04-08-op-batcher-span-channel-exceeds-max-rlp-bytes.md) | op-batcher SpanChannelOut: over-limit channel is still submitted, and derivation discards all of it (safe-head stall) |  |
| [05-01](05-01-op-reth-holocene-base-fee-params-divergence.md) | op-reth: Holocene EIP-1559 parameters read from the wrong block and ignored during validation, so op-reth nodes halt at activation or reject valid blocks |  |

## Low

| ID | Title | Severity notes |
|---|---|---|
| [00-1a1](00-1a1-kona-node-gossip-snappy-decompression-bomb.md) | kona-node gossip: unbounded snappy pre-allocation before validation (memory-exhaustion DoS) |  |
| [00-1d](00-1d-kona-client-interop-trace-extension-prestate-boundary.md) | kona-client interop FPP accepts a future-timestamped agreed pre-state at the trace-extension boundary, where op-program panics |  |
| [00-1e](00-1e-kona-interop-op-supernode-activation-block-message-gates.md) | Interop activation-boundary checks missing or wrong in kona `MessageGraph` and op-supernode, so node and fault-proof validity of executing messages diverge |  |
| [00-1g](00-1g-kona-frame-invalid-is-last-byte-divergence.md) | kona frame decoding: an `is_last` byte other than 0 or 1 was treated as `false` instead of invalidating the batcher transaction (derivation divergence from op-node) |  |
| [00-1h](00-1h-kona-brotli-truncated-channel-output-divergence.md) | kona brotli decompression: output cut short when input and output buffers ran out together, so kona decoded fewer batches than op-node from truncated channels |  |
| [00-1k](00-1k-op-node-kona-holocene-span-batch-overlap-not-validated.md) | op-node / kona Holocene batch stage: a span batch whose overlap disagreed with the safe chain was still applied, splicing a stale or replaced history onto the canonical chain |  |
| [00-2a](00-2a-kona-node-gossip-topic-unbound-message-id.md) | kona-node gossip — message-id not bound to topic — cross-topic replay suppresses real unsafe blocks |  |
| [00-3a](00-3a-op-node-op-supernode-unverified-blocks-labelled-safe.md) | op-node / op-supernode — interop safe head advanced past cross-chain verification in three paths (L1 reorg, EL-sync completion, verifier read error) | pre-activation; would be Medium on a live interop network |
| [00-3b](00-3b-op-node-superauthority-deny-list-bypass.md) | op-node / op-supernode — SuperAuthority deny-list bypassed via consolidation, unsafe sync and follow-mode sequencing — invalidated interop blocks re-adopted | pre-activation; would be Medium on a live interop network |
| [00-3d](00-3d-interop-mempool-builder-admits-invalid-executing-messages.md) | op-interop-filter / op-reth txpool / op-rbuilder — interop admission gaps let txs with invalid or unsafe executing messages reach sequencer blocks (incl. during failsafe) |  |
| [00-4a](00-4a-op-revm-sdm-builder-validator-gas-divergence.md) | SDM (post-exec refunds): sequencer builds blocks that validators reject — warm-state leaks from failed or declined transactions | On impact alone, A and B would be Medium. They are downgraded because SDM is gated on the unactivated Lagoon fork and is off by default. … |
| [00-6a](00-6a-kona-sp1-proposer-ineligible-ancestry-bond-loss.md) | kona-sp1-proposer: ZK proposer extends game chains with invalid, disallowed or unvalidated ancestry, so its bonds can be lost |  |
| [00-7a](00-7a-op-reth-txpool-admits-unincludable-txs.md) | op-reth tx-pool admits transactions that can never be included (L1-info gas reservation and Isthmus operator fee not enforced) |  |
| [00-8a](00-8a-kona-node-delegated-finalize-by-number.md) | kona-node (delegated derivation): upstream finalized hash dropped, so the engine irreversibly finalizes whatever block it has at that height |  |
| [01-01c](01-01c-kona-protocol-unbounded-zlib-and-truncation-divergence.md) | kona-protocol: unbounded zlib channel decompression (zip bomb), and reject-instead-of-truncate semantics that diverged from op-node |  |
| [01-04](01-04-kona-executor-holocene-extradata-pre-canyon-denominator.md) | kona executor: Holocene/Jovian header `extraData` used the pre-Canyon EIP-1559 denominator as the default, so the kona FPP computed wrong block hashes on chains with unset SystemConfig EIP-1559 params |  |
| [01-05](01-05-kona-derive-batcher-data-consensus-divergences.md) | kona derivation: four ways batcher-posted data was interpreted differently from op-node (frame ordering, brotli gate, oversized span-batch txs, singular-batch extraction errors) | Medium if the batcher is treated as untrusted |
| [01-06](01-06-kona-protocol-batch-decode-panics.md) | kona-protocol: panics while decoding malformed batcher data (unknown batch type, truncated span-batch fields) |  |
| [01-07](01-07-kona-derive-reset-uses-safe-head-system-config.md) | kona-derive — pipeline reset seeds L1 traversal with the safe head's SystemConfig instead of the walked-back one — batcher-rotation derivation divergence from op-node |  |
| [01-08](01-08-kona-derive-l1-retrieval-stale-dap-after-reset.md) | kona-derive — L1Retrieval did not clear the data-availability provider on reset — stale batch data leaks across a pipeline reset |  |
| [01-10](01-10-op-reth-proofs-storage-cursor-unbounded-recursion.md) | op-reth proofs-history trie — `MdbxStorageCursor::next` recursed once per deleted storage slot — possible stack-overflow crash of proof-serving nodes |  |
| [01-12](01-12-kona-derive-syscfg-update-log-errors-halt.md) | kona-derive / kona-genesis — malformed SystemConfig update logs halted derivation (and later skipped valid updates) — divergence from op-node |  |
| [01-13](01-13-kona-derive-reorg-blob-provider-liveness.md) | kona-derive / kona-node — wrong error classification on L1 reorgs and blob-provider anomalies — node halt, stall or crash | overall). Individual sub-issues are Low or Informational, see the table below |
| [01-16](01-16-op-node-origin-selector-stuck-on-reorg.md) | op-node sequencer — L1 origin selector gets stuck on a reorged-out L1 origin — sequencer keeps building on a dead L1 fork |  |
| [01-17](01-17-kona-host-hinting-and-cursor-liveness.md) | kona host / proof driver — wrong or missing preimage hints and an unevicted cursor map — fault-proof program stalls or grows memory | overall). 17a is Low; 17b, 17c and 17d are Informational |
| [01-20](01-20-contracts-policy-engine-staking-weight-reset.md) | PolicyEngineStaking: partial unstake resets `lastUpdate`, so stakers and beneficiaries lose accrued staking weight |  |
| [01-21](01-21-contracts-l2cm-upgrade-path-hardening.md) | L2ContractsManager / NUT upgrade path: CGT chains could not be upgraded, an unguarded factory initializer, and silent no-ops (audit/FMA findings) | A); Informational (B–E |
| [01-22](01-22-contracts-opcmv2-migrator-audit-fixes.md) | OPContractsManagerV2 / Migrator: CREATE2 front-running of chain deployments, plus hardening of privileged upgrade and migrate paths (audit findings) | A); Informational (B–F |
| [02-02](02-02-kona-node-holocene-deposits-only-fallback-corrupts-deposits.md) | kona-node Holocene deposits-only fallback: every transaction became a 1-byte `0x7E` blob, so the replacement block could never be built | would be Medium for a client in production use |
| [02-03](02-03-kona-derive-all-zero-blob-critical-error.md) | kona-derive: an all-zero EIP-4844 blob from the batcher is a critical pipeline error, halting kona-node and kona-client where op-node continues | would be Medium if kona-node or a kona-based proof system were in production for the chain |
| [02-06](02-06-kona-client-ecrecover-precompile-preimage-untruncated-input.md) | kona-client (FPVM): accelerated ecrecover built its precompile preimage from the full, unbounded calldata instead of the 128 bytes ecrecover reads | pre-production: CANNON_KONA was not yet a live game type |
| [02-07](02-07-op-alloy-holocene-extradata-length-not-enforced.md) | op-alloy Holocene extraData decoder accepts headers longer than 9 bytes, so Rust clients can disagree with op-geth/op-node on block validity |  |
| [02-10](02-10-contracts-safersafes-liveness-timelock-audit-fixes.md) | SaferSafes (LivenessModule2 / TimelockGuard): audit-driven fixes to ownership recovery, guard state and configuration validation | overall (per-item: 10a Low, 10b to 10e Informational |
| [02-11](02-11-contracts-verifyopcm-container-and-immutables-not-verified.md) | VerifyOPCM governance verification script skipped the ContractsContainer and OPCM immutables, so a malicious OPCM could pass verification |  |
| [03-02](03-02-op-revm-deposit-nonce-and-caller-touch-regression.md) | op-revm — deposit CALLs stop bumping the depositor nonce, and caller fee/nonce/mint changes can be dropped at commit (unreleased regression, yanked crates) | the defect class is High, but no node or proof-program release ever shipped it; see Impact |
| [03-04](03-04-kona-node-gossip-invalid-blocks-marked-seen.md) | kona-node P2P — gossip blocks with bad signatures are recorded as "seen" before signature checks — unauthenticated censorship of unsafe blocks | the defect class is Medium; kona-node had no release while it was live |
| [03-05](03-05-op-node-p2p-sync-server-mutex-deadlock.md) | op-node P2P — req/resp sync server returns without releasing `peerStatsLock` when the per-peer rate limiter errors — a single remote peer can permanently deadlock the alt-sync server |  |
| [03-06](03-06-kona-hardforks-wrong-set-ecotone-selector.md) | kona-hardforks — wrong `setEcotone()` selector in the Ecotone upgrade deposit — kona derives a different Ecotone activation block from op-node |  |
| [03-08](03-08-contracts-bedrock-u16-pause-handling-audit-fixes.md) | contracts-bedrock (Upgrade 16 RC) — pause-handling gaps: migration lifts a per-chain pause, `extend` creates a pause, bond unlocks frozen while paused | bordering Informational: every path needs a trusted role, and the code was only in release candidates |
| [03-09](03-09-kona-node-invalid-payload-panic-and-pre-holocene-deposit-fallback.md) | kona-node engine: an invalid derived payload panics the node, and the first fix wrongly applied the Holocene deposit-only fallback before Holocene |  |
| [04-01](04-01-op-node-span-batch-setcode-nil-to-panic.md) | op-node span batch decoder: nil-pointer panic on a SetCode tx flagged as contract creation | would be Medium if it had shipped in a release |
| [04-02c](04-02c-contracts-bedrock-fdg-closegame-during-pause-forces-refund.md) | FaultDisputeGame: `closeGame()` during a system pause locked games into REFUND mode, costing honest challengers their rewards | pre-deployment; would be Medium if deployed |
| [04-03](04-03-kona-derive-dap-ignores-systemconfig-batcher-rotation.md) | kona-derive: data source only accepted the genesis batcher, ignoring SystemConfig batcher rotations | kona-node pre-production; kona fault-proof game types were not the respected game type on any chain with value; would be High for a live … |
| [04-04](04-04-kona-proof-blob-preimage-key-mismatch-onchain-oracle.md) | kona fault-proof program: blob preimage keys did not match the on-chain PreimageOracle, so blob steps could not be proven on-chain | kona-based game types were not respected on any chain with value; would be High/Critical for a live kona-secured game type |
| [04-05](04-05-kona-protocol-l1-info-blob-base-fee-pectra-params.md) | kona-protocol: L1-info deposit used Cancun blob-fee parameters after L1 Pectra (and mishandled the Sepolia "Pectra blob schedule" fork) | kona-node pre-production; kona proofs not respected; fixed about two months before L1 mainnet Pectra |
| [05-02](05-02-op-reth-payload-builder-stale-gas-limit.md) | op-reth: the payload builder's EVM used the parent's gas limit instead of the gas limit in the payload attributes, so blocks built right after a gas-limit change diverge |  |
| [05-04](05-04-op-reth-debug-execute-payload-unbounded-dos.md) | op-reth: `debug_executePayload` ran full block building synchronously on the RPC runtime with no concurrency limit, letting remote callers DoS the node |  |
| [05-05](05-05-kona-client-claims-older-than-safe-head.md) | kona fault-proof client: claims about blocks older than the agreed safe head were checked against the agreed output root, so kona could declare an invalid claim valid | pre-production kona; the same bug in a live proof program would be rated High |
| [05-06](05-06-op-alloy-span-batch-protected-bits-misindexed.md) | op-alloy-protocol span-batch decoding: the EIP-155 "protected bits" were indexed by overall transaction position, so kona-derive rejected valid span batches or rebuilt legacy transactions incorrectly | pre-production kona; in a live fault-proof program or node this would be High |
| [05-07](05-07-kona-derive-derivation-divergences.md) | kona-derive: several derivation divergences from op-node (grouped; pre-production and mostly pre-Holocene-activation) | overall. Individual items are Low or Informational; see the table below |
| [05-09](05-09-kona-mpt-empty-storage-root.md) | kona-mpt: an emptied storage trie has no root commitment, so kona's fault-proof program rejects valid blocks | pre-production). The same bug in a production fault-proof program would be High to Critical |

## Informational

| ID | Title | Severity notes |
|---|---|---|
| [00-3c](00-3c-op-supernode-cycle-check-drops-chain-on-read-error.md) | op-supernode — interop cycle detection silently drops a chain on logs-DB read error — same-timestamp cycle can be missed |  |
| [00-5a](00-5a-contracts-zkdisputegame-internal-review-hardening.md) | ZKDisputeGame / OPCM: `rootClaimByChainId` ignores its chain-ID argument, plus missing config validation (internal review remediations) | Triage suggested Medium for `rootClaimByChainId`, but we could not find any on-chain consumer that reaches it |
| [00-5b](00-5b-contracts-superpermissioned-game-trapped-init-bond.md) | SuperPermissionedDisputeGame: payable `initialize()` with no bond accounting permanently traps any init bond | Triage suggested Low; downgraded because only a trusted-owner misconfiguration can trigger it |
| [00-9](00-9-dependencies-advisory-bumps.md) | Dependency security bumps, 2026-07 to 2026-09 (informational roll-up) | At most Low for cf871a7311 (hickory-proto through libp2p in kona-node |
| [01-03](01-03-kona-client-post-jovian-precompile-mapping.md) | kona-client FPVM precompiles: post-Jovian specs (INTEROP/OSAKA) mapped to the Isthmus accelerated set, a latent divergence caught before activation | latent, pre-activation |
| [01-09](01-09-kona-cannon-mips64-target-spec-str-miscompile.md) | kona cannon prestate build — MIPS64 target spec declares a 64-bit C `int` — LLVM miscompiles `str == str` to always false in the fault-proof program |  |
| [01-14](01-14-kona-derive-calldata-type3-batcher-tx.md) | kona-derive — CalldataSource ignored EIP-4844 (type-3) batcher transactions — pre-Ecotone derivation divergence from op-node |  |
| [01-15](01-15-op-node-span-batch-setcode-pre-isthmus.md) | op-node — span-batch validation did not drop SetCode (EIP-7702) transactions before Isthmus — derivation divergence from spec and kona |  |
| [01-18](01-18-kona-interop-pre-activation-divergences.md) | kona interop (pre-activation) — six state-transition and validity divergences from op-node / supernode — latent chain split and fault-proof unsoundness | Interop is not activated on any production chain. Once it activates, the same classes of bug would rate High (chain split / fault-proof s… |
| [01-23](01-23-contracts-op-node-uint64-hardening.md) | uint64 hardening: dispute games accepted L2 block numbers ≥ 2^64, and span-batch `v` recovery overflowed for very large chain IDs |  |
| [02-04](02-04-op-revm-rejected-tx-nonce-bump-not-journaled.md) | op-revm: caller nonce was bumped before the fee/balance check and not journaled, so a rejected tx leaked a nonce increment into the multi-tx journal | no production op-reth / kona code path reaches it; Low at most for third-party users of revm's multi-tx `transact_one` API |
| [02-08](02-08-contracts-opcm-upgrade-cannon-kona-zero-init-bond.md) | OPContractsManager upgrade registers the CANNON_KONA dispute game with a zero init bond, so anyone can create those games for free | would have been Low, "Griefing", had it shipped |
| [02-09](02-09-contracts-systemconfig-setfeature-ethlockbox-safety-checks.md) | SystemConfig.setFeature(ETH_LOCKBOX) could be toggled with a lockbox still configured or while paused, silently unpausing the chain or routing withdrawals to an empty portal | privileged-only misconfiguration guard; never in a release |
| [02-12](02-12-multi-client-jovian-preactivation-consensus-fixes.md) | Jovian hardfork: pre-activation consensus-divergence bugs across op-node, op-revm, alloy-op-evm, op-reth and kona | each would have been up to High, "Unintended chain split", if it had reached a network at Jovian activation |
| [03-11](03-11-op-reth-execute-payload-witness-missing-message-passer.md) | op-reth `debug_executePayload`: post-Isthmus execution witness omits the L2ToL1MessagePasser account, so stateless re-execution fails |  |
| [03-12](03-12-op-dispute-mon-huge-l2-block-number-not-flagged.md) | op-dispute-mon: games that claim an L2 block number above 2^63-1 fail enrichment instead of being flagged as invalid proposals |  |
| [04-02a](04-02a-contracts-bedrock-portal-failed-withdrawal-eth-stranded-outside-lockbox.md) | OptimismPortal2 (ETHLockbox design): ETH from failed withdrawals stranded in the portal instead of returned to the lockbox | accounting hygiene; no user loss beyond the protocol's existing failed-withdrawal semantics; pre-deployment code |
| [04-02b](04-02b-contracts-bedrock-asr-isgameregistered-ignores-game-asr.md) | AnchorStateRegistry.isGameRegistered accepted games bound to a different AnchorStateRegistry | defense in depth; needs an upgrade misconfiguration to matter; pre-deployment |
| [04-02d](04-02d-contracts-bedrock-opcm-deploy-pdg-wrong-game-type.md) | OPContractsManager.deploy: PermissionedDisputeGame built with a caller-supplied game type but registered as PERMISSIONED_CANNON | only reachable through the deployer's own non-standard input; fails visibly; the chain owner can fix it |
| [04-09](04-09-kona-node-p2p-gossip-validation-gaps.md) | kona-node P2P gossip: incomplete unsafe-block validation and wrong or static unsafe-block signer (pre-release) | kona-node was pre-release, and no production network relied on it |
| [04-10](04-10-op-alloy-ecotone-fjord-upgrade-deposits-wrong.md) | op-alloy / kona-derive: Ecotone and Fjord network-upgrade deposits built wrong (kona diverges at the activation blocks) | would be Medium for a production client syncing from genesis |
| [04-11](04-11-isthmus-pre-activation-consensus-conformance-fixes.md) | Isthmus pre-activation consensus-conformance fixes across op-reth, alloy-op-evm, op-alloy, kona, op-program and op-service | overall. Every item was fixed before Isthmus activated on OP Mainnet (2025-05-09). One item (11-C) was hit on OP Sepolia for about 2.5 h … |
| [04-12](04-12-interop-pre-mainnet-safety-rule-fixes.md) | Interop (pre-mainnet) cross-chain message safety-rule fixes in op-supervisor, op-program, kona-interop, op-reth and L2 interop contracts | Interop was not active on any production chain, only on devnets |
| [05-03](05-03-op-reth-pre-canyon-withdrawals-in-built-block.md) | op-reth: the payload builder attached a withdrawals list to pre-Canyon (pre-Shanghai) blocks, making the body inconsistent with the header and giving the node an unimportable payload | bordering on Low |

## Rejected after verification

Triage flagged these, but the writer agents found they were not security-relevant fixes:

| Triage ID | Commit | Reason |
|---|---|---|
| 00-1j | cc17dfe50d | The executor check can't be reached: op-node and kona already drop user txs in activation blocks, and op-reth unsafe import is unchanged |
| 00-3e | c0a5dad402 | CrossL2Inbox deposit rejection is defence-in-depth. Deposits can't carry the access list that `validateMessage` requires |
| 00-6b | dfea9e09dd | The VM timeout only exists in the `run-trace` tool, not the challenger service |
| 01-19 | 3b496bc97d | `closeGame()` / `setAnchorState()` were already permissionless; the change is automation only |
| 02-05 | d23c4f0684 | op-revm `transaction_id` reset has no observable effect on any path |
| 03-10 | 01ced848ac | Super-root length check is a robustness fix; the only input is a hash-committed prestate |
| 03-13 | d89e0ce3a3 | The cannon `getrandom` LL/SC change was made in Go and Solidity together, so proofs were never unsound |
| 04-07 | 8cc735def4 | The ASR blacklisted-anchor revert was deliberate design; the change is a design change, guardian-only |
| 05-08 | op-alloy #292 | No consumer ever loaded the buggy config path |
| 05-10 | f7cef71158 | The regression shipped only in op-batcher release candidates, and the batcher is trusted |
| 05-11 | 358a343ad7 | Audit hardening of an undeployed beta contract; the claimed issues don't hold |

## Open follow-ups

- **Unverified, [01-18](01-18-kona-interop-pre-activation-divergences.md):** the interop FPP reads the dependency set from host-supplied local preimage key 8. It is unclear whether the on-chain prestate or step commits to it.
- **Residual gap, [02-07](02-07-op-alloy-holocene-extradata-length-not-enforced.md):** op-reth still doesn't check the format of a block's own extraData at import, only when validating its child.
- **Residual gap, [03-09](03-09-kona-node-invalid-payload-panic-and-pre-holocene-deposit-fallback.md):** after the fix, a pre-Holocene invalid payload is retried forever by kona-node, which stalls it where op-node would drop the payload.
