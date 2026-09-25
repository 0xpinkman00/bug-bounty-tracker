# kona-client interop FPP accepts a future-timestamped agreed pre-state at the trace-extension boundary, where op-program panics

| Field | Value |
|---|---|
| **Target** | `rust/kona/bin/client/src/interop/mod.rs`, `rust/kona/crates/proof/proof-interop/src/boot.rs` (kona-client interop / super-root fault-proof program) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | Fault-proof program divergence from the reference implementation in pre-activation (interop / super-root) code. No live network impact. |
| **Fix commit(s)** | ed10d8009bea9a155bbcd706a235c09bd8c7ef1a (PR #20717, includes #20727), 2026-05-14 |
| **Vulnerable since** | Pre-dates the monorepo import of kona (2026-02-10). Present in `kona-client/v1.5.1` and earlier. Fixed from `kona-client/v1.5.2` (2026-05-18). |

## Brief / Intro

For interop chains, disputes are over "super roots": commitments to the state of all chains in a dependency set at one timestamp. A super-root dispute game bisects a trace of intermediate states, and at the bottom the fault-proof program is given an "agreed" starting state and a "claimed" ending state. After the game's target timestamp the trace is padded ("trace extension"): the correct answer is simply "nothing changes". op-program, the Go reference implementation, panics if the agreed starting state has a timestamp **later** than the game's target, because an honest party never agrees to such a state. kona-client did not check for this. Given a future-dated starting state and an identical claimed end state, it reported the claim as VALID. kona also disagreed with op-program in the other direction for one legitimate boundary case. The bug was in the interop proof path only, and it was fixed before interop, or any kona-based super-root game, was active on a public network.

## Vulnerability Details

The parent code is at `rust/kona/bin/client/src/interop/mod.rs:85-111` (`ed10d8009b^`):

```rust
match boot.agreed_pre_state {
    PreState::SuperRoot(ref super_root) => {
        if super_root.timestamp >= boot.claimed_l2_timestamp {          // includes '>' (future prestate)
            if boot.agreed_pre_state_commitment == boot.claimed_post_state {
                return Ok(());                                         // VALID
            } else { return Err(FaultProofProgramError::InvalidClaim(..)); }
        }
        sub_transition(oracle, boot, evm_factory).await
    }
    PreState::TransitionState(ref transition_state) => {
        if transition_state.pre_state.timestamp >= boot.claimed_l2_timestamp {
            return Err(FaultProofProgramError::InvalidClaim(..));       // always INVALID, even when ==
        }
        ...
```

The reference is op-program at `op-program/client/interop/interop.go:87-97` (at `ed10d8009b^`; op-program was later removed from the monorepo):

```go
if superRoot.Timestamp == bootInfo.GameTimestamp {
    return bootInfo.AgreedPrestate, nil                   // claim valid iff claim == prestate
} else if superRoot.Timestamp > bootInfo.GameTimestamp {
    panic(fmt.Sprintf("agreed prestate timestamp %v is after the game timestamp %v", ...))
}
```

For a `TransitionState`, op-program's `parseAgreedState` uses the transition's embedded `pre_state` super root, so both variants follow the same rule.

Two divergences follow:

| Pre-state | Condition | op-program | kona (parent) |
|---|---|---|---|
| `SuperRoot` / `TransitionState` | `ts > GT`, `claim == prestate` | panic (counts as INVALID) | SuperRoot: **VALID**; TransitionState: INVALID |
| `TransitionState` | `ts == GT`, `claim == prestate` | VALID | **INVALID** |

The preimage oracle only proves `keccak256(preimage) == key`. It does not check the timestamp inside a `SuperRoot`/`TransitionState` preimage. So a participant can register a well-formed super root with an arbitrary future timestamp and post its hash as a claim.

The fix adds the op-program invariant at boot (`boot.rs`) and narrows both arms to `==`:

```rust
assert!(
    agreed_pre_state.timestamp() <= l2_claim_block,
    "agreed prestate timestamp {} is after the game timestamp {}", ...
);
...
if super_root.timestamp == boot.claimed_l2_timestamp { /* claim == prestate ? Ok : InvalidClaim */ }
...
if transition_state.pre_state.timestamp == boot.claimed_l2_timestamp { /* same */ }
```

### Attack scenario (as described by the fix; practical reach is limited)

1. A malicious participant in a kona-based super-root game (`SUPER_CANNON_KONA`-style) registers a `SuperRoot` preimage `H` whose timestamp is later than the game's `l2SequenceNumber`.
2. In a bisection subtree, the participant posts `H` at two adjacent trace positions and defends its own claim, so that `H` becomes both the agreed pre-state and the disputed claim for a leaf.
3. An honest challenger who tries to counter the lower claim needs an execution-trace root with status INVALID or PANIC. Parent kona returns VALID for `(pre = H, claim = H)`, so the honest challenger cannot counter at that leaf. op-program would panic, and the counter would succeed.

**Assessment.** A correctly implemented honest challenger never agrees to `H`. It can counter `H` at the first position where `H` appears, where the agreed pre-state is still an honest value. So this is at most a way to make certain attacker sub-claims unassailable at the leaf level. It is not a demonstrated way to win the root claim against an honest challenger. The `TransitionState` `==` case (row 2) is also outside the honest trace, because the honest trace after the game timestamp is extended with the final `SuperRoot`, not with transition states.

### Was kona the respected proof program while this was live?

No, and the affected path was not active anywhere.
- Interop (the Lagoon hardfork) had no activation in the superchain registry: `docs/public-docs/snippets/generated/hardforks/lagoon.mdx` lists Mainnet and Sepolia as "Not scheduled". The first testnet activation (OP Sepolia and Unichain Sepolia) was planned for July 2026 (`docs/public-docs/notices/interop-prep.mdx`).
- The `cannon64-kona-interop` prestate first shipped with Upgrade 19, built from `kona-client/v1.6.0-rc.2`, and that tag contains this fix (`git merge-base --is-ancestor ed10d8009b kona-client/v1.6.0-rc.2` → true).

## Impact Details

- **Live impact:** none found. The vulnerable code was never the respected program for any live super-root game.
- **Potential impact:** a soundness gap between kona and op-program in interop super-root games. If it were reachable against honest play, it could have let an invalid super-root claim survive, and with it the bonds and cross-chain withdrawals it secures. The analysis above suggests an honest challenger can avoid the affected leaves.
- **Severity:** **Low**. Pre-activation code, a hard-to-reach boundary condition, and fixed before any deployment that used it.

## Proof of Concept

The fix adds `rust/kona/bin/client/tests/interop_trace_extension.rs`. The test below fails on the parent: the parent returns `Ok(())` instead of panicking.

```rust
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "agreed prestate timestamp")]
async fn rejects_super_root_with_timestamp_after_game_timestamp() {
    let prestate_timestamp: u64 = 1000;
    let claimed_l2_timestamp: u64 = prestate_timestamp - 1;      // pre-state is dated AFTER the game
    let (preimages, agreed_commit) = setup_interop_preimages(
        super_root_prestate(prestate_timestamp),
        claimed_l2_timestamp,
        B256::ZERO,
    );
    let mut preimages = preimages;
    // claimed post-state == agreed pre-state commitment (the same hash H at both positions)
    preimages.insert(PreimageKey::new_local(3), agreed_commit.as_slice().to_vec());

    let oracle = MockOracle::from_preimages(preimages);
    let hints = MockHintWriter::default();
    let _ = run(oracle, hints).await;       // parent: returns Ok(()) (VALID), no panic -> test fails
}
```

The `TransitionState` counterpart, `trace_extension_transition_state_at_game_timestamp_accepts_matching_claim`, fails on the parent because the parent returns `Err(InvalidClaim)` for the legitimate `==` case.

```bash
# fixed tree
cd rust && cargo test -p kona-client --test interop_trace_extension
# parent (separate worktree): copy the test file over, then run the same command
git worktree add /tmp/kona-parent ed10d8009b^
cp rust/kona/bin/client/tests/interop_trace_extension.rs /tmp/kona-parent/rust/kona/bin/client/tests/
cd /tmp/kona-parent/rust && cargo test -p kona-client --test interop_trace_extension
# expected on parent: rejects_super_root_with_timestamp_after_game_timestamp and
# rejects_transition_state_with_timestamp_after_game_timestamp fail (no panic),
# trace_extension_transition_state_at_game_timestamp_accepts_matching_claim fails (InvalidClaim)
```

Executed: no.

## Recommendation

The fix mirrors op-program. It panics in `BootInfo::load` when the agreed pre-state is dated after the game timestamp, and treats only `==` as the trace-extension boundary, for both pre-state variants.

Further suggestions:
- Now that op-program has been removed from the monorepo, keep a checked-in table of op-program-equivalent boundary behaviours (timestamps, invalid-transition sentinels, step counts), and test kona's interop `run()` against it.
- Consider having the on-chain super game or the op-challenger super trace provider reject claims whose embedded timestamp exceeds the game's sequence number. That catches the malformed pre-state before it reaches the FPP.

## References

- Fix commit: ed10d8009bea9a155bbcd706a235c09bd8c7ef1a
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/20717, https://github.com/ethereum-optimism/optimism/pull/20727
- Relevant files: `rust/kona/bin/client/src/interop/mod.rs`, `rust/kona/crates/proof/proof-interop/src/boot.rs`, `rust/kona/bin/client/tests/interop_trace_extension.rs`, `op-program/client/interop/interop.go` (at `ed10d8009b^`)
- Activation status: `docs/public-docs/op-stack/protocol/hardforks/lagoon.mdx`, `docs/public-docs/notices/interop-prep.mdx`
