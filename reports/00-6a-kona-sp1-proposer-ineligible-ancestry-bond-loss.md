# kona-sp1-proposer: ZK proposer extends game chains with invalid, disallowed or unvalidated ancestry, so its bonds can be lost

| Field | Value |
|---|---|
| **Target** | `rust/kona/sp1/crates/proposer/src/{proposer.rs,adapters.rs,ports.rs}` |
| **Asset type** | Blockchain/DLT (off-chain proposer agent for the `ZKDisputeGame`) |
| **Severity** | Low |
| **Impact category** | "Griefing (e.g. no profit motive for an attacker, but damage to the users or the protocol)". The proposer operator can lose bonds. In the pending-ancestry case, an attacker may collect those bonds as challenger |
| **Fix commit(s)** | da9097df327d4f3056877c3673892bf232ab9fdc (PR #22842), 2026-09-10; bf8daaed3e850a06fde4fb301ba70927dee815fa (PR #22787), 2026-09-15; 044257354b236216883f53bba331e29f14d5fd44 (PR #22910), 2026-09-24 |
| **Vulnerable since** | ace7dd6de6 (PR #22018, 2026-07-28), the port of the op-succinct proposer |

## Brief / Intro

In the ZK dispute game (`ZKDisputeGame`), each proposal is a *child* game that builds on a *parent* game and stakes an init bond. On-chain, a child can never do better than its ancestry. If the parent ends as `CHALLENGER_WINS`, the child is forced to `CHALLENGER_WINS` too, and its whole bond goes to whoever challenged the child. `kona-sp1-proposer` is the agent that picks which existing game to build on. It checked only a narrow set of conditions:

- whether the game itself matched the canonical super root;
- whether the *immediate* parent was blacklisted or retired.

It did not check the rest of the chain of ancestors. As a result it could stake bonds on chains that were already known to be doomed or that had not yet been validated. Three commits fixed this:

- da9097df32 validates the on-chain anchor at startup.
- bf8daaed3e walks the full ancestry for blacklisted, retired or `ChallengerWins` links and rechecks at the latest block before sending.
- 044257354b treats a game whose own validation is still pending as blocking all of its descendants.

## Vulnerability Details

### On-chain rule that turns bad ancestry into bond loss

`packages/contracts-bedrock/src/dispute/zk/ZKDisputeGame.sol:578-588`
```solidity
GameStatus parentGameStatus = getParentGameStatus();
if (parentGameStatus == GameStatus.IN_PROGRESS) revert ParentGameNotResolved();
// INVARIANT: If the parent game's claim is invalid, then the current game's claim is invalid.
if (parentGameStatus == GameStatus.CHALLENGER_WINS) {
    // ... Proposers should wait for sufficient parent finality before extending to avoid this loss.
    status = GameStatus.CHALLENGER_WINS;
    normalModeCredit[claimData.challenger] = totalBonds;
}
```
`initialize()` rejects a parent that is *already* `CHALLENGER_WINS`, blacklisted or retired (`ZKDisputeGame.sol:346-356`). It does not check grandparents, and it does not check a parent that fails *later*. Blacklisting does not propagate to descendants either (see the comment at `:575-577`).

### Proposer behaviour before the fixes

**(1) Only the immediate parent's standing was checked.** `plan_game_creation`:

`rust/kona/sp1/crates/proposer/src/proposer.rs:2721-2760` (parent `bf8daaed3e^`)
```rust
// A retired or blacklisted parent reverts child creation forever ...
if parent_game_index != u32::MAX {
    ...
    let standing = self.l1_view.parent_standing(parent_address, registry).await?;
    if standing.disallowed() { /* drop subtree */ }
}
```
A game `k` levels up the chain that was blacklisted or retired by the guardian, or that resolved `ChallengerWins` after it was cached, did not stop head selection. The proposer kept extending that branch and proving games on it. The fix adds `ancestry_eligible()`, which walks every cached ancestor up to the registered anchor:

`proposer.rs:416-448` (at `bf8daaed3e`)
```rust
fn ancestry_eligible(&self, game: &Game) -> bool {
    ...
    if game.disallowed || self.invalid_games.contains(&game.index) { return false; }
    let mut parent_index = game.parent_index;
    while parent_index != u32::MAX {
        ...
        if self.invalid_games.contains(&index) { return false; }
        let Some(ancestor) = self.games.get(&index) else { return true; };
        if ancestor.disallowed { return false; }
        ...
    }
    true
}
```
It also adds `latest_ancestry_eligible()`, which re-reads blacklist, retirement and `status()` at the *latest* L1 block right before `create` and `prove` are dispatched.

**(2) Pending ancestors did not block descendants.** When the proposer cannot validate a game's root claim, because the supernode has no data for that timestamp or returns an untrusted response, it holds the game as *pending* and outside the DAG. Its children were still judged only by whether the parent was in `invalid_games`:

`proposer.rs:2036-2046` (parent `bf8daaed3e^`)
```rust
if parent_index != u32::MAX &&
    self.state.read().await.invalid_games.contains(&U256::from(parent_index))
{ ... return invalid }
// a *pending* parent is not in invalid_games, so the child is validated on its own root
```
A child with a *correct* root claim built on a pending parent with an *invalid* root could therefore enter the DAG and become the canonical head. 044257354b adds `pending_games` to the ancestry walk. Pending games are "kept across incremental syncs so descendants remain ineligible until validation completes", and unvalidatable ones are tombstoned together with their subtree.

**(3) Registered anchor not verified.** da9097df32 makes startup wait until the `AnchorStateRegistry` anchor root matches a trusted supernode's super root at the anchor timestamp. Without that check, a misconfigured registry, or one that has not yet been corrected, could lead the proposer to build its first games on a root that the ZK proof will not support.

### Attack scenario (pending-ancestry variant, third-party-triggerable)

1. The attacker picks an L2 timestamp `t1` after the anchor for which the proposer's supernode returns an error or an untrusted response, such as a timestamp older than the supernode's retained safe history. The attacker creates game `P` at `t1` on the anchor, with an **invalid** root and the required init bond. The proposer marks `P` *pending*.
2. The attacker creates game `C` at `t2 > t1` with parent `P` and a **correct** root claim for `t2`. The proposer validates `C` against the canonical super root, finds it valid and admits it to the DAG, because `P` is pending, not invalid.
3. `C` becomes the canonical head. The honest proposer creates its own game `H` with parent `C` and stakes its init bond.
4. The attacker challenges `P`. Its invalid root can never be proven, so `P` resolves `CHALLENGER_WINS` and the attacker, as challenger, receives `P`'s bonds, which were their own. `C` then resolves `CHALLENGER_WINS` through inheritance. If the attacker also challenged `H`, `H` resolves `CHALLENGER_WINS` and **the attacker receives `H`'s init bond plus their own challenger bond**. If `H` was never challenged, its bond is credited to `address(0)` and is only recoverable by the DelayedWETH owner.
5. The proposer keeps extending the doomed branch every proposal interval until the branch is pruned, so each interval can cost it another bond.

The disallowed-ancestor variant (1) needs the guardian to blacklist or retire a game. That is a trusted action, and REFUND mode usually returns bonds. Its main cost is wasted proofs and proposals that do not advance the anchor.

## Impact Details

- **Loss:** the proposer operator's ZK game init bonds, plus proving costs for games that can never win. With the pending-ancestry trick an attacker can take the bonds as challenger. The attacker must put up bonds for `P` and `C`, and gets `P`'s bonds back.
- **Mitigating factors:**
  - The ZK dispute game and `kona-sp1-proposer` are new: the game is behind the `ZK_DISPUTE_GAME` dev feature and the proposer was ported on 2026-07-28. Neither was the respected game on a production chain in this window.
  - The pending-ancestry attack needs a timestamp the proposer's supernode cannot answer.
  - The damage is limited to the operator's own bonds. User withdrawals cannot be proven against these games because the claims involved are either correct or lose.
- **Severity:** **Low** (griefing or theft of an operator's bonds in pre-production software).

## Proof of Concept

The fixes added deterministic scenario tests using an in-memory L1 world. The most direct ones:

- `pending_parent_blocks_cached_descendant` (unit, `proposer.rs` at `044257354b`):
  ```rust
  let pending_parent = game_with(40, u32::MAX, 100);
  let descendant = game_with(41, 40, 200);
  let mut state = state(vec![descendant.clone()], None);
  state.pending_games.insert(pending_parent.index, CompactGameSummary::from(&pending_parent));
  assert!(!state.ancestry_eligible(&descendant));
  assert!(state.eligibility_chain(descendant.index).is_none());
  ```
- `disallowed_ancestor_blocks_the_branch_and_reparents_creation` (scenario, `proposer/scenario/tests.rs` at `bf8daaed3e`). It builds anchor → 1 → 2 → 3 and checks that the proposer plans `ProposeGame { parent_game_index: 3 }`. It then blacklists or retires game **2**, the grandparent of the next proposal, and asserts that the head falls back to game 1 and that no proposal or proof is scheduled on 2 or 3:
  ```rust
  world.update_game(&ancestor_target, |game| game.standing = standing);
  let blocked = scenario.tick().await.unwrap();
  assert_eq!(blocked.snapshot.canonical_head_index, Some(U256::from(1)));
  assert!(!blocked.scheduled.iter().any(|s| matches!(s.operation,
      OperationSummary::ProposeGame { parent_game_index: 2 | 3, .. })));
  ```
  On the parent code, only the *immediate* parent (3) was checked, so the proposer keeps proposing on 3.
- `latest_challenger_wins_does_not_permanently_invalidate_ancestry` / `creation_task_rechecks_ancestry_before_dispatch`: these cover the latest-block recheck.

Run (the proposer is a member of the main Rust workspace):
```bash
cd rust
cargo test -p kona-sp1-proposer ancestry
cargo test -p kona-sp1-proposer disallowed_ancestor_blocks_the_branch_and_reparents_creation
cargo test -p kona-sp1-proposer pending_parent_blocks_cached_descendant
```
The tests use APIs introduced by the fixes (`ancestry_eligible`, `pending_games`), so they do not compile on the parent commits. To show the failure there, revert only the eligibility filtering in `plan_game_creation` / `select_canonical_head` in a scratch clone and re-run the scenario test.

Executed: no. The SP1 and kona dependency tree is too heavy to build for this review.

## Recommendation

The combined fixes introduce an explicit trust boundary: the registered, supernode-verified anchor. Ancestry is extended or proven only when every link up to that boundary has been validated and is not disallowed or `ChallengerWins`, both in the cache and at the latest L1 block. Further suggestions:

- Consider making "cache gap → fail open" (`ancestry_eligible` returns `true` when an ancestor is missing) fail closed for games that are not the proposer's own. A gap is exactly the situation an attacker would try to create.
- Consider waiting for parent finality, or at least for the parent's challenge window to pass unchallenged, before extending a game that someone else created. The contract comment recommends this ("Proposers should wait for sufficient parent finality before extending").

## References

- Fix commits: da9097df327d4f3056877c3673892bf232ab9fdc, bf8daaed3e850a06fde4fb301ba70927dee815fa, 044257354b236216883f53bba331e29f14d5fd44
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/22842, https://github.com/ethereum-optimism/optimism/pull/22787, https://github.com/ethereum-optimism/optimism/pull/22910
- Relevant files: `rust/kona/sp1/crates/proposer/src/proposer.rs`, `proposer/scenario/tests.rs`, `adapters.rs`, `ports.rs`, `rust/kona/sp1/README.md`, `packages/contracts-bedrock/src/dispute/zk/ZKDisputeGame.sol`
