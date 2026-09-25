# kona cannon prestate build — MIPS64 target spec declares a 64-bit C `int` — LLVM miscompiles `str == str` to always false in the fault-proof program

| Field | Value |
|---|---|
| **Target** | `rust/kona/docker/cannon/mips64-unknown-none.json`, `rust/kona/docker/fpvm-prestates/cannon-repro.dockerfile`, `rust/kona/justfile` |
| **Asset type** | Blockchain/DLT (fault-proof program build) |
| **Severity** | Informational |
| **Impact category** | Fault-proof liveness / soundness for cannon-kona games *if* an affected prestate were deployed. A prestate built this way panics on every input, so pre-deployment testing catches it |
| **Fix commit(s)** | `04ab310dc6a79ae1358e7f70b838b1afddd7cda3` (PR #19730) — 2026-03-24; follow-up `3fc8c8ad1549445bdbee001c50779d096ed1886c` (PR #20167) — 2026-04-22 |
| **Vulnerable since** | The `cannon-builder:v1.0.0` image, which ships the bad spec. The miscompilation was observed in CI in March 2026 (issue #19654) |

## Brief / Intro

The kona fault-proof program is compiled for a MIPS64 virtual machine (Cannon). The on-chain dispute game replays it instruction by instruction, so the compiled binary (the "absolute prestate") must behave exactly like the source code. kona uses a custom target description for this. One field, `target-c-int-width`, was set to 64, but the MIPS64 n64 ABI defines C `int` as 32 bits. LLVM relies on that field when it lowers `memcmp`, and it produced code in which comparing two strings always returned "not equal". A kona program built this way cannot, for example, deserialize its built-in chain list, and it panics. If such a binary had been adopted as a game's prestate, the game would reject every proposal. It was found and fixed in CI before any such prestate was adopted, as far as the repository shows.

## Vulnerability Details

Parent `rust/kona/docker/cannon/mips64-unknown-none.json:8`:

```json
"target-pointer-width": 64,
"target-c-int-width": 64,
"llvm-abiname": "n64",
```

Rust's `str` / `[u8]` equality lowers to a `memcmp` call whose C return type is `int`. With the spec saying `int` is 64 bits while the n64 ABI (and the `memcmp` implementation) return a 32-bit value, LLVM mis-types the call result. It then eliminates the branch on the comparison, so `a == b` for strings always evaluates to `false` (commit message of `04ab310dc6`, reproducer https://github.com/ajsutton/rust-mips64-str-miscompile).

The symptom was tracked in issue #19654 (see commit `2fce604bbe`, "capture kona prestate debug artifacts"): the kona guest panicked deserializing `chainList.json` with ``missing field `name` ``, even though the file was valid. serde matches field names by string equality, so no field ever matched.

Before the fix, the reproducible prestate build did not even use the in-repo spec. `cannon-repro.dockerfile` built inside `cannon-builder:v1.0.0`, which has its own baked copy at `/mips64-unknown-none.json` with the same wrong value.

Fix (`04ab310dc6`):

```diff
-  "target-c-int-width": 64,
+  "target-c-int-width": 32,
```

```dockerfile
# Override the target spec baked into the cannon-builder image (which has
# target-c-int-width: 64) with the corrected one from the source tree.
COPY kona/docker/cannon/mips64-unknown-none.json /mips64-unknown-none.json
```

Follow-up (`3fc8c8ad15`): the `build-cannon-client` and `lint-cannon` just recipes (used by the `kona-host-client-offline-cannon` CI job) ran the baked image directly. They now bind-mount the corrected spec over `/mips64-unknown-none.json`.

### Attack scenario

There is no attacker; this is a build-integrity defect. The dangerous sequence would be:

1. A kona prestate is built with the affected image and toolchain and published.
2. Governance or a chain operator adopts that prestate for a cannon-kona game type (via OPCM `updatePrestate`).
3. Every execution of the program panics during boot. Honest challengers running the same prestate in Cannon get a panic final state for every claim. Any proposal, valid or not, can then be countered, and the counter wins at the leaf step.
4. The result: proposer bonds lost, and withdrawals relying on that game type cannot finalize (liveness failure). Invalid proposals are also rejected, so there is no direct theft.

## Impact Details

- The miscompile is not subtle. It breaks every string comparison and makes the program panic at start-up, so any prestate test run catches it: CI did, `kona-host-client-offline-cannon`, and prestate verification with `check-prestate`.
- I found no evidence in the repository that an affected prestate was adopted on a live chain. Adopting a prestate is a governance or operator action, which is a trusted role.
- The general class is serious, because a subtle miscompile of the fault-proof program could silently make it disagree with the canonical chain. That justifies recording the issue, but the concrete instance was self-revealing.
- **Severity:** Informational.

## Proof of Concept

**Executed: no.** It needs the cannon-builder Docker image and a MIPS64 toolchain.

A self-contained reproducer is maintained at https://github.com/ajsutton/rust-mips64-str-miscompile. A minimal equivalent:

```rust
// src/main.rs of a #![no_std] #![no_main] crate built for mips64-unknown-none
#[inline(never)]
#[unsafe(no_mangle)]
pub fn eq(a: &str, b: &str) -> bool { a == b }
```

```sh
# Inside us-docker.pkg.dev/oplabs-tools-artifacts/images/cannon-builder:v1.0.0
# 1) Buggy spec (target-c-int-width: 64, as baked into the image):
cargo rustc -Zbuild-std=core,alloc -Zjson-target-spec \
  --target /mips64-unknown-none.json --release -- --emit asm
# Inspect `eq`: the result of the memcmp call is not branched on; `eq("a","a")` returns 0.
# 2) Corrected spec (target-c-int-width: 32, rust/kona/docker/cannon/mips64-unknown-none.json):
#    the same build branches on memcmp's return value and returns 1.
```

End-to-end: build `kona-client` for cannon from `04ab310dc6^` (`just build-cannon-client` in `rust/kona`) and run it offline in cannon (`just run-client-cannon-offline …` in `rust/kona/bin/client`). The guest panics with ``missing field `name` `` while loading the chain registry. With `3fc8c8ad15` the same run completes.

## Recommendation

The fix corrects the spec and forces every build path to use the in-tree copy. Further hardening:

- Rebuild and republish the cannon-builder image with the corrected spec, and stop relying on overrides. The later refactors `96479f8432` and `035d27eb6f` move in this direction.
- Add a smoke test to the prestate pipeline that runs the MIPS ELF on a trivial known-good input in Cannon and requires exit code 0 before any prestate is published.
- Treat target-spec and toolchain changes to the FPP build as consensus-critical in review.

## References

- Fix commits: `04ab310dc6a79ae1358e7f70b838b1afddd7cda3`, `3fc8c8ad1549445bdbee001c50779d096ed1886c`
- Pull requests: https://github.com/ethereum-optimism/optimism/pull/19730, https://github.com/ethereum-optimism/optimism/pull/20167
- Symptom: https://github.com/ethereum-optimism/optimism/issues/19654
- Reproducer: https://github.com/ajsutton/rust-mips64-str-miscompile
- Relevant files: `rust/kona/docker/cannon/mips64-unknown-none.json`, `rust/kona/docker/fpvm-prestates/cannon-repro.dockerfile`, `rust/kona/justfile`
