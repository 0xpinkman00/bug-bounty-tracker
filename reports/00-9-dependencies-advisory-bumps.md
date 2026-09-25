# Dependency security bumps, 2026-07 to 2026-09 (informational roll-up)

| Field | Value |
|---|---|
| **Target** | Go module graph (`go.mod`, Go toolchain, builder images) and Rust workspaces (`rust/Cargo.lock`, `rust/op-rbuilder`, `rust/rollup-boost`, `rust/kona/sp1/programs`) |
| **Asset type** | Blockchain/DLT (node and service binaries) |
| **Severity** | Informational. At most Low for cf871a7311 (hickory-proto through libp2p in kona-node) |
| **Impact category** | None shown. These fix known third-party advisories, and we found no in-repo exploit path |
| **Fix commit(s)** | See table |
| **Vulnerable since** | Varies per dependency |

## Brief / Intro

Between July and September 2026 the monorepo took a series of dependency upgrades labelled `[SECURITY]` or tied to scanner findings (Grype, cargo-deny / RustSec, Renovate). These fix bugs in *third-party* code: the Go standard library, QUIC, WebRTC, compression and DNS libraries, OpenSSL bindings and others. This report lists each one and gives a quick judgement of whether an external attacker could plausibly reach the vulnerable code in an OP Stack binary. None of them came with an OP-specific proof of exploitability. The one most likely to matter is the hickory-proto DNS library removal in cf871a7311, because kona-node's libp2p stack pulled it in.

## Vulnerability Details

"Reachable?" is our judgement from the dependency graph and how the code is used. We did not reproduce any advisory. Where a commit does not name the advisory, we say so rather than guess.

| Fix commit (PR, date) | Crate / module (old → new) | Advisory ID(s) | Plausibly reachable by an external party? |
|---|---|---|---|
| cf871a7311519bc23182c9ea8239337b276c42b7 (#22714, 2026-09-02) | `libp2p` 0.56.0 → git rev `efc2bfc1`; removes `hickory-proto` / `hickory-resolver` 0.25.2 (only 0.26.1 remains); `yamux` 0.13.10 → 0.14.0 | RUSTSEC-2026-0118 (hickory-proto < 0.26.1, NSEC3 closest-encloser DNSSEC validation unbounded loop), RUSTSEC-2026-0119 (hickory-proto < 0.26.1, O(n²) name-compression CPU exhaustion in `BinEncoder`). Both were removed from the `deny.toml` ignore list | **Low / possible.** At the parent, `hickory-proto 0.25.2` was used only by `libp2p-dns` and `libp2p-mdns`, which is the kona-node gossip stack. The `deny.toml` comment blamed reth dns-discovery, but reth was already on 0.26.1. -0118 needs DNSSEC validation, which libp2p-dns does not enable by default. -0119 is on the encode side. Either would need a malicious DNS server or response on the resolution path of a `/dns` multiaddr. A kona-node that resolves attacker-supplied DNS bootnodes or peers is the most plausible exposure. kona-node was pre-production |
| 26eb47fc8a26c1a270d671aa25c58eaf14d026b8 (#21854, 2026-07-16) | Go toolchain 1.26.4 → 1.26.5 (all Go service images); `quic-go` v0.59.0 → v0.59.1; `openssl` crate 0.10.77 → 0.10.81; `serde_with` 3.18/3.17 → 3.21.0 | Go: CVE-2026-39822 (High), CVE-2026-42505 (Medium). quic-go: GHSA-vvgj-x9jq-8cj9. openssl: GHSA-8c75-8mhr-p7r9, GHSA-ghm9-cr32-g9qj, GHSA-hppc-g8h3-xhp3, GHSA-pqf5-4pqq-29f5, GHSA-xp3w-r5p5-63rr (High), GHSA-phqj-4mhp-q6mq, GHSA-xv59-967r-8726 (Medium), GHSA-xmgf-hq76-4vx2 (Low). serde_with: GHSA-7gcf-g7xr-8hxj | **Go stdlib: possibly.** The commit does not name the affected stdlib packages, but every Go service exposes `net/http` RPC and p2p. **quic-go: possibly.** It is the QUIC transport in op-node's go-libp2p, if QUIC listening is enabled. **openssl: unlikely.** In `rust/Cargo.lock` at the parent, the direct dependents are `kona-gossip`, which uses only `openssl::sha::sha256` for gossip message IDs (`gossip/src/config.rs:5`), and `native-tls`, which reaches it through `hyper-tls` / `alloy-transport-http` for outbound HTTPS to operator-configured RPC endpoints. The SHA-256 wrapper does see attacker bytes. We did not check whether any of the listed GHSAs affects `openssl::sha`. The TLS client side only talks to trusted endpoints. **serde_with: unlikely.** Config and RPC deserialisation of trusted input |
| 93d10d7ec9e956ed8340b015828b2d8276175aee (#22500, 2026-08-19) | `opentelemetry*` 0.31 → 0.32 (rollup-boost 0.28 → 0.32), `tracing-opentelemetry` 0.29 → 0.33, `lru` 0.16.3 → 0.18.2 across the main, op-rbuilder and rollup-boost workspaces | Not stated in the commit ("Roll up Rust dependency fixes") | **Unlikely.** Telemetry export goes to an operator-configured collector. `lru` is internal caching |
| eea9542814bdb8784a4d8d8628b31d19f2af4129 (#22750, 2026-09-03) | `golang.org/x/crypto` v0.55.0 → v0.56.0 | Not stated (Renovate `[SECURITY]`) | **Unlikely.** In-repo non-test code imports only `x/crypto/sha3`. Transitive users (go-libp2p noise/tls, ssh) depend on which subpackage the advisory covers |
| 24c58a79b502f00782a5181f16acfeac63229e30 (#22425, 2026-08-17) | `golang.org/x/mod` v0.38 → v0.40, plus `x/crypto` 0.53 → 0.55, `x/net` 0.56 → 0.58, `x/sys`, `x/term`, `x/text` 0.39 → 0.41, `x/tools` | Not stated | **Possible for `x/net`** (HTTP/2 and HTML parsing in RPC servers). `x/mod` and `x/tools` are build tooling only |
| 41a370b67dee7f74a83b3d3862375b687546ac3b (#22067, 2026-07-28) | `golang.org/x/text` v0.38.0 → v0.39.0 | Not stated | Unlikely. Indirect dependency |
| 6998f9e8f98a27381d143c37c923e4166a48ab91 (#22435, 2026-08-18) | `golang.org/x/image` v0.43.0 → v0.45.0 (indirect) | Not stated | **No.** No image decoding of untrusted input in services |
| 611e84758ba8c659a165c8877a7626f6ab2a1e06 (#22424, 2026-08-17) | Go toolchain 1.26.5 → 1.26.6 (`go.mod`); 1.25.12 → 1.25.13 (`cannon/testdata/common/go.mod`) | Not stated | Possibly (stdlib, same reasoning as 26eb47fc8a). The cannon testdata module is test-only |
| aeb240dad30cf1c601c4b7c608f10c434d790cae (#22065, 2026-07-28) | Go toolchain 1.24.10 → 1.25.12 in `cannon/testdata/common/go.mod` only | Not stated | **No.** Test programs only |
| a15fe1febad3afaf07366ab3b6518049dfe81cb0 (#22179, 2026-08-13) | `pion/stun/v3` v3.0.0 → v3.1.5, `pion/dtls/v3` v3.0.11 → v3.1.4, `pion/transport/v4` v4.0.1 → v4.0.2 (indirect, via go-libp2p WebRTC) | Not stated | **Unlikely.** Only reachable if an op-node p2p WebRTC transport is enabled. op-node uses TCP by default |
| a3de6abac3aeee8f2c8a75c76df70cb734d663a8 (#22180), 06680e2dc0d94e3a09028cd39165a9207f16d63b (#22069), d15bd5fffde4a0a0055502ce3dc36373f60ec9a3 (#22181), 2026-08-18 | `pion/stun` v0.6.1, `pion/dtls/v2` v2.2.12, `pion/stun/v2` v2.0.0 | Not stated | **No effective change.** Each diff removes and re-adds the *same* version line (a Renovate "major bump" that only moved the requirement within `go.mod`), so these commits fixed nothing |
| 2e04186bf651cc55972cc01c3070910f40a1c644 (#22066, 2026-07-28) | `quic-go/webtransport-go` v0.10.0 → v0.11.1; `quic-go` v0.59.1 → v0.60.0 | Not stated | **Possible only if** the go-libp2p WebTransport or QUIC listeners are enabled on op-node |
| e120125d933fa3221be7fd06d9be4aa4a043997d (#22064, 2026-08-13) | `klauspost/compress` v1.18.0 → v1.18.7 (direct) | Not stated | **Unlikely.** Direct users are `op-core/superchain` (embedded, trusted registry data), op-deployer artifact download (operator-chosen URL) and `op-preimage/hash.go`. Transitively it is used in go-libp2p and HTTP gzip. Batch/channel decompression in op-node uses zlib and brotli, not this library |
| ed6082c79c469379bed9409bd201109f3393a77b (#22254, 2026-08-13) | `rkyv` / `rkyv_derive` 0.8.16 → 0.8.17 (main and SP1 guest lockfiles) | Not stated | **Unlikely.** Zero-copy (de)serialisation of locally produced data |
| 165e2ba646c1958e3b87f0e8c55706b4b203d263 (#22962, 2026-09-21) | `imbl` 7.0.0 → 7.0.2, `imbl-sized-chunks` 0.1.3 → 0.2.0; drops `bitmaps` 3.2.1 | RUSTSEC-2026-0292 (imbl-sized-chunks, per the commit subject); also removes the ignore for RUSTSEC-2026-0247 (`bitmaps` unmaintained) | **Unlikely.** Used inside `reth-transaction-pool` data structures. A memory-safety bug in sized-chunks could in principle be reached through pool operations driven by peers, but no trigger is known |

### Attack scenario

None demonstrated. For the most plausible case (cf871a7311):
1. A kona-node is configured with, or learns, a `/dns4/...` peer multiaddr whose DNS resolution passes through an attacker-controlled resolver or zone.
2. The attacker's DNS response triggers the hickory-proto 0.25.2 CPU-exhaustion path.
3. The kona-node's resolver task spins, which slows or stalls peer discovery.

## Impact Details

These are hygiene updates. We found no in-repo path that makes any advisory exploitable in an OP Stack binary. The main exposure worth noting is kona-node's use of `hickory-proto` 0.25.2 through libp2p until 2026-09-02. Any effect would be local denial of service on a pre-production node. The three pion commits (a3de6abac3, 06680e2dc0, d15bd5fffd) were Renovate no-ops. The actual pion fix is a15fe1feba. **Informational.**

## Proof of Concept

None. Each advisory's upstream reproducer applies to the library itself. To check exposure at a given commit:

```bash
# Rust: which workspace crates pull the vulnerable version
cd rust && git show cf871a7311^:rust/Cargo.lock | grep -A1 'name = "hickory-proto"'
cargo tree -i hickory-proto@0.25.2 --locked   # at cf871a7311^: libp2p-dns, libp2p-mdns
cargo deny check advisories                   # at the parent commits, with the ignore entries removed

# Go: which binaries link a module
go version -m ./bin/op-node | grep -E 'quic-go|pion|x/net|klauspost'
govulncheck ./op-node/... ./op-batcher/... ./op-proposer/... ./op-challenger/...
```
Executed: partially. We inspected the lockfile and `go.mod` diffs, as quoted in the table. We did not run `cargo tree`, `cargo deny` or `govulncheck`.

## Recommendation

- Keep `cargo deny` advisory ignores tied to a tracking issue and an owner. The hickory ignore mis-attributed the dependency path (it said reth dns-discovery; the real path was libp2p), which delayed the right fix.
- Run `govulncheck` in CI in symbol mode, so that `[SECURITY]` bumps come with an answer to "is the vulnerable symbol reachable?".
- Configure Renovate so that "major-bump" PRs that do not change the resolved version (like the pion no-ops) are not labelled `[SECURITY]`.

## References

- Commits: cf871a7311, 26eb47fc8a, 93d10d7ec9, eea9542814, 24c58a79b5, 41a370b67d, 6998f9e8f9, 611e84758b, aeb240dad3, a15fe1feba, a3de6abac3, 06680e2dc0, d15bd5fffd, 2e04186bf6, e120125d93, ed6082c79c, 165e2ba646
- Pull requests: #22714, #21854, #22500, #22750, #22425, #22067, #22435, #22424, #22065, #22179, #22180, #22069, #22181, #22066, #22064, #22254, #22962 (https://github.com/ethereum-optimism/optimism/pull/<N>)
- Relevant files: `go.mod`, `go.sum`, `mise.toml`, `rust/Cargo.toml`, `rust/Cargo.lock`, `rust/deny.toml`, `rust/op-rbuilder/Cargo.lock`, `rust/rollup-boost/Cargo.lock`, `rust/kona/sp1/programs/Cargo.lock`
- Advisories: https://rustsec.org/advisories/RUSTSEC-2026-0118.html, https://rustsec.org/advisories/RUSTSEC-2026-0119.html, https://rustsec.org/advisories/RUSTSEC-2026-0292.html
