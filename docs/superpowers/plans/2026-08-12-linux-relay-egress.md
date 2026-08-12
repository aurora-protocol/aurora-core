# Linux Relay Egress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn authenticated proxy-flow sessions into bounded TCP and UDP destination traffic, compose that egress per live first-hop session, and replace the daemon's harness-only serving path with an explicit production construction boundary.

**Architecture:** `relay.ExitSession` remains the sole inbound frame validator and converts validated frame blocks into `ExitFrameEvent` values. A per-session `relay.SocketEgress` owns destination sockets, read pumps, target resolution, flow limits, and backward frame delivery through the established application queue. `server.FirstHopHandler` constructs the frame handler only after authenticated policy selection and closes it with the carrier. Production command composition accepts verified dependencies and can never fall back to harness packet exchange.

**Tech Stack:** Go 1.25.12, `context`, `net`, `net/netip`, existing protocol/flow/relay/session/transport packages, TLS 1.3 HTTP/2, Go race detector, fuzzing, benchmarks, and cross-platform compilation.

## Global Constraints

- Do not add a protocol specification version to core code, comments, filenames, logs, or documentation.
- Do not add names, code, comments, or documentation references from external inspiration projects.
- Add no module dependency; use the standard library and existing packages.
- Apply exit policy before every dial, including every address returned for a domain.
- IP-authoritative UDP modes never invoke a resolver. Domain UDP targets resolve only in the explicit relay-resolved mode.
- Do not pass target names, addresses, payloads, client addresses, keys, proofs, or nonces to public errors or stable diagnostics.
- Bound sessions, flows, per-flow read buffers, datagrams, queue retries, dial time, write time, idle time, and shutdown time.
- Every socket and goroutine belongs to one session context and is joined during idempotent close.
- Preserve the harness as a test/readiness surface only. Production constructors must reject test exchangers, memory replay stores, missing cover origin, or missing authenticated dependencies.
- Preserve the user-owned untracked `route/zz_dump_conf_test.go` in the main checkout.

---

## File Map

- `relay/egress.go`: validated-event interface, frame sink, session adapter, and bounded queue retry.
- `relay/egress_test.go`: adapter ordering, cloning, close, backpressure, and terminal-error tests.
- `relay/socket_egress.go`: target selection, TCP/UDP sockets, read pumps, limits, and lifecycle.
- `relay/socket_egress_test.go`: loopback TCP/UDP, DNS authority, policy, limits, half-close, idle, and shutdown tests.
- `server/first_hop.go`: authenticated per-session handler factory and lifecycle handoff.
- `server/first_hop_test.go`: factory validation, selected-policy handoff, error ordering, and close tests.
- `server/first_hop_integration_test.go`: encrypted TLS/H2 traffic through real loopback destinations.
- `server/production.go`: production first-hop options and strict server composition.
- `server/production_test.go`: missing-dependency, TLS, cover, policy, replay, and shutdown tests.
- `cmd/aurorad/main.go`: explicit `harness` and `serve` subcommands with production-only serve dependencies.
- `cmd/aurorad/main_test.go`: process argument validation and no-harness-fallback tests.
- `evidence/egress.go`: bounded non-sensitive TCP/UDP/session evidence.
- `evidence/egress_test.go`: evidence success and failure tests.
- `perf/egress_benchmark_test.go`: steady-state TCP/UDP throughput and allocation baselines.

---

### Task 1: Validated Egress and Session Contracts

**Files:** Create `relay/egress.go`; create `relay/egress_test.go`; modify `relay/relay.go` only where an owned event snapshot or local-close transition is required.

- [x] **Step 1: Write failing contract tests**

Define fakes for `FrameSink` and `Egress`. Assert that malformed or policy-denied blocks never reach egress, event payloads are owned copies, flow-open socket work completes before confirmations are queued, inbound block order is serialized, queue backpressure waits without spinning, cancellation interrupts waiting, and close is idempotent and joins egress.

- [x] **Step 2: Implement the minimum public contracts**

Use these shapes unless a test proves a narrower API is required:

```go
type FrameSink interface {
	QueueFrames(context.Context, protocol.FrameBlock) error
}

type Egress interface {
	HandleEvent(context.Context, ExitFrameEvent) ([]protocol.AuroraFrame, error)
	Close() error
}

type ExitSessionOptions struct {
	Policy             ExitPolicy
	RateLimit          ExitRateLimit
	UDPConfirmTTL      uint32
	QueueRetryInterval time.Duration
}
```

`NewExitSession` owns a validator, egress, and sink. `HandleFrameBlock` validates synchronously, invokes egress in frame order, then queues immediate confirmations in one backward block. It retries only `session.ErrBackpressure` on a bounded timer and returns cancellation or terminal sink errors unchanged.

- [x] **Step 3: Verify and commit**

Run `go test ./relay -run 'TestExitSession' -count=20` and `go test -race ./relay -run 'TestExitSession' -count=5`. Commit `feat: add validated relay egress sessions`.

---

### Task 2: Target Selection and Resource Limits

**Files:** Create `relay/socket_egress.go`; create `relay/socket_egress_test.go`.

- [x] **Step 1: Write failing target and constructor tests**

Cover nil context/sink/dialer/resolver, invalid limits, duplicate and zero flow IDs, maximum flows, IPv4/IPv6 formatting, domain canonicalization, resolver cancellation, empty answers, mixed public/private answers, all-denied answers, and deterministic selection. Assert an IP-authoritative UDP flow makes zero resolver calls.

- [x] **Step 2: Implement strict options and resolution**

Add `SocketEgressLimits` with nonzero normalized defaults and hard maxima for flows, TCP read bytes, UDP datagram bytes, dial/write/idle durations, and queue retry interval. Inject narrow `ContextDialer` and `IPResolver` interfaces. Resolve domain targets once, filter every answer through `ExitPolicy`, sort canonical `netip.Addr` values, choose deterministically, and dial the literal selected address. Return stable sentinel errors without target text.

- [x] **Step 3: Verify and commit**

Run `go test ./relay -run 'TestSocketEgress(Target|Options|Policy|Limits)' -count=20` and the race equivalent. Commit `feat: bound relay destination selection`.

---

### Task 3: TCP Destination Egress

**Files:** Modify `relay/socket_egress.go`; modify `relay/socket_egress_test.go`.

- [x] **Step 1: Write failing loopback TCP tests**

Use an injected policy that permits test loopback. Cover bounded dial, ordered writes, partial writes, write deadlines, destination-to-backward `STREAM_DATA`, EOF-to-`FLOW_CLOSE`, normal peer close with `CloseWrite`, reset close, duplicate close, blocked destination, per-flow buffer bounds, flow limit release, and session cancellation while dialing/reading/writing.

- [x] **Step 2: Implement one owned TCP flow object**

Create the socket during `ExitEventFlowOpened`, insert only after successful dial and final cancellation checks, then start exactly one bounded read pump. Serialize writes, refresh idle deadlines, retain at most one configured read buffer per flow, queue backward frames with bounded retry, and remove/close each flow exactly once. Normal peer close half-closes when supported and allows the read side to drain; terminal/reset/resource closes release immediately.

- [x] **Step 3: Stress lifecycle and commit**

Run focused tests 100 times and race tests 20 times, including a goroutine-count stabilization assertion after repeated open/close. Commit `feat: relay tcp proxy flows`.

---

### Task 4: UDP Association Egress

**Files:** Modify `relay/socket_egress.go`; modify `relay/socket_egress_test.go`.

- [x] **Step 1: Write failing loopback UDP tests**

Cover connected IP targets, datagram request/response, stream-fallback request data, response demultiplexing, authoritative-IP confirmation, relay-resolved confirmation, DNS answer hash, selected resolution source, datagram maximum, idle expiry, TTL expiry, address immutability, policy denial after resolution, duplicate close, and cancellation.

- [x] **Step 2: Implement connected UDP associations**

Dial `udp4` or `udp6` to the selected literal address. Accept only `DATAGRAM_DATA` and the defined encrypted stream fallback for UDP flows. Return `UDP_TARGET_CONFIRM` only after the connected socket exists; relay-resolved flows include the selected address, bounded TTL, canonical answer-set hash, and relay resolution source. One read pump emits backward datagram frames and closes idle or expired associations with an encrypted close frame.

- [x] **Step 3: Verify and commit**

Run focused tests 100 times, race tests 20 times, and cross-compile relay tests for Linux, Windows, macOS, and Android. Commit `feat: relay udp proxy associations`.

---

### Task 5: Per-Session First-Hop Composition

**Files:** Modify `server/first_hop.go`; modify `server/first_hop_test.go`; modify `server/first_hop_integration_test.go`.

- [x] **Step 1: Write failing factory and lifecycle tests**

Add a `FirstHopSessionFactory` receiving the authenticated application and selected `PolicyAccept`. Require exactly one static test handler or session factory. Assert the factory is never called before successful Finished/policy verification, sees an owned selected policy, fails before Capsule2 release, closes after duplex on every error/cancel/shutdown path, and rejects non-proxy personalities in the production egress factory.

- [x] **Step 2: Preserve policy from relay Finish and install the handler**

Change the private finish result to retain Capsule2, `*session.Application`, and selected policy. Build the per-session frame handler after Finish and before Capsule2 is written. Defer its closer before entering `RunPacketDuplex`. Keep the existing static handler path for focused transport tests, but do not expose it through production construction.

- [x] **Step 3: Run tests and commit**

Run all first-hop tests, 50 repeated live tests, and race tests for `server`, `relay`, `session`, and `transport`. Commit `feat: compose relay egress per session`.

---

### Task 6: Encrypted End-to-End Destination Tests

**Files:** Modify `server/first_hop_integration_test.go`; create `evidence/egress.go`; create `evidence/egress_test.go`.

- [x] **Step 1: Add real TLS/H2 TCP and UDP paths**

Generate fresh handshake material, establish a live client and relay application, open a TCP echo flow and a UDP echo association through encrypted packets, and assert byte-identical bidirectional data. Exercise key updates while flows are open, target EOF, policy denial, stalled target cancellation, and server shutdown.

- [x] **Step 2: Add bounded evidence**

Report only pass flags, counts, durations, queue peaks, flow peaks, and byte totals. Do not retain destinations or protocol material. Run success repeatedly and assert all sockets, carriers, sessions, and servers close.

- [x] **Step 3: Verify and commit**

Run live integration 100 times, evidence 20 times, and race-enabled integration 10 times. Commit `test: prove encrypted destination egress`.

---

### Task 7: Production Server Construction Boundary

**Files:** Create `server/production.go`; create `server/production_test.go`.

- [ ] **Step 1: Write failing production-constructor tests**

Require verified deployment, relay driver, TLS identity, authority/path/binding metadata, cover origin, persistent replay dependencies already enforced by the driver, exit policy, egress limits, and session concurrency limits. Reject static handlers, harness origins/exchangers, missing TLS, loopback-only placeholders, dynamic TLS callbacks, and invalid limits.

- [ ] **Step 2: Implement owned production composition**

Build `FirstHopHandler`, per-session socket egress, an HTTP/2-only server, and a semaphore-backed session cap from one immutable options snapshot. Expose `Serve(net.Listener)` and bounded `Shutdown(context.Context)` ownership without logging secrets or destinations. Keep harness constructors in their existing files and out of this API.

- [ ] **Step 3: Verify and commit**

Run production server tests 50 times and race tests 10 times. Commit `feat: add production relay server composition`.

---

### Task 8: Daemon Production Mode

**Files:** Modify `cmd/aurorad/main.go`; modify `cmd/aurorad/main_test.go`; add narrowly scoped production dependency loaders only when canonical parsing and secret ownership can be tested.

- [ ] **Step 1: Split harness and production command surfaces**

Keep readiness under an explicit `harness` subcommand. Add a `serve` subcommand that requires a production configuration and refuses every harness packet mode and synthetic credential path. Preserve exit code `2` for configuration errors and `1` for runtime failures.

- [ ] **Step 2: Add strict startup and shutdown tests**

Cover missing files, permission failures, malformed canonical objects, mismatched signing keys, non-durable stores, missing cover origin, incomplete TLS, signal cancellation, listener failure, and clean shutdown. Secret files must be read with restrictive permission checks and destroyed from owned byte slices where practical.

- [ ] **Step 3: Implement only verified loaders and commit**

Use canonical protocol decoders and explicit signer/verifier/store constructors; do not invent a permissive generic JSON representation for cryptographic structures. If a required production dependency has no real implementation, add and test that implementation in its owning package before wiring the command. Commit in dependency-sized slices, then commit `feat: run production relay service` once a separate process test passes.

---

### Task 9: Performance, Full Review, and Integration

**Files:** Create `perf/egress_benchmark_test.go`; modify only files required by findings; update this plan as steps complete.

- [ ] **Step 1: Benchmark and profile**

Measure TCP and UDP steady-state bytes, operations, allocations, queue peaks, flow peaks, goroutines, and process RSS at 1, 64, and configured-maximum concurrent flows. Profile retained memory and remove avoidable copies without weakening ownership.

- [ ] **Step 2: Run full gates**

Run formatting, `go test ./...`, lab tests, `go test -race ./...`, vet, staticcheck, vulnerability scanning, repository coverage, focused stress, and Linux/Windows/macOS/Android cross-compilation. Run record/frame fuzz targets and new egress-event fuzz targets for at least 10 seconds each.

- [ ] **Step 3: Independent P0-P3 reviews**

Request one security/policy/DNS review and one concurrency/resource/portability review. Add a failing regression test for every actionable finding, fix it, rerun focused and full gates, and repeat until both report no P0-P3 findings.

- [ ] **Step 4: Hygiene, push, and remote CI**

Scan changed files and commits for forbidden version text, external-project references, user identity/paths, unfinished-work markers, secret-bearing logs, and AI attribution. Push the draft branch, mark ready only after all gates, fast-forward `main` while preserving the untracked route test, and watch exact public CI through completion.
