# Aurora Production Maturity Design

## Objective

Move Aurora from a conformance-focused prototype to an audit-ready, deployable
system with a real data plane, bounded resource use, native Apple integration,
repeatable releases, and evidence for every production gate in the current
protocol specification.

Production readiness is not self-certified. Independent cryptographic,
traffic-analysis, active-probe, abuse/legal, platform-security, and deployment
reviews remain mandatory release gates. The repository must produce the code,
artifacts, measurements, and review packages those gates require.

## Current State

Aurora already has broad deterministic protocol coverage, real cryptographic
vectors, negative vectors, replay checks, route and flow state machines,
cover-origin behavior, Linux TUN plumbing, an Apple Network Extension, and
cross-platform build gates. The current production path is incomplete:

- the server creates a harness issuer instead of loading independently managed
  production services and keys;
- packet transport is a request/response carrier exchange rather than a
  persistent authenticated Aurora session;
- the native ABI exposes issuance codec operations but not client/session,
  stream, datagram, packet, path-change, or event lifecycles;
- the Apple packet tunnel therefore does not run the complete portable session
  engine;
- performance checks are deterministic policy simulations, with no Go
  benchmarks, allocation budgets, sustained-load tests, or RSS evidence;
- race tests pass locally, but race, coverage, fuzz, vulnerability, and artifact
  security gates are not all enforced in CI;
- only one implementation currently produces the protocol behavior, so
  independent interoperability is not yet proven.

## Decision

Use a measured hybrid migration.

1. Keep the existing Go implementation as the conformance oracle and initial
   server implementation.
2. Keep Swift as the native Apple application and entitlement boundary.
3. Freeze a versioned, ownership-safe C ABI for portable session operations.
4. Build the real persistent data plane and production server composition
   behind explicit interfaces.
5. Introduce Rust only behind the frozen ABI and only after the benchmark suite
   can prove that a candidate component improves memory use, latency, safety, or
   portability without changing protocol bytes.

An immediate rewrite is rejected because it would discard tested protocol
behavior before an interoperable production path exists. An indefinite Go-only
policy is also rejected because the mobile archive, long-lived session state,
and cross-language ownership boundary need stronger memory and lifecycle
guarantees. Rust becomes authoritative component by component after byte-level
parity, differential tests, and measured benefit are demonstrated.

## Target Architecture

### Portable Protocol Core

The portable core owns canonical encoding, cryptography, handshake and route
state, replay inputs, packet protection, flow scheduling, and transport-neutral
session events. It exposes no platform handles and never logs secret-bearing
objects.

The core is accessed through an opaque-handle ABI:

```text
client create -> configure -> connect -> poll events -> close
session feed carrier bytes -> emit carrier bytes
session open stream -> send stream bytes -> half/full close
session send datagram -> receive datagram event
session feed packet batch -> receive packet batch event
session path changed -> adaptation event
```

Inputs are borrowed for the duration of a call. Outputs are owned buffers with
one allocator/free pair. Handles are generation-tagged, cannot be reused after
close, and return structured status codes rather than panicking across the ABI.

### Native Platform Adapters

Swift owns Network Extension APIs, keychain access, app-group persistence,
URLSession/NWConnection transport integration, lifecycle notifications, and UI.
It does not encode protocol objects, spend tokens directly, or maintain packet
keys. Linux owns TUN setup, process lifecycle, sockets, and service integration
under the same rule. Other platform adapters follow the same event contract.

### Transport Layer

The baseline transport is a persistent HTTP/2 stream with ordinary origin
behavior on every unauthenticated or malformed path. HTTP/1 WebSocket is the
required fallback. HTTP/3 datagrams remain feature-gated until their cover
template, path behavior, and impairment tests pass.

Transport adapters carry opaque core bytes and expose backpressure, cancellation,
timeouts, path changes, and close reasons. They do not bypass handshake,
admission, replay, packet protection, or flow scheduling.

### Server Composition

Production server construction is separate from harness construction. The
server receives explicit implementations for:

- signed directory, relay, issuer, and cover metadata;
- atomic replay and spent-hint storage;
- issuer or verifier service clients;
- relay session and route forwarding;
- destination TCP/UDP egress with policy enforcement;
- cover-origin proxying;
- rate limiting and overload control;
- redacted diagnostics, metrics, and graceful shutdown.

Harness constructors remain test-only fixtures and cannot be selected by a
production build profile.

## Maturity Stages

### Stage 1: Evidence Floor

Add representative benchmarks for wire encoding, cryptographic operations,
handshake setup, packet seal/open, flow scheduling, replay inserts, carrier
encoding, and live server exchange. Record time, bytes, and allocations. Add
repeatable load and soak commands that report throughput, latency percentiles,
RSS, heap, goroutine count, and error totals without recording secrets.

CI must enforce race tests, coverage reporting, fuzz smoke tests for every
registered fuzz target, dependency vulnerability scanning, and benchmark
compile/run health. Performance regression evaluation compares like-for-like
runners and rejects a median regression greater than 5 percent or any new hot
path allocation unless explicitly reviewed with evidence.

### Stage 2: Real Single-Hop Session

Compose the existing handshake, admission, replay, packet, and flow packages
into one long-lived client and relay session. Run it over a persistent HTTP/2
carrier, forward real TCP streams and UDP datagrams, enforce backpressure, and
exercise TUN traffic without the packet-batch loopback shortcut.

The stage completes only when a process-level client and relay exchange traffic,
rotate keys, reject replay, survive cancellation and malformed input, and pass a
sustained impairment run.

### Stage 3: Stable Native ABI and Apple Data Plane

Replace the issuance-only dispatch ABI with opaque client/session handles and
typed event polling. Swift drives the same portable session used by Linux. The
Network Extension must connect, reconnect, react to network changes, process
packet batches with bounded buffering, and terminate without leaked tasks or
handles.

The stage requires simulator tests, signed-device test instructions, ABI misuse
tests, leak checks, and end-to-end packet flow against a real relay fixture.

### Stage 4: Production Server Services

Split relay, issuer, directory, and optional cover-sidecar processes into
independently configured services. Replace append-only single-node replay state
with an atomic transactional backend suitable for multiple relay workers. Add
key rotation, metadata publication, health/readiness separation, shutdown drain,
rate limiting, resource limits, and operator-safe diagnostics.

### Stage 5: Routes, Fallbacks, and Platform Coverage

Run split-route traffic through independent entry and exit processes. Complete
HTTP/1 WebSocket fallback and validate optional HTTP/3 behavior. Add production
adapters and build/runtime matrices for each supported operating system. A
platform is advertised only after its local interface, DNS, lifecycle, update,
and failure behavior passes the shared conformance suite on real hardware or a
documented equivalent environment.

### Stage 6: Rust Component Migration

Build a Rust implementation behind the frozen ABI, beginning with the
allocation-sensitive wire/packet/session path. Differential tests feed both
implementations every structural, real-crypto, negative, fuzz, and state-machine
case and require byte-identical outputs or identical failure classes.

A Rust component replaces its Go counterpart only when it:

- passes all differential and interoperability gates;
- does not weaken the selected audited cryptographic backend;
- reduces peak memory or hot-path allocations, or improves throughput/latency by
  at least 15 percent on two supported architectures;
- preserves reproducible builds and the stable ABI;
- has no unresolved high or critical security finding.

### Stage 7: Release and External Gates

Produce reproducible signed artifacts, SBOMs, provenance, update metadata,
rollback procedures, incident-response exercises, deployment manifests, and
review packages. Production labeling remains blocked until all independent
reviews and real deployment assessments return acceptable findings.

## Error and Resource Model

- Every network, storage, parsing, and cryptographic operation has a context or
  deadline and supports cancellation.
- Queues are bounded in packets and bytes. Overflow follows the selected flow
  priority and stale-datagram policy rather than growing memory.
- Input sizes are checked before allocation. Decoders reject trailing bytes,
  reserved values, integer overflow, and inconsistent nested lengths.
- Replay-store uncertainty, verifier unavailability, and key ambiguity fail
  closed using cover-neutral behavior.
- Session shutdown is idempotent and drains or cancels owned tasks exactly once.
- Secrets use the narrowest practical lifetime, are excluded from diagnostics,
  and are zeroized where the language and backend provide a reliable primitive.

## Testing Strategy

Each behavior change follows a failing-test-first cycle. The shared hierarchy is:

1. canonical and negative unit vectors;
2. property and fuzz tests;
3. differential implementation tests;
4. process-level client/server integration tests;
5. deterministic impairment tests;
6. sustained load, race, leak, and resource-bound tests;
7. platform build and runtime smoke tests;
8. signed-device and deployment tests;
9. independent interoperability and external review.

Synthetic evidence cannot satisfy a real deployment or independent review gate.
Every release claim names the command, artifact, environment, and current result
that proves it.

## First Execution Slice

The first implementation plan covers Stage 1 and the prerequisites for Stage 2:

- add benchmark and allocation coverage for the actual protocol hot paths;
- add a bounded process-level load harness around the live server carrier;
- measure the existing packet exchange and expose its limitations explicitly in
  machine-readable results;
- enforce race, coverage, fuzz-target inventory, and vulnerability checks in CI;
- define the production session interfaces and ownership contract without yet
  replacing working protocol primitives;
- convert the next plan into a real persistent single-hop session rather than
  extending the loopback carrier shortcut.

This ordering establishes evidence before optimization and freezes the boundary
needed for a safe Rust migration while directly advancing the real data plane.
