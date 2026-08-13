# Linux Local Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a runnable Linux client that securely establishes a provisioned Aurora session and serves local HTTP CONNECT and SOCKS5 TCP traffic through it.

**Architecture:** A reusable `client.ProvisionedSession` owns deferred relay authentication and issuer completion. `client.TCPProxyRuntime` translates local TCP proxy connections into authenticated proxy-flow frames and dispatches backward frames to the owning socket. `cmd/aurorac` composes the two, enforcing Linux host, loopback listener, and provisioning-file constraints.

**Tech Stack:** Go standard library, existing Aurora handshake/session/transport packages, Linux process and signal APIs.

**Spec:** `docs/superpowers/specs/2026-08-13-linux-local-proxy-design.md`

## Global Constraints

- Use the existing portable protocol implementation; command and listener code must not encode protocol messages or retain cryptographic state.
- Preserve the pinned carrier and validated provisioning path.
- Keep sensitive provisioning, issuer work, and frame contents out of logs.
- Bind loopback addresses by default and require an explicit opt-in for public listeners.
- Use TDD: add each behavior test, run it red, then add the smallest production change.
- Do not add a protocol or specification version string to code or documentation.
- Commit each independently testable task.

---

### Task 1: Reusable Provisioned Session

**Files:**
- Create: `client/provisioned_session.go`
- Create: `client/provisioned_session_test.go`
- Modify: `mobile/auroracore/session.go`
- Modify: `mobile/auroracore/session_test.go`

**Interfaces:**
- Produces `type IssuerWork struct { IssuerURL string; IssuerCarrierPath string; RequestBody []byte }`.
- Produces `func BeginProvisionedSession(ctx context.Context, provisioning NativeProvisioning, options ProvisionedSessionOptions) (*ProvisionedSession, IssuerWork, error)`.
- Produces `func (s *ProvisionedSession) Complete(ctx context.Context, issuerResponse []byte) (*handshake.EstablishedSession, error)` and `func (s *ProvisionedSession) Close() error`.
- `ProvisionedSessionOptions` supplies only clock, random source, handshake timeout, issuer lifetime, and issuer timeout for deterministic tests.

- [ ] **Step 1: Write the failing lifecycle tests**

```go
func TestProvisionedSessionIssuesOnlyAfterVerifiedPrelude(t *testing.T) {
    session, work, err := BeginProvisionedSession(context.Background(), fixtureProvisioning(t), testSessionOptions(t))
    if err != nil { t.Fatal(err) }
    defer session.Close()
    if work.IssuerURL == "" || len(work.RequestBody) == 0 { t.Fatal("issuer work was not produced") }
}

func TestProvisionedSessionRejectsSecondCompletion(t *testing.T) {
    session, work := establishedProvisionedSessionFixture(t)
    if _, err := session.Complete(context.Background(), issuerResponseFor(t, work)); err != nil { t.Fatal(err) }
    if _, err := session.Complete(context.Background(), issuerResponseFor(t, work)); err == nil { t.Fatal("second completion succeeded") }
}
```

- [ ] **Step 2: Run the lifecycle tests and verify they fail**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./client -run 'TestProvisionedSession' -count=1`

Expected: compile failure naming `BeginProvisionedSession` or `ProvisionedSession`.

- [ ] **Step 3: Implement the bounded deferred lifecycle**

```go
type ProvisionedSession struct {
    mu          sync.Mutex
    ctx         context.Context
    cancel      context.CancelFunc
    handshake   *handshake.ClientHandshake
    request     handshake.ClientProofRequest
    established *handshake.EstablishedSession
    closed      bool
}

func (s *ProvisionedSession) Complete(ctx context.Context, issuerResponse []byte) (*handshake.EstablishedSession, error) {
    // Decode the opaque issuer response, construct the replay proof, and
    // complete exactly one deferred handshake before releasing request state.
}
```

Clone and zero temporary proof material, enforce existing size limits, cancel abandoned work after the configured issuer timeout, and close the established session on failure. Move equivalent mobile lifecycle helpers to this API so the ABI path does not drift.

- [ ] **Step 4: Run focused tests**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./client ./mobile/auroracore -run 'TestProvisionedSession|TestNativeSession' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add client/provisioned_session.go client/provisioned_session_test.go mobile/auroracore/session.go mobile/auroracore/session_test.go
git commit -m "feat: share provisioned client session lifecycle"
```

### Task 2: TCP Local Proxy Runtime

**Files:**
- Create: `client/tcp_proxy_runtime.go`
- Create: `client/tcp_proxy_runtime_test.go`

**Interfaces:**
- Produces `type TCPProxyRuntimeOptions struct { MaxFlows int; ReadBufferBytes int; MaxPendingWriteBytes int }`.
- Produces `func NewTCPProxyRuntime(application *session.Application, options TCPProxyRuntimeOptions) (*TCPProxyRuntime, error)`.
- Produces `func (r *TCPProxyRuntime) Serve(ctx context.Context, listener net.Listener) error`.
- Produces `func (r *TCPProxyRuntime) HandleFrameBlock(ctx context.Context, block protocol.FrameBlock) error` for `transport.RunPacketDuplex`.
- Produces `func (r *TCPProxyRuntime) Close() error`.

- [ ] **Step 1: Write failing HTTP CONNECT forwarding tests**

```go
func TestTCPProxyRuntimeForwardsHTTPConnectBytes(t *testing.T) {
    runtime, application, carrier := newTCPProxyRuntimeFixture(t)
    conn := connectRuntime(t, runtime)
    fmt.Fprint(conn, "CONNECT target.example:443 HTTP/1.1\r\nHost: target.example:443\r\n\r\nhello")
    requireContains(t, readUntil(t, conn, "\r\n\r\n"), "200 Connection Established")
    requireFrame(t, carrier.NextClientFrame(), registry.FrameFlowOpen)
    requireStreamPayload(t, carrier.NextClientFrame(), []byte("hello"))
    carrier.SendRelayFrame(protocol.MustNewStreamDataFrame(flowID, []byte("world"), 0))
    requireEqual(t, readExactly(t, conn, 5), []byte("world"))
}
```

- [ ] **Step 2: Run the forwarding test and verify it fails**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./client -run TestTCPProxyRuntimeForwardsHTTPConnectBytes -count=1`

Expected: compile failure naming `NewTCPProxyRuntime`.

- [ ] **Step 3: Implement HTTP CONNECT and SOCKS5 TCP serving**

```go
func (r *TCPProxyRuntime) HandleFrameBlock(ctx context.Context, block protocol.FrameBlock) error {
    for _, frame := range block.Frames {
        switch frame.FrameType {
        case registry.FrameStreamData:
            r.writeToLocalFlow(frame.FlowID, frame.Payload)
        case registry.FrameFlowClose:
            r.closePeerFlow(frame)
        default:
            return fmt.Errorf("client: proxy runtime received unexpected relay frame")
        }
    }
    return nil
}
```

Use `LocalProxy.OpenTCPFrame`, `LocalProxy.SendTCP`, and `session.Application.QueueFrames` for all outbound messages. Allocate nonzero monotonic flow IDs, synchronize each connection write path, close and remove a flow exactly once, and do not queue any frame before a local handshake succeeds.

- [ ] **Step 4: Add and run failure-path tests**

```go
func TestTCPProxyRuntimeRejectsMalformedSOCKS(t *testing.T) {
    runtime, _, carrier := newTCPProxyRuntimeFixture(t)
    conn := connectRuntime(t, runtime)
    _, _ = conn.Write([]byte{0x05, 0x01, 0x02})
    requireConnClosed(t, conn)
    requireNoClientFrame(t, carrier)
}

func TestTCPProxyRuntimeClosesMappedConnectionsWhenCarrierEnds(t *testing.T) {
    runtime, _, _ := newTCPProxyRuntimeFixture(t)
    conn := openHTTPProxyFlow(t, runtime)
    if err := runtime.Close(); err != nil { t.Fatal(err) }
    requireConnClosed(t, conn)
}

func TestTCPProxyRuntimeEnforcesFlowLimit(t *testing.T) {
    runtime, _, carrier := newTCPProxyRuntimeFixtureWithOptions(t, TCPProxyRuntimeOptions{MaxFlows: 1})
    first := openHTTPProxyFlow(t, runtime)
    defer first.Close()
    second := connectRuntime(t, runtime)
    fmt.Fprint(second, "CONNECT target.example:443 HTTP/1.1\r\nHost: target.example:443\r\n\r\n")
    requireConnClosed(t, second)
    requireExactlyOneFlowOpen(t, carrier)
}
```

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./client -run TestTCPProxyRuntime -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add client/tcp_proxy_runtime.go client/tcp_proxy_runtime_test.go
git commit -m "feat: serve local TCP proxy flows"
```

### Task 3: Linux Client Command

**Files:**
- Create: `cmd/aurorac/main.go`
- Create: `cmd/aurorac/main_test.go`
- Create: `cmd/aurorac/signal_unix.go`
- Create: `cmd/aurorac/signal_windows.go`
- Modify: `README.md`

**Interfaces:**
- Produces `aurorac proxy --provisioning PATH --http-listen HOST:PORT --socks-listen HOST:PORT`.
- The command uses `BeginProvisionedSession`, an HTTPS issuer transport with no redirect or cache, `TCPProxyRuntime`, and `transport.RunPacketDuplex`.

- [ ] **Step 1: Write failing command validation tests**

```go
func TestProxyCommandRejectsNonLinuxAndPublicDefaultBind(t *testing.T) {
    if code := run([]string{"proxy", "--provisioning", fixturePath, "--http-listen", "0.0.0.0:8080"}, io.Discard, &stderr); code == 0 {
        t.Fatal("unsafe proxy configuration succeeded")
    }
}

func TestProvisioningFileRejectsGroupReadableMode(t *testing.T) {
    path := writeProvisioningFixture(t)
    if err := os.Chmod(path, 0o640); err != nil { t.Fatal(err) }
    if _, err := readRestrictedProvisioningFile(path); err == nil {
        t.Fatal("group-readable provisioning file succeeded")
    }
}
```

- [ ] **Step 2: Run command tests and verify they fail**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./cmd/aurorac -count=1`

Expected: package directory failure.

- [ ] **Step 3: Implement Linux composition and graceful shutdown**

```go
func runProxy(ctx context.Context, config proxyConfig) error {
    provisioning := readRestrictedProvisioningFile(config.provisioningPath)
    session, work, err := client.BeginProvisionedSession(ctx, provisioning, client.ProvisionedSessionOptions{})
    response, err := issuerTransport.Post(ctx, work)
    established, err := session.Complete(ctx, response)
    runtime, err := client.NewTCPProxyRuntime(established.Application, config.runtimeOptions())
    return runCarrierAndListeners(ctx, established, runtime, config)
}
```

Require loopback addresses unless `--allow-public-listeners` is set. Require a regular owner-only provisioning file, reject symlinks, and report only listener addresses and generic lifecycle state. Cancel all listeners and the carrier on the first terminal error or OS shutdown signal.

- [ ] **Step 4: Run command tests and build Linux binary**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./cmd/aurorac -count=1`

Run: `GOCACHE=/private/tmp/aurora-gocache GOOS=linux GOARCH=amd64 go build ./cmd/aurorac`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add cmd/aurorac README.md
git commit -m "feat: add Linux local proxy client"
```

### Task 4: End-To-End Verification And Delivery

**Files:**
- Modify: `server/first_hop_integration_test.go`
- Modify: `cmd/auroractl/main.go`
- Modify: `cmd/auroractl/main_test.go`

**Interfaces:**
- Produces an `auroractl client-proxy-check` gate that runs a provisioned client runtime against the strict first-hop fixture and a local TCP echo service.

- [ ] **Step 1: Write the failing real-carrier integration test**

```go
func TestProvisionedTCPProxyInteroperatesWithFirstHopRelay(t *testing.T) {
    relay, provisioning := newStrictFirstHopFixture(t)
    proxy := startProvisionedTCPProxy(t, provisioning)
    conn := connectHTTPProxy(t, proxy, relay.EchoTarget())
    requireRoundTrip(t, conn, []byte("client payload"))
}
```

- [ ] **Step 2: Run it and verify it fails until all pieces are wired**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./server ./cmd/auroractl -run 'TestProvisionedTCPProxy|TestClientProxyCheck' -count=1`

Expected: initial failure due to the missing check command or runtime wiring.

- [ ] **Step 3: Add the gate and integration wiring**

```go
case "client-proxy-check":
    report, err := server.RunProvisionedClientProxyConformance()
    return writeClientProxyReport(stdout, report, err)
```

The gate must fail closed on connection, handshake, forwarding, cleanup, or secret-redaction failures. It must use only loopback fixture endpoints.

- [ ] **Step 4: Run full verification**

Run: `GOCACHE=/private/tmp/aurora-gocache go test -p 1 ./... -count=1`

Run: `GOCACHE=/private/tmp/aurora-gocache go test -race ./client ./server ./cmd/aurorac -count=1`

Run: `GOCACHE=/private/tmp/aurora-gocache go vet ./...`

Run: `GOCACHE=/private/tmp/aurora-gocache GOOS=linux GOARCH=amd64 go build ./cmd/aurorac ./cmd/aurorad`

Run: `GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl client-proxy-check`

Expected: all commands pass.

- [ ] **Step 5: Commit final verification artifacts**

```sh
git add server/first_hop_integration_test.go cmd/auroractl/main.go cmd/auroractl/main_test.go
git commit -m "test: verify provisioned Linux proxy interop"
```

## Plan Self-Review

- Spec coverage: the plan covers reusable authenticated session ownership, no-root HTTP CONNECT and SOCKS5 TCP interfaces, Linux command validation, bounded resources, teardown, and real relay interoperability. Privileged TUN setup, UDP association serving, and local DNS listening are separate follow-up increments documented in the design scope.
- Placeholder scan: no deferred implementation markers or generic test steps remain.
- Type consistency: `ProvisionedSession` supplies established application and carrier state to `TCPProxyRuntime`; the command owns lifecycle composition; the integration gate exercises that public path.
