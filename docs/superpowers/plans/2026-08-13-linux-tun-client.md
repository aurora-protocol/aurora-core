# Linux TUN Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a runnable Linux TUN client that securely routes IPv4 and IPv6 traffic through one provisioned Aurora session.

**Architecture:** `client.PacketTUNRuntime` composes the existing packet adapter with a packet device and provides the incoming frame callback used by the existing encrypted duplex. `cmd/aurorac` performs Linux-only route discovery and reversible interface configuration before it runs those two pumps. It protects the carrier through explicit host routes before installing tunnel defaults.

**Tech Stack:** Go standard library, existing Aurora client/session/transport packages, Linux TUN device support, and the system `ip` executable.

**Spec:** `docs/superpowers/specs/2026-08-13-linux-tun-client-design.md`

## Global Constraints

- Reuse validated provisioning, the pinned carrier, and existing packet/frame logic; do not implement protocol encoding in the command layer.
- Do not add a protocol or specification version string to code or documentation.
- Keep provisioning, issuer work, endpoint values, and encrypted frame contents out of logs.
- Use bounded buffers, bounded resolver results, and cancellation-aware cleanup.
- Never overwrite or delete an operator-managed route; clean only routes this process successfully added.
- Refuse unsafe route layouts rather than risking a carrier loop or a traffic leak.
- Use TDD: add each behavior test, run it red, then add the smallest production change.
- Commit each independently testable task.

---

### Task 1: Portable Packet-Device Runtime

**Files:**
- Create: `client/packet_tun_runtime.go`
- Create: `client/packet_tun_runtime_test.go`

**Interfaces:**
- Produces `type PacketTUNRuntimeOptions struct { ReadBufferBytes int; Now func() time.Time }`.
- Produces `func NewPacketTUNRuntime(adapter *PacketAdapter, device io.ReadWriteCloser, options PacketTUNRuntimeOptions) (*PacketTUNRuntime, error)`.
- Produces `func (r *PacketTUNRuntime) Serve(context.Context) error`.
- Produces `func (r *PacketTUNRuntime) HandleFrameBlock(context.Context, protocol.FrameBlock) error`.
- Produces `func (r *PacketTUNRuntime) Close() error`.

- [x] **Step 1: Write failing packet-device tests**

```go
func TestPacketTUNRuntimeWritesSyntheticAndRelayPackets(t *testing.T) {
    runtime, _, relayApp, device := newPacketTUNRuntimeFixture(t)
    go runtime.Serve(context.Background())
    device.Reads <- tcpSYN(t)
    requireFrameType(t, relayApp, registry.FrameFlowOpen)
    requireTCPFlags(t, device.NextWrite(t), tcpFlagSYN|tcpFlagACK)
    requireRelayFrameWritesPacket(t, runtime, relayApp, device)
}

func TestPacketTUNRuntimeCloseUnblocksRead(t *testing.T) {
    runtime, _, _, device := newPacketTUNRuntimeFixture(t)
    done := make(chan error, 1)
    go func() { done <- runtime.Serve(context.Background()) }()
    _ = runtime.Close()
    requireTerminalDeviceError(t, <-done)
    requireDeviceClosed(t, device)
}
```

- [x] **Step 2: Run the new tests and verify they fail**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./client -run PacketTUNRuntime -count=1`

Expected: compile failure naming `NewPacketTUNRuntime`.

- [x] **Step 3: Implement bounded local and relay packet handling**

```go
func (r *PacketTUNRuntime) Serve(ctx context.Context) error {
    for {
        size, err := r.device.Read(r.readBuffer)
        if size > 0 {
            if err := r.adapter.Ingress(ctx, r.readBuffer[:size], r.now()); err != nil { return err }
            if err := r.writePackets(r.adapter.DrainLocalPackets()); err != nil { return err }
        }
        if err != nil { return err }
    }
}

func (r *PacketTUNRuntime) HandleFrameBlock(ctx context.Context, block protocol.FrameBlock) error {
    packets, err := r.adapter.HandleFrameBlocks(ctx, []protocol.FrameBlock{block}, r.now())
    if err != nil { return err }
    return r.writePackets(packets)
}
```

Validate options before allocation, copy no packet beyond the fixed device
buffer, reject partial writes, serialize device writes, zero temporary packet
buffers, and make close idempotent.

- [x] **Step 4: Run focused tests and race test**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./client -run PacketTUNRuntime -count=1`

Run: `GOCACHE=/private/tmp/aurora-gocache go test -race ./client -run PacketTUNRuntime -count=1`

Expected: PASS.

- [x] **Step 5: Commit**

```sh
git add client/packet_tun_runtime.go client/packet_tun_runtime_test.go
git commit -m "feat: run packet adapter on tunnel devices"
```

### Task 2: Linux Route Controller

**Files:**
- Create: `cmd/aurorac/linux_tun.go`
- Create: `cmd/aurorac/linux_tun_test.go`

**Interfaces:**
- Produces `type tunConfig struct { provisioningPath string; devicePath string; interfaceName string; mtu int; ipv4 netip.Prefix; ipv6 netip.Prefix; issuerTimeout time.Duration }`.
- Produces `func parseTUNConfig([]string, io.Writer) (tunConfig, error)`.
- Produces `func resolveRelayRoutes(context.Context, string) ([]linuxHostRoute, error)`.
- Produces `func (m *linuxTUNNetworkManager) Configure(context.Context, []linuxHostRoute) (*linuxTUNNetworkState, error)` and `func (s *linuxTUNNetworkState) Close() error`.

- [x] **Step 1: Write failing route-validation and rollback tests**

```go
func TestLinuxTUNNetworkConfiguresBypassesBeforeDefaults(t *testing.T) {
    runner := newRecordingIPRunner(routeGetJSON("192.0.2.1", "eth0"), defaultsJSON(100))
    manager := newLinuxTUNNetworkManagerForTest(runner)
    state, err := manager.Configure(context.Background(), fixtureRoutes())
    if err != nil { t.Fatal(err) }
    defer state.Close()
    requireCommands(t, runner, []string{
        "-4 route add 203.0.113.7/32 via 192.0.2.1 dev eth0 metric 5",
        "link set dev aurora0 mtu 1280 up",
        "-4 route add default dev aurora0 metric 99",
    })
}

func TestLinuxTUNNetworkRollsBackOnlyOwnedRoutes(t *testing.T) {
    runner := failOnDefaultRouteRunner()
    manager := newLinuxTUNNetworkManagerForTest(runner)
    if _, err := manager.Configure(context.Background(), fixtureRoutes()); err == nil { t.Fatal("setup succeeded") }
    requireNoRouteReplace(t, runner)
    requireReverseOwnedCleanup(t, runner)
}
```

- [x] **Step 2: Run the new tests and verify they fail**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./cmd/aurorac -run 'LinuxTUN|TUNConfig|RelayRoute' -count=1`

Expected: compile failure naming `linuxTUNNetworkManager`.

- [x] **Step 3: Implement fail-closed Linux network setup**

Use `ip -j -4/-6 route get ADDRESS` and `ip -j -4/-6 route show
default` to build bounded typed route data. Require correct address families,
concrete non-tunnel interfaces, and main-table routes. Select a route metric
strictly lower than every existing default, add exact bypasses with `route add`,
configure TUN addresses and link state, then add IPv4 and IPv6 defaults. On
failure or close, remove successful additions in reverse order. Resolve the
production `ip` executable from absolute system paths only.

- [x] **Step 4: Add and run malformed-data tests**

```go
func TestResolveRelayRoutesRejectsUnsafeJSON(t *testing.T) {
    for _, output := range []string{"[]", `[{"dev":"aurora0"}]`, `[{"gateway":"::1","dev":"eth0"}]`} {
        if _, err := resolveRelayRoutesWithRunner(context.Background(), "https://relay.example", runnerFor(output)); err == nil {
            t.Fatal("unsafe route response was accepted")
        }
    }
}

func TestParseTUNConfigRequiresHostPrefixes(t *testing.T) {
    if _, err := parseTUNConfig([]string{"--provisioning", "/tmp/p", "--ipv4-address", "10.77.0.2/24"}, io.Discard); err == nil {
        t.Fatal("non-host tunnel prefix was accepted")
    }
}
```

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./cmd/aurorac -run 'LinuxTUN|TUNConfig|RelayRoute' -count=1`

Expected: PASS.

- [x] **Step 5: Commit**

```sh
git add cmd/aurorac/linux_tun.go cmd/aurorac/linux_tun_test.go
git commit -m "feat: configure Linux tunnel routes safely"
```

### Task 3: Linux TUN Client Command

**Files:**
- Modify: `cmd/aurorac/main.go`
- Modify: `cmd/aurorac/main_test.go`
- Modify: `README.md`

**Interfaces:**
- Produces `aurorac tun --provisioning PATH [--tun-device PATH] [--tun-iface NAME] [--tun-mtu BYTES] [--ipv4-address ADDR/32] [--ipv6-address ADDR/128]`.
- Produces `func runTUN(context.Context, tunConfig, io.Writer) error`.
- Produces `func runTUNComponents(context.Context, *handshake.EstablishedSession, *client.PacketTUNRuntime, func() error) error`.

- [x] **Step 1: Write failing command lifecycle tests**

```go
func TestTUNRejectsNonLinuxBeforeProvisioning(t *testing.T) {
    restore := setProxyGOOSForTest("darwin")
    defer restore()
    if code := run([]string{"tun", "--provisioning", "/private/p"}, io.Discard, &bytes.Buffer{}); code != 2 {
        t.Fatal("non-Linux tunnel command succeeded")
    }
}

func TestRunTUNComponentsClosesDeviceAndCarrierOnCancellation(t *testing.T) {
    established, runtime, device := packetTUNComponentsFixture(t)
    ctx, cancel := context.WithCancel(context.Background())
    done := make(chan error, 1)
    go func() { done <- runTUNComponents(ctx, established, runtime, func() error { return nil }) }()
    cancel()
    requireNoError(t, <-done)
    requireDeviceClosed(t, device)
}
```

- [x] **Step 2: Run command tests and verify they fail**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./cmd/aurorac -run 'TUN|Tun' -count=1`

Expected: failure because `tun` is not a recognized command.

- [x] **Step 3: Compose the provisioned session, device, routes, and duplex**

Read the restricted provisioning file and retain only the relay origin required
for preflight route lookup. Open and complete one provisioned session before
installing tunnel defaults. Open the existing Linux TUN device, configure owned
routes, construct `PacketAdapter` with the configured MTU as its packet bound,
construct `PacketTUNRuntime`, then run its local pump together with
`transport.RunPacketDuplex`. On first failure or signal, close the packet
runtime, established session, and owned routes, preserving terminal errors.

- [x] **Step 4: Update user-facing command documentation and verify builds**

Document the Linux host prerequisite, owner-only provisioning file, root or
network-administration permission requirement, and route-safety failure modes
without adding protocol internals or a specification version string.

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./cmd/aurorac -count=1`

Run: `GOCACHE=/private/tmp/aurora-gocache GOOS=linux GOARCH=amd64 go build ./cmd/aurorac`

Run: `GOCACHE=/private/tmp/aurora-gocache GOOS=darwin GOARCH=arm64 go build ./cmd/aurorac`

Expected: PASS.

- [x] **Step 5: Commit**

```sh
git add cmd/aurorac/main.go cmd/aurorac/main_test.go README.md
git commit -m "feat: add Linux tunnel client command"
```

### Task 4: Strict Relay Integration And Delivery

**Files:**
- Modify: `server/first_hop_integration_test.go`
- Modify: `docs/superpowers/plans/2026-08-13-linux-tun-client.md`

**Interfaces:**
- Adds strict encrypted-duplex coverage where `PacketTUNRuntime` accepts a
  local TCP SYN, the paired relay application receives a TUN-bound `FLOW_OPEN`,
  and a relay stream frame becomes a local IP packet through the runtime.

- [x] **Step 1: Write the failing strict integration test**

```go
func TestLiveFirstHopPacketTUNRuntimeInterop(t *testing.T) {
    clientSession, relaySession := strictProvisionedSessions(t)
    runtime, device := packetTUNRuntimeForEstablishedSession(t, clientSession)
    go runTUNComponents(context.Background(), clientSession, runtime)
    device.Inject(tcpSYN(t))
    requireTUNBoundOpenAtRelay(t, relaySession)
    relaySession.SendStreamData(t, []byte("response"))
    requireLocalTCPPayload(t, device.NextWrite(t), []byte("response"))
}
```

- [x] **Step 2: Run it and verify it fails until the composition is connected**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./server -run TestLiveFirstHopPacketTUNRuntimeInterop -count=1`

Expected: initial failure until the test uses the strict carrier fixture and
the TUN runtime endpoint.

- [x] **Step 3: Add integration wiring and run production verification**

Keep the fixture loopback-only, retain no provisioned bytes after use, and use
the existing strict relay framing rather than mocked protocol messages.

Run: `GOCACHE=/private/tmp/aurora-gocache go test -p 1 ./... -count=1`

Run: `GOCACHE=/private/tmp/aurora-gocache go test -race ./client ./server ./cmd/aurorac -count=1`

Run: `GOCACHE=/private/tmp/aurora-gocache go vet ./...`

Run: `GOCACHE=/private/tmp/aurora-gocache GOOS=linux GOARCH=amd64 go build ./cmd/aurorac ./cmd/aurorad`

Run: `GOCACHE=/private/tmp/aurora-gocache GOOS=darwin GOARCH=arm64 go build ./cmd/aurorac`

Expected: all commands pass.

- [x] **Step 4: Commit verification artifacts**

```sh
git add server/first_hop_integration_test.go docs/superpowers/plans/2026-08-13-linux-tun-client.md
git commit -m "test: verify Linux tunnel client interop"
```
