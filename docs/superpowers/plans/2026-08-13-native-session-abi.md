# Native Session ABI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the Apple Network Extension establish and drive the same authenticated portable client session as the Linux relay, without reimplementing protocol encoding or cryptography in Swift.

**Architecture:** Split the portable client handshake after verified Prelude1 so a native adapter can obtain an admission proof bound to the authenticated admission context, then resume the still-owned carrier to complete Capsule1 and Capsule2. Keep ephemeral keys, bindings, the HTTP/2 carrier, and application-session keys wholly inside the portable core. Expose handles through the C archive; Swift stores only a validated provisioning bundle, relays opaque issuer traffic, and pumps raw packets through a portable packet-to-flow adapter.

**Tech Stack:** Go portable core and c-archive ABI, TLS HTTP/2 carrier, Swift, Network Extension, Keychain, App Groups, XCTest, Go race detector and fuzzing.

**Spec:** `docs/superpowers/specs/2026-08-04-production-maturity-design.md` and `docs/superpowers/specs/2026-08-12-persistent-single-hop-design.md`

## Global Constraints

- `aurorad serve` is Linux-only; native Apple targets are clients only.
- The portable core owns all wire encoding, cryptographic operations, transcript bindings, replay construction, session keys, and teardown.
- Provisioning input uses a bounded canonical binary format, never permissive JSON for cryptographic objects.
- Native code may persist only sanitized configuration in the App Group and secret provisioning material in the Keychain.
- Each handle is process-local, single-session, concurrency-safe, bounded, and invalid after close.
- Public core source and documentation contain no external-project references and no new protocol-version strings.
- The existing public `aurora-core` and private `aurora-apple` repositories remain separate because they have distinct build, signing, and entitlement systems.

---

### Task 1: Split the Client Handshake at the Issuance Boundary

**Files:**
- Modify: `handshake/client.go`
- Create: `handshake/client_resume.go`
- Modify: `handshake/client_test.go`
- Test: `handshake/client_resume_test.go`

**Interfaces:**
- Consumes: `ClientDriver`, `ClientCarrierOpener`, `ClientProofRequest`, `BootstrapCarrier`, and the existing `EstablishedSession` ownership rules.
- Produces: `ClientDriver.Begin(context.Context, ClientCarrierOpener) (*ClientHandshake, ClientProofRequest, error)` plus `ClientHandshake.Complete(context.Context, protocol.AdmissionProof, protocol.ReplayProof) (*EstablishedSession, error)` and `ClientHandshake.Close() error`.

- [x] **Step 1: Write failing lifecycle tests**

```go
func TestClientHandshakeDefersCapsuleUntilProofsArrive(t *testing.T) {
    driver, opener := newClientDriverAndCarrier(t)
    handshake, request, err := driver.Begin(context.Background(), opener)
    if err != nil { t.Fatal(err) }
    if len(request.AdmissionContextHash) != 48 { t.Fatal("missing bound admission context") }
    assertCarrierOnlyReceivedPrelude0(t, opener)
    proofs := validProofsForRequest(t, request)
    session, err := handshake.Complete(context.Background(), proofs.admission, proofs.replay)
    if err != nil { t.Fatal(err) }
    defer session.Close()
    assertCarrierCompletedCapsules(t, opener)
}
```

- [x] **Step 2: Run the focused test and confirm the API is absent**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./handshake -run '^TestClientHandshakeDefersCapsuleUntilProofsArrive$'`

Expected: compile failure because `ClientDriver.Begin` does not exist.

- [x] **Step 3: Pause the verified prelude phase with a deferred proof provider**

```go
type ClientHandshake struct {
    provider *deferredClientProofProvider
    cancel context.CancelFunc
    done chan struct{}
    mu sync.Mutex
    completionClaimed bool
    closed bool
    result clientHandshakeResult
}

func (d *ClientDriver) Begin(ctx context.Context, opener ClientCarrierOpener) (*ClientHandshake, ClientProofRequest, error)
```

`Begin` uses a shallow `ClientDriver` clone that shares the original access-hint usage state but substitutes a one-shot proof provider. The existing `Connect` implementation performs deployment validation, carrier setup, Prelude0, Prelude1 verification, and secret derivation before the provider publishes a copied `ClientProofRequest`; it cannot send Capsule1 while waiting for the caller.

- [x] **Step 4: Make `Complete` own supplied proofs and release the established session**

```go
func (h *ClientHandshake) Complete(
    ctx context.Context,
    admissionProof protocol.AdmissionProof,
    replayProof protocol.ReplayProof,
) (*EstablishedSession, error)
```

`Complete` clones supplied proof objects, returns them through the deferred provider, and waits for the unchanged `Connect` path to perform validation, Capsule1 sealing, Capsule2 verification, application-secret derivation, and stream acquisition. It consumes the handle on success or failure, and repeated completion returns an error without writing another capsule.

- [x] **Step 5: Preserve `ClientDriver.Connect` unchanged**

```go
func (d *ClientDriver) Connect(ctx context.Context, opener ClientCarrierOpener) (*EstablishedSession, error)
```

`Connect` remains the single synchronous implementation. `Begin` drives it with the deferred provider, preventing protocol drift between portable callers and the native ABI.

- [x] **Step 6: Add cancellation, double-completion, proof-rejection, and zeroization tests**

```go
func TestClientHandshakeCloseCancelsPendingCarrier(t *testing.T)
func TestClientHandshakeRejectsSecondCompleteWithoutCarrierWrite(t *testing.T)
func TestClientHandshakeRejectsInvalidProofBeforeCapsuleWrite(t *testing.T)
func TestClientDriverConnectMatchesResumableHandshake(t *testing.T)
```

- [x] **Step 7: Run focused, race, and full core tests**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./handshake && GOCACHE=/private/tmp/aurora-gocache go test -race ./handshake && GOCACHE=/private/tmp/aurora-gocache go test ./...`

- [x] **Step 8: Commit**

```bash
git add handshake/client.go handshake/client_resume.go handshake/client_test.go handshake/client_resume_test.go
git commit -m "feat: resume client handshake after issuance"
```

### Task 2: Add a Bounded Native Provisioning Bundle

**Files:**
- Create: `client/native_provisioning.go`
- Test: `client/native_provisioning_test.go`
- Modify: `admission/access_hint.go`
- Test: `admission/access_hint_test.go`

**Interfaces:**
- Consumes: canonical `RelayDescriptor`, `CoverTemplate`, `PublicKeyRecord`, `AccessHintCredential`, and `trust.VerifyRelayDeployment`.
- Produces: `client.NativeProvisioning` with `ParseNativeProvisioning([]byte, time.Time) (NativeProvisioning, error)` and `VerifiedDeployment() (trust.VerifiedRelayDeployment, error)`.

- [ ] **Step 1: Write malformed, oversized, stale, and signature-mismatch bundle tests**

```go
func TestParseNativeProvisioningRejectsMalformedAndTrailingBytes(t *testing.T)
func TestNativeProvisioningRejectsInvalidAccessHint(t *testing.T)
func TestNativeProvisioningVerifiesDeploymentBeforeUse(t *testing.T)
```

- [ ] **Step 2: Encode the access hint using a fixed canonical layout**

```go
func EncodeAccessHintCredential(value AccessHintCredential) ([]byte, error)
func DecodeAccessHintCredential(encoded []byte) (AccessHintCredential, error)
```

The binary layout writes fixed issuer, relay-bucket, selector, and secret fields followed by epoch, expiry, and maximum-use values. It rejects trailing bytes and never logs field values.

- [ ] **Step 3: Define and parse the provisioning bundle**

```go
type NativeProvisioning struct {
    RelayURL string
    IssuerURL string
    IssuerCarrierPath string
    Descriptor []byte
    TrustedDescriptorHash []byte
    Template []byte
    TemplateAuthorityKey []byte
    RequestClassID uint64
    Suite uint64
    AccessHint []byte
    PolicyOffer []byte
    TransportHints []byte
}
```

Use `wire.Encoder` and length-bounded opaque fields. Decode all protocol objects with their canonical decoders, require HTTPS URLs, exact absolute carrier paths, a production suite, a valid one-use access hint, and a non-lab policy before returning.

- [ ] **Step 4: Verify the deployment from decoded fields**

```go
func (p NativeProvisioning) VerifiedDeployment(now time.Time) (trust.VerifiedRelayDeployment, error)
func (p NativeProvisioning) ClientDriverConfig(now time.Time, provider handshake.ClientProofProvider) (handshake.ClientDriverConfig, error)
```

- [ ] **Step 5: Run package tests and fuzz parsing**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./admission ./client && GOCACHE=/private/tmp/aurora-gocache go test ./client -run '^$' -fuzz '^FuzzParseNativeProvisioning$' -fuzztime=10s`

- [ ] **Step 6: Commit**

```bash
git add admission/access_hint.go admission/access_hint_test.go client/native_provisioning.go client/native_provisioning_test.go
git commit -m "feat: validate native client provisioning"
```

### Task 3: Expose Resumable Sessions Through the C Archive

**Files:**
- Modify: `mobile/auroracore/auroracore.go`
- Create: `mobile/auroracore/session.go`
- Create: `mobile/auroracore/session_test.go`
- Modify: `mobile/auroracore/stub.go`

**Interfaces:**
- Consumes: `client.NativeProvisioning`, `handshake.ClientHandshake`, and existing `AuroraCoreCall` allocation/free rules.
- Produces: `AuroraCoreCall` operations `beginNativeSession`, `completeNativeSession`, `closeNativeSession`, `queueFrameBlock`, `nextPacket`, and `handlePacket`.

- [ ] **Step 1: Write ABI misuse tests**

```go
func TestNativeSessionHandleRejectsUnknownAndClosedValues(t *testing.T)
func TestNativeSessionBeginReturnsIssuerRequestOnlyAfterPrelude1(t *testing.T)
func TestNativeSessionCompletionOwnsAndDestroysProvisioningSecrets(t *testing.T)
func TestNativeSessionPacketCallsRejectMalformedFramesAndPackets(t *testing.T)
```

- [ ] **Step 2: Implement a bounded process-local handle registry**

```go
type nativeSessionRegistry struct {
    mu sync.Mutex
    next uint64
    sessions map[uint64]*nativeSession
}

type nativeSession struct {
    handshake *handshake.ClientHandshake
    established *handshake.EstablishedSession
    issuerURL string
    issuerCarrierPath string
}
```

Allocate monotonically nonzero handles, cap live sessions, remove before close, and serialize all operations for one handle. Never return pointer addresses as handles.

- [ ] **Step 3: Return a bounded binary issuer-work item from `beginNativeSession`**

```go
type nativeIssuerWork struct {
    Handle uint64
    IssuerURL string
    IssuerCarrierPath string
    RequestBody []byte
}
```

The core creates the issue request with the exact admission-context hash from `ClientProofRequest`; Swift only posts the returned opaque body and returns the opaque response.

- [ ] **Step 4: Complete the handshake and expose encrypted application packet operations**

```go
func (r *nativeSessionRegistry) complete(handle uint64, issuerResponse []byte) error
func (r *nativeSessionRegistry) queueFrameBlock(handle uint64, encoded []byte) error
func (r *nativeSessionRegistry) nextPacket(handle uint64) ([]byte, error)
func (r *nativeSessionRegistry) handlePacket(handle uint64, encoded []byte) ([]byte, error)
```

Use portable-core decoders for issuer responses and frame blocks; preserve queue backpressure and return status-only errors without secrets.

- [ ] **Step 5: Add race, leak, and cross-compile coverage**

Run: `GOCACHE=/private/tmp/aurora-gocache go test -race ./mobile/auroracore && GOCACHE=/private/tmp/aurora-gocache GOOS=darwin GOARCH=arm64 go test -c ./mobile/auroracore && GOCACHE=/private/tmp/aurora-gocache GOOS=ios GOARCH=arm64 go test -c ./mobile/auroracore`

- [ ] **Step 6: Commit**

```bash
git add mobile/auroracore
git commit -m "feat: expose native client session handles"
```

### Task 4: Build the Portable Packet-to-Flow Adapter

**Files:**
- Create: `client/packet_adapter.go`
- Create: `client/packet_adapter_test.go`
- Create: `client/packet_adapter_fuzz_test.go`
- Modify: `client/local_interfaces.go`

**Interfaces:**
- Consumes: `session.Application`, `flow.Manager`, local DNS forwarder, and raw IPv4/IPv6 packets.
- Produces: `client.PacketAdapter` with `Ingress(context.Context, []byte, time.Time) error`, `NextEncryptedPacket(context.Context) ([]byte, error)`, and `HandleEncryptedPacket(context.Context, []byte, time.Time) ([][]byte, error)`.

- [ ] **Step 1: Write TCP, UDP, DNS, malformed-IP, and bounded-flow tests**

```go
func TestPacketAdapterOpensTCPAndForwardsStreamData(t *testing.T)
func TestPacketAdapterOpensUDPAndForwardsDatagrams(t *testing.T)
func TestPacketAdapterCapturesDNSWithoutPublicResolverLeak(t *testing.T)
func TestPacketAdapterRejectsMalformedPacketsWithoutFlowAllocation(t *testing.T)
```

- [ ] **Step 2: Parse only bounded IPv4 and IPv6 TCP/UDP packets**

Reject fragments, unsupported extension headers, malformed lengths, noninitial TCP segments, and packets exceeding the configured MTU. Allocate flow identifiers from a monotonic random-prefix generator and cap concurrent mappings.

- [ ] **Step 3: Convert local packets to existing client flow frames**

```go
type PacketAdapterOptions struct {
    MaxFlows int
    MaxPacketBytes int
    UDPMode transport.UDPMode
    Now func() time.Time
}
```

Map new TCP/UDP tuples through `LocalProxy`, queue FlowOpen and data frames on `session.Application`, and make queue backpressure a local drop or retry signal rather than unbounded buffering.

- [ ] **Step 4: Convert relay frames back to valid local IP packets**

Decode only allowed server-direction frames, close mappings on FLOW_CLOSE, preserve per-flow ordering, and produce packets with correct address and port reversal. DNS responses must only use the local DNS forwarder path.

- [ ] **Step 5: Fuzz and stress the adapter**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./client -run '^$' -fuzz '^FuzzPacketAdapterIngress$' -fuzztime=10s && GOCACHE=/private/tmp/aurora-gocache go test -race ./client`

- [ ] **Step 6: Commit**

```bash
git add client/packet_adapter.go client/packet_adapter_test.go client/packet_adapter_fuzz_test.go client/local_interfaces.go
git commit -m "feat: adapt local packets to encrypted flows"
```

### Task 5: Drive the Native Session from AuroraKit

**Files:**
- Modify: `Sources/AuroraKit/AuroraCoreBridge.swift`
- Create: `Sources/AuroraKit/AuroraNativeSession.swift`
- Modify: `Sources/AuroraKit/AuroraPacketTunnelRuntime.swift`
- Modify: `Sources/AuroraKit/AuroraTokenWallet.swift`
- Modify: `Tests/AuroraKitTests/AuroraKitTests.swift`

**Interfaces:**
- Consumes: C archive handle operations, opaque native provisioning bundle, issuer work item, and `AuroraPacketFlow`.
- Produces: `AuroraNativeSession` conforming to `AuroraPacketTunnelCore` and an `AuroraSecureCredentialStore` entry for provisioning material.

- [ ] **Step 1: Write Swift tests against a mock C-core adapter**

```swift
func testNativeSessionPostsOnlyCoreProducedIssuerWork() async throws
func testNativeSessionRejectsUnknownHandleAndAlwaysClosesIt() async throws
func testPacketTunnelRuntimePropagatesBackpressureWithoutGrowingBuffer() async throws
func testProvisioningBundleUsesKeychainNotSharedDefaults() async throws
```

- [ ] **Step 2: Add the typed core bridge**

```swift
protocol AuroraNativeCoreAdapter: Sendable {
    func beginSession(provisioning: Data) throws -> AuroraIssuerWork
    func completeSession(handle: UInt64, issuerResponse: Data) throws
    func queuePacket(handle: UInt64, packet: Data, protocolNumber: Int) throws
    func nextPacket(handle: UInt64) throws -> Data?
    func handlePacket(handle: UInt64, packet: Data) throws -> [Data]
    func closeSession(handle: UInt64)
}
```

`AuroraCoreBridge` must decode only the fixed C response layouts and free every returned allocation exactly once.

- [ ] **Step 3: Store provisioning in the Keychain and keep profile text sanitized**

Use a dedicated keychain account for the opaque provisioning bundle. The App Group portable profile contains endpoint and route settings only; never include access hints, proofs, relay descriptors, or session handles.

- [ ] **Step 4: Replace `AuroraServerBackedPacketTunnelCore` packet-batch calls**

`connect` begins the native session, posts its issuer-work body to the configured issuer carrier, completes the session, then uses typed packet calls for every inbound and outbound packet. On any error it closes the handle before returning.

- [ ] **Step 5: Run package and Xcode target tests**

Run: `swift test && xcodebuild -project AuroraApple.xcodeproj -scheme AuroraMac -configuration Debug -sdk macosx CODE_SIGNING_ALLOWED=NO build && xcodebuild -project AuroraApple.xcodeproj -scheme AuroraPacketTunnel_iOS -configuration Debug -sdk iphonesimulator CODE_SIGNING_ALLOWED=NO build`

- [ ] **Step 6: Commit**

```bash
git add Sources/AuroraKit Tests/AuroraKitTests
git commit -m "feat: connect Apple tunnels through native sessions"
```

### Task 6: Verify Linux Relay to Apple Client Interoperability

**Files:**
- Create: `mobile/auroracore/native_session_integration_test.go`
- Modify: `server/first_hop_integration_test.go`
- Modify: `.github/workflows/ci.yml`
- Modify: `aurora-apple/scripts/aurora-apple-check.sh`

**Interfaces:**
- Consumes: strict `ProductionFirstHopServer`, verified client provisioning fixtures, the native C ABI, and AuroraKit tests.
- Produces: an encrypted packet-flow test proving the production server and Apple adapter share the same portable session.

- [ ] **Step 1: Write the process-level interoperability test**

```go
func TestNativeSessionFFIExchangesTCPAndUDPThroughProductionFirstHop(t *testing.T)
```

Start the production first-hop fixture with TLS, a loopback TCP echo destination, and a UDP echo destination. Build the native provisioning fixture from its verified deployment, obtain a bound issuer proof after Prelude1, exchange flow data, and assert no diagnostic packet-batch endpoint is used.

- [ ] **Step 2: Add teardown and failure assertions**

```go
func TestNativeSessionFFIRejectsReplayAndClosesHandle(t *testing.T)
func TestNativeSessionFFIStopsOnCarrierCancellation(t *testing.T)
func TestNativeSessionFFIRejectsExpiredProvisioningBeforeNetworkOpen(t *testing.T)
```

- [ ] **Step 3: Add CI build and test gates**

Run core native-session tests on Linux and compile the C archive for macOS and iOS. Run the Apple repository script after rebuilding its framework from the exact core revision.

- [ ] **Step 4: Perform final review and commit**

Run: `GOCACHE=/private/tmp/aurora-gocache go test ./... && GOCACHE=/private/tmp/aurora-gocache go test -race ./... && GOCACHE=/private/tmp/aurora-gocache go vet ./... && swift test`

Review changed code for secret logs, retained key material, unbounded allocations, stale handles, cross-platform behavior, and external references. Add a regression test for every actionable finding before committing:

```bash
git add mobile server .github/workflows/ci.yml
git commit -m "test: verify native client relay interoperability"
```

## Plan Review

**Spec coverage:** Task 1 creates the post-Prelude issuance boundary; Task 2 verifies all deployment and access-hint inputs; Task 3 freezes the native session ABI; Task 4 handles actual local packet data; Task 5 makes the iOS/macOS Network Extension use that ABI; and Task 6 proves encrypted traffic against the strict Linux server. The plan deliberately excludes production entitlement signing and real issuer deployment credentials because they require operator-controlled identities and infrastructure, not repository code.

**Placeholder scan:** The plan names the affected files, types, methods, test cases, commands, and commit boundaries. No implementation step relies on an unspecified serializer, endpoint, or crypto parser.

**Type consistency:** `ClientHandshake` supplies the proof request consumed by the C archive; `NativeProvisioning` supplies the `ClientDriverConfig`; the ABI owns an `EstablishedSession`; `PacketAdapter` consumes its application session; and `AuroraNativeSession` drives those typed ABI operations from the Network Extension.
