# Live First-Hop Handshake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a randomized, authenticated first-hop session over one fresh TLS 1.3 HTTP/2 request and hand the resulting directional application secrets to the persistent packet session.

**Architecture:** A verified relay-deployment value carries descriptor, cover-template, and request-class trust into both peers. The HTTP/2 adapter owns fresh-connection enforcement, live TLS exporter facts, bounded record I/O, cover fallback, and cancellation; transport-neutral client and relay drivers own Prelude, Capsule, admission, replay, policy, Finished, and application-secret state transitions. No `session.Application` is created until every authenticated bootstrap check succeeds.

**Tech Stack:** Go 1.25.12, `crypto/tls`, `net/http` HTTP/2, existing canonical wire/protocol/crypto/admission/session/transport packages, real ECDH and ML-KEM, external transcript signers, `go test`, race detector, fuzzing, benchmarks, and cross-compilation.

## Global Constraints

- Do not add a protocol specification version to core code, comments, filenames, logs, or documentation.
- Do not add names, code, comments, or documentation references from external inspiration projects.
- Add no new module dependency; use the Go standard library and existing modules.
- Production uses TLS 1.3, negotiated `h2`, stream identifier `1`, no TLS resumption, no connection pooling, and no inner or outer early data.
- Production configuration supplies authority, concrete path, normalized authority hash, request class, path-template ID, response status and headers, and verified metadata; there is no default carrier path.
- Bound every bootstrap record before allocation and enforce the signed cover-envelope minimum and maximum before writing.
- Spend the access hint atomically before response headers and spend admission/replay state before releasing application traffic.
- Production relay construction requires external private-key signers, an exact hint resolver, an admission verifier, and durable replay stores; memory stores are test-only.
- Never emit admission, replay, policy, route, destination, or application data before the client verifies Prelude1 signatures.
- Before a valid bound Prelude0, every failure returns the configured ordinary cover response and consumes the failed gateway-owned body locally.
- After response headers, every failure cancels the stream within configured deadlines and writes no error body, secret, proof, nonce, target, client address, or protocol-specific status.
- Preserve canonical encoding and the existing vector outputs; adapters carry opaque records and do not redefine protocol objects.
- Preserve the user-owned untracked `route/zz_dump_conf_test.go` in the main checkout.

---

## File Map

- `trust/deployment.go`: verified descriptor/template/request-class value and deterministic trust checks.
- `trust/deployment_test.go`: hash pinning, signatures, validity, suite/method, and clone-ownership tests.
- `crypto/mlkem.go`: suite-generic randomized ML-KEM key generation and encapsulation interfaces.
- `crypto/mlkem_test.go`: all production-suite round trips and unsupported-suite rejection.
- `handshake/binding.go`: TLS exporter, channel identifier, connection hash, stream binding, and first-hop context.
- `handshake/binding_test.go`: TLS/H2/resumption/property and client/server exporter agreement tests.
- `handshake/driver.go`: dependency contracts, production/test constructors, configuration ownership, and terminal result types.
- `handshake/padding.go`: cryptographically randomized signed-envelope padding with exact bounds.
- `handshake/padding_test.go`: minimum, maximum, ownership, entropy, and impossible-envelope tests.
- `handshake/client.go`: client Prelude/Capsule/Finished/application-session state machine.
- `handshake/client_test.go`: disclosure ordering, downgrade, signature, Finished, policy, and cancellation tests.
- `handshake/relay.go`: relay hint/signature/admission/replay/policy state machine.
- `handshake/relay_test.go`: exact lookup, spend ordering, replay, verifier failure, and no-session-on-failure tests.
- `transport/http2_client.go`: fresh non-resumable HTTP/2 streaming client carrier and lifecycle ownership.
- `transport/http2_client_test.go`: protocol restrictions, bounded records, response validation, cancellation, and leak tests.
- `server/first_hop.go`: connection-scoped first-request gate, pre-header cover fallback, and relay duplex handoff.
- `server/first_hop_test.go`: live TLS/H2 gate, cover-neutral failure, second-request cancellation, and header-order tests.
- `server/first_hop_integration_test.go`: randomized end-to-end handshake plus encrypted bidirectional application packets.
- `evidence/first_hop.go`: bounded live-first-hop evidence result without secret-bearing fields.
- `evidence/first_hop_test.go`: success/failure/resource assertions.
- `perf/first_hop_benchmark_test.go`: randomized bootstrap latency and retained-allocation baselines.

---

### Task 1: Verified Relay Deployment Boundary

**Files:**
- Create: `trust/deployment.go`
- Create: `trust/deployment_test.go`

**Interfaces:**
- Consumes: `ValidateCoverTemplateTime`, `ValidateRequestClass`, `RelayDescriptorHash`, `RelayDescriptorSignatureInput`, `CoverTemplateHash`, `CoverTemplateFamilySignatureInput`, `CoverTemplateInstanceSignatureInput`, and `crypto.VerifySignature`; structural cover checks stay in `trust` to avoid the existing `cover -> trust` dependency cycle.
- Produces: `RelayDeploymentVerification`, `VerifiedRelayDeployment`, and `VerifyRelayDeployment(RelayDeploymentVerification) (VerifiedRelayDeployment, error)`.
- Produces: owned accessors `Descriptor() protocol.RelayDescriptor`, `Template() protocol.CoverTemplate`, `RequestClass() protocol.RequestClass`, `DescriptorHash() []byte`, and `TemplateHash() []byte`.

- [x] **Step 1: Write the failing trust-boundary tests**

Create real ECDSA and ML-DSA keys and a signed descriptor/template fixture. Assert acceptance only when the computed descriptor hash equals the externally trusted hash, descriptor and epoch intervals include `NowUnix`, replay metadata is unexpired, both requested suite and HTTP/2 method are listed, the template hash appears exactly once in `CoverTemplateInstanceHashes`, and the selected class is gateway-owned, permits Prelude and Capsule, and uses the HTTP/2 method family.

Add table cases for a wrong trusted hash, bad classical or PQ descriptor signature, wrong template-authority signature, bad template-instance signature, expired descriptor/epoch/replay/template, duplicate or missing template commitment, missing suite/method, wrong class type, and caller mutation after construction. Use this exact public input shape:

```go
type RelayDeploymentVerification struct {
	Descriptor               protocol.RelayDescriptor
	TrustedDescriptorHash    []byte
	Template                 protocol.CoverTemplate
	TemplateAuthorityKey     protocol.PublicKeyRecord
	RequestClassID           uint64
	Suite                     uint64
	Method                    uint64
	NowUnix                   uint64
	MaxTemplateFutureSkew     uint64
	RequirePQDescriptorProof  bool
}
```

- [x] **Step 2: Run the focused tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-first-hop-cache go test ./trust -run 'TestVerifyRelayDeployment' -count=1`

Expected: FAIL because the deployment types and verifier do not exist.

- [x] **Step 3: Implement deterministic validation and an owned strong value**

Store every slice in unexported fields and deep-clone nested protocol values at construction and access. The verifier must perform checks in this order: canonical hash and trusted-hash equality; descriptor intervals and structural field lengths; long-term classical signature; required long-term PQ signature; cover-template structural/time validation; exact template commitment; exact request-class selection; template family signature under the single supplied authority key; template instance signature under the descriptor long-term classical key; suite/method/epoch/replay compatibility.

Use a non-zero marker so a zero value cannot be consumed:

```go
type VerifiedRelayDeployment struct {
	verified       bool
	descriptor     protocol.RelayDescriptor
	template       protocol.CoverTemplate
	requestClass   protocol.RequestClass
	descriptorHash []byte
	templateHash   []byte
}

func (d VerifiedRelayDeployment) Valid() bool { return d.verified }
```

Never trial-search signing keys: the caller supplies one already authenticated template-authority key, and the selected request class is located by exact ID.

- [x] **Step 4: Run trust verification**

Run:

```bash
gofmt -w trust/deployment.go trust/deployment_test.go
GOCACHE=/private/tmp/aurora-first-hop-cache go test ./trust -count=1
GOCACHE=/private/tmp/aurora-first-hop-cache go test -race ./trust -count=1
```

Expected: all trust tests pass with no race report.

- [x] **Step 5: Commit the verified metadata boundary**

```bash
git add trust/deployment.go trust/deployment_test.go
git commit -m "feat: add verified relay deployment boundary"
```

---

### Task 2: Suite-Generic Randomized Hybrid Operations

**Files:**
- Modify: `crypto/mlkem.go`
- Create: `crypto/mlkem_test.go`

**Interfaces:**
- Produces: `MLKEMDecapsulationKey` with `EncapsulationKeyBytes() []byte`, `Decapsulate([]byte) ([]byte, error)`, and `Destroy()`.
- Produces: `GenerateMLKEMForSuite(uint64) (MLKEMDecapsulationKey, error)`.
- Produces: `EncapsulateMLKEMForSuite(uint64, []byte) (sharedKey, ciphertext []byte, err error)`.
- Preserves: all existing concrete 768/1024 constructors and vector behavior.

- [x] **Step 1: Write failing all-suite randomized tests**

For every production suite, generate two independent keys, assert their public bytes differ, encapsulate to each key, decapsulate, and compare shared secrets. Assert returned public/shared/ciphertext slices are caller-owned, `Destroy` is idempotent and prevents later decapsulation, malformed keys/ciphertexts fail, and lab/unknown suites are rejected.

- [x] **Step 2: Run the focused tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-first-hop-cache go test ./crypto -run 'TestMLKEMForSuite' -count=1`

Expected: FAIL because the suite-generic API does not exist.

- [x] **Step 3: Add the private-key interface and dispatch without changing primitives**

Wrap the existing standard-library key types behind a small interface. Dispatch 768 and 1024 families using the existing suite registry, clone every returned slice, zero wrapper-owned cached bytes in `Destroy`, and return a stable error after destruction. Do not add deterministic seeds to an exported production constructor.

- [x] **Step 4: Run crypto regression and race tests**

Run:

```bash
gofmt -w crypto/mlkem.go crypto/mlkem_test.go
GOCACHE=/private/tmp/aurora-first-hop-cache go test ./crypto -count=1
GOCACHE=/private/tmp/aurora-first-hop-cache go test -race ./crypto -count=1
```

Expected: all existing vectors and new randomized tests pass.

- [x] **Step 5: Commit suite-generic hybrid operations**

```bash
git add crypto/mlkem.go crypto/mlkem_test.go
git commit -m "feat: add randomized suite hybrid helpers"
```

---

### Task 3: Live TLS HTTP/2 Binding

**Files:**
- Create: `handshake/binding.go`
- Create: `handshake/binding_test.go`

**Interfaces:**
- Consumes: existing `CoverStreamBinding` and `FirstHopBindingContext`.
- Produces: `HTTP2BindingMetadata`, `FirstHopBinding`, and `DeriveHTTP2FirstHopBinding(tls.ConnectionState, HTTP2BindingMetadata, []byte) (FirstHopBinding, error)`.

- [x] **Step 1: Write failing live-binding tests**

Use a real TLS 1.3 client/server connection over `net.Pipe`, negotiate `h2`, and derive the binding independently from both `ConnectionState` values. Assert byte-identical outer exporter, channel exporter, connection hash, cover-stream binding, and handshake context. Assert stream ID is `1`, HTTP version is `h2`, all returned slices are owned, and changing class, method, authority hash, path-template ID, or client cover random changes the stream binding.

Add rejection cases for TLS below 1.3, non-`h2` ALPN, `DidResume`, non-48-byte authority hash, non-16-byte path-template ID, non-32-byte cover random, zero class/method, and exporter failure.

- [x] **Step 2: Run the focused tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-first-hop-cache go test ./handshake -run 'TestDeriveHTTP2FirstHopBinding' -count=1`

Expected: FAIL because the binding metadata and live derivation do not exist.

- [x] **Step 3: Implement exporter-derived binding facts**

Use this public shape:

```go
type HTTP2BindingMetadata struct {
	NormalizedAuthorityHash []byte
	PathTemplateID          []byte
	RequestClassID          uint64
	MethodFamilyID          uint64
}

type FirstHopBinding struct {
	OuterExporterValue       []byte
	TLSExporterChannelID     []byte
	ConnectionIDHash         []byte
	CoverStreamBinding       []byte
	HandshakeBindingContext  []byte
}
```

Call `ConnectionState.ExportKeyingMaterial` with the protocol-defined outer and channel labels, empty context, and 48-byte output. Compute `connection_id_hash` from the `h2` label, channel exporter, and 48 zero resumption bytes. Feed HTTP version `h2`, stream ID `1`, configured metadata, and the client random into `CoverStreamBinding`, then derive `FirstHopBindingContext`. Validate every input before exporter calls and clone all outputs.

- [x] **Step 4: Run handshake binding verification**

Run:

```bash
gofmt -w handshake/binding.go handshake/binding_test.go
GOCACHE=/private/tmp/aurora-first-hop-cache go test ./handshake -count=1
GOCACHE=/private/tmp/aurora-first-hop-cache go test -race ./handshake -count=1
```

Expected: client/server live bindings agree and all existing handshake vectors remain green.

- [x] **Step 5: Commit live binding derivation**

```bash
git add handshake/binding.go handshake/binding_test.go
git commit -m "feat: derive first-hop binding from live tls"
```

---

### Task 4: Handshake Contracts and Envelope Padding

**Files:**
- Modify: `trust/deployment.go`
- Create: `handshake/driver.go`
- Create: `handshake/driver_test.go`
- Create: `handshake/padding.go`
- Create: `handshake/padding_test.go`
- Modify: `admission/replay_cache.go`
- Modify: `transport/record.go`
- Create: `wire/limits.go`

**Interfaces:**
- Consumes: `trust.VerifiedRelayDeployment`, `admission.ReplayCache`, `session.Config`, and canonical protocol types.
- Produces: `ClientCarrierOpener`, `BootstrapCarrier`, `ClientProofProvider`, `HintCredentialResolver`, `AdmissionVerifier`, `TranscriptSigner`, and `PolicySelector`.
- Produces: `ClientDriverConfig`, `RelayDriverConfig`, `EstablishedSession`, `NewClientDriver`, `NewRelayDriver`, and package-private test constructors that alone permit memory replay stores.
- Produces: exact bounded-padding helpers for Prelude0, Prelude1, Capsule1, and Capsule2.

- [x] **Step 1: Write failing constructor and dependency tests**

Assert production constructors reject a zero verified deployment, nil provider/resolver/verifier/selector/signer, signer public-key mismatch, lab suites, memory hint/token/bootstrap caches, missing limits, wrong request-class method, replay epoch already expired, and mutable caller inputs. Assert `ClientDriver.Connect` rejects a nil opener in Task 5. Assert the test constructor accepts explicit memory caches but still rejects every missing cryptographic dependency.

Use these exact contracts:

```go
type BootstrapCarrier interface {
	Binding() FirstHopBinding
	WriteRecord([]byte) error
	ReadRecord() ([]byte, error)
	ApplicationStreams() (io.ReadCloser, io.WriteCloser, error)
	Close() error
}

type ClientCarrierOpener interface {
	Open(context.Context, []byte) (BootstrapCarrier, error)
}

type ClientProofRequest struct {
	AdmissionContextHash    []byte
	HandshakeBindingContext []byte
	RouteInstanceID         uint64
	HopIndex                uint8
	ReplayEpochID           uint64
	ReplayEpochValidUntil   uint64
	ReplayWindowID          []byte
}

type ClientProofProvider interface {
	BuildProofs(context.Context, ClientProofRequest) (protocol.AdmissionProof, protocol.ReplayProof, error)
}

type HintCredentialResolver interface {
	ResolveAccessHint(context.Context, []byte, []byte, uint64, []byte) (admission.AccessHintCredential, error)
}

type AdmissionVerifier interface {
	VerifyAdmission(context.Context, protocol.AdmissionProof, uint64) error
}

type TranscriptSigner interface {
	PublicKey() protocol.PublicKeyRecord
	SignTranscript(context.Context, []byte) ([]byte, error)
}

type PolicySelector interface {
	SelectPolicy(context.Context, protocol.PolicyOffer, protocol.ClientTransportHints) (protocol.PolicyAccept, error)
}

type ClientDriverConfig struct {
	Deployment      trust.VerifiedRelayDeployment
	Suite           uint64
	AccessHint      admission.AccessHintCredential
	PolicyOffer     protocol.PolicyOffer
	TransportHints  protocol.ClientTransportHints
	ProofProvider   ClientProofProvider
	RequirePQ       bool
	SessionLimits   session.Limits
	Rekey           session.RekeyPolicy
	Entropy         session.EntropySource
}

type RelayDriverConfig struct {
	Deployment         trust.VerifiedRelayDeployment
	HintResolver       HintCredentialResolver
	HintSpentCache     DurableReplayCache
	AdmissionVerifier  AdmissionVerifier
	TokenSpentCache    DurableReplayCache
	BootstrapCache     DurableReplayCache
	ClassicalSigner    TranscriptSigner
	PQSigner           TranscriptSigner
	PolicySelector     PolicySelector
	RequirePQ          bool
	SessionLimits      session.Limits
	Rekey              session.RekeyPolicy
	Entropy            session.EntropySource
}

type EstablishedSession struct {
	Application     *session.Application
	ReadCarrier     io.ReadCloser
	WriteCarrier    io.WriteCloser
	Policy          protocol.PolicyAccept
	RouteInstanceID uint64
	closeOnce       sync.Once
}

func NewClientDriver(ClientDriverConfig) (*ClientDriver, error)
func NewRelayDriver(RelayDriverConfig) (*RelayDriver, error)
func (s *EstablishedSession) Close() error
```

- [x] **Step 2: Write failing padding tests**

For each bootstrap object, use a counting cryptographic reader and assert the encoded or sealed body is within its signed envelope, padding bytes come from the reader, preexisting caller padding is replaced rather than retained, the maximum is checked after final encoding/signing/tag overhead, impossible intervals fail without partial output, and the input object remains unchanged.

- [x] **Step 3: Run the focused tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-first-hop-cache go test ./handshake -run 'Test(NewClientDriver|NewRelayDriver|Pad)' -count=1`

Expected: FAIL because driver contracts and padding helpers do not exist.

- [x] **Step 4: Implement owned configuration and production/test separation**

`NewRelayDriver` accepts only replay stores implementing:

```go
type DurableReplayCache interface {
	admission.ReplayCache
	Durable() bool
}
```

Add `Durable() bool` to existing memory and file caches, returning false and true respectively. Production construction requires three durable stores: spent hint, spent token, and bootstrap dedup. The package-private `newRelayDriverForTest` accepts ordinary replay caches. Both constructors verify signer public keys byte-for-byte against the deployment epoch keys and deep-clone all protocol/config inputs.

Pin the selected suite and method inside `trust.VerifiedRelayDeployment`; driver construction must reject attempts to reuse the verified capability with another advertised suite or method. Validate suite-specific envelope floors and reject bootstrap envelopes above the shared operational record bound.

Define `EstablishedSession` with owned `*session.Application`, aligned application `io.ReadCloser`/`io.WriteCloser`, selected policy, route instance, and a close function. Its `Close` must be idempotent, close carrier streams and application state once, and zero copied handshake material.

- [x] **Step 5: Implement exact bounded padding**

Padding helpers repeatedly encode using existing canonical encoders, add the exact remaining randomized bytes plus a 16-byte signature-size guard where ECDSA DER length can vary, and re-encode until the final body is in `[min,max]`. Abort after four monotonic attempts, reject `min > max`, reject maxima above the record limit, and never truncate a canonical object or signature. Capsule helpers account for the fixed AEAD tag before comparing the carrier record body to its envelope.

- [x] **Step 6: Run contract, admission, and padding verification**

Run:

```bash
gofmt -w admission/replay_cache.go handshake/driver.go handshake/padding.go handshake/padding_test.go
GOCACHE=/private/tmp/aurora-first-hop-cache go test ./admission ./handshake -count=1
GOCACHE=/private/tmp/aurora-first-hop-cache go test -race ./admission ./handshake -count=1
```

Expected: constructors fail closed, padding stays in signed bounds, and existing caches remain compatible.

- [x] **Step 7: Commit contracts and envelope enforcement**

```bash
git add admission/replay_cache.go admission/replay_cache_test.go trust/deployment.go trust/deployment_test.go wire/limits.go transport/record.go handshake/driver.go handshake/driver_test.go handshake/padding.go handshake/padding_test.go
git commit -m "feat: define production handshake dependencies"
```

---

### Task 5: Disclosure-Safe Client Handshake Driver

**Files:**
- Create: `handshake/client.go`
- Create: `handshake/client_test.go`
- Modify: `handshake/driver.go`
- Modify: `handshake/driver_test.go`
- Modify: `crypto/dh.go`
- Modify: `crypto/dh_test.go`

**Interfaces:**
- Consumes: Task 4 contracts, randomized hybrid helpers, existing signature/Finished/key-schedule functions, and `session.NewApplication`.
- Produces: `(*ClientDriver).Connect(context.Context, ClientCarrierOpener) (*EstablishedSession, error)`.
- Preserves: existing `ClientSession` state-machine methods and tests.

- [x] **Step 1: Write the failing happy-path state test**

Use a scripted carrier with a real live-binding value, real randomized ECDH/ML-KEM, real ECDSA and ML-DSA Prelude1 signatures, a production-shaped Blind RSA proof provider, and a valid PolicyAccept. Assert the records are exactly `Prelude0`, sealed `Capsule1`, then application packets; the returned application writes direction `0`, reads direction `1`, uses hop layer `0`, and interoperates with a separately built relay application.

Assert generated client nonce, cover random, replay nonce, ECDH public key, and ML-KEM public key differ across 32 runs. Decode every sent Prelude0 and verify descriptor/template/class fields and access hint against the returned live binding.

- [x] **Step 2: Write failing disclosure-order and downgrade tests**

Instrument `ClientProofProvider` with a call counter and retain every carrier write. For malformed Prelude1, selected suite not offered, descriptor/template mismatch, bad hybrid share, bad classical signature, missing/bad required PQ signature, and canceled context, assert the provider is never called and no Capsule1 record exists.

For valid Prelude1 followed by malformed/bad-tag Capsule2, wrong route instance, wrong ServerFinished, selected version/suite/method/policy/route/shape/personality outside the offer, or an invalid virtual-address assignment, assert Capsule1 may have been sent but no application session or streams are released. Every failure must close the carrier and destroy ephemeral key material.

- [x] **Step 3: Run the client tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-first-hop-cache go test ./handshake -run 'TestClientDriver' -count=1`

Expected: FAIL because `ClientDriver.Connect` does not exist.

- [x] **Step 4: Implement Prelude0 only after the live binding exists**

`Connect` must:

```text
1. read 32 random bytes for client_cover_random;
2. open the carrier and obtain its live FirstHopBinding;
3. read a distinct 32-byte client_nonce;
4. generate suite-specific ECDH and ML-KEM private keys;
5. compute AccessHint from HandshakeBindingContext and client_nonce;
6. build and envelope-pad canonical Prelude0;
7. write exactly one Prelude0 record;
8. advance ClientSession to Prelude1 verification.
```

Require `Prelude0.RequestClassID` to match the verified request class. Never place proof, replay, policy, transport hints, route ID, target metadata, or application bytes in the opener, headers, or Prelude0.

- [x] **Step 5: Verify Prelude1 before requesting proofs**

Read and strictly decode one canonical Prelude1 with no trailing bytes. Call `ClientSession.VerifyCoverPrelude1` first. Only after success, derive ECDH and ML-KEM shared secrets, handshake secrets, and the first-hop route ID. Build an `admission.ContextInput` with hop `0`, the actual encrypted policy/hints values, verified hashes, and live binding. Call `ClientProofProvider.BuildProofs` only after this point.

Validate provider output before sealing: structural proof/replay checks, admission redemption hash equals the computed context in constant time, replay epoch/window exactly match the verified descriptor, token redemption hash and replay context recompute exactly, and proof expiry is before neither `now` nor replay validity.

- [x] **Step 6: Seal Capsule1 and finish the client application state**

Build Capsule1 with route ID and caller-owned policy/hints, compute ClientFinished over the unsigned capsule, envelope-pad before the final Finished computation, seal, and write one record. Read/open Capsule2, validate route ID and `PolicyAccept.ValidateForOffer`, recompute and constant-time verify ServerFinished, then derive application secrets.

Construct the application only after all checks:

```go
session.Config{
	Suite:           selectedSuite,
	RouteInstanceID: routeInstanceID,
	HopLayer:        0,
	Write: session.DirectionConfig{Direction: 0, Secret: app.ClientAppSecret0, Key: app.ClientAppKey0, IV: app.ClientAppIV0},
	Read:  session.DirectionConfig{Direction: 1, Secret: app.ServerAppSecret0, Key: app.ServerAppKey0, IV: app.ServerAppIV0},
	Limits: cfg.SessionLimits,
	Rekey:  cfg.Rekey,
	Entropy: cfg.Entropy,
}
```

Acquire aligned application streams only after `session.NewApplication` succeeds. On every return path, zero locally owned shared secrets, handshake secrets, plaintext capsules, and temporary keys where practical.

- [x] **Step 7: Run client verification and repeated randomized tests**

Run:

```bash
gofmt -w handshake/client.go handshake/client_test.go handshake/session.go
GOCACHE=/private/tmp/aurora-first-hop-cache go test ./handshake -run 'TestClientDriver' -count=20
GOCACHE=/private/tmp/aurora-first-hop-cache go test -race ./handshake -run 'TestClientDriver' -count=5
```

Expected: all randomized and failure-order cases pass with no race report.

- [x] **Step 8: Commit the client driver**

```bash
git add crypto/dh.go crypto/dh_test.go handshake/client.go handshake/client_test.go handshake/driver.go handshake/driver_test.go docs/superpowers/plans/2026-08-12-live-first-hop-handshake.md
git commit -m "feat: add authenticated first-hop client driver"
```

---

### Task 6: Fail-Closed Relay Handshake Driver

**Files:**
- Create: `handshake/relay.go`
- Create: `handshake/relay_test.go`
- Modify: `handshake/client.go`
- Modify: `handshake/control.go`
- Modify: `handshake/driver.go`

**Interfaces:**
- Consumes: Task 4 relay dependencies, `VerifyAndSpendAccessHintAt`, `VerifyAndSpendReplay`, existing control/Finished/key-schedule functions, and `session.NewApplication`.
- Produces: `(*RelayDriver).Begin(context.Context, FirstHopBinding, protocol.CoverPrelude0, uint64) (*RelayHandshake, protocol.CoverPrelude1, error)`.
- Produces: `(*RelayHandshake).Finish(context.Context, []byte, uint64) ([]byte, *session.Application, protocol.PolicyAccept, error)` and idempotent `Close()`.

- [x] **Step 1: Write failing Begin ordering tests**

Instrument the exact hint resolver, spent-hint cache, and signers with an ordered event log. Assert one successful Begin records:

```text
resolve exact tuple
verify hint
insert spent hint
sign classical transcript
sign PQ transcript
return Prelude1
```

Assert malformed Prelude0, bad descriptor/template/class, no shared suite, malformed hybrid share, resolver zero/multiple/error simulation, credential tuple mismatch, expired credential, bad hint, cache error, duplicate hint, signer error, and canceled context return no Prelude1 and no live `RelayHandshake`. Verify a bad structural Prelude0 does not spend a hint, while a valid one spends exactly once before either signer can expose bytes.

- [x] **Step 2: Write failing Finish ordering and replay tests**

For a real sealed Capsule1, instrument admission verification, token cache, bootstrap cache, policy selection, application construction, and Capsule2 write readiness. Assert ordering:

```text
AEAD open and structural checks
ClientFinished verification
admission-context equality
admission authenticator verification
token and bootstrap replay insertion
policy selection and offer validation
ServerFinished and Capsule2 construction
application construction
```

Add cases for bad tag, malformed plaintext, route mismatch, wrong ClientFinished, expired/wrong-scope proof, wrong admission context, wrong replay epoch/window/hash, token replay with a fresh replay nonce, cache uncertainty, policy denial/downgrade, and session-constructor failure. Assert no application is returned and no post-failure method can reuse the handshake.

- [x] **Step 3: Run the relay tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-first-hop-cache go test ./handshake -run 'TestRelayDriver|TestRelayHandshake' -count=1`

Expected: FAIL because relay Begin/Finish do not exist.

- [x] **Step 4: Implement exact Prelude0 validation and one-time hint spending**

`Begin` must strictly validate canonical structure, version, descriptor/template hashes, selected gateway-owned class, suite offer intersection, method support, nonce/random lengths, hint namespace fields, and hybrid client shares. Resolve exactly the tuple from Prelude0; compare every returned credential namespace field and expiry; call `VerifyAndSpendAccessHintAt` with `HandshakeBindingContext`, never bare stream binding.

After spending, generate fresh server ECDH material, encapsulate to the client ML-KEM key, construct and envelope-pad unsigned Prelude1, hash the transcript using the live cover-stream binding, sign with both configured epoch signers, and re-check final envelope bounds. Derive relay-side shared and handshake secrets and return an opaque single-use `RelayHandshake` that owns them. A signer failure after hint spend is fail-closed; it must not roll back or reuse the hint.

- [x] **Step 5: Implement Capsule1 verification, policy, and application creation**

`Finish` opens the control capsule and checks route ID before any verifier call. Recompute ClientFinished and compare in constant time. Recompute `AdmissionContextHash`, compare it to the proof redemption context in constant time, verify replay epoch/window against authenticated descriptor state, then call the external admission verifier. Only after verifier success call `VerifyAndSpendReplay`; any cache error or duplicate terminates the handshake.

Call the policy selector after replay insertion, require `PolicyAccept.ValidateForOffer`, and require selected method/suite/version to equal the authenticated carrier/prelude values. Compute ServerFinished, pad and seal Capsule2, derive application secrets, and create:

```go
session.Config{
	Suite:           selectedSuite,
	RouteInstanceID: routeInstanceID,
	HopLayer:        0,
	Write: session.DirectionConfig{Direction: 1, Secret: app.ServerAppSecret0, Key: app.ServerAppKey0, IV: app.ServerAppIV0},
	Read:  session.DirectionConfig{Direction: 0, Secret: app.ClientAppSecret0, Key: app.ClientAppKey0, IV: app.ClientAppIV0},
	Limits: cfg.SessionLimits,
	Rekey:  cfg.Rekey,
	Entropy: cfg.Entropy,
}
```

Return ciphertext and application together so the HTTP adapter can write Capsule2 before handing application traffic to a callback. `Close` and every terminal error must destroy retained secrets and make repeated Begin/Finish use fail.

- [x] **Step 6: Run relay verification and repeated randomized tests**

Run:

```bash
gofmt -w handshake/relay.go handshake/relay_test.go handshake/session.go
GOCACHE=/private/tmp/aurora-first-hop-cache go test ./handshake -run 'TestRelayDriver|TestRelayHandshake' -count=20
GOCACHE=/private/tmp/aurora-first-hop-cache go test -race ./handshake -run 'TestRelayDriver|TestRelayHandshake' -count=5
```

Expected: exact ordering, replay, and terminal-lifecycle tests pass.

- [x] **Step 7: Commit the relay driver**

```bash
git add handshake/client.go handshake/control.go handshake/driver.go handshake/relay.go handshake/relay_test.go docs/superpowers/plans/2026-08-12-live-first-hop-handshake.md
git commit -m "feat: add fail-closed first-hop relay driver"
```

---

### Task 7: Fresh HTTP/2 Client Carrier

**Files:**
- Create: `transport/http2_client.go`
- Create: `transport/http2_client_test.go`
- Modify: `transport/carrier.go`

**Interfaces:**
- Consumes: `handshake.HTTP2BindingMetadata`, `handshake.DeriveHTTP2FirstHopBinding`, and Task 4 `BootstrapCarrier` contract.
- Produces: `HTTP2ClientCarrierConfig`, `HTTP2ClientCarrier`, and `NewHTTP2ClientCarrierOpener(HTTP2ClientCarrierConfig) (handshake.ClientCarrierOpener, error)`.
- Produces: a streaming HTTP/2 request builder that preserves existing visible-header validation.

Use this exact opener configuration:

```go
type HTTP2ClientCarrierConfig struct {
	Request            *http.Request
	TLSConfig          *tls.Config
	BindingMetadata    handshake.HTTP2BindingMetadata
	ExpectedStatus     int
	ExpectedHeader     http.Header
	MaxRecordBodyBytes uint32
	Dialer             *net.Dialer
}
```

- [x] **Step 1: Write failing live-carrier tests**

Start a real TLS server configured for HTTP/2. Assert `Open` returns after TLS handshake and binding derivation but before response headers, allowing Prelude0 to be written through an `io.Pipe`. After the server responds, assert fragmented records round-trip and `ApplicationStreams` returns the same aligned request/response bodies exactly once.

Inspect server connection state and assert TLS 1.3, `h2`, `DidResume == false`, first stream behavior, one TCP connection, and no reuse across two opener calls. Assert configured authority/path/headers are preserved and no visible protocol marker is added.

- [x] **Step 2: Write failing validation and lifecycle tests**

Reject HTTP URLs, non-POST requests, wrong host/path/class/method metadata, client TLS configs allowing pre-1.3 or session caches, nil root trust, proxy functions, disabled certificate verification, response status/header mismatch, non-H2 ALPN, resumed state, oversized records, duplicate `ApplicationStreams`, and nil context.

Cancel before dial, while waiting for TLS, while waiting for response headers, during blocked request write, and after application upgrade. In each case assert request pipe, response body, transport idle connections, result goroutine, and socket close within one second. Repeat 100 times and compare goroutine count with a bounded settling allowance.

- [x] **Step 3: Run the carrier tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-first-hop-cache go test ./transport -run 'TestHTTP2ClientCarrier' -count=1`

Expected: FAIL because the HTTP/2 opener does not exist.

- [x] **Step 4: Implement a fresh non-resumable HTTP/2 transport per Open**

Clone caller TLS configuration, require certificate verification, set both TLS bounds to TLS 1.3, set ALPN to only `h2`, and require `ClientSessionCache == nil`. Create one `http.Transport` per Open with HTTP/2 enabled, HTTP/1 disabled through `http.Protocols`, `DisableKeepAlives`, no proxy, and a custom `DialTLSContext` that completes the TLS handshake, validates state, signals a cloned `ConnectionState`, and returns the live `*tls.Conn`.

Start `RoundTrip` in one owned goroutine with an `io.Pipe` request body. Race the TLS-state signal, request error, and context. Derive the live binding only after handshake success, then return the carrier before response headers. `ReadRecord` waits for and validates the configured cover status/header before constructing one bounded `RecordReader`; `WriteRecord` uses one `RecordWriter` on the pipe. `ApplicationStreams` marks one irreversible upgrade and returns wrappers that coordinate close with the transport goroutine.

- [x] **Step 5: Preserve visible request construction rules**

Add `BuildStreamingH2CarrierRequest` beside `BuildCarrierRequest`. It must call the existing class selector and visible-header validator, require HTTPS and the HTTP/2 method family, clone headers, set caller authority and concrete path, and leave content length unknown. It must not invent content type, path, query, cookie, cache, or response headers.

- [x] **Step 6: Run transport verification and lifecycle stress**

Run:

```bash
gofmt -w transport/http2_client.go transport/http2_client_test.go transport/carrier.go
GOCACHE=/private/tmp/aurora-first-hop-cache go test ./transport -run 'TestHTTP2ClientCarrier' -count=20
GOCACHE=/private/tmp/aurora-first-hop-cache go test -race ./transport -run 'TestHTTP2ClientCarrier' -count=5
```

Expected: all live transport and cancellation tests pass without leak or race evidence.

- [x] **Step 7: Commit the client carrier**

```bash
git add transport/http2_client.go transport/http2_client_test.go transport/carrier.go
git commit -m "feat: add fresh http2 bootstrap carrier"
```

---

### Task 8: Relay HTTP/2 Gate and Cover-Neutral Adapter

**Files:**
- Create: `server/first_hop.go`
- Create: `server/first_hop_test.go`
- Create: `server/first_hop_integration_test.go`
- Modify: `server/cover_origin.go`
- Modify: `server/server.go`
- Modify: `server/server_test.go`

**Interfaces:**
- Consumes: `handshake.RelayDriver`, bounded record codec, and `transport.RunPacketDuplex`.
- Produces: `FirstHopOptions`, `FirstHopHandler`, `NewFirstHopHandler(FirstHopOptions) (*FirstHopHandler, error)`, and `(*FirstHopHandler).ConnContext(context.Context, net.Conn) context.Context`.
- Produces: `NewFirstHopHTTPServer(string, *FirstHopHandler, *tls.Config) (*http.Server, error)` with TLS 1.3, HTTP/2-only, and session-ticket enforcement.

Use this exact handler configuration:

```go
type FirstHopOptions struct {
	Driver               *handshake.RelayDriver
	Authority            string
	Path                 string
	BindingMetadata      handshake.HTTP2BindingMetadata
	CoverStatus          int
	CoverHeader          http.Header
	Origin               relay.Origin
	CoverOrigin          http.Handler
	MaxRecordBodyBytes   uint32
	FrameHandler         transport.FrameBlockHandler
	PostHeaderTimeout    time.Duration
}
```

- [x] **Step 1: Write failing connection-gate tests**

Construct a real `http.Server` with `ConnContext: handler.ConnContext`, TLS 1.3 only, session tickets disabled, and HTTP/2 only. Assert the exact configured POST as the first request may claim the connection; a prior ordinary request consumes the claim; non-TLS, HTTP/1, resumed, wrong authority/path/method, or a handler without connection context receives byte-identical cover; and a second request after a carrier claim cancels the active carrier before that second request receives cover.

Race 32 concurrent requests on one HTTP/2 connection and assert at most one enters the handshake driver. Repeat under the race detector.

- [x] **Step 2: Write failing pre-header and post-header behavior tests**

Use a blocking spent-hint cache. Write a valid Prelude0 and assert the client receives no response headers before atomic hint insertion completes. For malformed record prefix/body, malformed Prelude0, bad class/binding/share/hint, duplicate hint, and hint-store error, assert the configured cover status, headers, and body are byte-identical and the failed request body is not forwarded to the cover origin.

After a valid Prelude1 has flushed headers, inject malformed Capsule1, bad ClientFinished, verifier error, replay, or policy failure. Assert no ordinary cover body, no public error text/status change, no session callback, and stream cancellation within the configured one-second test deadline.

- [x] **Step 3: Run server tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-first-hop-cache go test ./server -run 'TestFirstHop' -count=1`

Expected: FAIL because the connection gate and handler do not exist.

- [x] **Step 4: Implement connection-scoped first-request ownership**

Attach one unexported state object per accepted `net.Conn` through `ConnContext`. At request entry, obtain the actual HTTP/2 stream identifier from the pinned standard-library response writer and fail closed if the runtime shape is unsupported. Only stream `1` may continue to candidate validation. Any higher stream poisons the claim and atomically extracts and invokes the active carrier cancel before falling through to cover. A first ordinary or invalid candidate permanently consumes stream `1`.

The candidate gate must require `r.TLS != nil`, TLS 1.3, `h2`, no resumption, exact authority/path/method, configured request class/method, and a bounded request body. It must not infer a class from a public header.

`NewFirstHopHTTPServer` clones and validates the TLS config, sets minimum and maximum TLS versions to TLS 1.3, disables session tickets, advertises only `h2`, installs HTTP/2-only `http.Protocols`, installs `handler.ConnContext`, and sets bounded header/idle/write timeouts. It rejects a nil handler, empty address, certificate-free TLS config, or a conflicting protocol/session setting.

- [x] **Step 5: Implement pre-header bootstrap and cover fallback**

Read only the first bounded record, strictly decode Prelude0, derive live binding from `*r.TLS` plus `Prelude0.ClientCoverRandom`, and call `RelayDriver.Begin`. Until Begin succeeds, do not mutate response headers. On any failure, close/cancel the bootstrap state and call `serveCoverFailure` with a sanitized body-less request so gateway-owned failed bytes cannot reach an upstream origin.

After Begin succeeds, copy only configured cover response headers, write configured status, write the Prelude1 record, and flush with `http.ResponseController.Flush`. Then read Capsule1, call `Finish`, write/flush Capsule2, and only then start application duplex. After headers, all errors cancel the request, set immediate read/write deadlines through `ResponseController`, close application state, and return without another body write.

- [x] **Step 6: Hand aligned bodies to the persistent packet pump**

Wrap `r.Body` as the read closer and the response writer as a write closer whose `Close` sets a write deadline and cancels the request. Invoke `transport.RunPacketDuplex` with the established relay application, configured frame handler, and the same maximum record body. The session context owns the pump, second-request cancel, client disconnect, server shutdown, and callback lifetime.

- [x] **Step 7: Run server gate and failure verification**

Run:

```bash
gofmt -w server/first_hop.go server/first_hop_test.go server/server.go
GOCACHE=/private/tmp/aurora-first-hop-cache go test ./server -run 'TestFirstHop' -count=20
GOCACHE=/private/tmp/aurora-first-hop-cache go test -race ./server -run 'TestFirstHop' -count=5
```

Expected: one claim per connection, exact cover fallback before headers, and bounded cancellation after headers.

- [x] **Step 8: Commit the relay HTTP/2 adapter**

```bash
git add server/first_hop.go server/first_hop_test.go server/first_hop_integration_test.go server/cover_origin.go server/server.go server/server_test.go
git commit -m "feat: bind relay handshake to fresh http2"
```

---

### Task 9: Randomized Live Handshake and Application Integration

**Files:**
- Create: `server/first_hop_integration_test.go`
- Create: `evidence/first_hop.go`
- Create: `evidence/first_hop_test.go`
- Create: `perf/first_hop_benchmark_test.go`

**Interfaces:**
- Consumes: Tasks 1-8 plus `transport.RunPacketDuplex` and `session.Application`.
- Produces: `evidence.FirstHopResult` and `evidence.RunFirstHop(context.Context, evidence.FirstHopHarness) (FirstHopResult, error)` with bounded counters only.

- [x] **Step 1: Write the failing randomized process-boundary integration test**

Generate fresh TLS, descriptor long-term, epoch ECDSA, epoch ML-DSA, ECDH, ML-KEM, hint, and Blind RSA material for each test run. Start a real TCP TLS HTTP/2 server and a separate client transport. Complete Prelude0/1 and Capsule1/2, then run both application pumps over the same request/response bodies.

Queue a forward proxy-flow frame block on the client; assert the relay receives byte-identical validated frames and queues a backward response; assert the client receives that response. Trigger one directional key update in each direction, continue traffic, and assert both pumps retain bounded queue stats and close cleanly.

- [x] **Step 2: Add live negative and concurrency cases**

Over real TLS sockets, cover wrong exporter metadata, wrong path-template ID, bad Prelude1 signature with proof-provider call count zero, replayed AccessHint, replayed AdmissionProof with a fresh ReplayProof, wrong ClientFinished, wrong ServerFinished, malformed record lengths, early disconnect at each handshake record, second request cancellation, server shutdown, and 32 concurrent independent connections.

Assert failure classes only locally, no secret response/log fields, no application callback on failure, and no replay-store rollback after uncertainty. Run the successful randomized path 100 times and replay/cancellation paths 50 times.

- [x] **Step 3: Run integration tests and verify red or incomplete behavior**

Run: `GOCACHE=/private/tmp/aurora-first-hop-cache go test ./server -run 'TestLiveFirstHop' -count=1 -v`

Expected: FAIL until every transport/driver handoff is correctly composed.

- [x] **Step 4: Implement bounded evidence reporting**

Define only non-sensitive fields:

```go
type FirstHopResult struct {
	Passed                bool
	TLS13                 bool
	HTTP2                 bool
	FreshConnection       bool
	PreludeAuthenticated  bool
	AdmissionSpent        bool
	ReplayRejected        bool
	ApplicationRoundTrip  bool
	KeyUpdateRoundTrip    bool
	PeakQueuedPackets     int
	PeakQueuedBytes       int
	HandshakeDuration     time.Duration
	Findings              []string
}
```

The harness dependency starts a loopback live server with caller-supplied randomized credentials; production packages must not import the evidence package. Cap findings, do not retain errors containing cryptographic material, and enforce a context deadline.

- [x] **Step 5: Add latency and allocation benchmarks**

Benchmark one complete randomized bootstrap separately from steady-state application packets. Report `ns/op`, `B/op`, and `allocs/op`; close every server/carrier/session inside the iteration. Add a 64-connection parallel benchmark with a fixed upper bound on live sessions and record/queue limits, but no pass/fail throughput constant in unit tests.

- [x] **Step 6: Run repeated integration, evidence, race, and benchmark gates**

Run:

```bash
gofmt -w server/first_hop_integration_test.go evidence/first_hop.go evidence/first_hop_test.go perf/first_hop_benchmark_test.go
GOCACHE=/private/tmp/aurora-first-hop-cache go test ./server -run 'TestLiveFirstHop' -count=100
GOCACHE=/private/tmp/aurora-first-hop-cache go test ./evidence -run 'TestFirstHop' -count=20
GOCACHE=/private/tmp/aurora-first-hop-cache go test -race ./server ./handshake ./transport ./evidence -count=1
GOCACHE=/private/tmp/aurora-first-hop-cache go test ./perf -run '^$' -bench 'BenchmarkLiveFirstHop' -benchmem -count=5
```

Expected: all integration/evidence/race commands pass; benchmark output records the baseline without test-time performance assertions.

- [x] **Step 7: Commit live integration evidence**

```bash
git add server/first_hop_integration_test.go evidence/first_hop.go evidence/first_hop_test.go perf/first_hop_benchmark_test.go
git commit -m "test: add live first-hop session evidence"
```

---

### Task 10: Full Verification, Independent Review, and Integration

**Files:**
- Modify only files required by findings from the gates below.

**Interfaces:**
- Consumes: the complete live first-hop slice.
- Produces: a reviewed, pushed branch with zero known P0-P3 findings and exact verification evidence.

- [ ] **Step 1: Run formatting, unit, race, vet, and static analysis**

Run:

```bash
gofmt -w $(git diff --name-only --diff-filter=ACM -- '*.go')
GOCACHE=/private/tmp/aurora-first-hop-cache go test ./... -count=1
GOCACHE=/private/tmp/aurora-first-hop-cache go test -race ./... -count=1
GOCACHE=/private/tmp/aurora-first-hop-cache go vet ./...
```

Install or invoke `honnef.co/go/tools/cmd/staticcheck@2026.1`, then run `staticcheck -checks 'all,-U1000' ./...`. Expected: no finding; `U1000` remains separately audited because this repository intentionally retains conformance helpers that are not called by production packages.

- [ ] **Step 2: Run focused stress and fuzz campaigns**

Run 100 non-race and 50 race repetitions covering connection claims, cancellation, replay, wrong Finished, and application handoff. Run at least 10 seconds each for existing record fuzz targets and any new strict Prelude/Capsule decoder fuzz target. Expected: no failure, race, panic, unbounded allocation, or goroutine leak evidence.

- [ ] **Step 3: Run security and portability gates**

Run:

```bash
GOCACHE=/private/tmp/aurora-first-hop-cache go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
GOOS=linux GOARCH=amd64 GOCACHE=/private/tmp/aurora-first-hop-cache go test -exec=/usr/bin/true ./...
GOOS=windows GOARCH=amd64 GOCACHE=/private/tmp/aurora-first-hop-cache go test -exec=/usr/bin/true ./...
GOOS=darwin GOARCH=arm64 GOCACHE=/private/tmp/aurora-first-hop-cache go test -exec=/usr/bin/true ./...
GOOS=android GOARCH=arm64 CGO_ENABLED=0 GOCACHE=/private/tmp/aurora-first-hop-cache go test -exec=/usr/bin/true ./...
```

Inspect public errors/logs and response bodies for payloads, keys, proofs, nonces, targets, client addresses, or differentiated pre-authentication failures. Expected: no reachable vulnerability and no sensitive output.

- [ ] **Step 4: Measure coverage and performance**

Generate repository and package coverage; require the repository floor to remain at least 70% and the new handshake, HTTP/2 carrier, gate, and trust files to have focused success and failure coverage. Run benchmarks five times and compare retained bytes and allocations against the pre-optimization commit. Fix avoidable per-record buffering or retained handshake objects without weakening ownership.

- [ ] **Step 5: Run hygiene scans**

Search all changed core files and commits for protocol specification version text, external inspiration-project names, user paths or identity, unfinished-work markers, fixed carrier paths, protocol markers in visible headers, and AI attribution. Expected: no match except required protocol-domain strings already defined by canonical formulas.

- [ ] **Step 6: Request two independent code reviews and fix every P0-P3 finding**

Reviewer one focuses on cryptographic ordering, transcript/binding correctness, admission/replay atomicity, downgrade resistance, secret lifetime, and cover-neutral failures. Reviewer two focuses on HTTP/2 connection semantics, cancellation/deadlocks/leaks, bounded allocation, request/response ownership, API compatibility, and test quality.

For each finding, add a failing regression test, confirm red, implement the minimal fix, rerun focused and full gates, commit, and repeat reviews until both report no P0-P3 findings.

- [ ] **Step 7: Integrate and verify remote CI**

```bash
git status --short
git log --oneline --decorate -12
git push -u origin feature/live-first-hop
```

Fast-forward into `main` only after local gates and both reviews are clean, preserve the main checkout's untracked route test, push `main`, and watch the exact GitHub Actions run through completion. Expected: macOS, Ubuntu, Windows, race/coverage/fuzz/benchmark/live-load/vulnerability jobs all green.

- [ ] **Step 8: Record the next production boundary**

Update the active plan state only after remote CI is green: mark live TLS/HTTP binding and randomized first-hop handshake complete, then move Linux relay egress to in progress. Do not claim a production-ready end-to-end service until process configuration, real destination egress, impairment/release gates, and Swift clients are integrated.
