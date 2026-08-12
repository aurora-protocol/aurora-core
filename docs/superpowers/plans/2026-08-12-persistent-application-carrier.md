# Persistent Application Carrier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first production-maturity slice of the persistent single-hop path: bounded opaque record I/O plus a concurrency-safe encrypted application session with replay rejection, backpressure, directional key rotation, cancellation, and transport-neutral duplex pumping.

**Architecture:** A new `session.Application` composes the existing canonical frame, packet, replay-window, and key-update primitives. `transport.RecordReader`, `transport.RecordWriter`, and `transport.RunPacketDuplex` carry owned encrypted packet bytes without knowing handshake or flow semantics. This slice deliberately stops below first-hop bootstrap and destination egress; its live duplex tests use paired application secrets and are recorded as incremental evidence only.

**Tech Stack:** Go 1.25.12, standard library concurrency and I/O, existing Aurora wire/protocol/packet/crypto packages, `go test`, race detector, fuzzing, and cross-compilation.

## Global Constraints

- Do not add a protocol specification version to core code, comments, filenames, logs, or documentation.
- Do not add names, code, comments, or documentation references from external inspiration projects.
- Keep canonical frame and packet bytes owned by the existing `protocol`, `packet`, and `wire` packages.
- Add no dependency; use the Go standard library and existing modules.
- Bound every record, packet queue, byte queue, and control reservation before allocation or cryptographic state mutation.
- Return owned byte slices across package boundaries and never log payloads, keys, proofs, nonces, targets, or client identity.
- Preserve existing exported behavior and all existing conformance vectors.
- Do not wire this incremental slice into the production command or claim the single-hop stage complete.
- Preserve the user-owned untracked `route/zz_dump_conf_test.go` in the main checkout.

---

## File Map

- `transport/record.go`: opaque unsigned-24 record framing, limits, and serialized writes.
- `transport/record_test.go`: fragmentation, short-write, malformed-length, ownership, and concurrency tests.
- `transport/record_fuzz_test.go`: bounded arbitrary-prefix and arbitrary-body fuzz tests.
- `packet/key_update.go`: prepare/commit API that makes write-key rotation transactional.
- `packet/packet_test.go`: prepare/commit state and non-mutation tests.
- `session/application.go`: bounded application packet lifecycle and terminal state.
- `session/application_test.go`: packet round trip, replay, metadata, backpressure, cancellation, and close tests.
- `session/key_update.go`: local and received directional key-update orchestration.
- `session/key_update_test.go`: old-key update packet, new-key traffic, acknowledgement, duplicate, and exhaustion tests.
- `transport/duplex.go`: carrier-neutral record pumps and coordinated cancellation.
- `transport/duplex_test.go`: full-duplex paired-session integration, fragmentation, cancellation, and leak tests.
- `perf/session_benchmark_test.go`: application-session throughput and allocation baselines.
- `evidence/session.go`: bounded live session evidence result.
- `evidence/session_test.go`: deterministic result and resource-limit tests.
- `cmd/auroractl/main.go`: add a non-production evidence command only if the current command structure has an existing evidence switch; otherwise leave command code unchanged and invoke the evidence package from tests.

---

### Task 1: Bounded Opaque Record Codec

**Files:**
- Create: `transport/record.go`
- Create: `transport/record_test.go`
- Create: `transport/record_fuzz_test.go`

**Interfaces:**
- Produces: `NewRecordReader(io.Reader, uint32) (*RecordReader, error)`
- Produces: `(*RecordReader).Read() ([]byte, error)`
- Produces: `NewRecordWriter(io.Writer, uint32) (*RecordWriter, error)`
- Produces: `(*RecordWriter).Write([]byte) error`
- Produces: `DefaultMaxRecordBodyBytes`, `ErrEmptyRecord`, and `ErrRecordTooLarge`

- [ ] **Step 1: Write the failing reader and writer tests**

Create table tests that assert exact three-byte big-endian prefixes, one-byte-at-a-time fragmented reads, a writer that returns one byte per call, rejection of zero and `max+1` lengths before body allocation, rejection of a configured maximum above `0xffffff`, returned-slice ownership, and 32 concurrent writes that decode into 32 intact records.

Use this short writer in `transport/record_test.go`:

```go
type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}
```

- [ ] **Step 2: Run the focused tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-session-cache go test ./transport -run 'TestRecord|TestNewRecord' -count=1`

Expected: FAIL because the record constructors and sentinels do not exist.

- [ ] **Step 3: Implement strict unsigned-24 framing**

Implement constructors that normalize `max == 0` to `DefaultMaxRecordBodyBytes`, reject maxima above `0xffffff`, and reject nil readers or writers. `Read` uses `io.ReadFull` for the prefix and body, rejects zero and over-limit lengths before `make`, and returns a newly allocated body. `Write` rejects empty and over-limit bodies before locking, writes one prefix and one body under a mutex, retries short writes, and never retains the input.

The public shape must be:

```go
const DefaultMaxRecordBodyBytes uint32 = 1 << 20

var (
	ErrEmptyRecord    = errors.New("transport: empty record")
	ErrRecordTooLarge = errors.New("transport: record too large")
)

type RecordReader struct {
	r   io.Reader
	max uint32
}

type RecordWriter struct {
	mu  sync.Mutex
	w   io.Writer
	max uint32
}
```

- [ ] **Step 4: Add bounded fuzz targets**

Add `FuzzRecordReader` with a hard 4096-byte test maximum and `FuzzRecordRoundTrip` that caps generated bodies at 4096 bytes. The first target may return any documented parse error but must not panic; the second must return byte-identical owned output.

- [ ] **Step 5: Run formatting, unit tests, fuzz smoke, and race tests**

Run:

```bash
gofmt -w transport/record.go transport/record_test.go transport/record_fuzz_test.go
GOCACHE=/private/tmp/aurora-session-cache go test ./transport -run 'TestRecord|TestNewRecord' -count=1
GOCACHE=/private/tmp/aurora-session-cache go test ./transport -run '^$' -fuzz FuzzRecord -fuzztime=2s
GOCACHE=/private/tmp/aurora-session-cache go test -race ./transport
```

Expected: all commands pass with no race report.

- [ ] **Step 6: Commit the codec**

```bash
git add transport/record.go transport/record_test.go transport/record_fuzz_test.go
git commit -m "feat: add bounded carrier record codec"
```

---

### Task 2: Transactional Directional Key Updates

**Files:**
- Modify: `packet/key_update.go`
- Modify: `packet/packet_test.go`

**Interfaces:**
- Produces: `PreparedKeyUpdate`
- Produces: `(*DirectionState).PrepareUpdate(uint64, []byte, bool, uint64, time.Time) (PreparedKeyUpdate, error)`
- Produces: `(*DirectionState).CommitPreparedUpdate(PreparedKeyUpdate, time.Time) error`
- Preserves: `(*DirectionState).InitiateUpdate(uint64, []byte, bool, uint64) (protocol.KeyUpdate, error)`

- [ ] **Step 1: Write failing transactional-state tests**

Add tests proving that prepare does not change phase, material, drain state, or pending acknowledgement; commit changes them exactly once; committing against a changed source phase fails without mutation; committing the same preparation twice fails; preparation rejects active drain and phase `255`; and the existing `InitiateUpdate` behavior remains equivalent to prepare plus commit.

Capture state before each negative call and compare all exported fields plus `PendingKeyUpdateRetransmission` afterward.

- [ ] **Step 2: Run the focused tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-session-cache go test ./packet -run 'TestDirectionStatePrepare|TestDirectionStateCommit' -count=1`

Expected: FAIL because `PreparedKeyUpdate`, `PrepareUpdate`, and `CommitPreparedUpdate` do not exist.

- [ ] **Step 3: Add prepare and commit without duplicating derivation**

Use an opaque preparation token that owns cloned material and records the source identity:

```go
type PreparedKeyUpdate struct {
	Frame       protocol.KeyUpdate
	Next        KeyMaterial
	sourcePhase uint8
	sourceKey   []byte
	committed   bool
}
```

`PrepareUpdate` calls `expireDrain(now)`, rejects an active drain and phase
exhaustion, constructs and validates the next frame, derives next material, and
returns clones without mutating `DirectionState`. `CommitPreparedUpdate`
requires matching route, hop, direction, phase, and current key bytes before it
stores previous material, advances phase, starts `MaxDrainWindow`, and records
the pending update when acknowledgement is required.

Refactor `InitiateUpdate` to call prepare and commit with one `time.Now()` value.

- [ ] **Step 4: Run packet verification**

Run:

```bash
gofmt -w packet/key_update.go packet/packet_test.go
GOCACHE=/private/tmp/aurora-session-cache go test ./packet -count=1
GOCACHE=/private/tmp/aurora-session-cache go test -race ./packet
```

Expected: all existing and new packet tests pass.

- [ ] **Step 5: Commit transactional rotation**

```bash
git add packet/key_update.go packet/packet_test.go
git commit -m "feat: make write key updates transactional"
```

---

### Task 3: Bounded Application Packet Session

**Files:**
- Create: `session/application.go`
- Create: `session/application_test.go`

**Interfaces:**
- Consumes: `packet.Protector`, `packet.Receiver`, and `packet.DirectionState`
- Produces: `Config`, `DirectionConfig`, `Limits`, and `Application`
- Produces: `NewApplication(Config) (*Application, error)`
- Produces: `(*Application).QueueFrames(context.Context, protocol.FrameBlock) error`
- Produces: `(*Application).NextPacket(context.Context) ([]byte, error)`
- Produces: `(*Application).HandlePacket(context.Context, time.Time, []byte) ([]protocol.FrameBlock, error)`
- Produces: `(*Application).Close() error`
- Produces: `ErrBackpressure` and `ErrClosed`

- [ ] **Step 1: Write failing constructor and packet-round-trip tests**

Create paired configurations where client write material equals relay read
material and relay write material equals client read material. Tests must cover
invalid suite/direction/material/limits, owned key input, one frame-block round
trip, packet replay rejection, wrong route/direction/key phase, malformed
canonical packet bytes, failed-open non-mutation, and packet-number continuity.

Use explicit limits in every fixture:

```go
Limits{
	MaxQueuedPackets:       8,
	MaxQueuedBytes:         64 << 10,
	ControlReservedPackets: 1,
	ControlReservedBytes:   4 << 10,
	ReplayWindow:           64,
}
```

- [ ] **Step 2: Write failing backpressure and lifecycle tests**

Fill packet and byte capacity, assert `ErrBackpressure` without packet-number
advance, dequeue one packet and assert progress, cancel a blocked `NextPacket`,
close while callers wait, call close twice, and race queue/dequeue/close under
`go test -race`.

- [ ] **Step 3: Run the session tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-session-cache go test ./session -count=1`

Expected: FAIL because package `session` and its API do not exist.

- [ ] **Step 4: Implement validated construction and bounded queueing**

Define exact configuration fields:

```go
type DirectionConfig struct {
	Direction uint8
	Secret    []byte
	Key       []byte
	IV        []byte
}

type Config struct {
	Suite           uint64
	RouteInstanceID uint64
	HopLayer        uint8
	Write           DirectionConfig
	Read            DirectionConfig
	Limits          Limits
	Random          io.Reader
}
```

The application owns cloned key material, a `packet.Receiver`, per-phase write
packet numbers, an ordered `[][]byte` queue, exact queued bytes, one buffered
state-change channel, one closed channel, and one terminal error under a mutex.

`QueueFrames` validates before locking, computes a conservative encoded packet
reservation, checks context cancellation, and returns `ErrBackpressure`
immediately when capacity is unavailable. It seals only while capacity is
reserved, commits exact bytes, and signals readers. Data frames cannot consume
control-reserved capacity. `NextPacket` waits for a packet, close, or context
cancellation; after a dequeue it returns an owned packet, releases exact
capacity, and signals producers.

- [ ] **Step 5: Implement strict packet opening and terminal close**

`HandlePacket` rejects empty and over-limit input before decode, uses
`packet.Receiver.OpenWithDirectionState`, and returns a one-element owned block
slice only after complete validation. Any cryptographic or protocol error is
returned without closing the session; a caller chooses whether that peer error
is terminal. `Close` is idempotent, sets `ErrClosed`, zeroes owned key slices,
closes the notification channel exactly once, and wakes all waiters.

- [ ] **Step 6: Run unit and race tests**

Run:

```bash
gofmt -w session/application.go session/application_test.go
GOCACHE=/private/tmp/aurora-session-cache go test ./session -count=1
GOCACHE=/private/tmp/aurora-session-cache go test -race ./session
```

Expected: all tests pass with no race report.

- [ ] **Step 7: Commit the application session**

```bash
git add session/application.go session/application_test.go
git commit -m "feat: add bounded application packet session"
```

---

### Task 4: Session Key-Update Orchestration

**Files:**
- Create: `session/key_update.go`
- Create: `session/key_update_test.go`
- Modify: `session/application.go`

**Interfaces:**
- Consumes: `packet.PreparedKeyUpdate`
- Produces: `(*Application).InitiateKeyUpdate(context.Context, uint64) error`
- Extends: `(*Application).HandlePacket` to consume update and acknowledgement frames before returning application frames

- [ ] **Step 1: Write failing local-update tests**

Assert the update frame is sealed with the old write key and old phase, the
following data packet uses the new write key and phase, phase-specific packet
numbers begin at zero, a full data queue does not prevent the reserved control
update, a full control reserve returns `ErrBackpressure` without phase change,
and phase exhaustion returns an error without mutation.

- [ ] **Step 2: Write failing receive-update tests**

Assert a receiver opens old-phase update packets, rotates only its read
direction, queues an acknowledgement through the opposite write direction,
accepts byte-identical duplicates only during the drain window, rejects changed
duplicates and skipped phases, applies acknowledgements to the write state, and
does not return control frames to the flow dispatcher.

- [ ] **Step 3: Run the focused tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-session-cache go test ./session -run 'TestApplication.*KeyUpdate' -count=1`

Expected: FAIL because session key-update orchestration is absent.

- [ ] **Step 4: Implement control-reserved queueing and transactional send**

`InitiateKeyUpdate` reads 16 random bytes with `io.ReadFull`, reserves control
capacity, calls `PrepareUpdate`, encodes one key-update frame, seals it with the
current protector and old phase, commits the preparation only after queue
insertion succeeds, and releases the reservation on every error.

Use these internal helpers so normal and control queue accounting cannot drift:

```go
func (a *Application) queueBlock(ctx context.Context, block protocol.FrameBlock, control bool) error
func (a *Application) enqueueEncodedLocked(encoded []byte, control bool) error
func (a *Application) signalLocked()
```

- [ ] **Step 5: Implement received control handling**

After packet open, scan the validated block once. Decode key-update and
acknowledgement payloads with `wire.Reader`, require EOF, and apply them under
the session mutex. Generate acknowledgement nonces from the configured random
reader and enqueue acknowledgements through reserved control capacity. Return a
new block containing only non-key-control frames; return no block when all
frames were consumed internally.

- [ ] **Step 6: Run packet and session verification**

Run:

```bash
gofmt -w session/application.go session/key_update.go session/key_update_test.go
GOCACHE=/private/tmp/aurora-session-cache go test ./packet ./session -count=1
GOCACHE=/private/tmp/aurora-session-cache go test -race ./packet ./session
```

Expected: all tests pass with no race report.

- [ ] **Step 7: Commit key rotation**

```bash
git add session/application.go session/key_update.go session/key_update_test.go
git commit -m "feat: rotate application session keys"
```

---

### Task 5: Transport-Neutral Full-Duplex Pump

**Files:**
- Create: `transport/duplex.go`
- Create: `transport/duplex_test.go`

**Interfaces:**
- Consumes: Task 1 record codec and Task 3 application API
- Produces: `PacketEndpoint`
- Produces: `FrameBlockHandler`
- Produces: `RunPacketDuplex(context.Context, io.ReadCloser, io.WriteCloser, PacketEndpoint, FrameBlockHandler, uint32) error`

- [ ] **Step 1: Write failing paired-session integration tests**

Connect two paired `session.Application` values with two `io.Pipe` pairs. Queue
simultaneous frame blocks in both directions and assert both handlers receive
the exact blocks. Repeat with wrappers that fragment every read and write,
cancel while idle, cancel while one writer is blocked, inject one malformed
record, and close one endpoint. Assert all pumps terminate and the number of
goroutines returns to within two of the starting count after a bounded wait.

- [ ] **Step 2: Run the focused tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-session-cache go test ./transport -run 'TestRunPacketDuplex' -count=1`

Expected: FAIL because the duplex API does not exist.

- [ ] **Step 3: Implement coordinated reader and writer pumps**

Define transport-owned interfaces to avoid importing the concrete session type:

```go
type PacketEndpoint interface {
	NextPacket(context.Context) ([]byte, error)
	HandlePacket(context.Context, time.Time, []byte) ([]protocol.FrameBlock, error)
	Close() error
}

type FrameBlockHandler func(context.Context, protocol.FrameBlock) error
```

`RunPacketDuplex` derives a cancellable context, creates one `RecordReader` and
one `RecordWriter`, runs exactly one read pump and one write pump, cancels on
the first non-context error, closes both carrier halves and the endpoint once,
waits for both pumps, and returns the first stable error. Closing the carrier
halves is what unblocks an idle read or blocked write after cancellation. The
reader calls the handler in record order and never retains a block; the writer
emits complete records in packet order.

- [ ] **Step 4: Run transport and session race tests**

Run:

```bash
gofmt -w transport/duplex.go transport/duplex_test.go
GOCACHE=/private/tmp/aurora-session-cache go test ./transport ./session -count=1
GOCACHE=/private/tmp/aurora-session-cache go test -race ./transport ./session
```

Expected: all tests pass with no race or leak failure.

- [ ] **Step 5: Commit the duplex pump**

```bash
git add transport/duplex.go transport/duplex_test.go
git commit -m "feat: add persistent packet duplex pump"
```

---

### Task 6: Performance Evidence and Slice Review

**Files:**
- Create: `perf/session_benchmark_test.go`
- Create: `evidence/session.go`
- Create: `evidence/session_test.go`
- Modify: `.github/workflows/ci.yml` only if the existing production-evidence job needs an explicit session evidence invocation

**Interfaces:**
- Consumes: paired application sessions and `transport.RunPacketDuplex`
- Produces: `evidence.SessionResult`
- Produces: `evidence.RunSession(context.Context, SessionOptions) (SessionResult, error)`

- [ ] **Step 1: Write failing evidence and allocation tests**

Require `SessionOptions` to bound duration, message count, payload bytes,
concurrency, queue packets, and queue bytes. Assert zero or excessive values are
rejected. A 200-message paired run must report sent, received, bytes, duration,
throughput, p50, p95, peak queued bytes, goroutine delta, and errors. Add
`testing.AllocsPerRun` bounds for one packet queue/dequeue and one record
round trip, using measured baseline values plus at most 10 percent headroom.

- [ ] **Step 2: Run the focused tests and verify red**

Run: `GOCACHE=/private/tmp/aurora-session-cache go test ./evidence ./perf -run 'TestRunSession|TestApplicationSessionAlloc' -count=1`

Expected: FAIL because session evidence and benchmarks do not exist.

- [ ] **Step 3: Implement bounded in-memory live evidence**

Use paired sessions and fragmented `io.Pipe` wrappers, monotonic timing, the
existing percentile helper, and exact atomic counters. Cancel at the configured
deadline, join all goroutines, and reject results unless sent equals received
and errors are zero. Do not serialize payload bytes into the result.

- [ ] **Step 4: Add representative benchmarks**

Add these benchmarks with setup before `b.ResetTimer()`:

```text
BenchmarkApplicationQueueAndOpen1200
BenchmarkApplicationBidirectional64K
BenchmarkRecordRoundTrip1200
BenchmarkPacketDuplexParallel
```

Each benchmark calls `ReportAllocs` and keeps queue limits fixed.

- [ ] **Step 5: Run complete local verification**

Run:

```bash
gofmt -w perf/session_benchmark_test.go evidence/session.go evidence/session_test.go
git diff --check
GOCACHE=/private/tmp/aurora-session-cache go vet ./...
GOCACHE=/private/tmp/aurora-session-cache go test ./... -count=1
GOCACHE=/private/tmp/aurora-session-cache go test -race ./...
GOCACHE=/private/tmp/aurora-session-cache go test ./transport -run '^$' -fuzz FuzzRecord -fuzztime=10s
GOCACHE=/private/tmp/aurora-session-cache go test ./perf -run '^$' -bench 'Application|Record|Duplex' -benchtime=200ms -benchmem
GOOS=linux GOARCH=amd64 go test -c ./session -o /private/tmp/aurora-session-linux.test
GOOS=windows GOARCH=amd64 go test -c ./session -o /private/tmp/aurora-session-windows.test.exe
GOOS=darwin GOARCH=arm64 go test -c ./transport -o /private/tmp/aurora-transport-macos.test
GOOS=android GOARCH=arm64 go test -c ./transport -o /private/tmp/aurora-transport-android.test
```

Expected: every command passes.

- [ ] **Step 6: Commit evidence**

```bash
git add perf/session_benchmark_test.go evidence/session.go evidence/session_test.go .github/workflows/ci.yml
git commit -m "test: add persistent session evidence"
```

- [ ] **Step 7: Perform two-stage and final reviews**

For every task, dispatch one specification-compliance reviewer and one
code-quality reviewer, fix every P3-or-higher finding, and rerun the focused
tests. After Task 6, dispatch a fresh whole-slice review covering concurrency,
cryptographic mutation ordering, replay, queue accounting, ownership,
cancellation, and cross-platform behavior. Record zero unresolved P3-or-higher
findings before integration.

- [ ] **Step 8: Merge, push, and verify remote CI**

Fast-forward `main` only after preserving the main checkout's untracked route
test. Push `main`, inspect every GitHub Actions matrix job and production
evidence job, fix any failure on the feature branch, and repeat until the commit
is green remotely. Remove the feature worktree only after local and remote
verification succeed.

---

## Next Slice Boundary

After this plan is green and integrated, the next implementation plan composes
the live TLS/HTTP binding and randomized first-hop handshake into the duplex,
followed by a separate relay-egress and process-composition plan. Neither paired
application secrets nor in-memory pipes satisfy those remaining production
gates.
