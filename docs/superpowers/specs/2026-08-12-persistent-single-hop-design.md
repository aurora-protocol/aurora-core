# Persistent Single-Hop Session Design

## Objective

Replace the request/response packet-exchange shortcut with a long-lived,
authenticated single-hop session that carries canonical encrypted packets over
an ordinary HTTP/2 cover request. The delivered path must bound memory, apply
backpressure, reject replay, rotate directional keys, cancel cleanly, and drive
real TCP and UDP egress without moving protocol ownership into the HTTP or
socket adapters.

This stage is complete only when separate client and relay processes exchange
TCP and UDP traffic through the session and pass replay, key-update,
cancellation, malformed-input, impairment, race, and sustained-load gates. Unit
tests using pre-established application secrets are incremental evidence, not a
substitute for the authenticated process-level path.

## Current Boundary

The repository already provides canonical bootstrap messages, handshake and
application key derivation, signature and hybrid-share verification, admission
and replay primitives, packet protection, packet-number replay windows,
directional key updates, proxy-flow frames, bounded flow scheduling, cover
request selection, and relay flow-policy validation. These components are
tested independently.

The executable path does not compose them. The server accepts a clear carrier
type and a complete packet batch, invokes a loopback or device exchanger, and
returns one complete response. Its command constructs a harness issuer even
outside readiness checks. The relay flow handler emits destination events but
does not own destination sockets. No component owns the lifecycle of an
authenticated, persistent application session.

## Approaches Considered

### Extend Packet-Batch Request/Response

Repeated HTTP requests could retain the existing carrier and add a session ID.
This is rejected because it preserves polling latency, creates an avoidable
replay and correlation surface, cannot provide natural bidirectional
backpressure, and keeps the production path dependent on the harness
exchanger.

### Put Session State in the HTTP Handler

The HTTP adapter could derive keys, decode frames, and open destination
sockets. This is rejected because protocol state would become inseparable from
one carrier, native clients could not reuse it, and cancellation or transport
replacement would risk mutating cryptographic state inconsistently.

### Portable Session with Opaque Carrier Bytes

The selected approach introduces a transport-neutral session core. It consumes
and emits canonical bootstrap or packet payloads while the HTTP/2 adapter owns
only TLS binding inputs, bounded record I/O, flushing, deadlines, and
cancellation. A relay egress adapter consumes validated flow events and returns
frames. This preserves one protocol implementation and creates the ownership
boundary needed by Linux, Swift, and a later measured Rust component.

## Architecture

### Carrier Record Layer

The persistent request and response bodies are sequences of records:

```text
record_length: unsigned 24-bit big-endian
record_body:   record_length opaque octets
```

The layer adds no cleartext protocol marker, message type, session ID, or
destination metadata. Session state determines the expected canonical body:

```text
client request:  prelude0 -> capsule1 -> forward application packets
relay response:  prelude1 -> capsule2 -> backward application packets
```

The record prefix exists only to recover message boundaries from a byte stream;
it is not part of any canonical protocol object. Record sizes are checked
before allocation. The configured maximum cannot exceed the canonical
three-octet length domain and defaults to one mebibyte. Empty records are
invalid. Writers serialize complete records under one lock, retry short writes,
and never retain caller-owned slices. Readers accept arbitrary fragmentation
and return an owned body.

Cover-template envelope and record-size policies remain responsible for
visible sizes, padding, timing, and chunking. The codec does not invent its own
padding policy.

### First HTTP/2 Binding Profile

The baseline carrier uses TLS 1.3 and one full-duplex HTTP/2 POST selected from
a verified gateway-owned cover request class. Production configuration supplies
the authority, path template, request class, method family, and cover response;
there is no production default tunnel path.

The standard HTTP server does not expose arbitrary HTTP/2 stream identifiers.
The first profile therefore makes the carrier the first and sole request on a
fresh TLS connection. Both peers use stream identifier `1`, and the relay
accepts it only when a connection-scoped gate atomically claims the first
request. Any earlier request consumes that claim, so a later carrier attempt
falls through to ordinary cover behavior. The client uses a fresh transport,
disables session resumption, and does not pool the connection. The relay also
rejects non-TLS, non-HTTP/2, resumed, or multiply claimed carrier connections.
After a carrier claim succeeds, any second request on that connection cancels
the active carrier before receiving ordinary cover behavior.

Both peers derive the existing outer exporter and channel identifier from the
live TLS connection. The resumption-secret contribution is zero because
resumption is disabled for this profile. Binding construction remains in the
handshake package; the HTTP adapter only supplies authenticated transport facts
and the template-selected request metadata.

This restriction is intentionally narrow. A future carrier may expose real
stream identifiers through a lower-level adapter, but it must pass the same
binding interface and tests before allowing pooled or concurrent streams.

The server does not send response headers until Prelude0 is structurally
valid, bound to the live stream, and its access hint is atomically spent. An
invalid initial body can therefore return the configured ordinary cover
response. After a valid prelude begins a streaming response, later failures
cancel the stream with bounded timing and no secret-bearing response or log.

### Handshake Driver

The client driver owns this state transition:

```text
load verified descriptor and template
open bound carrier
generate ephemeral classical and decapsulation keys
send Prelude0
verify Prelude1 signatures and hybrid shares
derive handshake secrets
send encrypted Capsule1 with admission and client finished
verify encrypted Capsule2 and server finished
derive application secrets
start application session
```

Admission proof, replay proof, policy offer, transport hints, route metadata,
destination metadata, and application packets cannot be emitted before Prelude1
verification succeeds.

The relay driver validates the request class and binding, resolves exactly one
access-hint credential, atomically spends the hint before sending Prelude1,
generates its ephemeral shares, signs the transcript with configured epoch
keys, verifies and spends the admission/replay proof after opening Capsule1,
computes Capsule2, and creates the application session only after all checks
pass. Replay-store uncertainty and verifier failure fail closed.

Harness credentials and deterministic randomness are injectable only through
test constructors. Production constructors require cryptographic randomness,
verified metadata, non-memory replay storage, and externally configured private
key providers.

### Application Session

`session.Application` owns both directional packet states:

```text
suite, route instance, and hop layer
write protector and write key state
read receiver and read key state
bounded outbound packet queue
close state and terminal error
```

Its public operations are:

```text
QueueFrames(ctx, FrameBlock) error
NextPacket(ctx) (encodedPacket, error)
HandlePacket(now, encodedPacket) ([]FrameBlock, error)
InitiateKeyUpdate(ctx, reason) error
Close() error
```

Queueing validates the complete frame block and reserves conservative byte and
packet capacity before state mutation. Packet sealing and packet-number
advancement occur only while that reservation is held; a sealing failure
releases it, and successful sealing commits the exact encoded size. A full
queue returns a typed backpressure error; it never grows and never silently
drops stream data. Realtime datagram expiry is handled by the existing flow
scheduler before queueing.

Opening checks canonical encoding, route metadata, packet-number replay, AEAD,
frame direction, and key-update consistency before emitting frames. Duplicate
or stale packets do not mutate flow state. Received key updates rotate only the
read direction and enqueue an acknowledgement using the write direction.
Locally initiated updates are sealed with the old write material, then activate
the new write material with the existing bounded drain and retransmission
rules. Key phases cannot wrap.

The object has one lifecycle owner. Close is idempotent, wakes blocked callers,
zeroes owned key slices where practical, and guarantees that no operation can
emit data after terminal failure.

### Relay Egress

`relay.Egress` consumes only validated `ExitFrameEvent` values. Its production
implementation owns a bounded map of flow ID to destination socket and applies
the already selected exit policy before dialing.

TCP behavior:

- `FLOW_OPEN` uses a context-bounded dial and starts one bounded read pump;
- `STREAM_DATA` performs deadline-bounded writes and preserves per-flow order;
- destination reads become backward `STREAM_DATA` frames through the session
  queue;
- half-close is used when supported, and `FLOW_CLOSE` releases the socket once;
- per-flow and session byte limits prevent an idle or blocked destination from
  retaining unbounded memory.

UDP behavior:

- one connected UDP socket is created per accepted association;
- an IP target is authoritative, while domain resolution occurs only for the
  explicitly selected relay-resolved mode;
- request datagrams are written to the connected target and responses retain
  flow-ID demultiplexing;
- HTTP/2 carries UDP as encrypted stream-fallback packets;
- read deadlines and idle expiry close stale associations;
- address changes, private-address resolution, and policy changes fail closed.

DNS is not silently delegated to the host resolver when the flow mode requires
client-authoritative addressing. Every goroutine and socket belongs to the
session context and is joined during shutdown.

### Process Composition

Production and harness construction remain separate. `aurorad` receives a
production configuration containing TLS identity, verified relay and cover
metadata, epoch signing keys, hint credential lookup, admission verifier,
durable replay stores, exit policy, queue limits, dial limits, and cover origin.
It cannot select loopback exchange or harness issuer modes.

A portable client command initially exposes a local explicit proxy for
process-level tests and Linux operation. TUN integration feeds the same
proxy-flow/session API after packet parsing; it does not send raw TUN packet
batches through the old exchanger. The old request/response carrier remains
available only to readiness and compatibility tests until all callers migrate,
then is removed from production builds.

## Concurrency and Resource Model

- One goroutine reads each carrier direction; one serial writer owns each body.
- Packet and frame validation occurs synchronously before dispatch.
- All queues have explicit packet and byte limits.
- Every dial, read, write, and shutdown operation has a context or deadline.
- Session cancellation closes the request body, response body, egress sockets,
  queues, and worker goroutines exactly once.
- The relay caps concurrent sessions, flows per session, aggregate queued
  bytes, record size, frame count, and destination I/O rate.
- A protocol failure becomes one terminal session error; secondary close errors
  never replace it.
- Diagnostics use stable failure classes and counters only. They exclude
  payloads, keys, proofs, nonces, target names, and client addresses.

## Error Behavior

Before a valid bound Prelude0, every wrong method, path, request class, TLS
property, record, hint, or share maps to the configured ordinary cover handler.
The handler consumes at most the configured body limit and does not forward a
failed gateway-owned body to a remote origin.

After authentication begins, malformed capsules, finished mismatches, replay,
bad packets, skipped key phases, unsupported frames, policy denial, and overload
terminate or close the affected flow according to their existing failure class.
No error string is written to the public carrier. Local callers receive typed
errors suitable for retry policy without secret data.

## Verification

The implementation proceeds test first and adds these gates:

1. fragmented record round trips, short writes, truncation, zero length,
   over-limit length, cancellation, and allocation bounds;
2. application packet round trips, duplicate rejection, wrong direction,
   failed-open non-mutation, queue backpressure, close races, directional key
   rotation, lost acknowledgements, and phase exhaustion;
3. live TLS HTTP/2 full-duplex exchange with exporter agreement, first-stream
   claim enforcement, cover fallback, cancellation, slow reader/writer, and no
   goroutine leak;
4. real randomized client/relay handshake with wrong signatures, malformed
   hybrid shares, replayed hints and proofs, wrong finished values, unavailable
   stores, and strict release ordering;
5. loopback TCP and UDP destination exchange through encrypted packets, policy
   denial, blocked writes, idle expiry, half-close, and session shutdown;
6. separate-process client/relay tests with key rotation and reconnect;
7. deterministic latency, loss, fragmentation, and cancellation impairment;
8. sustained race-enabled load with throughput, latency, allocations, RSS,
   goroutine, queue-depth, reconnect, and error evidence;
9. Linux, macOS, Windows, Android, and iOS build gates for the portable core,
   followed by Linux runtime and Apple native integration in the next stage.

Every commit receives a behavior review and a code-quality review. The branch
receives a final P3-or-higher review after full tests, race tests, coverage,
fuzz smoke, vulnerability scanning, cross-platform builds, and live load
evidence pass.

## Delivery Order

1. bounded record codec;
2. application-session packet and key lifecycle;
3. live HTTP/2 duplex and binding facts;
4. randomized first-hop handshake driver;
5. TCP and UDP egress;
6. production server and portable client composition;
7. TUN migration, impairment, load, and release evidence.

Each item is independently reviewed and committed. Production CLI selection is
changed only after the authenticated process-level path passes, so partial work
cannot accidentally relabel a harness as production-ready.
