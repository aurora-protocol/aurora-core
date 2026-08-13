# Linux Local Proxy Design

## Purpose

Provide a runnable Linux client process that turns an authenticated Aurora
carrier into local HTTP CONNECT and SOCKS5 TCP proxy services. The process
must use the same validated provisioning, handshake, issuer, packet, and
frame logic as native clients. It must not add protocol logic to the command
layer.

## Scope

This increment establishes a reusable provisioned-session lifecycle and a
bounded TCP proxy runtime. UDP association serving, a local DNS listener, and
privileged TUN route management remain separate follow-up increments. Existing
packet-tunnel DNS transport stays unchanged.

## Architecture

`client.ProvisionedSession` owns a single deferred client handshake. It accepts
validated provisioning, emits a bounded issuer request only after relay
authentication, validates the issuer response, then exposes the established
application and carrier streams. It owns cancellation and securely disposes of
the handshake state and proof material on every terminal path.

`client.TCPProxyRuntime` owns local listeners and a set of bounded TCP flow
mappings. For each CONNECT or SOCKS5 request it allocates an opaque flow ID,
queues a `FLOW_OPEN`, relays stream data over the established application, and
writes authenticated backward stream data to the matching local connection.
The carrier reader and writer are driven by the existing packet duplex. The
runtime treats unknown flow frames, malformed local handshakes, frame dispatch
errors, and carrier termination as connection or runtime failures without
logging sensitive protocol material.

`cmd/aurorac` is a Linux-only composition root. It reads a restricted
provisioning file, submits issuer work through an HTTPS client that neither
caches nor follows redirects, starts the provisioned session, and binds
loopback-only proxy listeners by default. It contains no cryptographic or
frame encoding logic.

## Data Flow

1. The command reads one bounded provisioning bundle from an owner-restricted
   file and starts `ProvisionedSession`.
2. The portable handshake opens the pinned carrier and returns issuer work.
3. The command posts the opaque issuer request, then returns its opaque
   response to `ProvisionedSession`.
4. Once established, the runtime accepts a local TCP proxy request, creates a
   flow, queues `FLOW_OPEN`, and forwards local reads as `STREAM_DATA`.
5. The packet duplex decrypts backward frames and dispatches stream bytes to
   the owning local connection. Peer close frames close that connection and
   release its mapping.
6. Shutdown cancels listeners, closes local connections, terminates carrier
   streams, and zeroes owned request material.

## Limits And Failure Handling

- Proxy listeners default to loopback addresses and reject wildcard binds
  unless an explicit opt-in is provided.
- The runtime has explicit limits for active flows, local read buffer size,
  and per-connection pending write bytes.
- Local HTTP accepts only CONNECT and SOCKS5 accepts only no-auth CONNECT.
- A failed local request never queues a flow frame. A failed flow open closes
  its local connection and releases its flow ID.
- A terminal carrier error closes all mapped local connections and makes new
  accepts fail.
- The command validates restrictive provisioning file permissions before it
  reads sensitive material and does not print provisioning, issuer, or frame
  contents.

## Tests

- Unit tests cover issuer-work lifecycle, issuer response rejection, duplicate
  completion, and terminal cleanup.
- Runtime tests use in-memory carriers and connections to prove HTTP CONNECT
  and SOCKS5 TCP byte forwarding, peer-close propagation, flow-limit
  enforcement, malformed local handshakes, and carrier-failure cleanup.
- Command tests cover Linux gating, loopback bind defaults, rejected public
  binds, file-permission checks, and status-only diagnostics.
- Integration tests run a real client packet duplex against the strict
  first-hop relay fixture and a local TCP echo target.
