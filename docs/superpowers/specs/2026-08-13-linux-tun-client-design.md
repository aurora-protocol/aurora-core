# Linux TUN Client Design

## Purpose

Provide a Linux client command that carries system IP traffic through one
authenticated Aurora session. The command reuses validated provisioning, the
pinned carrier, the encrypted packet duplex, and the existing packet adapter.
It does not add protocol encoding, cryptographic state, or a parallel flow
implementation to the command layer.

## Scope

`aurorac tun` creates and configures a Linux TUN interface, establishes a
provisioned session, and routes IPv4 and IPv6 traffic through that session. It
uses the TCP, UDP, fake-IP, and encrypted DNS behavior already implemented by
`client.PacketAdapter`. It complements, rather than replaces, the existing
local HTTP CONNECT and SOCKS5 proxy command.

The command does not edit system resolver configuration. DNS packets selected
by the tunnel route are captured by the packet adapter and carried as encrypted
DNS frames. It refuses to start on an unsafe or unsupported route layout rather
than silently exposing the carrier or creating a forwarding loop.

## Architecture

`client.PacketTUNRuntime` is portable packet-device orchestration. It owns a
bounded device read loop, sends captured packets to `PacketAdapter.Ingress`,
writes synthetic local responses, and provides a frame-block callback for
`transport.RunPacketDuplex`. A mutex serializes TUN writes because synthetic
TCP packets and relay responses can arrive concurrently. The runtime closes the
device on terminal shutdown, unblocking its read loop.

`cmd/aurorac` is the Linux composition root. Before it installs tunnel
defaults, it parses the relay origin from validated provisioning, resolves its
numeric addresses, and asks Linux for each current route. It then opens the
pinned carrier and completes issuer authentication on the pre-existing network.
Only after session establishment does the command configure the TUN link, add
exact relay bypass routes, and add lower-metric IPv4 and IPv6 defaults through
the TUN.

Linux route management uses the system `ip` executable with fixed arguments
and structured JSON output. It is isolated behind an injected runner so tests
can validate command order and rollback without privileges. The production
runner resolves `ip` only from standard absolute system locations. It never
uses a caller-controlled command path.

## Route Safety

1. Relay addresses are resolved before a default route is installed. The
   command deduplicates and bounds the address list, rejects unspecified,
   multicast, and link-local relay addresses, and leaves loopback addresses to
   the kernel local table.
2. For every non-loopback relay address, `ip -j route get` must return a
   concrete non-tunnel device and an IPv4 or IPv6 next hop of the correct family
   when one is required. Non-main routing tables are refused because a reliable
   cleanup and precedence guarantee cannot be made from the available route
   information.
3. Existing default routes are inspected before setup. The tunnel default
   receives a metric strictly lower than every existing default for that IP
   family. A default with metric zero prevents safe precedence and causes a
   fail-closed error rather than an ambiguous equal-cost route.
4. Setup order is relay bypasses, link address and MTU, then tunnel defaults.
   Any failure removes only entries successfully added by this process in the
   reverse order. The command uses `route add`, never `replace`, so it
   cannot overwrite an operator-managed route.
5. Normal shutdown first deletes the exact owned defaults and bypasses, then
   closes the TUN device and established session. Every cleanup error is
   retained for the caller; sensitive provisioning and issuer buffers are
   zeroed.

## Data Flow

1. `aurorac tun` validates Linux-only flags and reads a restricted native
   provisioning file.
2. It resolves relay IPs and snapshots their current non-tunnel routes.
3. The command starts `ProvisionedSession`, submits opaque issuer work using
   the existing no-redirect HTTPS transport, then receives an established
   application and carrier.
4. The command creates the TUN device, configures owned routes, and starts
   `PacketTUNRuntime`.
5. A local device packet enters `PacketAdapter.Ingress`; any synthetic
   response is written back to the device; the existing packet duplex sends the
   resulting encrypted packet through the carrier.
6. The packet duplex decrypts relay records, calls
   `PacketTUNRuntime.HandleFrameBlock`, and the adapter creates the IP packets
   written to the TUN device.
7. Carrier, device, or signal termination cancels both pumps, cleans owned
   routes, closes the device and carrier, and releases the session.

## Limits And Failure Handling

- The Linux interface uses the existing validated `platform.LinuxTUNConfig`.
- Default addresses are host prefixes and are configurable only as IPv4 /32
  and IPv6 /128 values. MTU is validated by the platform configuration and is
  also the packet runtime read bound.
- Relay DNS resolution, relay addresses, route lookup count, TUN packet size,
  and packet-adapter flow count are bounded.
- The command prints only interface and lifecycle status. It never prints
  provisioning, issuer material, carrier URLs, route response bodies, or
  encrypted frames.
- The device read loop treats malformed local IP packets, short device writes,
  and unexpected device errors as terminal errors. Existing kernel TCP
  retransmission handles a packet that is not accepted before an application
  frame is queued.
- Linux host gating happens before provisioning access. Non-Linux builds still
  compile the command but reject `tun` deterministically.

## Tests

- `client` unit tests use paired session applications and an in-memory packet
  device to prove captured TCP opens an encrypted flow, synthetic packets are
  written once, relay frame blocks return IP packets, short writes fail, and
  closing the runtime unblocks a pending device read.
- `cmd/aurorac` unit tests inject the Linux command runner, resolver, TUN
  opener, and provisioned-session composition boundary. They prove Linux
  gating, flag validation, route JSON rejection, command ordering, route
  rollback, relay-bypass precedence, no unsafe command path, and shutdown
  cleanup.
- A strict first-hop integration test sends a packet-adapter TCP flow through
  the real encrypted packet duplex and relay fixture, proving the new TUN
  runtime shares the established application instead of constructing a second
  session.
- The delivery gate runs full Go tests, focused race tests, vet,
  cross-platform builds, fuzz smoke, repository review, and hosted CI.

