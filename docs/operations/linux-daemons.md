# Linux Daemons

`aurorad serve` and the private `aurorad issuer` backend are designed to run as
independent unprivileged system services. The supplied units use the `aurora` account,
dedicated persistent replay-state directories, strict file permissions, a
controlled restart policy, and process sandboxing. They listen only on
unprivileged ports, so they require no network-related capabilities.

## Install

Build or obtain the reviewed `aurorad` binary, then install it as root-owned:

```sh
install -o root -g root -m 0755 aurorad /usr/local/bin/aurorad
useradd --system --home-dir /var/lib/aurora --shell /usr/sbin/nologin aurora
install -d -o aurora -g aurora -m 0700 /etc/aurora
install -o root -g root -m 0644 deploy/systemd/aurorad-relay.service /etc/systemd/system/
install -o root -g root -m 0644 deploy/systemd/aurorad-issuer.service /etc/systemd/system/
```

Copy the relevant example to its final name, replace every placeholder with
the deployment's verified values and paths, then make the file readable only
by the service account:

```sh
install -o aurora -g aurora -m 0600 deploy/systemd/relay.json.example /etc/aurora/relay.json
install -o aurora -g aurora -m 0600 deploy/systemd/issuer.json.example /etc/aurora/issuer.json
```

Each file is one JSON object with an `arguments` array. It is the sole
argument source: `--config` cannot be combined with command-line settings,
cannot recursively select another file, rejects unknown or duplicated JSON
fields and repeated command options, and is opened as a regular owner-only
file. It contains file paths and operational settings, not private key
contents.

All private key, access-hint, and replay-state inputs must be regular files
or directories owned by `aurora` with mode `0600` or `0700` as appropriate.
Public deployment objects may remain root-owned and readable by the service.
The units create `/var/lib/aurora-relay` and `/var/lib/aurora-issuer` with
mode `0700`; do not delete or replace their replay-state files while either
service is stopped or running.

Enable only the roles that the host serves:

```sh
systemctl daemon-reload
systemctl enable --now aurorad-relay.service
systemctl enable --now aurorad-issuer.service
systemctl status aurorad-relay.service aurorad-issuer.service
```

The units send `SIGTERM` during a normal stop and allow 20 seconds before the
service manager escalates. The daemon stops accepting work, closes active
relay state, and has a 15-second internal shutdown budget. Inspect failures
through the journal without echoing private configuration contents:

```sh
journalctl -u aurorad-relay.service -u aurorad-issuer.service --since today
```

Do not use the diagnostic `harness` command in either service unit.

## Private issuer backend boundary

`aurorad issuer` is not a public issuer URL and does not complete the
production cover-slot requirement by itself. It is a loopback-only Blind-RSA
signing backend for a separately deployed public cover gateway. That gateway
remains an explicit external integration boundary: it must admit issuance only
after the verified, nontrivial cover-slot predicate required by Section 35.6.1,
without exposing a standalone public path, media type, status, or timing
discriminator for issuer traffic. Public cover-gateway admission and deployment
are incomplete in this repository.

The backend accepts exactly one operation from an authenticated gateway:
HTTP/2 over TLS 1.3, `POST /`, `application/octet-stream`, and an exact
89-byte carrier containing type `0x04` plus its 88-byte Blind-RSA request. A
successful response is carrier type `0x05`. All routes associated with health,
metadata, JSON issuance, verifier, spend, packet exchange, or diagnostics are
absent and receive the same empty redacted failure. Do not point public clients
at this listener and do not use one of those routes as a readiness probe.

Keep `--listen` on a literal loopback address. Wildcards, hostnames, and
non-loopback addresses fail before files are loaded or a socket is opened. Set
`--gateway-client-ca` to a dedicated certificate-signing CA containing only the
trust roots used for gateway client identities; the gateway must present a
client-auth certificate chaining to that CA. The server certificate and client
CA are separate inputs. TLS is fixed to version 1.3 with h2-only ALPN, required
and verified client certificates, and disabled session tickets. The supplied
systemd unit additionally denies all process IP traffic except IPv4 and IPv6
loopback.

`--max-concurrent-issues` bounds global private-key operations for the process
and must be between 1 and 64; the example uses 16. HTTP connection, stream,
header, read, write, and idle limits provide separate outer bounds.
Authenticated HTTP/2 requests that reach the backend handler but fail its
method, path, media-type, body-size, cancellation, readiness, or signing checks
receive the same empty redacted response. Client-certificate and ALPN failures
terminate during TLS negotiation before any application response; malformed
HTTP/2 framing and server resource-limit failures can likewise terminate before
the handler. None of these paths exposes key material.

The `auroractl issuer-check`, `issuerd-check`, and `issuerd-http-check`
commands are deterministic lab/self-test harnesses. Their health and metadata
checks describe those harnesses, not this production backend and not live
gateway readiness. Monitor the service process and journal locally; validate
end-to-end public issuance at the external cover gateway without adding a
public backend probe route.
