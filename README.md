# Aurora Prototype

This repository is the portable Go monorepo for the Aurora prototype. It contains the shared protocol core plus the local client engine, relay services, operational helpers, and generated vectors.

Implemented now:

- canonical Section 9 wire encoding and decoding with opaque8/16/24, vector element-count, reserved enum rejection, bootstrap critical extension rejection, and all-object canonical round-trip coverage;
- Appendix A registry constants;
- `PublicKeyRecord`, `AuthorityKeyRecord`, `ObjectSignature`, admission, replay, policy, frame, flow, route-envelope, packet, and key-update structures;
- `DirectoryConsensus`, `RelayDescriptor`, `CoverTemplate`, routing records, cover profiles, and canonical trust-chain hash/signature inputs;
- Appendix B.4 and B.5 structural vectors;
- SHA-384/SHA-512 suite hashes, TLS-style HKDF labels, AES-256-GCM, route-prelude wrapping, packet protection, standard-library ML-KEM wrappers with CIRCL agreement checks, and ML-DSA verification;
- AccessHint computation, spent-hint cache, token redemption hash, token spent key, replay context hash, and bootstrap dedup key;
- first-hop and split-route prelude transcript hashing, sealed control capsules, Finished messages, application traffic secret derivation, first application packet vectors, and exit-layer packet vectors;
- signed real-crypto metadata vectors for directory consensus, relay descriptors, and cover templates;
- negative-vector generation and checks for malformed public keys, wrong key encodings, wrong signatures, wrong AEAD tags, and replay;
- policy profiles, PAL scoring, PACE reference behavior, local config parsing, threat-safe logging wrappers, `auroractl`, a runnable Linux local proxy client with HTTP CONNECT and SOCKS5 TCP/UDP-association listeners, client FLOW_OPEN frame emission, relay frame-block flow demux, fake-IP mapped UDP flow integration, UDP target confirm TTL enforcement, synthetic local DNS forwarder responses, negative-cache-aware local DNS responses, P5 split-route conformance harness, P6 proxy-flow conformance harness, P0 host build matrix checks, cover-template-validated H2/H1/shadow-origin/H3 datagram and explicitly gated MASQUE carrier request builders, shared opaque carrier session adapters, append-only file replay cache, relay admission/exit gates, protocol decode fuzz harness, HTTP cover-origin gateway handler, gateway-backed active-probe harness, deterministic DPI/classifier baseline harness, external evaluation evidence verifier, deployment security assessment evidence verifier, platform adapter conformance profiles, packet-to-core platform ABI forwarding, platform packaging and entitlement conformance matrix, release readiness evidence verifier, Privacy Pass Blind RSA production proof harness, private proof-type validation gates, issuer operations conformance harness, issuer service lab-readiness harness, issuer HTTP lab-handler readiness harness, a loopback-only gateway-mTLS Blind-RSA production backend, runnable Linux server harness, live HTTP/HTTPS server-client interop harness, binary issuer verifier mTLS handler, cover-origin deployment conformance harness, vector drift tests, P9 measured cover production-candidate threshold gate, P10 deterministic performance/bad-path impairment harness (loss/jitter/UDP-blocked/QUIC-blocked/HoL/overload/peak-hour/carrier-cache scenarios with interactive-priority, UDP stale-drop, reconnect-storm-free downgrade, block-suspect cooldown, and padding-under-congestion acceptance), P11 prototype-interop release-gate checklist plus the aggregate `p0-p11-check`, and ops helpers.

## Layout

- `admission`, `crypto`, `flow`, `handshake`, `packet`, `policy`, `protocol`, `route`, `transport`, `trust`, and `wire`: portable protocol implementation.
- `client`: local-interface-neutral client engine.
- `platform`: thin platform adapter contracts for local proxy and packet interfaces.
- `relay`: relay-side cover, admission, and exit-policy gates.
- `server`: runnable prototype/readiness handler combining cover-origin fallback and an opaque diagnostic carrier; the public production gateway and its verified cover-slot admission predicate remain external.
- `ops`: operational verifier and directory helper logic.
- `vectors`: generated structural vector bundle and drift tests.
- `mobile/auroracore`: C-archive (`buildmode=c-archive`) binding exposing the portable wire, AdmissionProof, and opaque issuer-carrier codec to native thin adapters (e.g. the Apple `AuroraCore.xcframework`), so platform adapters never reimplement protocol logic (Section 35.10).
- `cmd/aurorac`: Linux local proxy and TUN client process using an owner-only native provisioning file.
- `cmd/auroractl`: local vector, config, and capability diagnostics.

Native app or driver repositories should be split out only when they need their own platform build systems.

This is not a production VPN or circumvention client. The spec still requires independent cryptographic review, a public cover-neutral gateway with verified cover-slot admission, external issuer/gateway deployment and live token issuance, signed platform release artifacts and device provisioning, real deployment security assessment, external active-probe evaluation, and external DPI/classifier evaluation before production use.

## Commands

Use a workspace-local Go build cache in sandboxed environments:

```bash
GOCACHE=/private/tmp/aurora-gocache go test ./...
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl vectors
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl vectors --check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl vectors --negative --check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl negative-vectors-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl wire-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl transport-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl flow-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl route-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl host-build-check --portable
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl classifier-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl evaluation-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl deployment-security-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl platform-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl packaging-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl release-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl proof-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl issuer-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl issuerd-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl issuerd-http-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl server-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl client-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl cover-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl perf-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl release-gate-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl p0-p8-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl p0-p11-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/aurorad harness --readiness-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/aurorad serve --listen 0.0.0.0:9443 --authority cover.example:443 --path /assets/upload/42 --tls-cert /path/fullchain.pem --tls-key /path/privkey.pem --cover-origin-url https://cover.example --relay-descriptor /etc/aurora/relay-descriptor.bin --trusted-descriptor-hash /etc/aurora/relay-descriptor.hash --cover-template /etc/aurora/cover-template.bin --template-authority-key /etc/aurora/template-authority-key.bin --request-class 7 --suite 2 --classical-signer-key /etc/aurora/epoch-classical.pem --pq-signer-key /etc/aurora/epoch-pq.bin --access-hints /etc/aurora/access-hints.bin --token-verification-key /etc/aurora/token-verification-key.der --hint-spent-cache /var/lib/aurora/hint-spent.log --token-spent-cache /var/lib/aurora/token-spent.log --bootstrap-cache /var/lib/aurora/bootstrap-replay.log --max-sessions 256
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/aurorad issuer --listen 127.0.0.1:9444 --tls-cert /etc/aurora/issuer-cert.pem --tls-key /etc/aurora/issuer-key.pem --gateway-client-ca /etc/aurora/gateway-client-ca.pem --issuer-metadata /etc/aurora/issuer-metadata.bin --metadata-authority-key /etc/aurora/issuer-authority-key.bin --blind-rsa-key /etc/aurora/issuer-blind-rsa.pem --spent-token-cache /var/lib/aurora-issuer/spent-token.log --relay-bucket-id 00000000000000000000000000000000 --origin-info-policy 1 --max-concurrent-issues 16
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/aurorac proxy --provisioning-wallet /etc/aurora/client-wallet.bin --wallet-state /var/lib/aurora/client-wallet-state.bin
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/aurorac tun --provisioning-wallet /etc/aurora/client-wallet.bin --wallet-state /var/lib/aurora/client-wallet-state.bin
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl capabilities
```

`aurorad harness` is a local diagnostic surface. `aurorad serve` is the Linux production entry point: it requires a verified canonical deployment, both epoch signing keys, bounded access-hint credentials, a validated admission verification key, three independent durable replay caches, TLS, a cover origin, and an explicit concurrent-session limit. Private key and access-hint files must be regular files with owner-only permissions. The daemon rejects harness flags, loopback listen addresses, malformed objects, mismatched epoch keys, and missing production dependencies before binding its socket. Egress defaults are bounded and deny private destination ranges; use `aurorad serve --help` to tune the explicit queue, rate, timeout, and destination-policy limits. The `serve` and `issuer` commands also accept an owner-only JSON argument file through `--config`; the [Linux daemon guide](docs/operations/linux-daemons.md) provides hardened systemd units and installation requirements.

`aurorad issuer` is a private backend, not the public production issuer surface. It accepts only exact binary Blind-RSA carrier requests at `POST /` over TLS 1.3, HTTP/2, and a gateway client certificate chaining to the dedicated `--gateway-client-ca`. It rejects wildcard, hostname, and non-loopback listeners; exposes no health, metadata, JSON, verifier, spend, or packet routes; and globally bounds concurrent signing. A separately deployed gateway must enforce the Section 35.6.1 nontrivial cover-slot predicate and forward the opaque carrier without adding a standalone public path or media-type discriminator. That public gateway integration remains external and incomplete. The `issuer-check`, `issuerd-check`, and `issuerd-http-check` commands are lab self-tests, not live backend or gateway readiness probes.

`aurorac proxy` is the Linux local client entry point. It validates and erases the provisioning wallet after use, records a wallet reservation before opening a carrier, posts issuer work over non-redirecting HTTPS, and starts loopback-only HTTP CONNECT and SOCKS5 listeners by default. The SOCKS5 listener accepts TCP CONNECT and UDP ASSOCIATE; each UDP destination is confirmed by the relay before a response is returned, and the association is bound to its SOCKS control peer. The wallet and state files must be regular owner-only files, and the state directory must be owner-only. A wallet provides a fresh entry for each recovery attempt; maintain at least eight unused entries per relay bucket and replenish before fewer than three remain. A single-entry `--provisioning` source is supported only with `--wallet-state` and is deliberately non-recovering. Public listeners require `--allow-public-listeners`; local DNS service remains a separate proxy deployment surface.

`aurorac tun` is the Linux packet-tunnel entry point. It uses the same wallet and durable reservation requirements as the proxy command, requires access to the configured TUN device, a standard system `ip` executable, network-administration permission, and the standard Linux routing-policy rules for both address families. It resolves the relay before changing routes, adds exact relay bypass routes, then adds lower-metric IPv4 and IPv6 defaults through the TUN. It refuses a route layout where a safe tunnel precedence cannot be established, and removes only routes and addresses it added before closing the device. The command does not modify resolver configuration; DNS packets captured by the tunnel use the encrypted packet path. Use `aurorac tun --help` to set the TUN device, interface name, MTU, host addresses, or issuer timeout.

Config examples follow Section 28:

```toml
[aurora]
profile = "adversarial-dpi"
route = "split-2"
speed = "balanced"
```
