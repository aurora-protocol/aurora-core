# Aurora Prototype

This repository is the portable Go monorepo for the Aurora prototype. It contains the shared protocol core plus the local client engine, relay services, operational helpers, and generated vectors.

Implemented now:

- canonical Section 9 wire encoding and decoding;
- Appendix A registry constants;
- `PublicKeyRecord`, `AuthorityKeyRecord`, `ObjectSignature`, admission, replay, policy, frame, flow, route-envelope, packet, and key-update structures;
- `DirectoryConsensus`, `RelayDescriptor`, `CoverTemplate`, routing records, cover profiles, and canonical trust-chain hash/signature inputs;
- Appendix B.4 and B.5 structural vectors;
- SHA-384/SHA-512 suite hashes, TLS-style HKDF labels, AES-256-GCM, route-prelude wrapping, packet protection, standard-library ML-KEM wrappers with CIRCL agreement checks, and ML-DSA verification;
- AccessHint computation, spent-hint cache, token redemption hash, token spent key, replay context hash, and bootstrap dedup key;
- first-hop and split-route prelude transcript hashing, sealed control capsules, Finished messages, application traffic secret derivation, first application packet vectors, and exit-layer packet vectors;
- signed real-crypto metadata vectors for directory consensus, relay descriptors, and cover templates;
- policy profiles, PAL scoring, PACE reference behavior, local config parsing, threat-safe logging wrappers, `auroractl`, the local proxy client, cover-template-validated H2/H1/shadow-origin/H3 datagram and explicitly gated MASQUE carrier request builders, relay admission/exit gates, HTTP cover-origin gateway handler, gateway-backed active-probe harness, deterministic DPI/classifier baseline harness, external evaluation evidence verifier, deployment security assessment evidence verifier, platform adapter conformance profiles, platform packaging and entitlement conformance matrix, release readiness evidence verifier, Privacy Pass Blind RSA production proof harness, issuer operations conformance harness, issuer service readiness harness, issuer HTTP daemon readiness harness, cover-origin deployment conformance harness, vector drift tests, and ops helpers.

## Layout

- `admission`, `crypto`, `flow`, `handshake`, `packet`, `policy`, `protocol`, `route`, `transport`, `trust`, and `wire`: portable protocol implementation.
- `client`: local-interface-neutral client engine.
- `platform`: thin platform adapter contracts for local proxy and packet interfaces.
- `relay`: relay-side cover, admission, and exit-policy gates.
- `ops`: operational verifier and directory helper logic.
- `vectors`: generated structural vector bundle and drift tests.
- `cmd/auroractl`: local vector, config, and capability diagnostics.

Native app or driver repositories should be split out only when they need their own platform build systems.

This is not a production VPN or circumvention client. The spec still requires independent cryptographic review, issuer daemon deployment and live token issuance, signed platform release artifacts and device provisioning, real deployment security assessment, external active-probe evaluation, and external DPI/classifier evaluation before production use.

## Commands

Use a workspace-local Go build cache in sandboxed environments:

```bash
GOCACHE=/private/tmp/aurora-gocache go test ./...
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl vectors
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl vectors --check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl wire-check
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
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl cover-check
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl capabilities
```

Config examples follow Section 28:

```toml
[aurora]
profile = "adversarial-dpi"
route = "split-2"
speed = "balanced"
```
