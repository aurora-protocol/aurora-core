# Aurora Prototype

This repository is the portable Go monorepo for the Aurora prototype. It contains the shared protocol core plus the local client engine, relay services, operational helpers, generated vectors, and thin platform adapter contracts.

Implemented now:

- canonical Section 9 wire encoding and decoding;
- Appendix A registry constants;
- `PublicKeyRecord`, `AuthorityKeyRecord`, `ObjectSignature`, admission, replay, policy, frame, flow, route-envelope, packet, and key-update structures;
- `DirectoryConsensus`, `RelayDescriptor`, `CoverTemplate`, routing records, cover profiles, and canonical trust-chain hash/signature inputs;
- Appendix B.4 and B.5 structural vectors;
- SHA-384/SHA-512 suite hashes, TLS-style HKDF labels, AES-256-GCM, route-prelude wrapping, packet protection, and standard-library ML-KEM wrappers;
- AccessHint computation, spent-hint cache, token redemption hash, token spent key, replay context hash, and bootstrap dedup key;
- first-hop prelude transcript hashing, handshake key schedule, ClientFinished, ServerFinished, and application traffic secret derivation;
- policy profiles, PAL scoring, PACE reference behavior, local config parsing, threat-safe logging wrappers, `auroractl`, the local proxy client, relay admission/exit gates, vector drift tests, ops helpers, and generic platform adapter contracts.

## Layout

- `admission`, `crypto`, `flow`, `handshake`, `packet`, `policy`, `protocol`, `route`, `transport`, `trust`, and `wire`: portable protocol implementation.
- `client`: local-interface-neutral client engine.
- `relay`: relay-side cover, admission, and exit-policy gates.
- `ops`: operational verifier and directory helper logic.
- `vectors`: generated structural vector bundle and drift tests.
- `platform`: thin adapter contracts for platform packet APIs.
- `cmd/auroractl`: local vector, config, and capability diagnostics.

This is not a production VPN or circumvention client. The spec still requires independent cryptographic review, real ML-DSA support, production Privacy Pass verification, cover-origin gateway behavior, active-probe testing, platform adapters, and DPI/classifier evaluation before production use.

## Commands

Use a workspace-local Go build cache in sandboxed environments:

```bash
GOCACHE=/private/tmp/aurora-gocache go test ./...
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl vectors
GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl capabilities
```

Config examples follow Section 28:

```toml
[aurora]
profile = "adversarial-dpi"
route = "split-2"
speed = "balanced"
```
