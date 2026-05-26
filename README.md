# Aurora Prototype

This workspace contains a dependency-free Go prototype foundation for the Aurora protocol specification.

Implemented now:

- canonical Section 9 wire encoding and decoding;
- Appendix A registry constants;
- `PublicKeyRecord`, `AuthorityKeyRecord`, `ObjectSignature`, admission, replay, policy, frame, flow, route-envelope, packet, and key-update structures;
- `DirectoryConsensus`, `RelayDescriptor`, `CoverTemplate`, routing records, cover profiles, and canonical trust-chain hash/signature inputs;
- Appendix B.4 and B.5 structural vectors;
- SHA-384/SHA-512 suite hashes, TLS-style HKDF labels, AES-256-GCM, route-prelude wrapping, packet protection, and standard-library ML-KEM wrappers;
- AccessHint computation, spent-hint cache, token redemption hash, token spent key, replay context hash, and bootstrap dedup key;
- first-hop prelude transcript hashing, handshake key schedule, ClientFinished, ServerFinished, and application traffic secret derivation;
- policy profiles, PAL scoring, PACE reference behavior, local config parsing, threat-safe logging wrappers, and `auroractl`.

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
