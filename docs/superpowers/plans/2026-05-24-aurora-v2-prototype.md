# Aurora Prototype Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a runnable Aurora prototype foundation from the specification, covering the wire, structural-vector, cryptographic-helper, admission/replay, packet, key-update, policy, config, logging, and CLI layers that can be implemented safely without external audited dependencies.

**Architecture:** The repository starts as a portable Go module because this workspace has no existing source code or git repository, and Go 1.25 includes standard-library AES-GCM, HKDF, ECDH, and ML-KEM primitives. The implementation keeps protocol encoding separate from crypto, admission, packet protection, policy, config, and CLI packages so later platform adapters can remain thin.

**Tech Stack:** Go 1.25 standard library only; no dependency downloads required.

---

### Task 1: Skeleton and Safety Floor

**Files:**
- Create: `go.mod`
- Create: `README.md`
- Create: `logging/redactor.go`
- Test: `logging/redactor_test.go`

- [x] **Step 1: Create a dependency-free Go module**

```bash
go mod init aurora.local/prototype
```

- [x] **Step 2: Add threat-safe logging primitives**

Implement a redactor that refuses to format raw admission proofs, replay proofs, token authenticators, hint secrets, capsule plaintext, and route-wrap plaintext unless a lab-only call path is used.

- [x] **Step 3: Run logging tests**

```bash
go test ./logging
```

Expected: PASS.

### Task 2: Wire Encoder/Decoder Freeze

**Files:**
- Create: `wire/varint.go`
- Create: `wire/encoder.go`
- Create: `wire/reader.go`
- Test: `wire/wire_test.go`

- [x] **Step 1: Write failing tests for Appendix A varint encodings**

Cover minimal QUIC-style varints and reject non-minimal encodings.

- [x] **Step 2: Implement scalar, opaque, vector, and pre_hash helpers**

Use network byte order and exact length-prefix semantics from Section 9.

- [x] **Step 3: Run wire tests**

```bash
go test ./wire
```

Expected: PASS.

### Task 3: Registries and Structural Objects

**Files:**
- Create: `registry/registry.go`
- Create: `protocol/types.go`
- Create: `protocol/records.go`
- Test: `protocol/records_test.go`

- [x] **Step 1: Encode registries from Appendix A and Section 13.3**

Include protocol version, suites, policies, route modes, personalities, methods, proof types, wrap suite, signature schemes, key encodings, token key schemes, frame types, and authority usage flags.

- [x] **Step 2: Implement PublicKeyRecord, AuthorityKeyRecord, ObjectSignature**

Derive `authority_key_id` with `Truncate128(H_pre(label || Encode(PublicKeyRecord)))`.

- [x] **Step 3: Reproduce Appendix B.5**

Expected: PublicKeyRecord, AuthorityKeyRecord, ObjectSignature, unsigned ObjectSignature, and structural hashes match the spec hex.

### Task 4: Crypto Helpers and Appendix B.4

**Files:**
- Create: `crypto/hash.go`
- Create: `crypto/hkdf.go`
- Create: `crypto/aead.go`
- Create: `crypto/control.go`
- Create: `crypto/routewrap.go`
- Create: `crypto/mlkem.go`
- Test: `crypto/crypto_test.go`

- [x] **Step 1: Implement H_pre, suite hashes, HKDF-Expand-Label, AES-256-GCM**

Keep suite-dependent hashing explicit.

- [x] **Step 2: Implement control AAD construction**

Reproduce Appendix B.4 control preimage and SHA-384 AAD.

- [x] **Step 3: Implement route-prelude wrapping**

Reproduce Appendix B.4 route-wrap context, key, IV, AAD, and ciphertext/tag.

- [x] **Step 4: Add ML-KEM-768 and ML-KEM-1024 wrappers plus ML-DSA verification**

Expose standard-library generation, encapsulation, decapsulation helpers, and CIRCL-backed ML-DSA verification.

### Task 5: Admission and Replay

**Files:**
- Create: `protocol/admission.go`
- Create: `admission/access_hint.go`
- Create: `admission/replay.go`
- Test: `admission/admission_test.go`

- [x] **Step 1: Encode AdmissionProof, ReplayProof, PolicyOffer, and ClientTransportHints**

Keep `network_cohort_hint` bounded and encode the route-hop empty hints exactly.

- [x] **Step 2: Implement AccessHint and spent-hint keys**

Use Section 13.13 and 13.14 formulas.

- [x] **Step 3: Implement token_redemption_hash, token_spent_key, replay_context_hash, and bootstrap_dedup_key**

Verify that changing only `ReplayProof.client_replay_nonce` does not change `token_spent_key`.

### Task 6: Packets, Frames, and KEY_UPDATE

**Files:**
- Create: `protocol/frames.go`
- Create: `packet/packet.go`
- Create: `packet/key_update.go`
- Test: `packet/packet_test.go`

- [x] **Step 1: Encode FrameBlock, AuroraFrame, AuroraPacket, FlowOpen, UDP_TARGET_CONFIRM, FLOW_CLOSE, KEY_UPDATE, KEY_UPDATE_ACK, and KEY_UPDATE_REQUEST**

Validate frame `flow_id` consistency for flow-management frames before mutation.

- [x] **Step 2: Implement packet AEAD protection**

Use packet AAD, packet nonce construction, key phase, direction, hop layer, and packet-number rules.

- [x] **Step 3: Implement key update derivation and bounded state checks**

Reject skipped key phases and generate ACK payloads when required.

### Task 7: Policy, Config, CLI, and Documentation

**Files:**
- Create: `policy/policy.go`
- Create: `config/config.go`
- Create: `cmd/auroractl/main.go`
- Create: `README.md`
- Test: `policy/policy_test.go`
- Test: `config/config_test.go`

- [x] **Step 1: Implement policy profile defaults**

Map fast-web, balanced-web, adversarial-dpi, adversarial-dpi-strict, emergency-web, lab, and smart.

- [x] **Step 2: Implement PAL scoring and low-latency override**

Use Section 22 reference formula and gates.

- [x] **Step 3: Implement local config parser**

Support the Section 28 examples without external TOML dependencies.

- [x] **Step 4: Implement CLI vector/config/capability commands**

`auroractl vectors` prints generated Appendix B structural values.

### Task 8: Verification and Gap Disclosure

**Files:**
- Modify: `README.md`

- [x] **Step 1: Run all tests**

```bash
go test ./...
```

Expected: PASS.

- [x] **Step 2: Review for P3+ issues**

Check for fake production claims, unsafe logging, missing vector coverage, replay-key mistakes, and wire-visible forbidden strings in public protocol encoders.

- [x] **Step 3: Document unsupported production requirements**

Explicitly list the full real-crypto vector package, Privacy Pass production proof verification, real cover-origin gateway, active-probe harness, platform adapters, and DPI evaluation as future production work.
