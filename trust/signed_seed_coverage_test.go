package trust

// Adversarial coverage for the residual count-0 branches in
// trust/signed_seed.go. The existing signed_seed_test.go covers the happy
// verification path, the tampered-seed rejection, the wrong-usage signer
// rejection, the ambiguous-signer rejection, the trust-store promote/revoke
// lifecycle, and the concurrent replay/idempotency paths. The residual count-0
// branches are the error returns inside the seed-record hash/signature-input
// helpers, the non-happy VerifySignedSeedRecord branches, the
// validateAuthorityKeyID / validateSignedSeedAuthorityKeys rejection branches,
// the addSignedSeedBootstrapKeys / applySignedSeedAuthorityUpdates slice-edit
// branches, the rejectDuplicateAuthorityKeys duplicate path, the identity
// helpers' encode-error short-circuits, the clone encode-failure path, and the
// NewSignedSeedTrustStore / AuthorityKeys / Accept guard branches.
//
// This file drives them by calling the package-level validators and slice
// helpers directly (white-box) and by exercising the store with seeds built
// from the existing signedSeedAuthorityForTest / signedSeedForTest fixtures
// (which mint a real, canonically-keyed P-256 authority and a properly signed
// seed). Each case perturbs exactly one field so the firing branch is
// attributable to that perturbation alone.
//
// Uncovered blocks (measured count 0 before this file), mapped to source lines:
//   - SignedSeedRecordHash (19, 75%): Encode error 22.
//   - SignedSeedRecordSignatureInput (27, 75%): hash error 30.
//   - VerifySignedSeedRecord (36, 73.7%): ValidateStructural 38,
//     rejectDuplicateAuthorityKeys 44, validateSignedSeedAuthorityKeys(updates)
//     47, validateAuthorityKeyID(signer) 54, VerifySignature 60.
//   - NewSignedSeedTrustStore (75, 70%): empty roots 77, clone error 81,
//     validate error 84.
//   - Accept (96, 75.8%): nil receiver 98, seed-id conflict 113,
//     addBootstrapKeys error 127, rejectDuplicateAuthorityKeys(combined) 135.
//   - AuthorityKeys (144, 75%): nil receiver 146.
//   - addSignedSeedBootstrapKeys (164, 64.3%): conflict-with-pinned 168,
//     continue-equal-pinned 170, conflict-with-promoted 174, clone error 180,
//     append 182.
//   - applySignedSeedAuthorityUpdates (187, 70%): update-pinned 190,
//     clone error 194, append-new 199.
//   - validateSignedSeedAuthorityKeys (205, 75%): error propagation 208,
//     happy 211.
//   - validateAuthorityKeyID (214, 60%): structural 216, Ed25519 disabled 219,
//     non-canonical 226, happy 228.
//   - signedSeedAuthorityRecordIdentity (260, 88.9%): encode-error "" 268.
//   - signedSeedAuthoritySignerIdentity (273, 87.5%): encode-error "" 280.
//   - cloneSignedSeedAuthorityKeys (291, 80%): encode error 296.
//
// Dead-by-design (documented, not covered):
//   - VerifySignedSeedRecord line 58 (SignedSeedRecordSignatureInput error
//     after ValidateStructural passed). SignedSeedRecordSignatureInput fails only
//     if Encode(seed.Unsigned()) fails, but every field Encode reads was
//     already validated by SignedSeedRecord.ValidateStructural (SeedID 16 bytes,
//     hints <= 0xffff, hash fields 48 bytes, authority-key counts <= 64, each
//     authority key ValidateStructural'd, signature completeness). No
//     constructible seed that passes ValidateStructural can fail to encode.
//   - Accept line 105 (SignedSeedRecordHash error after ValidateStructural):
//     same reasoning as line 58.
//   - Accept line 117 (authorityKeysLocked error) and line 124 (clone promoted
//     error), and AuthorityKeys line 152 (authorityKeysLocked error): every key
//     in the store entered through NewSignedSeedTrustStore (which clones and
//     validateSignedSeedAuthorityKeys the roots) or through a prior Accept
//     (which clones additions/updates and runs VerifySignedSeedRecord, itself
//     calling validateSignedSeedAuthorityKeys). Each such key has therefore
//     passed validateAuthorityKeyID — which encodes the public key — and
//     cloneSignedSeedAuthorityKeys — which encodes the full record. Re-cloning
//     the same record re-encodes the same bytes and cannot fail.
//   - validateAuthorityKeyID line 223 (protocol.Encode(key.PublicKey) error
//     after ValidateStructural passed). key.ValidateStructural already ran
//     PublicKey.ValidateCompatibility, which constrains every scheme to a
//     small fixed length (SEC1 65/97, ML-DSA 1957/2537, Ed25519 32) or to a
//     valid SPKI that x509.ParsePKIXPublicKey accepts (necessarily tiny); and
//     validateSignatureKeyEncodingCompatibility already rejected incompatible
//     encodings. WriteVarint never fails for a valid uint64 and WriteOpaque16
//     cannot overflow a <=0xffff blob, so Encode cannot fail here.
//   - cloneSignedSeedAuthorityKeys line 301 (round-trip mismatch after a
//     successful Encode). Encode produces a complete canonical encoding;
//     DecodeAuthorityKeyRecord reads exactly the fields Encode wrote; so
//     reader.EOF() is true and reader.Err() is nil. The mismatch check is
//     unreachable for any key whose Encode succeeded.
//
// Not duplicated: the VerifySignedSeedRecord happy path (line 63), the Accept
// idempotent-replay return (line 111), the AuthorityKeys happy path, and the
// applySignedSeedAuthorityUpdates replace-existing branch (197) are already
// covered by signed_seed_test.go and are not re-asserted here.
//
// No new package-level consts/vars/types are added. The one new helper,
// signedSeedCovCloneKey, is referenced by >=2 tests (U1000-safe). The seed and
// authority-key fixtures (signedSeedAuthorityForTest, signedSeedForTest,
// signedSeedAuthorityKeyID) are existing testing.TB helpers in this package
// and are reused. No context.Context, no deprecated APIs.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// signedSeedCovCloneKey returns a deep copy of a single authority key via the
// package's own encode/decode clone path. Used wherever a test needs a key
// whose slices are independent of the fixture it came from (so mutating the
// copy does not corrupt shared state). Referenced by >=2 tests, so not U1000.
func signedSeedCovCloneKey(t testing.TB, key protocol.AuthorityKeyRecord) protocol.AuthorityKeyRecord {
	t.Helper()
	cloned, err := cloneSignedSeedAuthorityKeys([]protocol.AuthorityKeyRecord{key})
	if err != nil {
		t.Fatalf("signedSeedCovCloneKey: clone failed: %v", err)
	}
	return cloned[0]
}

// signedSeedCovNonCanonicalUpdate returns a copy of key whose AuthorityKeyID is
// perturbed so it no longer equals AuthorityKeyID(Encode(key.PublicKey)), while
// remaining 16 bytes and otherwise structurally valid. It passes
// protocol.AuthorityKeyRecord.ValidateStructural (which does not check
// canonicality) but fails trust.validateAuthorityKeyID's canonicality check.
func signedSeedCovNonCanonicalUpdate(t testing.TB, key protocol.AuthorityKeyRecord) protocol.AuthorityKeyRecord {
	t.Helper()
	out := signedSeedCovCloneKey(t, key)
	out.AuthorityKeyID[0] ^= 0xff
	return out
}

func TestSignedSeedRecordHashAndSignatureInputDecidesPerCondition(t *testing.T) {
	root, rootPrivate := signedSeedAuthorityForTest(t, 0x10, registry.UsageMaySignSignedSeedRecord)
	seed := signedSeedForTest(t, root, rootPrivate, 200, nil, nil)

	// Happy paths (lines 24 and 32): a well-formed seed hashes and signature-inputs.
	if h, err := SignedSeedRecordHash(seed); err != nil || len(h) == 0 {
		t.Fatalf("SignedSeedRecordHash happy: h=%v err=%v", h, err)
	}
	if in, err := SignedSeedRecordSignatureInput(seed); err != nil || len(in) == 0 {
		t.Fatalf("SignedSeedRecordSignatureInput happy: in=%v err=%v", in, err)
	}

	// Encode error (line 22 for hash, line 30 for signature input): a hint over
	// the 0xffff WriteOpaque16 limit makes Encode(seed.Unsigned()) fail. These
	// helpers call Encode directly, with no prior ValidateStructural, so the
	// oversized hint reaches the encoder.
	oversized := seed
	oversized.DirectoryConsensusHint = make([]byte, 0x10000)
	if h, err := SignedSeedRecordHash(oversized); err == nil {
		t.Fatalf("SignedSeedRecordHash oversized hint: expected error, got h=%v", h)
	}
	if in, err := SignedSeedRecordSignatureInput(oversized); err == nil {
		t.Fatalf("SignedSeedRecordSignatureInput oversized hint: expected error, got in=%v", in)
	}
}

func TestVerifySignedSeedRecordDecidesPerCondition(t *testing.T) {
	root, rootPrivate := signedSeedAuthorityForTest(t, 0x20, registry.UsageMaySignSignedSeedRecord)
	seed := signedSeedForTest(t, root, rootPrivate, 200, nil, nil)

	// Precompute the mutated seeds that the table below references by value.
	badVersion := seed
	badVersion.SeedVersion = 0 // ValidateStructural rejects this before any signature check.
	tampered := seed
	tampered.SeedSignature.Signature = append([]byte(nil), seed.SeedSignature.Signature...)
	tampered.SeedSignature.Signature[0] ^= 0xff // stays non-empty, but VerifySignature fails.

	cases := []struct {
		name    string
		seed    protocol.SignedSeedRecord
		keys    []protocol.AuthorityKeyRecord
		now     uint64
		wantSub string
	}{
		{
			// Line 38: ValidateStructural rejects an unsupported seed version before
			// any trust work runs; signature validity is irrelevant here.
			name:    "unsupported seed version",
			seed:    badVersion,
			keys:    []protocol.AuthorityKeyRecord{root},
			now:     200,
			wantSub: "unsupported signed seed version",
		},
		{
			// Line 44: two trusted keys sharing a signer identity (AuthorityKeyID +
			// scheme + encoding) are rejected as duplicates before signing.
			name: "duplicate trusted keys",
			seed: seed,
			keys: []protocol.AuthorityKeyRecord{
				root,
				withAuthorityID(root, bytes.Repeat([]byte{0x2f}, 16)),
			},
			now:     200,
			wantSub: "duplicate authority key",
		},
		{
			// Line 44: a bootstrap authority key that passes protocol
			// ValidateStructural (no canonicality check there) but fails the trust
			// canonicality check is rejected at the bootstrap validation stage.
			name:    "non-canonical authority key bootstrap",
			seed:    signedSeedForTest(t, root, rootPrivate, 201, []protocol.AuthorityKeyRecord{signedSeedCovNonCanonicalUpdate(t, root)}, nil),
			keys:    []protocol.AuthorityKeyRecord{root},
			now:     201,
			wantSub: "authority key id is not canonical",
		},
		{
			// Line 47: an authority-key update that passes protocol
			// ValidateStructural (no canonicality check) but fails the trust
			// canonicality check is rejected at the updates validation stage.
			name:    "non-canonical authority key update",
			seed:    signedSeedForTest(t, root, rootPrivate, 201, nil, []protocol.AuthorityKeyRecord{signedSeedCovNonCanonicalUpdate(t, root)}),
			keys:    []protocol.AuthorityKeyRecord{root},
			now:     201,
			wantSub: "authority key id is not canonical",
		},
		{
			// Line 54: the located signer itself is non-canonical. LocateAuthorityKeyByID
			// matches by AuthorityKeyID + scheme + encoding and only runs key.Validate
			// (structural/interval/status/usage — not canonicality), so a non-canonical
			// signer is located and then rejected by validateAuthorityKeyID.
			name:    "non-canonical signer",
			seed:    signedSeedForTest(t, signedSeedCovNonCanonicalUpdate(t, root), rootPrivate, 202, nil, nil),
			keys:    []protocol.AuthorityKeyRecord{signedSeedCovNonCanonicalUpdate(t, root)},
			now:     202,
			wantSub: "authority key id is not canonical",
		},
		{
			// Line 60: a structurally valid, canonically signed seed whose signature
			// bytes are tampered fails VerifySignature after every prior check passes.
			name:    "tampered signature",
			seed:    tampered,
			keys:    []protocol.AuthorityKeyRecord{root},
			now:     200,
			wantSub: "signed seed signature verification failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifySignedSeedRecord(tc.seed, tc.keys, tc.now)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestValidateAuthorityKeyIDDecidesPerCondition(t *testing.T) {
	root, _ := signedSeedAuthorityForTest(t, 0x30, registry.UsageMaySignSignedSeedRecord)
	ed25519Key := protocol.AuthorityKeyRecord{
		AuthorityID:    bytes.Repeat([]byte{0x05}, 16),
		AuthorityKeyID: bytes.Repeat([]byte{0x06}, 16),
		AuthorityRole:  1,
		PublicKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigEd25519Lab,
			KeyEncoding:     registry.KeyEd25519RawPublic,
			PublicKey:       bytes.Repeat([]byte{0x07}, 32),
		},
		ValidFromUnix:  100,
		ValidUntilUnix: 1000,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignSignedSeedRecord,
	}

	cases := []struct {
		name    string
		key     protocol.AuthorityKeyRecord
		wantSub string
	}{
		// Line 216: structural failure (AuthorityID not 16 bytes) propagates from
		// AuthorityKeyRecord.ValidateStructural.
		{"structural failure", withAuthorityID(root, bytes.Repeat([]byte{0x08}, 15)), "authority IDs must be 16 bytes"},
		// Line 219: a structurally valid Ed25519 authority key is disabled.
		{"ed25519 disabled", ed25519Key, "lab authority key is disabled"},
		// Line 226: structural and Ed25519 checks pass but the AuthorityKeyID is not
		// the canonical hash of the encoded public key.
		{"non-canonical key id", signedSeedCovNonCanonicalUpdate(t, root), "authority key id is not canonical"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAuthorityKeyID(tc.key)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}

	// Line 228 (happy): a canonical key validates cleanly.
	if err := validateAuthorityKeyID(root); err != nil {
		t.Fatalf("validateAuthorityKeyID happy: err = %v", err)
	}
}

func TestValidateSignedSeedAuthorityKeysDecidesPerCondition(t *testing.T) {
	root, _ := signedSeedAuthorityForTest(t, 0x31, registry.UsageMaySignSignedSeedRecord)

	// Line 208: a non-canonical key propagates validateAuthorityKeyID's error.
	bad := []protocol.AuthorityKeyRecord{signedSeedCovNonCanonicalUpdate(t, root)}
	if err := validateSignedSeedAuthorityKeys(bad); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("validateSignedSeedAuthorityKeys error: err = %v", err)
	}

	// Line 211 (happy): a canonical key set validates cleanly.
	if err := validateSignedSeedAuthorityKeys([]protocol.AuthorityKeyRecord{root}); err != nil {
		t.Fatalf("validateSignedSeedAuthorityKeys happy: err = %v", err)
	}
}

func TestAddSignedSeedBootstrapKeysDecidesPerCondition(t *testing.T) {
	root, _ := signedSeedAuthorityForTest(t, 0x40, registry.UsageMaySignSignedSeedRecord)
	child, _ := signedSeedAuthorityForTest(t, 0x41, registry.UsageMaySignSignedSeedRecord)

	t.Run("conflict with pinned root", func(t *testing.T) {
		// Same record identity as root (AuthorityID + AuthorityKeyID + scheme +
		// encoding) but different PublicKey bytes, so authorityKeysEqual is false.
		addition := signedSeedCovCloneKey(t, root)
		addition.PublicKey.PublicKey[0] ^= 0xff
		var promoted []protocol.AuthorityKeyRecord
		err := addSignedSeedBootstrapKeys([]protocol.AuthorityKeyRecord{root}, &promoted, []protocol.AuthorityKeyRecord{addition})
		if err == nil || !strings.Contains(err.Error(), "conflicts with pinned root") {
			t.Fatalf("err = %v, want conflicts with pinned root", err)
		}
		if len(promoted) != 0 {
			t.Fatalf("promoted mutated on conflict: %d", len(promoted))
		}
	})

	t.Run("continue equal pinned root", func(t *testing.T) {
		// An addition identical to the pinned root is a no-op (line 170 continue).
		addition := signedSeedCovCloneKey(t, root)
		var promoted []protocol.AuthorityKeyRecord
		if err := addSignedSeedBootstrapKeys([]protocol.AuthorityKeyRecord{root}, &promoted, []protocol.AuthorityKeyRecord{addition}); err != nil {
			t.Fatalf("err = %v", err)
		}
		if len(promoted) != 0 {
			t.Fatalf("promoted grew on equal pinned: %d", len(promoted))
		}
	})

	t.Run("conflict with promoted key", func(t *testing.T) {
		// Same record identity as the promoted child but different PublicKey.
		addition := signedSeedCovCloneKey(t, child)
		addition.PublicKey.PublicKey[0] ^= 0xff
		promoted := []protocol.AuthorityKeyRecord{signedSeedCovCloneKey(t, child)}
		err := addSignedSeedBootstrapKeys(nil, &promoted, []protocol.AuthorityKeyRecord{addition})
		if err == nil || !strings.Contains(err.Error(), "conflicts with promoted key") {
			t.Fatalf("err = %v, want conflicts with promoted key", err)
		}
	})

	t.Run("continue equal promoted key", func(t *testing.T) {
		addition := signedSeedCovCloneKey(t, child)
		promoted := []protocol.AuthorityKeyRecord{signedSeedCovCloneKey(t, child)}
		if err := addSignedSeedBootstrapKeys(nil, &promoted, []protocol.AuthorityKeyRecord{addition}); err != nil {
			t.Fatalf("err = %v", err)
		}
		if len(promoted) != 1 {
			t.Fatalf("promoted changed on equal promoted: %d", len(promoted))
		}
	})

	t.Run("clone failure", func(t *testing.T) {
		// An addition whose AuthorityID is the wrong length is not locatable
		// (record identity encodes to "") and then fails to clone (line 180).
		bad := signedSeedCovCloneKey(t, child)
		bad.AuthorityID = bytes.Repeat([]byte{0x09}, 15)
		var promoted []protocol.AuthorityKeyRecord
		err := addSignedSeedBootstrapKeys(nil, &promoted, []protocol.AuthorityKeyRecord{bad})
		if err == nil {
			t.Fatalf("err = nil, want clone error")
		}
	})

	t.Run("append new and happy", func(t *testing.T) {
		// A new addition with no pinned/promoted match is cloned and appended
		// (line 182); an empty additions slice returns nil (line 184).
		var promoted []protocol.AuthorityKeyRecord
		if err := addSignedSeedBootstrapKeys(nil, &promoted, []protocol.AuthorityKeyRecord{signedSeedCovCloneKey(t, child)}); err != nil {
			t.Fatalf("append: err = %v", err)
		}
		if len(promoted) != 1 {
			t.Fatalf("append: promoted = %d, want 1", len(promoted))
		}
		if err := addSignedSeedBootstrapKeys(nil, &promoted, nil); err != nil {
			t.Fatalf("empty additions: err = %v", err)
		}
	})
}

func TestApplySignedSeedAuthorityUpdatesDecidesPerCondition(t *testing.T) {
	root, _ := signedSeedAuthorityForTest(t, 0x50, registry.UsageMaySignSignedSeedRecord)
	child, _ := signedSeedAuthorityForTest(t, 0x51, registry.UsageMaySignSignedSeedRecord)

	t.Run("cannot update pinned root", func(t *testing.T) {
		// An update whose record identity matches a pinned root is rejected.
		update := signedSeedCovCloneKey(t, root)
		var promoted []protocol.AuthorityKeyRecord
		err := applySignedSeedAuthorityUpdates([]protocol.AuthorityKeyRecord{root}, &promoted, []protocol.AuthorityKeyRecord{update})
		if err == nil || !strings.Contains(err.Error(), "cannot update pinned bootstrap root") {
			t.Fatalf("err = %v, want cannot update pinned bootstrap root", err)
		}
	})

	t.Run("clone failure", func(t *testing.T) {
		// An update not locatable in pinned (record identity "") whose AuthorityID
		// length is wrong fails to clone (line 194).
		bad := signedSeedCovCloneKey(t, child)
		bad.AuthorityID = bytes.Repeat([]byte{0x0a}, 15)
		var promoted []protocol.AuthorityKeyRecord
		err := applySignedSeedAuthorityUpdates([]protocol.AuthorityKeyRecord{root}, &promoted, []protocol.AuthorityKeyRecord{bad})
		if err == nil {
			t.Fatalf("err = nil, want clone error")
		}
	})

	t.Run("append new update", func(t *testing.T) {
		// An update not in pinned or promoted is appended (line 199).
		var promoted []protocol.AuthorityKeyRecord
		if err := applySignedSeedAuthorityUpdates([]protocol.AuthorityKeyRecord{root}, &promoted, []protocol.AuthorityKeyRecord{signedSeedCovCloneKey(t, child)}); err != nil {
			t.Fatalf("append new: err = %v", err)
		}
		if len(promoted) != 1 {
			t.Fatalf("append new: promoted = %d, want 1", len(promoted))
		}
	})

	t.Run("replace existing promoted update", func(t *testing.T) {
		// An update whose record identity matches an existing promoted key
		// replaces it in place (line 197) rather than appending.
		existing := signedSeedCovCloneKey(t, child)
		promoted := []protocol.AuthorityKeyRecord{existing}
		if err := applySignedSeedAuthorityUpdates(nil, &promoted, []protocol.AuthorityKeyRecord{signedSeedCovCloneKey(t, child)}); err != nil {
			t.Fatalf("replace: err = %v", err)
		}
		if len(promoted) != 1 {
			t.Fatalf("replace: promoted = %d, want 1", len(promoted))
		}
	})
}

func TestRejectDuplicateAuthorityKeysDecidesPerCondition(t *testing.T) {
	root, _ := signedSeedAuthorityForTest(t, 0x60, registry.UsageMaySignSignedSeedRecord)
	dup := withAuthorityID(root, bytes.Repeat([]byte{0x6f}, 16)) // same signer identity, different AuthorityID

	if err := rejectDuplicateAuthorityKeys([]protocol.AuthorityKeyRecord{root, dup}); err == nil || !strings.Contains(err.Error(), "duplicate authority key") {
		t.Fatalf("duplicate: err = %v, want duplicate authority key", err)
	}
	if err := rejectDuplicateAuthorityKeys([]protocol.AuthorityKeyRecord{root}); err != nil {
		t.Fatalf("unique: err = %v", err)
	}
	if err := rejectDuplicateAuthorityKeys(nil); err != nil {
		t.Fatalf("empty: err = %v", err)
	}
}

func TestIdentityHelpersAndCloneDecidesPerCondition(t *testing.T) {
	root, _ := signedSeedAuthorityForTest(t, 0x70, registry.UsageMaySignSignedSeedRecord)

	// Line 268: signedSeedAuthorityRecordIdentity short-circuits to "" when the
	// AuthorityID length is wrong (WriteOpaqueFixed sets an encoder error).
	badAuthorityID := signedSeedCovCloneKey(t, root)
	badAuthorityID.AuthorityID = bytes.Repeat([]byte{0x0b}, 15)
	if got := signedSeedAuthorityRecordIdentity(badAuthorityID); got != "" {
		t.Fatalf("recordIdentity with bad AuthorityID = %q, want empty", got)
	}

	// Line 280: signedSeedAuthoritySignerIdentity short-circuits to "" when the
	// AuthorityKeyID length is wrong.
	badAuthorityKeyID := signedSeedCovCloneKey(t, root)
	badAuthorityKeyID.AuthorityKeyID = bytes.Repeat([]byte{0x0c}, 15)
	if got := signedSeedAuthoritySignerIdentity(badAuthorityKeyID); got != "" {
		t.Fatalf("signerIdentity with bad AuthorityKeyID = %q, want empty", got)
	}

	// Line 296: cloneSignedSeedAuthorityKeys fails to encode a key with a wrong
	// AuthorityID length.
	cloned, err := cloneSignedSeedAuthorityKeys([]protocol.AuthorityKeyRecord{badAuthorityID})
	if err == nil || cloned != nil {
		t.Fatalf("clone bad key: err=%v cloned=%v, want error", err, cloned)
	}

	// Happy path: a canonical key clones cleanly.
	cloned, err = cloneSignedSeedAuthorityKeys([]protocol.AuthorityKeyRecord{root})
	if err != nil || len(cloned) != 1 {
		t.Fatalf("clone happy: err=%v cloned=%v", err, cloned)
	}
}

func TestNewSignedSeedTrustStoreAndAuthorityKeysDecidesPerCondition(t *testing.T) {
	root, _ := signedSeedAuthorityForTest(t, 0x80, registry.UsageMaySignSignedSeedRecord)

	t.Run("empty roots rejected", func(t *testing.T) {
		if _, err := NewSignedSeedTrustStore(nil); err == nil || !strings.Contains(err.Error(), "requires pinned bootstrap roots") {
			t.Fatalf("nil roots: err = %v", err)
		}
		if _, err := NewSignedSeedTrustStore([]protocol.AuthorityKeyRecord{}); err == nil || !strings.Contains(err.Error(), "requires pinned bootstrap roots") {
			t.Fatalf("empty roots: err = %v", err)
		}
	})

	t.Run("clone failure on malformed root", func(t *testing.T) {
		bad := signedSeedCovCloneKey(t, root)
		bad.AuthorityID = bytes.Repeat([]byte{0x0d}, 15)
		if _, err := NewSignedSeedTrustStore([]protocol.AuthorityKeyRecord{bad}); err == nil {
			t.Fatalf("err = nil, want clone error")
		}
	})

	t.Run("validate failure on non-canonical root", func(t *testing.T) {
		// The root clones cleanly but its AuthorityKeyID is non-canonical, so
		// validateSignedSeedAuthorityKeys rejects it (line 84).
		nonCanonical := signedSeedCovNonCanonicalUpdate(t, root)
		if _, err := NewSignedSeedTrustStore([]protocol.AuthorityKeyRecord{nonCanonical}); err == nil || !strings.Contains(err.Error(), "not canonical") {
			t.Fatalf("err = %v, want not canonical", err)
		}
	})

	t.Run("nil receiver AuthorityKeys", func(t *testing.T) {
		var s *SignedSeedTrustStore
		if got := s.AuthorityKeys(); got != nil {
			t.Fatalf("nil receiver AuthorityKeys = %v, want nil", got)
		}
	})
}

func TestSignedSeedTrustStoreAcceptDecidesPerCondition(t *testing.T) {
	root, rootPrivate := signedSeedAuthorityForTest(t, 0x90, registry.UsageMaySignSignedSeedRecord)

	t.Run("nil receiver", func(t *testing.T) {
		var s *SignedSeedTrustStore
		seed := signedSeedForTest(t, root, rootPrivate, 200, nil, nil)
		if err := s.Accept(seed, 200); err == nil || !strings.Contains(err.Error(), "nil signed seed trust store") {
			t.Fatalf("err = %v, want nil signed seed trust store", err)
		}
	})

	t.Run("seed id conflict", func(t *testing.T) {
		childA, _ := signedSeedAuthorityForTest(t, 0x91, registry.UsageMaySignSignedSeedRecord)
		childB, _ := signedSeedAuthorityForTest(t, 0x92, registry.UsageMaySignSignedSeedRecord)
		store, err := NewSignedSeedTrustStore([]protocol.AuthorityKeyRecord{root})
		if err != nil {
			t.Fatal(err)
		}
		// Both seeds share SeedID (byte 200) but differ in BootstrapAuthorityKeys,
		// so their hashes differ; the second Accept hits the conflict branch (113).
		seedA := signedSeedForTest(t, root, rootPrivate, 200, []protocol.AuthorityKeyRecord{childA}, nil)
		seedB := signedSeedForTest(t, root, rootPrivate, 200, []protocol.AuthorityKeyRecord{childB}, nil)
		if err := store.Accept(seedA, 200); err != nil {
			t.Fatalf("accept seedA: %v", err)
		}
		if err := store.Accept(seedB, 200); err == nil || !strings.Contains(err.Error(), "signed seed id conflicts") {
			t.Fatalf("accept seedB: err = %v, want signed seed id conflicts", err)
		}
	})

	t.Run("bootstrap key conflicts with pinned root", func(t *testing.T) {
		store, err := NewSignedSeedTrustStore([]protocol.AuthorityKeyRecord{root})
		if err != nil {
			t.Fatal(err)
		}
		// A bootstrap key with root's record identity (AuthorityID + AuthorityKeyID
		// + scheme + encoding) but a different AuthorityRole conflicts with the
		// pinned root (line 127 via addSignedSeedBootstrapKeys). AuthorityRole is
		// not part of the record identity or the canonical key id, so the key stays
		// canonical and VerifySignedSeedRecord accepts it, but the full-record
		// authorityKeysEqual comparison differs.
		conflict := signedSeedCovCloneKey(t, root)
		conflict.AuthorityRole++
		seed := signedSeedForTest(t, root, rootPrivate, 201, []protocol.AuthorityKeyRecord{conflict}, nil)
		if err := store.Accept(seed, 201); err == nil || !strings.Contains(err.Error(), "conflicts with pinned root") {
			t.Fatalf("err = %v, want conflicts with pinned root", err)
		}
	})

	t.Run("promoted duplicate after authority update", func(t *testing.T) {
		// Accept a seed promoting childA, then a second seed whose authority-key
		// update shares childA's signer identity (AuthorityKeyID + scheme +
		// encoding) but differs in AuthorityID. applySignedSeedAuthorityUpdates
		// appends it (distinct record identity) rather than replacing, leaving two
		// promoted keys with one signer identity, which the final combined
		// rejectDuplicateAuthorityKeys rejects (line 135).
		childA, _ := signedSeedAuthorityForTest(t, 0x93, registry.UsageMaySignSignedSeedRecord)
		store, err := NewSignedSeedTrustStore([]protocol.AuthorityKeyRecord{root})
		if err != nil {
			t.Fatal(err)
		}
		seedA := signedSeedForTest(t, root, rootPrivate, 200, []protocol.AuthorityKeyRecord{childA}, nil)
		if err := store.Accept(seedA, 200); err != nil {
			t.Fatalf("accept seedA: %v", err)
		}
		variant := signedSeedCovCloneKey(t, childA)
		variant.AuthorityID = bytes.Repeat([]byte{0x94}, 16)
		seedB := signedSeedForTest(t, root, rootPrivate, 210, nil, []protocol.AuthorityKeyRecord{variant})
		if err := store.Accept(seedB, 210); err == nil || !strings.Contains(err.Error(), "duplicate authority key") {
			t.Fatalf("accept seedB: err = %v, want duplicate authority key", err)
		}
	})

	t.Run("authority update targets pinned root", func(t *testing.T) {
		// An authority-key update whose record identity matches a pinned root is
		// canonical (so VerifySignedSeedRecord accepts it) but is rejected by
		// applySignedSeedAuthorityUpdates as an attempted pinned-root update
		// (line 130 via applySignedSeedAuthorityUpdates line 190).
		store, err := NewSignedSeedTrustStore([]protocol.AuthorityKeyRecord{root})
		if err != nil {
			t.Fatal(err)
		}
		update := signedSeedCovCloneKey(t, root)
		update.AuthorityRole++
		seed := signedSeedForTest(t, root, rootPrivate, 220, nil, []protocol.AuthorityKeyRecord{update})
		if err := store.Accept(seed, 220); err == nil || !strings.Contains(err.Error(), "cannot update pinned bootstrap root") {
			t.Fatalf("err = %v, want cannot update pinned bootstrap root", err)
		}
	})
}

// withAuthorityID returns a copy of key with AuthorityID replaced. It preserves
// AuthorityKeyID (and therefore the signer identity) while making the full
// record differ. Referenced by >=2 tests, so not U1000.
func withAuthorityID(key protocol.AuthorityKeyRecord, authorityID []byte) protocol.AuthorityKeyRecord {
	key.AuthorityID = authorityID
	return key
}
