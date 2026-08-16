package protocol

// Adversarial coverage for protocol/signed_seed.go.
//
// The happy paths (EncodeTo/DecodeSignedSeedRecord round trip, Unsigned,
// cloneSignedSeedAuthorityKeys) and several ValidateStructural branches —
// the validity interval (95-97), the 48-byte hash fields (109-111), the
// AuthorityKeyUpdates validation propagation (119-121), the lab seed
// signature scheme (125-127), and the duplicate-authority case (160-162) —
// are already covered by signed_seed_test.go and are not re-asserted here.
//
// This file covers the residual count-0 blocks, perturbing exactly one input
// per case so the branch under test is the one that fires:
//
//   - ValidateStructural 89-91: SeedVersion != registry.Version20.
//   - ValidateStructural 92-94: SeedID length != 16 bytes.
//   - ValidateStructural 98-100: a hint slice longer than 0xffff bytes (the
//     record is constructed, not encoded, so the opaque16 cap does not apply).
//   - ValidateStructural 113-115: more than maximumSignedSeedAuthorityKeys
//     bootstrap keys (returns before the per-key validation, so the extra
//     keys may be zero-valued).
//   - ValidateStructural 116-118: validateSignedSeedAuthorityKeySet(bootstrap,
//     nil) error propagation. Reached via the two bootstrap-key-error cases
//     below (invalid structure and lab scheme), each of which fails the
//     bootstrap set and propagates before the update set is examined.
//   - ValidateStructural 122-124: SeedSignature.SignerKeyID length != 16.
//   - ValidateStructural 128-130: validateSignatureKeyEncodingCompatibility
//     rejects an incompatible KeyEncoding for the (non-lab) seed signature
//     scheme (so the lab-signature check at 125-127 does not fire first).
//   - decodeSignedSeedAuthorityKeys 136-139: a reader whose vector count
//     exceeds maximumSignedSeedAuthorityKeys. Reached by a direct in-package
//     call with a crafted reader (the count check fires before the decode
//     loop runs).
//   - validateSignedSeedAuthorityKeySet 153-155: a bootstrap key whose own
//     ValidateStructural fails (AuthorityID length != 16).
//   - validateSignedSeedAuthorityKeySet 156-158: a bootstrap key with the
//     SigEd25519Lab scheme. PublicKeyRecord.ValidateCompatibility accepts the
//     lab scheme (with a 32-byte key + KeyEd25519RawPublic), so the key passes
//     its own ValidateStructural and reaches the lab-authority-key guard.
//   - signedSeedAuthoritySignerIdentity 174-176: encoder.Bytes() error when a
//     varint field is out of range (SignatureScheme = math.MaxUint64), causing
//     the identity helper to return "". Reached by a direct in-package call.
//
// No dead-by-design blocks remain: every count-0 line is reachable. The
// lab-signature seed check (125-127) is distinct from the lab-authority-key
// check (156-158): the former rejects the seed record's own signature
// scheme, the latter rejects an authority key's public-key scheme, and both
// are independently reachable.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). No new package-level helpers are introduced: the test
// reuses the in-package signedSeedRecordFixture / fill / bytesReader fixtures
// and inlines all other constructs, so there is nothing for staticcheck U1000
// to flag. No context.Context, no goroutines, no deprecated APIs.

import (
	"math"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestSignedSeedValidateStructuralErrorBranches(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*SignedSeedRecord)
		wantSubstr string
	}{
		{
			"unsupported version",
			func(s *SignedSeedRecord) { s.SeedVersion = 0 },
			"unsupported signed seed version",
		},
		{
			"seed id wrong length",
			func(s *SignedSeedRecord) { s.SeedID = fill(0x09, 15) },
			"signed seed id must be 16 bytes",
		},
		{
			"hint exceeds size limit",
			func(s *SignedSeedRecord) { s.DirectoryConsensusHint = make([]byte, 0x10000) },
			"hint exceeds size limit",
		},
		{
			"authority key count exceeds maximum",
			func(s *SignedSeedRecord) {
				// Bring the bootstrap set to 65 entries. The count check
				// (113-115) returns before the per-key validation, so the
				// appended zero-valued keys are never examined.
				s.BootstrapAuthorityKeys = append(s.BootstrapAuthorityKeys, make([]AuthorityKeyRecord, 64)...)
			},
			"authority key count is invalid",
		},
		{
			"bootstrap key invalid structure",
			func(s *SignedSeedRecord) { s.BootstrapAuthorityKeys[0].AuthorityID = fill(0x06, 15) },
			"authority IDs must be 16 bytes",
		},
		{
			"bootstrap key lab scheme",
			func(s *SignedSeedRecord) {
				key := &s.BootstrapAuthorityKeys[0]
				key.PublicKey.SignatureScheme = registry.SigEd25519Lab
				key.PublicKey.KeyEncoding = registry.KeyEd25519RawPublic
				key.PublicKey.PublicKey = fill(0x07, 32)
			},
			"lab authority key disabled",
		},
		{
			"signature incomplete",
			func(s *SignedSeedRecord) { s.SeedSignature.SignerKeyID = fill(0x08, 15) },
			"signature is incomplete",
		},
		{
			"signature key encoding incompatible",
			func(s *SignedSeedRecord) {
				// P-256 scheme with a P-384 key encoding is incompatible; the
				// scheme is not lab, so the lab-signature check does not fire.
				s.SeedSignature.KeyEncoding = registry.KeyP384SEC1Uncompressed
			},
			"incompatible with key encoding",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seed := signedSeedRecordFixture()
			c.mutate(&seed)
			err := seed.ValidateStructural(200)
			if err == nil {
				t.Fatalf("ValidateStructural accepted invalid %q", c.name)
			}
			if !strings.Contains(err.Error(), c.wantSubstr) {
				t.Fatalf("%q: err = %v, want substring %q", c.name, err, c.wantSubstr)
			}
		})
	}
}

func TestDecodeSignedSeedAuthorityKeysCountOverflow(t *testing.T) {
	// A reader whose first varint (the vector count) is
	// maximumSignedSeedAuthorityKeys+1 must trip the count guard (136-139)
	// before the decode loop runs. Provide enough trailing bytes that
	// ReadVectorCount does not itself error on "exceeds remaining", so the
	// count>max half of the guard is the one that fires.
	enc := wire.NewEncoder()
	enc.WriteVarint(maximumSignedSeedAuthorityKeys + 1)
	raw, err := enc.Bytes()
	if err != nil {
		t.Fatalf("encode count: %v", err)
	}
	raw = append(raw, make([]byte, maximumSignedSeedAuthorityKeys+8)...)
	r := bytesReader(raw)

	out := decodeSignedSeedAuthorityKeys(r, "bootstrap authority key")
	if out != nil {
		t.Fatalf("decodeSignedSeedAuthorityKeys = %v, want nil on count overflow", out)
	}
	if r.Err() == nil {
		t.Fatal("reader err = nil, want count-overflow error")
	}
	if !strings.Contains(r.Err().Error(), "count is invalid") {
		t.Fatalf("reader err = %v, want count is invalid", r.Err())
	}
}

func TestSignedSeedAuthoritySignerIdentityEncoderError(t *testing.T) {
	// A key whose PublicKey.SignatureScheme exceeds wire.MaxVarint fails the
	// encoder's WriteVarint, so encoder.Bytes() returns an error and the
	// identity helper returns "" (174-176). The AuthorityKeyID is a valid
	// 16 bytes so WriteOpaqueFixed succeeds before the failing WriteVarint.
	key := AuthorityKeyRecord{
		AuthorityKeyID: fill(0x02, 16),
		PublicKey:      PublicKeyRecord{SignatureScheme: math.MaxUint64},
	}
	if got := signedSeedAuthoritySignerIdentity(key); got != "" {
		t.Fatalf("signedSeedAuthoritySignerIdentity = %q, want empty on encoder error", got)
	}

	// Anchor: a well-formed key produces a non-empty identity, proving the
	// empty result above is because of the out-of-range scheme, not a broken
	// helper.
	valid := signedSeedRecordFixture().BootstrapAuthorityKeys[0]
	if id := signedSeedAuthoritySignerIdentity(valid); id == "" {
		t.Fatal("signedSeedAuthoritySignerIdentity returned empty for a valid key")
	}
}
