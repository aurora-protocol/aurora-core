package admission

import (
	"bytes"
	"testing"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/wire"
)

// validHintCredential returns a credential that satisfies validate().
func validHintCredential() AccessHintCredential {
	return AccessHintCredential{
		HintIssuerID:  rep(0x51, 16),
		RelayBucketID: rep(0x52, 16),
		HintEpochID:   7,
		HintSelector:  rep(0x53, 16),
		HintSecret:    rep(0x54, 32),
		ExpiryUnix:    9999,
		MaxUses:       1,
	}
}

// TestEncodeDecodeAccessHintCredentialRoundTrip covers the single-credential
// codec (distinct from the already-tested set codec): encode then decode, full
// field equality, and non-aliasing of decoded fields with the encoded buffer.
func TestEncodeDecodeAccessHintCredentialRoundTrip(t *testing.T) {
	cred := validHintCredential()
	encoded, err := EncodeAccessHintCredential(cred)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAccessHintCredential(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.HintIssuerID, cred.HintIssuerID) ||
		!bytes.Equal(decoded.RelayBucketID, cred.RelayBucketID) ||
		decoded.HintEpochID != cred.HintEpochID ||
		!bytes.Equal(decoded.HintSelector, cred.HintSelector) ||
		!bytes.Equal(decoded.HintSecret, cred.HintSecret) ||
		decoded.ExpiryUnix != cred.ExpiryUnix ||
		decoded.MaxUses != cred.MaxUses {
		t.Fatalf("round-trip mismatch: %+v", decoded)
	}
	decoded.HintSecret[0] ^= 0xff
	if bytes.Equal(decoded.HintSecret, cred.HintSecret) {
		t.Fatal("decoded HintSecret aliases encoded storage")
	}
}

// TestEncodeAccessHintCredentialRejectsInvalidCredential covers each validate()
// branch through the single encoder.
func TestEncodeAccessHintCredentialRejectsInvalidCredential(t *testing.T) {
	cases := []struct {
		name string
		mut  func(AccessHintCredential) AccessHintCredential
	}{
		{"short issuer id", func(c AccessHintCredential) AccessHintCredential { c.HintIssuerID = rep(0x51, 15); return c }},
		{"short relay bucket", func(c AccessHintCredential) AccessHintCredential { c.RelayBucketID = rep(0x52, 15); return c }},
		{"short selector", func(c AccessHintCredential) AccessHintCredential { c.HintSelector = rep(0x53, 15); return c }},
		{"short secret", func(c AccessHintCredential) AccessHintCredential { c.HintSecret = rep(0x54, 31); return c }},
		{"max uses != 1", func(c AccessHintCredential) AccessHintCredential { c.MaxUses = 2; return c }},
	}
	for _, tc := range cases {
		if _, err := EncodeAccessHintCredential(tc.mut(validHintCredential())); err == nil {
			t.Fatalf("%s: invalid credential accepted", tc.name)
		}
	}
}

// TestDecodeAccessHintCredentialRejectsMalformedWire covers the trailing-bytes,
// truncation, and empty-input rejection paths in the single decoder.
func TestDecodeAccessHintCredentialRejectsMalformedWire(t *testing.T) {
	cred := validHintCredential()
	encoded, err := EncodeAccessHintCredential(cred)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAccessHintCredential(append(append([]byte(nil), encoded...), 0)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	if _, err := DecodeAccessHintCredential(encoded[:len(encoded)-1]); err == nil {
		t.Fatal("truncated wire accepted")
	}
	if _, err := DecodeAccessHintCredential(nil); err == nil {
		t.Fatal("empty wire accepted")
	}
}

// TestDecodeAccessHintCredentialRejectsInvalidDecodedFields covers the
// post-decode validate() path: a wire blob that decodes cleanly but whose
// MaxUses != 1 must be rejected.
func TestDecodeAccessHintCredentialRejectsInvalidDecodedFields(t *testing.T) {
	e := wire.NewEncoder()
	encodeAccessHintCredential(e, AccessHintCredential{
		HintIssuerID:  rep(0x51, 16),
		RelayBucketID: rep(0x52, 16),
		HintEpochID:   7,
		HintSelector:  rep(0x53, 16),
		HintSecret:    rep(0x54, 32),
		ExpiryUnix:    9999,
		MaxUses:       2,
	})
	blob, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAccessHintCredential(blob); err == nil {
		t.Fatal("decoded credential with max_uses != 1 accepted")
	}
}

// TestDeriveHintSecretDeterministicAndMatchesHKDFOracle pins the HKDF
// construction (extract over a fixed label, then expand-label over the canonical
// context) and verifies determinism and per-input distinctness.
func TestDeriveHintSecretDeterministicAndMatchesHKDFOracle(t *testing.T) {
	verifierSecret := []byte("verifier-secret")
	issuerID := rep(0x61, 16)
	relayBucketID := rep(0x62, 16)
	hintEpochID := uint64(9)
	hintSelector := rep(0x63, 16)

	got, err := DeriveHintSecret(verifierSecret, issuerID, relayBucketID, hintEpochID, hintSelector)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("DeriveHintSecret length = %d, want 32", len(got))
	}
	got2, err := DeriveHintSecret(verifierSecret, issuerID, relayBucketID, hintEpochID, hintSelector)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, got2) {
		t.Fatal("DeriveHintSecret not deterministic for identical inputs")
	}

	// Oracle: HKDF-Extract(SHA-384) over the fixed label, then HKDF-Expand-Label
	// over the canonical context (issuerID 16, relayBucketID 16, epoch 8, selector 16).
	ctx := wire.NewEncoder()
	ctx.WriteOpaqueFixed(issuerID, 16)
	ctx.WriteOpaqueFixed(relayBucketID, 16)
	ctx.WriteUint64(hintEpochID)
	ctx.WriteOpaqueFixed(hintSelector, 16)
	contextBytes, err := ctx.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	prk, err := auroracrypto.HKDFExtractSHA384(verifierSecret, []byte("aurora v2.0 hint"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := auroracrypto.HKDFExpandLabelSHA384(prk, "hint secret", contextBytes, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("DeriveHintSecret = %x, want %x", got, want)
	}

	// Distinctness: a different selector must yield a different secret.
	other, err := DeriveHintSecret(verifierSecret, issuerID, relayBucketID, hintEpochID, rep(0x64, 16))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, other) {
		t.Fatal("DeriveHintSecret identical for different selectors")
	}
}

// TestDeriveHintSecretRejectsMalformedInputs covers the wire-layer error path:
// DeriveHintSecret does not pre-validate input lengths, so a short issuer id
// makes WriteOpaqueFixed set a wire error that surfaces from context.Bytes().
func TestDeriveHintSecretRejectsMalformedInputs(t *testing.T) {
	verifierSecret := []byte("verifier-secret")
	if _, err := DeriveHintSecret(verifierSecret, rep(0x61, 15), rep(0x62, 16), 9, rep(0x63, 16)); err == nil {
		t.Fatal("short issuer id accepted")
	}
	if _, err := DeriveHintSecret(verifierSecret, rep(0x61, 16), rep(0x62, 16), 9, rep(0x63, 15)); err == nil {
		t.Fatal("short selector accepted")
	}
}
