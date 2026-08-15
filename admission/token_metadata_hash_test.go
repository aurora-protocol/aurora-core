package admission

import (
	"bytes"
	"testing"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// TestRFC9577AuthenticatorInputHashMatchesOracle pins the authenticator-input
// hash to RFC9577AuthenticatorInput followed by the labeled PreHash (SHA-384).
func TestRFC9577AuthenticatorInputHashMatchesOracle(t *testing.T) {
	proof := protocol.AdmissionProof{
		ProofType:  registry.ProofBlindRSA2048,
		TokenNonce: rep(0x71, 32),
		TokenKeyID: rep(0x72, 32),
	}
	challengeDigest := rep(0x73, 32)

	got, err := RFC9577AuthenticatorInputHash(proof, challengeDigest)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 48 {
		t.Fatalf("hash length = %d, want 48 (SHA-384)", len(got))
	}
	ai, err := RFC9577AuthenticatorInput(proof, challengeDigest)
	if err != nil {
		t.Fatal(err)
	}
	want := auroracrypto.PreHashLabel("aurora v2.0 authenticator input", ai)
	if !bytes.Equal(got, want) {
		t.Fatalf("RFC9577AuthenticatorInputHash = %x, want %x", got, want)
	}
}

// TestRFC9577AuthenticatorInputHashRejectsOversizedProofType covers the proof
// type range check propagated from RFC9577AuthenticatorInput.
func TestRFC9577AuthenticatorInputHashRejectsOversizedProofType(t *testing.T) {
	proof := protocol.AdmissionProof{
		ProofType:  0x10000,
		TokenNonce: rep(0x71, 32),
		TokenKeyID: rep(0x72, 32),
	}
	if _, err := RFC9577AuthenticatorInputHash(proof, rep(0x73, 32)); err == nil {
		t.Fatal("oversized proof type accepted")
	}
}