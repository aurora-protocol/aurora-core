package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// signedConsensusForWindowTest returns a consensus with window [10,30) signed by
// one authority whose key is valid over the wider window [0,1000), so the
// consensus window is the only time-dependent input under test.
func signedConsensusForWindowTest(t *testing.T) (protocol.DirectoryConsensus, []protocol.AuthorityKeyRecord, func(protocol.DirectoryConsensus) protocol.DirectoryConsensus) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entry := protocol.SignatureEntry{
		AuthorityID:     rb(0xaa, 16),
		AuthorityKeyID:  rb(0xbb, 16),
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
	}
	sign := func(c protocol.DirectoryConsensus) protocol.DirectoryConsensus {
		t.Helper()
		signed := entry
		input, err := DirectoryConsensusSignatureInput(c, signed)
		if err != nil {
			t.Fatal(err)
		}
		signed.Signature, err = ecdsa.SignASN1(rand.Reader, priv, input)
		if err != nil {
			t.Fatal(err)
		}
		c.AuthoritySignatures = []protocol.SignatureEntry{signed}
		return c
	}
	keys := []protocol.AuthorityKeyRecord{{
		AuthorityID:    entry.AuthorityID,
		AuthorityKeyID: entry.AuthorityKeyID,
		PublicKey: protocol.PublicKeyRecord{
			SignatureScheme: entry.SignatureScheme,
			KeyEncoding:     entry.KeyEncoding,
			PublicKey:       mustECDSAPublicKeyBytes(t, &priv.PublicKey),
		},
		ValidFromUnix:  0,
		ValidUntilUnix: 1000,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignDirectoryConsensus | registry.UsageMayRotateDirectoryAuthority,
	}}
	return sign(directoryConsensusForSignatureTest(entry)), keys, sign
}

func TestVerifyDirectoryConsensusSignaturesEnforcesConsensusValidityWindow(t *testing.T) {
	consensus, keys, sign := signedConsensusForWindowTest(t)
	if err := VerifyDirectoryConsensusSignatures(consensus, keys, 20, 1); err != nil {
		t.Fatalf("in-window consensus rejected: %v", err)
	}
	for _, tc := range []struct {
		label string
		now   uint64
	}{
		{"expired", 30},
		{"long expired", 500},
		{"not yet valid", 9},
	} {
		err := VerifyDirectoryConsensusSignatures(consensus, keys, tc.now, 1)
		if err == nil || !strings.Contains(err.Error(), "validity") {
			t.Fatalf("%s consensus accepted at now=%d: err = %v", tc.label, tc.now, err)
		}
	}

	empty := consensus
	empty.ValidFromUnix, empty.ValidUntilUnix = 20, 20
	if err := VerifyDirectoryConsensusSignatures(sign(empty), keys, 20, 1); err == nil {
		t.Fatal("consensus with an empty validity interval accepted")
	}

	wrongVersion := consensus
	wrongVersion.Version = registry.Version20 + 1
	err := VerifyDirectoryConsensusSignatures(sign(wrongVersion), keys, 20, 1)
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("consensus with an unsupported version accepted: err = %v", err)
	}

	// The rotation path verifies the next consensus with the same rules.
	if err := ValidateAuthorityKeyRotation(AuthorityKeyRotationInput{
		PreviousKeys:  keys,
		NextKeys:      keys,
		NextConsensus: consensus,
		NowUnix:       500,
	}); err == nil {
		t.Fatal("rotation accepted an expired next consensus")
	}
}
