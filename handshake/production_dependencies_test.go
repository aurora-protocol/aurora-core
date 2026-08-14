package handshake

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestBlindRSAAdmissionVerifierRejectsInvalidKeyAndCanceledContext(t *testing.T) {
	if _, err := NewBlindRSAAdmissionVerifier([]byte("not-a-key")); err == nil {
		t.Fatal("invalid Blind RSA verification key accepted")
	}
	context, cancel := context.WithCancel(context.Background())
	cancel()
	verifier := &BlindRSAAdmissionVerifier{verificationKeyDER: []byte("not-used")}
	if err := verifier.VerifyAdmission(context, protocol.AdmissionProof{}, 0); err == nil {
		t.Fatal("canceled admission context accepted")
	}
}

func TestProductionTranscriptSignersMatchEpochPublicKeys(t *testing.T) {
	fixture := newTestVerifiedDeploymentFixture(t, time.Now())
	descriptor := fixture.deployment.Descriptor()
	classicalSigner, err := NewECDSAP256TranscriptSigner(fixture.epochClassical)
	if err != nil {
		t.Fatal(err)
	}
	pqSigner, err := NewMLDSA65TranscriptSigner(fixture.epochPQ)
	if err != nil {
		t.Fatal(err)
	}
	for name, signer := range map[string]TranscriptSigner{
		"classical": classicalSigner,
		"PQ":        pqSigner,
	} {
		t.Run(name, func(t *testing.T) {
			message := []byte("production transcript signer test")
			signature, err := signer.SignTranscript(context.Background(), message)
			if err != nil {
				t.Fatal(err)
			}
			if err := auroracrypto.VerifySignature(signer.PublicKey().SignatureScheme, signer.PublicKey().KeyEncoding, signer.PublicKey().PublicKey, message, signature); err != nil {
				t.Fatalf("verify transcript signature: %v", err)
			}
		})
	}
	if !publicKeysEqual(classicalSigner.PublicKey(), descriptor.EpochAuthClassicalKey) || !publicKeysEqual(pqSigner.PublicKey(), descriptor.EpochAuthPQKey) {
		t.Fatal("production signer public key does not match descriptor epoch key")
	}
}

func TestECDSAP256TranscriptSignerRejectsMalformedPrivateKey(t *testing.T) {
	private := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}}
	if _, err := NewECDSAP256TranscriptSigner(private); err == nil {
		t.Fatal("malformed P-256 private key was accepted")
	}
}

func TestFixedProxyPolicySelectorProducesValidOfferBoundPolicy(t *testing.T) {
	deployment := testVerifiedDeployment(t, time.Now())
	offer := validClientDriverConfig(t, time.Now()).PolicyOffer
	selector, err := NewFixedProxyPolicySelector(deployment.Suite(), registry.PolicyBalancedWeb, registry.RouteFast1, registry.ShapeNormal)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := selector.SelectPolicy(context.Background(), offer, offerTransportHintsForTest())
	if err != nil {
		t.Fatal(err)
	}
	if err := selected.ValidateForOffer(offer); err != nil {
		t.Fatalf("fixed production policy invalid for offer: %v", err)
	}
	if selected.SelectedTunnelPersonality != registry.PersonalityProxyFlow || selected.SelectedSuite != deployment.Suite() || selected.SelectedMethod != registry.MethodWebH2Stream {
		t.Fatalf("unexpected fixed policy: %+v", selected)
	}
	offer.OfferedSuites = []uint64{registry.SuiteHybrid768AESGCM}
	if _, err := selector.SelectPolicy(context.Background(), offer, offerTransportHintsForTest()); err == nil {
		t.Fatal("fixed selector accepted an offer without its configured suite")
	}
}

func TestStaticAccessHintResolverRejectsInvalidCredentialSet(t *testing.T) {
	if _, err := NewStaticAccessHintResolver(nil); err == nil {
		t.Fatal("static access hint resolver accepted an empty credential set")
	}
	credential := validClientDriverConfig(t, time.Now()).AccessHint
	if _, err := NewStaticAccessHintResolver([]admission.AccessHintCredential{credential, credential}); err == nil {
		t.Fatal("static access hint resolver accepted duplicate credentials")
	}
}

func offerTransportHintsForTest() protocol.ClientTransportHints {
	return protocol.ClientTransportHints{Padding: bytes.Repeat([]byte{0x41}, 8)}
}
