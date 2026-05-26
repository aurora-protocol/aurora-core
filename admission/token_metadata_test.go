package admission

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestBlindRSA2048VerifierAcceptsPSSAuthenticator(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := marshalRSAPSSPublicKeyForTest(t, &priv.PublicKey)
	proof := signedBlindRSAProofForTest(t, priv, keyDER)

	verifier := BlindRSA2048Verifier{TokenVerificationKeyDER: keyDER}
	if err := verifier.VerifyBlindRSA2048(proof); err != nil {
		t.Fatalf("valid Blind RSA proof rejected: %v", err)
	}

	proof.TokenAuthenticator[0] ^= 0x80
	if err := verifier.VerifyBlindRSA2048(proof); err == nil {
		t.Fatalf("tampered Blind RSA authenticator accepted")
	}
}

func TestBlindRSA2048VerifierRejectsRSAEncryptionSPKI(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	proof := signedBlindRSAProofForTest(t, priv, keyDER)
	if err := (BlindRSA2048Verifier{TokenVerificationKeyDER: keyDER}).VerifyBlindRSA2048(proof); err == nil {
		t.Fatalf("rsaEncryption SPKI accepted for Blind RSA token key")
	}
}

func signedBlindRSAProofForTest(t *testing.T, priv *rsa.PrivateKey, keyDER []byte) protocol.AdmissionProof {
	t.Helper()
	keyID := sha256.Sum256(keyDER)
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              rep(0x31, 16),
		TokenKeyID:            keyID[:],
		RelayBucketID:         rep(0x32, 16),
		TokenScopeID:          rep(0x33, 16),
		ExpiryUnix:            2000000000,
		TokenNonce:            rep(0x34, 32),
		RedemptionContextHash: rep(0x35, 48),
	}
	challengeDigest, err := RFC9577TokenChallengeDigest(proof.ProofType, []byte("issuer.example"), []byte("origin.example"), proof.RedemptionContextHash)
	if err != nil {
		t.Fatal(err)
	}
	metadata := protocol.AuroraTokenMetadata{
		RFC9577TokenType:       uint16(proof.ProofType),
		RFC9577ChallengeDigest: challengeDigest,
		RFC9577TokenKeyID:      append([]byte(nil), proof.TokenKeyID...),
		IssuerName:             []byte("issuer.example"),
		OriginInfo:             []byte("origin.example"),
		IssuerMetadataHash:     rep(0x36, 48),
	}
	proof.TokenPublicMetadata, err = protocol.Encode(metadata)
	if err != nil {
		t.Fatal(err)
	}
	authenticatorInput, err := RFC9577AuthenticatorInput(proof, challengeDigest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(authenticatorInput)
	proof.TokenAuthenticator, err = rsa.SignPSS(rand.Reader, priv, crypto.SHA384, digest[:], &rsa.PSSOptions{
		SaltLength: 48,
		Hash:       crypto.SHA384,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func marshalRSAPSSPublicKeyForTest(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	rsaKey, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{
		N: key.N,
		E: key.E,
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10},
		},
		SubjectPublicKey: asn1.BitString{Bytes: rsaKey, BitLength: len(rsaKey) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
