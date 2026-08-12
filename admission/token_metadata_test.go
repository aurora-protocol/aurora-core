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
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
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

func TestValidateBlindRSA2048VerificationKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := marshalRSAPSSPublicKeyForTest(t, &priv.PublicKey)
	if err := ValidateBlindRSA2048VerificationKey(keyDER); err != nil {
		t.Fatalf("valid Blind RSA verification key rejected: %v", err)
	}
	if err := ValidateBlindRSA2048VerificationKey(append(keyDER, 0)); err == nil {
		t.Fatal("verification key with trailing bytes accepted")
	}
}

func TestVerifyBlindRSA2048WithIssuerMetadataEnforcesIssuerPolicy(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := marshalRSAPSSPublicKeyForTest(t, &priv.PublicKey)
	proof := signedBlindRSAProofForTest(t, priv, keyDER)
	metadata := blindRSAIssuerMetadataForTest(proof, keyDER)
	proof = bindProofToIssuerMetadataForTest(t, proof, metadata)

	if err := VerifyBlindRSA2048WithIssuerMetadata(proof, metadata, 100); err != nil {
		t.Fatalf("valid metadata-bound Blind RSA proof rejected: %v", err)
	}

	withoutKey := metadata
	withoutKey.TokenKeyMappings = nil
	if err := VerifyBlindRSA2048WithIssuerMetadata(bindProofToIssuerMetadataForTest(t, proof, withoutKey), withoutKey, 100); err == nil {
		t.Fatalf("Blind RSA proof accepted without issuer token key mapping")
	}

	wrongScope := metadata
	wrongScope.RelayBucketScopes = append([]protocol.RelayBucketScope(nil), metadata.RelayBucketScopes...)
	wrongScope.RelayBucketScopes[0].RelayBucketID = rep(0xfe, 16)
	if err := VerifyBlindRSA2048WithIssuerMetadata(bindProofToIssuerMetadataForTest(t, proof, wrongScope), wrongScope, 100); err == nil {
		t.Fatalf("Blind RSA proof accepted outside relay bucket scope")
	}

	wrongOrigin := metadata
	wrongOrigin.OriginInfoPolicies = append([]protocol.OriginInfoPolicy(nil), metadata.OriginInfoPolicies...)
	wrongOrigin.OriginInfoPolicies[0].OriginInfo = []byte("other-origin.example")
	if err := VerifyBlindRSA2048WithIssuerMetadata(bindProofToIssuerMetadataForTest(t, proof, wrongOrigin), wrongOrigin, 100); err == nil {
		t.Fatalf("Blind RSA proof accepted outside origin policy")
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

func blindRSAIssuerMetadataForTest(proof protocol.AdmissionProof, keyDER []byte) protocol.IssuerMetadata {
	return protocol.IssuerMetadata{
		MetadataVersion:     registry.Version20,
		IssuerID:            append([]byte(nil), proof.IssuerID...),
		ValidFromUnix:       10,
		ValidUntilUnix:      200,
		IssuerName:          []byte("issuer.example"),
		SupportedProofTypes: []uint64{registry.ProofBlindRSA2048},
		TokenKeyMappings: []protocol.IssuerTokenKeyRecord{{
			ProofType:  registry.ProofBlindRSA2048,
			TokenKeyID: append([]byte(nil), proof.TokenKeyID...),
			TokenVerificationKey: protocol.TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
				TokenVerificationKey:       append([]byte(nil), keyDER...),
			},
			ValidFromUnix:  10,
			ValidUntilUnix: 200,
			KeyStatus:      registry.IssuerStatusActive,
		}},
		OriginInfoPolicies: []protocol.OriginInfoPolicy{{
			PolicyID:             7,
			OriginInfo:           []byte("origin.example"),
			AllowEmptyOriginInfo: false,
			ValidFromUnix:        10,
			ValidUntilUnix:       200,
		}},
		RelayBucketScopes: []protocol.RelayBucketScope{{
			RelayBucketID:         append([]byte(nil), proof.RelayBucketID...),
			TokenScopeID:          append([]byte(nil), proof.TokenScopeID...),
			AllowedOriginPolicyID: []uint64{7},
			ValidFromUnix:         10,
			ValidUntilUnix:        200,
		}},
		MetadataSigningKeyID: rep(0x37, 16),
		SignatureScheme:      registry.SigECDSAP256SHA384DER,
		KeyEncoding:          registry.KeyP256SEC1Uncompressed,
	}
}

func bindProofToIssuerMetadataForTest(t *testing.T, proof protocol.AdmissionProof, metadata protocol.IssuerMetadata) protocol.AdmissionProof {
	t.Helper()
	metadataHash, err := auroratrust.IssuerMetadataHash(metadata)
	if err != nil {
		t.Fatal(err)
	}
	tokenMetadata, err := protocol.DecodeAuroraTokenMetadataBytes(proof.TokenPublicMetadata)
	if err != nil {
		t.Fatal(err)
	}
	tokenMetadata.IssuerMetadataHash = metadataHash
	proof.TokenPublicMetadata, err = protocol.Encode(tokenMetadata)
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
