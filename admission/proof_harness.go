package admission

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"math/big"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

type ProductionProofHarnessReport struct {
	Passed                              bool
	BlindRSA2048Verified                bool
	BlindRSAAuthenticatorTamperRejected bool
	BlindRSAOriginPolicyRejected        bool
	VOPRFProofOnlyRejected              bool
	LabStaticTokenRejected              bool
}

func RunProductionProofHarness(now uint64) (ProductionProofHarnessReport, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ProductionProofHarnessReport{}, err
	}
	keyDER, err := marshalRSAPSSPublicKey(&priv.PublicKey)
	if err != nil {
		return ProductionProofHarnessReport{}, err
	}
	proof, err := signedBlindRSAProof(priv, keyDER)
	if err != nil {
		return ProductionProofHarnessReport{}, err
	}
	metadata, err := blindRSAIssuerMetadata(proof, keyDER)
	if err != nil {
		return ProductionProofHarnessReport{}, err
	}
	proof, err = bindProofToIssuerMetadata(proof, metadata)
	if err != nil {
		return ProductionProofHarnessReport{}, err
	}

	report := ProductionProofHarnessReport{}
	report.BlindRSA2048Verified = VerifyBlindRSA2048WithIssuerMetadata(proof, metadata, now) == nil

	tampered := cloneAdmissionProof(proof)
	tampered.TokenAuthenticator[0] ^= 0x80
	report.BlindRSAAuthenticatorTamperRejected = VerifyBlindRSA2048WithIssuerMetadata(tampered, metadata, now) != nil

	wrongOrigin := metadata
	wrongOrigin.OriginInfoPolicies = append([]protocol.OriginInfoPolicy(nil), metadata.OriginInfoPolicies...)
	wrongOrigin.OriginInfoPolicies[0].OriginInfo = []byte("other-origin.example")
	wrongOriginProof, err := bindProofToIssuerMetadata(proof, wrongOrigin)
	if err != nil {
		return ProductionProofHarnessReport{}, err
	}
	report.BlindRSAOriginPolicyRejected = VerifyBlindRSA2048WithIssuerMetadata(wrongOriginProof, wrongOrigin, now) != nil

	voprfProof := cloneAdmissionProof(proof)
	voprfProof.ProofType = registry.ProofVOPRFP384SHA384
	report.VOPRFProofOnlyRejected = VerifyBlindRSA2048(voprfProof, keyDER) != nil

	labProof := cloneAdmissionProof(proof)
	labProof.ProofType = registry.ProofLabStaticToken
	report.LabStaticTokenRejected = labProof.ValidateStructural(now, false) != nil

	report.Passed = report.BlindRSA2048Verified &&
		report.BlindRSAAuthenticatorTamperRejected &&
		report.BlindRSAOriginPolicyRejected &&
		report.VOPRFProofOnlyRejected &&
		report.LabStaticTokenRejected
	return report, nil
}

func signedBlindRSAProof(priv *rsa.PrivateKey, keyDER []byte) (protocol.AdmissionProof, error) {
	keyID := sha256.Sum256(keyDER)
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              repeatedBytes(0x31, 16),
		TokenKeyID:            keyID[:],
		RelayBucketID:         repeatedBytes(0x32, 16),
		TokenScopeID:          repeatedBytes(0x33, 16),
		ExpiryUnix:            2000000000,
		TokenNonce:            repeatedBytes(0x34, 32),
		RedemptionContextHash: repeatedBytes(0x35, 48),
	}
	challengeDigest, err := RFC9577TokenChallengeDigest(proof.ProofType, []byte("issuer.example"), []byte("origin.example"), proof.RedemptionContextHash)
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	metadata := protocol.AuroraTokenMetadata{
		RFC9577TokenType:       uint16(proof.ProofType),
		RFC9577ChallengeDigest: append([]byte(nil), challengeDigest...),
		RFC9577TokenKeyID:      append([]byte(nil), proof.TokenKeyID...),
		IssuerName:             []byte("issuer.example"),
		OriginInfo:             []byte("origin.example"),
		IssuerMetadataHash:     repeatedBytes(0x36, 48),
	}
	proof.TokenPublicMetadata, err = protocol.Encode(metadata)
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	authenticatorInput, err := RFC9577AuthenticatorInput(proof, challengeDigest)
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	digest := sha512.Sum384(authenticatorInput)
	proof.TokenAuthenticator, err = rsa.SignPSS(rand.Reader, priv, crypto.SHA384, digest[:], &rsa.PSSOptions{
		SaltLength: 48,
		Hash:       crypto.SHA384,
	})
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	return proof, nil
}

func blindRSAIssuerMetadata(proof protocol.AdmissionProof, keyDER []byte) (protocol.IssuerMetadata, error) {
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
		MetadataSigningKeyID: repeatedBytes(0x37, 16),
		SignatureScheme:      registry.SigECDSAP256SHA384DER,
		KeyEncoding:          registry.KeyP256SEC1Uncompressed,
	}, nil
}

func bindProofToIssuerMetadata(proof protocol.AdmissionProof, metadata protocol.IssuerMetadata) (protocol.AdmissionProof, error) {
	metadataHash, err := auroratrust.IssuerMetadataHash(metadata)
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	tokenMetadata, err := protocol.DecodeAuroraTokenMetadataBytes(proof.TokenPublicMetadata)
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	tokenMetadata.IssuerMetadataHash = metadataHash
	proof.TokenPublicMetadata, err = protocol.Encode(tokenMetadata)
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	return proof, nil
}

func marshalRSAPSSPublicKey(key *rsa.PublicKey) ([]byte, error) {
	rsaKey, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{
		N: key.N,
		E: key.E,
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
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
}

func cloneAdmissionProof(proof protocol.AdmissionProof) protocol.AdmissionProof {
	proof.IssuerID = append([]byte(nil), proof.IssuerID...)
	proof.TokenKeyID = append([]byte(nil), proof.TokenKeyID...)
	proof.RelayBucketID = append([]byte(nil), proof.RelayBucketID...)
	proof.TokenScopeID = append([]byte(nil), proof.TokenScopeID...)
	proof.TokenNonce = append([]byte(nil), proof.TokenNonce...)
	proof.RedemptionContextHash = append([]byte(nil), proof.RedemptionContextHash...)
	proof.TokenPublicMetadata = append([]byte(nil), proof.TokenPublicMetadata...)
	proof.TokenAuthenticator = append([]byte(nil), proof.TokenAuthenticator...)
	proof.BindingProof = append([]byte(nil), proof.BindingProof...)
	proof.Extensions = append([]protocol.Extension(nil), proof.Extensions...)
	for i := range proof.Extensions {
		proof.Extensions[i].Body = append([]byte(nil), proof.Extensions[i].Body...)
	}
	return proof
}

func repeatedBytes(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
