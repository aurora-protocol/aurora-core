package issuerd

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/logging"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

type Service struct {
	nowUnix                uint64
	metadata               protocol.IssuerMetadata
	authorityKeys          []protocol.AuthorityKeyRecord
	blindRSAKey            *rsa.PrivateKey
	blindRSATokenKeyDER    []byte
	spentTokens            *admission.MemoryReplayCache
	voprfVerifierAvailable bool
}

type IssueBlindRSA2048Request struct {
	TokenNonce            []byte
	RedemptionContextHash []byte
	ExpiryUnix            uint64
}

type VOPRFVerifierRequest struct {
	ProofType           uint64
	RelayBucketID       []byte
	RequestAuthPolicyID uint64
}

type LogInput struct {
	AdmissionProof   protocol.AdmissionProof
	HintSecret       []byte
	CapsulePlaintext []byte
}

type ServiceReadinessReport struct {
	Passed                    bool
	MetadataPublished         bool
	BlindRSAIssuedAndVerified bool
	VOPRFVerifierService      bool
	VOPRFVerifierFailClosed   bool
	AtomicSpentTokenStore     bool
	SensitiveLogsRedacted     bool
	MetadataHashBoundToken    bool
	Findings                  []string
}

func NewHarnessService(nowUnix uint64) (*Service, error) {
	authoritySigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serviceSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	blindRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	blindRSAKeyDER, err := marshalRSAPSSPublicKey(&blindRSAKey.PublicKey)
	if err != nil {
		return nil, err
	}
	blindRSAKeyID := sha256.Sum256(blindRSAKeyDER)
	voprfKey := []byte("issuerd harness voprf verification key")
	voprfKeyID := sha256.Sum256(voprfKey)

	metadata := protocol.IssuerMetadata{
		MetadataVersion:     registry.Version20,
		IssuerID:            repeatedByte(0x80, 16),
		ValidFromUnix:       100,
		ValidUntilUnix:      1000,
		IssuerName:          []byte("issuer.example"),
		SupportedProofTypes: []uint64{registry.ProofBlindRSA2048, registry.ProofVOPRFP384SHA384},
		TokenKeyMappings: []protocol.IssuerTokenKeyRecord{{
			ProofType:  registry.ProofBlindRSA2048,
			TokenKeyID: blindRSAKeyID[:],
			TokenVerificationKey: protocol.TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
				TokenVerificationKey:       blindRSAKeyDER,
			},
			ValidFromUnix:  100,
			ValidUntilUnix: 1000,
			KeyStatus:      registry.IssuerStatusActive,
		}, {
			ProofType:  registry.ProofVOPRFP384SHA384,
			TokenKeyID: voprfKeyID[:],
			TokenVerificationKey: protocol.TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyVOPRFP384SHA384,
				TokenVerificationKey:       voprfKey,
			},
			ValidFromUnix:  100,
			ValidUntilUnix: 1000,
			KeyStatus:      registry.IssuerStatusActive,
		}},
		OriginInfoPolicies: []protocol.OriginInfoPolicy{{
			PolicyID:             7,
			OriginInfo:           []byte("origin.example"),
			AllowEmptyOriginInfo: false,
			ValidFromUnix:        100,
			ValidUntilUnix:       1000,
		}},
		RelayBucketScopes: []protocol.RelayBucketScope{{
			RelayBucketID:         repeatedByte(0x81, 16),
			TokenScopeID:          repeatedByte(0x82, 16),
			AllowedOriginPolicyID: []uint64{7},
			ValidFromUnix:         100,
			ValidUntilUnix:        1000,
		}},
		VerifierServices: []protocol.IssuerVerifierServiceRecord{{
			ServiceID:         repeatedByte(0x83, 16),
			ServiceKind:       registry.VerifierServiceKindVOPRF,
			ServiceProtocolID: registry.IssuerVerifierVOPRFMTLS13,
			ServiceAuthKey: protocol.PublicKeyRecord{
				SignatureScheme: registry.SigECDSAP256SHA384DER,
				KeyEncoding:     registry.KeyP256SEC1Uncompressed,
				PublicKey:       elliptic.Marshal(elliptic.P256(), serviceSigner.PublicKey.X, serviceSigner.PublicKey.Y),
			},
			AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
			AllowedRelayBucketIDs: [][]byte{repeatedByte(0x81, 16)},
			RequestAuthPolicyID:   9,
			ValidFromUnix:         100,
			ValidUntilUnix:        1000,
			ServiceStatus:         registry.IssuerStatusActive,
		}},
		MetadataSigningKeyID: repeatedByte(0x84, 16),
		SignatureScheme:      registry.SigECDSAP256SHA384DER,
		KeyEncoding:          registry.KeyP256SEC1Uncompressed,
	}
	input, err := auroratrust.IssuerMetadataSignatureInput(metadata)
	if err != nil {
		return nil, err
	}
	metadata.MetadataSignature, err = ecdsa.SignASN1(rand.Reader, authoritySigner, input)
	if err != nil {
		return nil, err
	}
	authorityKeys := []protocol.AuthorityKeyRecord{{
		AuthorityID:    repeatedByte(0x85, 16),
		AuthorityKeyID: metadata.MetadataSigningKeyID,
		PublicKey: protocol.PublicKeyRecord{
			SignatureScheme: metadata.SignatureScheme,
			KeyEncoding:     metadata.KeyEncoding,
			PublicKey:       elliptic.Marshal(elliptic.P256(), authoritySigner.PublicKey.X, authoritySigner.PublicKey.Y),
		},
		ValidFromUnix:  90,
		ValidUntilUnix: 1100,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignIssuerMetadata,
	}}
	return &Service{
		nowUnix:                nowUnix,
		metadata:               metadata,
		authorityKeys:          authorityKeys,
		blindRSAKey:            blindRSAKey,
		blindRSATokenKeyDER:    blindRSAKeyDER,
		spentTokens:            admission.NewMemoryReplayCache(),
		voprfVerifierAvailable: true,
	}, nil
}

func RunServiceReadinessHarness(nowUnix uint64) (ServiceReadinessReport, error) {
	service, err := NewHarnessService(nowUnix)
	if err != nil {
		return ServiceReadinessReport{}, err
	}
	report := ServiceReadinessReport{}

	metadata := service.PublishIssuerMetadata()
	if err := auroratrust.VerifyIssuerMetadataSignature(metadata, service.AuthorityKeys(), nowUnix); err != nil {
		report.addFinding("issuer metadata publication failed verification: " + err.Error())
	} else {
		report.MetadataPublished = true
	}

	proof, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
		TokenNonce:            repeatedByte(0x44, 32),
		RedemptionContextHash: repeatedByte(0x45, 48),
		ExpiryUnix:            nowUnix + 100,
	})
	if err != nil {
		report.addFinding("Blind RSA issuance failed: " + err.Error())
	} else {
		if err := admission.VerifyBlindRSA2048WithIssuerMetadata(proof, metadata, nowUnix); err != nil {
			report.addFinding("issued Blind RSA proof failed verification: " + err.Error())
		} else {
			report.BlindRSAIssuedAndVerified = true
		}
		report.MetadataHashBoundToken = tokenMetadataMatchesIssuerMetadata(proof, metadata)
		if !report.MetadataHashBoundToken {
			report.addFinding("issued token metadata hash does not bind published metadata")
		}
		if _, err := service.SpendToken(proof); err != nil {
			report.addFinding("first token spend failed: " + err.Error())
		} else if _, err := service.SpendToken(proof); err == nil {
			report.addFinding("spent-token store accepted a duplicate token")
		} else {
			report.AtomicSpentTokenStore = true
		}
		logLine := service.RedactedOperationalLog(LogInput{
			AdmissionProof:   proof,
			HintSecret:       []byte("harness hint secret material"),
			CapsulePlaintext: []byte("harness capsule plaintext"),
		})
		report.SensitiveLogsRedacted = logLineHasRedactions(logLine) &&
			!strings.Contains(logLine, hex.EncodeToString(proof.TokenPublicMetadata)) &&
			!strings.Contains(logLine, hex.EncodeToString(proof.TokenAuthenticator)) &&
			!strings.Contains(logLine, "harness hint secret material") &&
			!strings.Contains(logLine, "harness capsule plaintext")
		if !report.SensitiveLogsRedacted {
			report.addFinding("operational log leaked token/capsule/hint material")
		}
	}

	request := VOPRFVerifierRequest{
		ProofType:           registry.ProofVOPRFP384SHA384,
		RelayBucketID:       repeatedByte(0x81, 16),
		RequestAuthPolicyID: 9,
	}
	if err := service.VerifyVOPRFRequest(request); err != nil {
		report.addFinding("VOPRF verifier service rejected valid request: " + err.Error())
	} else {
		report.VOPRFVerifierService = true
	}
	service.SetVOPRFVerifierAvailable(false)
	if err := service.VerifyVOPRFRequest(request); err == nil {
		report.addFinding("VOPRF verifier service outage did not fail closed")
	} else {
		report.VOPRFVerifierFailClosed = true
	}

	report.Passed = report.MetadataPublished &&
		report.BlindRSAIssuedAndVerified &&
		report.VOPRFVerifierService &&
		report.VOPRFVerifierFailClosed &&
		report.AtomicSpentTokenStore &&
		report.SensitiveLogsRedacted &&
		report.MetadataHashBoundToken
	return report, nil
}

func (s *Service) PublishIssuerMetadata() protocol.IssuerMetadata {
	return s.metadata
}

func (s *Service) AuthorityKeys() []protocol.AuthorityKeyRecord {
	return append([]protocol.AuthorityKeyRecord(nil), s.authorityKeys...)
}

func (s *Service) IssueBlindRSA2048(req IssueBlindRSA2048Request) (protocol.AdmissionProof, error) {
	if len(req.TokenNonce) != 32 {
		return protocol.AdmissionProof{}, fmt.Errorf("issuerd: token nonce length %d, want 32", len(req.TokenNonce))
	}
	if len(req.RedemptionContextHash) != 48 {
		return protocol.AdmissionProof{}, fmt.Errorf("issuerd: redemption context hash length %d, want 48", len(req.RedemptionContextHash))
	}
	if req.ExpiryUnix <= s.nowUnix || req.ExpiryUnix > s.metadata.ValidUntilUnix {
		return protocol.AdmissionProof{}, fmt.Errorf("issuerd: token expiry outside issuer metadata validity")
	}
	scope := s.metadata.RelayBucketScopes[0]
	keyID := sha256.Sum256(s.blindRSATokenKeyDER)
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              append([]byte(nil), s.metadata.IssuerID...),
		TokenKeyID:            keyID[:],
		RelayBucketID:         append([]byte(nil), scope.RelayBucketID...),
		TokenScopeID:          append([]byte(nil), scope.TokenScopeID...),
		ExpiryUnix:            req.ExpiryUnix,
		TokenNonce:            append([]byte(nil), req.TokenNonce...),
		RedemptionContextHash: append([]byte(nil), req.RedemptionContextHash...),
	}
	originInfo := s.metadata.OriginInfoPolicies[0].OriginInfo
	challengeDigest, err := admission.RFC9577TokenChallengeDigest(proof.ProofType, s.metadata.IssuerName, originInfo, proof.RedemptionContextHash)
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	metadataHash, err := auroratrust.IssuerMetadataHash(s.metadata)
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	tokenMetadata := protocol.AuroraTokenMetadata{
		RFC9577TokenType:       uint16(proof.ProofType),
		RFC9577ChallengeDigest: append([]byte(nil), challengeDigest...),
		RFC9577TokenKeyID:      append([]byte(nil), proof.TokenKeyID...),
		IssuerName:             append([]byte(nil), s.metadata.IssuerName...),
		OriginInfo:             append([]byte(nil), originInfo...),
		IssuerMetadataHash:     metadataHash,
	}
	proof.TokenPublicMetadata, err = protocol.Encode(tokenMetadata)
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	authenticatorInput, err := admission.RFC9577AuthenticatorInput(proof, challengeDigest)
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	digest := sha512.Sum384(authenticatorInput)
	proof.TokenAuthenticator, err = rsa.SignPSS(rand.Reader, s.blindRSAKey, stdcrypto.SHA384, digest[:], &rsa.PSSOptions{
		SaltLength: 48,
		Hash:       stdcrypto.SHA384,
	})
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	return proof, nil
}

func (s *Service) SpendToken(proof protocol.AdmissionProof) ([]byte, error) {
	if err := admission.VerifyBlindRSA2048WithIssuerMetadata(proof, s.metadata, s.nowUnix); err != nil {
		return nil, err
	}
	redemption, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		return nil, err
	}
	spentKey, err := admission.TokenSpentKey(redemption)
	if err != nil {
		return nil, err
	}
	if !s.spentTokens.InsertIfAbsent(spentKey) {
		return nil, fmt.Errorf("issuerd: token already spent")
	}
	return spentKey, nil
}

func (s *Service) VerifyVOPRFRequest(req VOPRFVerifierRequest) error {
	if !s.voprfVerifierAvailable {
		return fmt.Errorf("issuerd: VOPRF verifier unavailable")
	}
	for _, service := range s.metadata.VerifierServices {
		if service.ServiceKind != registry.VerifierServiceKindVOPRF ||
			service.ServiceProtocolID != registry.IssuerVerifierVOPRFMTLS13 ||
			service.RequestAuthPolicyID != req.RequestAuthPolicyID ||
			service.ServiceStatus != registry.IssuerStatusActive ||
			s.nowUnix < service.ValidFromUnix || s.nowUnix >= service.ValidUntilUnix {
			continue
		}
		if !containsUint64(service.AllowedProofTypes, req.ProofType) {
			continue
		}
		for _, bucketID := range service.AllowedRelayBucketIDs {
			if bytes.Equal(bucketID, req.RelayBucketID) {
				return nil
			}
		}
	}
	return fmt.Errorf("issuerd: no verifier service authorizes request")
}

func (s *Service) SetVOPRFVerifierAvailable(available bool) {
	s.voprfVerifierAvailable = available
}

func (s *Service) RedactedOperationalLog(input LogInput) string {
	admissionProof, _ := protocol.Encode(input.AdmissionProof)
	fields := []logging.Field{
		logging.SafeField("admission_proof", logging.Secret{
			Kind: logging.AdmissionProofPlaintext,
			Data: admissionProof,
		}, false),
		logging.SafeField("token_authenticator", logging.Secret{
			Kind: logging.TokenAuthenticator,
			Data: input.AdmissionProof.TokenAuthenticator,
		}, false),
		logging.SafeField("hint_secret", logging.Secret{
			Kind: logging.HintSecret,
			Data: input.HintSecret,
		}, false),
		logging.SafeField("capsule_plaintext", logging.Secret{
			Kind: logging.CapsulePlaintext,
			Data: input.CapsulePlaintext,
		}, false),
	}
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		parts = append(parts, field.Key+"="+field.Value)
	}
	return strings.Join(parts, " ")
}

func tokenMetadataMatchesIssuerMetadata(proof protocol.AdmissionProof, metadata protocol.IssuerMetadata) bool {
	tokenMetadata, err := protocol.DecodeAuroraTokenMetadataBytes(proof.TokenPublicMetadata)
	if err != nil {
		return false
	}
	metadataHash, err := auroratrust.IssuerMetadataHash(metadata)
	if err != nil {
		return false
	}
	return bytes.Equal(tokenMetadata.IssuerMetadataHash, metadataHash)
}

func logLineHasRedactions(line string) bool {
	for _, marker := range []string{
		"[redacted:admission-proof:",
		"[redacted:token-authenticator:",
		"[redacted:hint-secret:",
		"[redacted:capsule-plaintext:",
	} {
		if !strings.Contains(line, marker) {
			return false
		}
	}
	return true
}

func (r *ServiceReadinessReport) addFinding(finding string) {
	r.Findings = append(r.Findings, finding)
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

func containsUint64(values []uint64, want uint64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func repeatedByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
