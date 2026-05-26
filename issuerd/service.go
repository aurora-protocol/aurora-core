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
	"crypto/x509"
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
	spentTokens            admission.ReplayCache
	verifierServiceSigners map[string]*ecdsa.PrivateKey
	authorizedRelayKeys    map[uint64][]protocol.PublicKeyRecord
	voprfVerifierAvailable bool
}

type ServiceOptions struct {
	SpentTokenCache admission.ReplayCache
}

const (
	harnessValidityBackfillSeconds  uint64 = 100
	harnessValidityLifetimeSeconds  uint64 = 86_400
	harnessAuthorityBackfillSeconds uint64 = 110
	harnessAuthorityLifetimeSeconds uint64 = 90_000
)

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
	return NewHarnessServiceWithOptions(nowUnix, ServiceOptions{})
}

func NewHarnessServiceWithOptions(nowUnix uint64, opts ServiceOptions) (*Service, error) {
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
	validFrom, validUntil := harnessValidityWindow(
		nowUnix,
		harnessValidityBackfillSeconds,
		harnessValidityLifetimeSeconds,
	)
	authorityValidFrom, authorityValidUntil := harnessValidityWindow(
		nowUnix,
		harnessAuthorityBackfillSeconds,
		harnessAuthorityLifetimeSeconds,
	)

	metadata := protocol.IssuerMetadata{
		MetadataVersion:     registry.Version20,
		IssuerID:            repeatedByte(0x80, 16),
		ValidFromUnix:       validFrom,
		ValidUntilUnix:      validUntil,
		IssuerName:          []byte("issuer.example"),
		SupportedProofTypes: []uint64{registry.ProofBlindRSA2048, registry.ProofVOPRFP384SHA384},
		TokenKeyMappings: []protocol.IssuerTokenKeyRecord{{
			ProofType:  registry.ProofBlindRSA2048,
			TokenKeyID: blindRSAKeyID[:],
			TokenVerificationKey: protocol.TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
				TokenVerificationKey:       blindRSAKeyDER,
			},
			ValidFromUnix:  validFrom,
			ValidUntilUnix: validUntil,
			KeyStatus:      registry.IssuerStatusActive,
		}, {
			ProofType:  registry.ProofVOPRFP384SHA384,
			TokenKeyID: voprfKeyID[:],
			TokenVerificationKey: protocol.TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyVOPRFP384SHA384,
				TokenVerificationKey:       voprfKey,
			},
			ValidFromUnix:  validFrom,
			ValidUntilUnix: validUntil,
			KeyStatus:      registry.IssuerStatusActive,
		}},
		OriginInfoPolicies: []protocol.OriginInfoPolicy{{
			PolicyID:             7,
			OriginInfo:           []byte("origin.example"),
			AllowEmptyOriginInfo: false,
			ValidFromUnix:        validFrom,
			ValidUntilUnix:       validUntil,
		}},
		RelayBucketScopes: []protocol.RelayBucketScope{{
			RelayBucketID:         repeatedByte(0x81, 16),
			TokenScopeID:          repeatedByte(0x82, 16),
			AllowedOriginPolicyID: []uint64{7},
			ValidFromUnix:         validFrom,
			ValidUntilUnix:        validUntil,
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
			ValidFromUnix:         validFrom,
			ValidUntilUnix:        validUntil,
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
		ValidFromUnix:  authorityValidFrom,
		ValidUntilUnix: authorityValidUntil,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignIssuerMetadata,
	}}
	spentTokens := opts.SpentTokenCache
	if spentTokens == nil {
		spentTokens = admission.NewMemoryReplayCache()
	}
	return &Service{
		nowUnix:                nowUnix,
		metadata:               metadata,
		authorityKeys:          authorityKeys,
		blindRSAKey:            blindRSAKey,
		blindRSATokenKeyDER:    blindRSAKeyDER,
		spentTokens:            spentTokens,
		verifierServiceSigners: map[string]*ecdsa.PrivateKey{string(metadata.VerifierServices[0].ServiceID): serviceSigner},
		authorizedRelayKeys:    make(map[uint64][]protocol.PublicKeyRecord),
		voprfVerifierAvailable: true,
	}, nil
}

func harnessValidityWindow(nowUnix, backfill, lifetime uint64) (uint64, uint64) {
	var validFrom uint64
	if nowUnix > backfill {
		validFrom = nowUnix - backfill
	}
	validUntil := ^uint64(0)
	if nowUnix <= validUntil-lifetime {
		validUntil = nowUnix + lifetime
	}
	return validFrom, validUntil
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
	inserted, err := s.spentTokens.InsertIfAbsent(spentKey)
	if err != nil {
		return nil, fmt.Errorf("issuerd: spent-token store failed: %w", err)
	}
	if !inserted {
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

func (s *Service) VerifyIssuerVerifierRequest(req protocol.IssuerVerifierRequest) (protocol.IssuerVerifierResponse, error) {
	service, signer, err := s.verifierServiceForRequest(req)
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	requestHash, err := auroratrust.IssuerVerifierRequestHash(req)
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	validUntil, err := verifierResponseValidUntil(s.nowUnix, req, service)
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	decision := registry.VerifierDecisionAccept
	inserted, err := s.spentTokens.InsertIfAbsent(req.TokenSpentKey)
	if err != nil {
		return protocol.IssuerVerifierResponse{}, fmt.Errorf("issuerd: spent-token store failed: %w", err)
	}
	if !inserted {
		decision = registry.VerifierDecisionRejectReplayOrSpent
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	resp := protocol.IssuerVerifierResponse{
		ResponseVersion: registry.Version20,
		ServiceID:       append([]byte(nil), service.ServiceID...),
		RequestHash:     requestHash,
		Decision:        decision,
		DecisionDetail:  decision,
		TokenSpentKey:   append([]byte(nil), req.TokenSpentKey...),
		ValidUntilUnix:  validUntil,
		ResponseNonce:   nonce,
	}
	if decision == registry.VerifierDecisionAccept {
		resp.DecisionDetail = 0
	}
	input, err := auroratrust.IssuerVerifierResponseSignatureInput(requestHash, resp)
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	resp.ServiceSignature, err = ecdsa.SignASN1(rand.Reader, signer, input)
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	return resp, nil
}

func (s *Service) AuthorizeRelayClientKey(requestAuthPolicyID uint64, key protocol.PublicKeyRecord) {
	if s.authorizedRelayKeys == nil {
		s.authorizedRelayKeys = make(map[uint64][]protocol.PublicKeyRecord)
	}
	key.PublicKey = append([]byte(nil), key.PublicKey...)
	s.authorizedRelayKeys[requestAuthPolicyID] = append(s.authorizedRelayKeys[requestAuthPolicyID], key)
}

func (s *Service) AuthorizeVerifierRequestClient(req protocol.IssuerVerifierRequest, cert *x509.Certificate) error {
	service, _, err := s.verifierServiceForRequest(req)
	if err != nil {
		return err
	}
	if cert == nil {
		return fmt.Errorf("issuerd: verifier request lacks relay client certificate")
	}
	for _, key := range s.authorizedRelayKeys[service.RequestAuthPolicyID] {
		if certificateMatchesPublicKeyRecord(cert, key) {
			return nil
		}
	}
	return fmt.Errorf("issuerd: relay client certificate is not authorized for request auth policy")
}

func (s *Service) verifierServiceForRequest(req protocol.IssuerVerifierRequest) (protocol.IssuerVerifierServiceRecord, *ecdsa.PrivateKey, error) {
	if s == nil || !s.ready() {
		return protocol.IssuerVerifierServiceRecord{}, nil, fmt.Errorf("issuerd: verifier unavailable")
	}
	if !s.voprfVerifierAvailable {
		return protocol.IssuerVerifierServiceRecord{}, nil, fmt.Errorf("issuerd: VOPRF verifier unavailable")
	}
	if err := validateIssuerVerifierRequestShape(req); err != nil {
		return protocol.IssuerVerifierServiceRecord{}, nil, err
	}
	if !bytes.Equal(req.IssuerID, s.metadata.IssuerID) {
		return protocol.IssuerVerifierServiceRecord{}, nil, fmt.Errorf("issuerd: issuer mismatch")
	}
	metadataHash, err := auroratrust.IssuerMetadataHash(s.metadata)
	if err != nil {
		return protocol.IssuerVerifierServiceRecord{}, nil, err
	}
	if !bytes.Equal(req.IssuerMetadataHash, metadataHash) {
		return protocol.IssuerVerifierServiceRecord{}, nil, fmt.Errorf("issuerd: issuer metadata hash mismatch")
	}
	if !s.hasUsableTokenKey(req.ProofType, req.TokenKeyID) {
		return protocol.IssuerVerifierServiceRecord{}, nil, fmt.Errorf("issuerd: token key is not usable")
	}
	var matched []protocol.IssuerVerifierServiceRecord
	for _, service := range s.metadata.VerifierServices {
		if !bytes.Equal(service.ServiceID, req.ServiceID) {
			continue
		}
		if err := service.Allows(req.ProofType, req.RelayBucketID, s.nowUnix, true); err != nil {
			continue
		}
		matched = append(matched, service)
	}
	if len(matched) != 1 {
		return protocol.IssuerVerifierServiceRecord{}, nil, fmt.Errorf("issuerd: verifier service selection returned %d matches", len(matched))
	}
	signer := s.verifierServiceSigners[string(matched[0].ServiceID)]
	if signer == nil {
		return protocol.IssuerVerifierServiceRecord{}, nil, fmt.Errorf("issuerd: verifier service signer unavailable")
	}
	return matched[0], signer, nil
}

func validateIssuerVerifierRequestShape(req protocol.IssuerVerifierRequest) error {
	if req.RequestVersion != registry.Version20 {
		return fmt.Errorf("issuerd: unsupported verifier request version 0x%x", req.RequestVersion)
	}
	for name, field := range map[string][]byte{
		"service_id":               req.ServiceID,
		"issuer_id":                req.IssuerID,
		"relay_bucket_id":          req.RelayBucketID,
		"token_nonce":              req.TokenNonce,
		"challenge_digest":         req.ChallengeDigest,
		"authenticator_input_hash": req.AuthenticatorInputHash,
		"token_spent_key":          req.TokenSpentKey,
		"request_nonce":            req.RequestNonce,
		"issuer_metadata_hash":     req.IssuerMetadataHash,
		"relay_descriptor_hash":    req.RelayDescriptorHash,
		"token_key_id":             req.TokenKeyID,
	} {
		if expectedVerifierRequestFieldLength(name) != len(field) {
			return fmt.Errorf("issuerd: verifier request %s length %d", name, len(field))
		}
	}
	if req.ProofType != registry.ProofVOPRFP384SHA384 {
		return fmt.Errorf("issuerd: verifier request proof type 0x%x is not VOPRF", req.ProofType)
	}
	if len(req.TokenAuthenticator) == 0 {
		return fmt.Errorf("issuerd: verifier request lacks token authenticator")
	}
	if req.ReplayEpochValidUntilUnix == 0 {
		return fmt.Errorf("issuerd: verifier request lacks replay epoch expiry")
	}
	if req.RequestTimeUnix == 0 {
		return fmt.Errorf("issuerd: verifier request lacks request time")
	}
	return nil
}

func expectedVerifierRequestFieldLength(name string) int {
	switch name {
	case "service_id", "issuer_id", "relay_bucket_id":
		return 16
	case "token_nonce", "challenge_digest", "request_nonce", "token_key_id":
		return 32
	default:
		return 48
	}
}

func (s *Service) hasUsableTokenKey(proofType uint64, tokenKeyID []byte) bool {
	for _, key := range s.metadata.TokenKeyMappings {
		if key.ProofType != proofType || !bytes.Equal(key.TokenKeyID, tokenKeyID) {
			continue
		}
		if s.nowUnix < key.ValidFromUnix || s.nowUnix >= key.ValidUntilUnix {
			return false
		}
		return key.KeyStatus == registry.IssuerStatusActive || key.KeyStatus == registry.IssuerStatusRetiring
	}
	return false
}

func certificateMatchesPublicKeyRecord(cert *x509.Certificate, key protocol.PublicKeyRecord) bool {
	switch key.SignatureScheme {
	case registry.SigECDSAP256SHA256DER, registry.SigECDSAP256SHA384DER:
		return certificateECDSAKeyMatchesRecord(cert, elliptic.P256(), registry.KeyP256SEC1Uncompressed, registry.KeyP256SPKI, key)
	case registry.SigECDSAP384SHA384DER:
		return certificateECDSAKeyMatchesRecord(cert, elliptic.P384(), registry.KeyP384SEC1Uncompressed, registry.KeyP384SPKI, key)
	default:
		return false
	}
}

func certificateECDSAKeyMatchesRecord(cert *x509.Certificate, curve elliptic.Curve, sec1Encoding, spkiEncoding uint64, key protocol.PublicKeyRecord) bool {
	if cert == nil {
		return false
	}
	pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pk.Curve != curve {
		return false
	}
	var encoded []byte
	var err error
	switch key.KeyEncoding {
	case sec1Encoding:
		encoded = elliptic.Marshal(curve, pk.X, pk.Y)
	case spkiEncoding:
		encoded, err = x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			return false
		}
	default:
		return false
	}
	return bytes.Equal(encoded, key.PublicKey)
}

func verifierResponseValidUntil(nowUnix uint64, req protocol.IssuerVerifierRequest, service protocol.IssuerVerifierServiceRecord) (uint64, error) {
	validUntil := req.RequestTimeUnix + 300
	for _, candidate := range []uint64{service.ValidUntilUnix, req.ReplayEpochValidUntilUnix, nowUnix + 100} {
		if candidate < validUntil {
			validUntil = candidate
		}
	}
	if validUntil <= nowUnix {
		return 0, fmt.Errorf("issuerd: verifier response freshness window already expired")
	}
	return validUntil, nil
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
