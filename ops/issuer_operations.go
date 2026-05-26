package ops

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

type HintEpochProvision struct {
	IssuerID                     []byte
	RelayBucketID                []byte
	HintEpochID                  uint64
	VerifierSecret               []byte
	ValidFromUnix                uint64
	ValidUntilUnix               uint64
	OperatorChannelAuthenticated bool
	OperatorChannelEncrypted     bool
	RotationAuditID              string
	Revoked                      bool
	UserSpecificHintTable        bool
}

type IssuerOperationsProfile struct {
	Metadata                                protocol.IssuerMetadata
	AuthorityKeys                           []protocol.AuthorityKeyRecord
	HintEpochs                              []HintEpochProvision
	NowUnix                                 uint64
	PublicRelay                             bool
	IssuerCoordinatedVOPRF                  bool
	ReplayStoreAtomicInsertIfAbsent         bool
	VerifierOutageFailsClosed               bool
	OperationalLogsRedactSensitiveMaterial  bool
	MaxHintEpochSeconds                     uint64
	VerifierServiceRTTMillis                uint64
	MaxVerifierServiceRTTMillis             uint64
	ImplementedVerifierRequestAuthPolicyIDs map[uint64]bool
}

type IssuerOperationsReport struct {
	Passed                 bool
	MetadataVerified       bool
	HintProvisioning       bool
	AtomicReplayStore      bool
	VerifierFailClosed     bool
	SensitiveLogsRedacted  bool
	PublicRelayProofPolicy bool
	Findings               []string
}

func VerifyIssuerOperationsProfile(profile IssuerOperationsProfile) (IssuerOperationsReport, error) {
	report := IssuerOperationsReport{}
	if err := auroratrust.VerifyIssuerMetadataSignature(profile.Metadata, profile.AuthorityKeys, profile.NowUnix); err != nil {
		report.addFinding("issuer metadata verification failed: " + err.Error())
	} else {
		report.MetadataVerified = true
	}

	report.HintProvisioning = verifyHintProvisioning(profile, &report)
	report.AtomicReplayStore = profile.ReplayStoreAtomicInsertIfAbsent
	if !report.AtomicReplayStore {
		report.addFinding("replay store does not promise atomic insert-if-absent")
	}
	report.VerifierFailClosed = verifyVerifierOperations(profile, &report)
	report.SensitiveLogsRedacted = profile.OperationalLogsRedactSensitiveMaterial
	if !report.SensitiveLogsRedacted {
		report.addFinding("operational logs do not redact token/capsule/hint material")
	}
	report.PublicRelayProofPolicy = verifyPublicRelayProofPolicy(profile, &report)

	report.Passed = report.MetadataVerified &&
		report.HintProvisioning &&
		report.AtomicReplayStore &&
		report.VerifierFailClosed &&
		report.SensitiveLogsRedacted &&
		report.PublicRelayProofPolicy
	return report, nil
}

func RunIssuerOperationsHarness(nowUnix uint64) (IssuerOperationsReport, error) {
	profile, err := issuerOperationsHarnessProfile(nowUnix)
	if err != nil {
		return IssuerOperationsReport{}, err
	}
	return VerifyIssuerOperationsProfile(profile)
}

func BuildAccessHintCredential(provision HintEpochProvision, hintSelector []byte, expiryUnix, nowUnix uint64) (admission.AccessHintCredential, error) {
	if err := validateHintEpochProvision(provision, nowUnix, 0); err != nil {
		return admission.AccessHintCredential{}, err
	}
	if len(hintSelector) != 16 {
		return admission.AccessHintCredential{}, fmt.Errorf("ops: hint selector must be 16 bytes")
	}
	if expiryUnix == 0 || expiryUnix > provision.ValidUntilUnix {
		return admission.AccessHintCredential{}, fmt.Errorf("ops: access hint credential expiry exceeds hint epoch")
	}
	if expiryUnix <= nowUnix {
		return admission.AccessHintCredential{}, fmt.Errorf("ops: access hint credential expiry is not in the future")
	}
	secret, err := admission.DeriveHintSecret(provision.VerifierSecret, provision.IssuerID, provision.RelayBucketID, provision.HintEpochID, hintSelector)
	if err != nil {
		return admission.AccessHintCredential{}, err
	}
	return admission.AccessHintCredential{
		HintIssuerID:  append([]byte(nil), provision.IssuerID...),
		RelayBucketID: append([]byte(nil), provision.RelayBucketID...),
		HintEpochID:   provision.HintEpochID,
		HintSelector:  append([]byte(nil), hintSelector...),
		HintSecret:    secret,
		ExpiryUnix:    expiryUnix,
		MaxUses:       1,
	}, nil
}

func issuerOperationsHarnessProfile(nowUnix uint64) (IssuerOperationsProfile, error) {
	authoritySigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return IssuerOperationsProfile{}, err
	}
	serviceSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return IssuerOperationsProfile{}, err
	}
	voprfKey := []byte("aurora harness voprf token verification key")
	voprfKeyID := sha256.Sum256(voprfKey)
	blindRSAKey := []byte("aurora harness blind rsa token verification key")
	blindRSAKeyID := sha256.Sum256(blindRSAKey)
	metadata := protocol.IssuerMetadata{
		MetadataVersion:     registry.Version20,
		IssuerID:            repeatedOpsByte(0x80, 16),
		ValidFromUnix:       100,
		ValidUntilUnix:      1000,
		IssuerName:          []byte("issuer.example"),
		SupportedProofTypes: []uint64{registry.ProofVOPRFP384SHA384, registry.ProofBlindRSA2048},
		TokenKeyMappings: []protocol.IssuerTokenKeyRecord{{
			ProofType:  registry.ProofVOPRFP384SHA384,
			TokenKeyID: voprfKeyID[:],
			TokenVerificationKey: protocol.TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyVOPRFP384SHA384,
				TokenVerificationKey:       voprfKey,
			},
			ValidFromUnix:  100,
			ValidUntilUnix: 1000,
			KeyStatus:      registry.IssuerStatusActive,
		}, {
			ProofType:  registry.ProofBlindRSA2048,
			TokenKeyID: blindRSAKeyID[:],
			TokenVerificationKey: protocol.TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
				TokenVerificationKey:       blindRSAKey,
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
			RelayBucketID:         repeatedOpsByte(0x81, 16),
			TokenScopeID:          repeatedOpsByte(0x82, 16),
			AllowedOriginPolicyID: []uint64{7},
			ValidFromUnix:         100,
			ValidUntilUnix:        1000,
		}},
		VerifierServices: []protocol.IssuerVerifierServiceRecord{{
			ServiceID:         repeatedOpsByte(0x83, 16),
			ServiceKind:       registry.VerifierServiceKindVOPRF,
			ServiceProtocolID: registry.IssuerVerifierVOPRFMTLS13,
			ServiceAuthKey: protocol.PublicKeyRecord{
				SignatureScheme: registry.SigECDSAP256SHA384DER,
				KeyEncoding:     registry.KeyP256SEC1Uncompressed,
				PublicKey:       elliptic.Marshal(elliptic.P256(), serviceSigner.PublicKey.X, serviceSigner.PublicKey.Y),
			},
			AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
			AllowedRelayBucketIDs: [][]byte{repeatedOpsByte(0x81, 16)},
			RequestAuthPolicyID:   9,
			ValidFromUnix:         100,
			ValidUntilUnix:        1000,
			ServiceStatus:         registry.IssuerStatusActive,
		}},
		MetadataSigningKeyID: repeatedOpsByte(0x84, 16),
		SignatureScheme:      registry.SigECDSAP256SHA384DER,
		KeyEncoding:          registry.KeyP256SEC1Uncompressed,
	}
	input, err := auroratrust.IssuerMetadataSignatureInput(metadata)
	if err != nil {
		return IssuerOperationsProfile{}, err
	}
	metadata.MetadataSignature, err = ecdsa.SignASN1(rand.Reader, authoritySigner, input)
	if err != nil {
		return IssuerOperationsProfile{}, err
	}
	return IssuerOperationsProfile{
		Metadata: metadata,
		AuthorityKeys: []protocol.AuthorityKeyRecord{{
			AuthorityID:    repeatedOpsByte(0x85, 16),
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
		}},
		HintEpochs: []HintEpochProvision{{
			IssuerID:                     append([]byte(nil), metadata.IssuerID...),
			RelayBucketID:                repeatedOpsByte(0x81, 16),
			HintEpochID:                  11,
			VerifierSecret:               repeatedOpsByte(0x86, 32),
			ValidFromUnix:                100,
			ValidUntilUnix:               500,
			OperatorChannelAuthenticated: true,
			OperatorChannelEncrypted:     true,
			RotationAuditID:              "rotation-11",
		}},
		NowUnix:                                 nowUnix,
		PublicRelay:                             true,
		ReplayStoreAtomicInsertIfAbsent:         true,
		VerifierOutageFailsClosed:               true,
		OperationalLogsRedactSensitiveMaterial:  true,
		MaxHintEpochSeconds:                     86400,
		VerifierServiceRTTMillis:                50,
		MaxVerifierServiceRTTMillis:             200,
		ImplementedVerifierRequestAuthPolicyIDs: map[uint64]bool{9: true},
	}, nil
}

func verifyHintProvisioning(profile IssuerOperationsProfile, report *IssuerOperationsReport) bool {
	maxEpochSeconds := profile.MaxHintEpochSeconds
	if maxEpochSeconds == 0 {
		maxEpochSeconds = 24 * 60 * 60
	}
	activeScopes := activeRelayBucketScopes(profile.Metadata, profile.NowUnix)
	if len(activeScopes) == 0 {
		report.addFinding("issuer metadata has no active relay bucket scope")
		return false
	}
	passed := true
	for _, scope := range activeScopes {
		var matched bool
		for _, provision := range profile.HintEpochs {
			if !bytes.Equal(provision.IssuerID, profile.Metadata.IssuerID) || !bytes.Equal(provision.RelayBucketID, scope.RelayBucketID) {
				continue
			}
			matched = true
			if !verifyHintEpochProvisionControls(provision, profile.NowUnix, maxEpochSeconds, report) {
				passed = false
			}
		}
		if !matched {
			report.addFinding("active relay bucket lacks hint epoch provisioning")
			passed = false
		}
	}
	return passed
}

func verifyHintEpochProvisionControls(provision HintEpochProvision, nowUnix, maxEpochSeconds uint64, report *IssuerOperationsReport) bool {
	passed := true
	if len(provision.IssuerID) != 16 || len(provision.RelayBucketID) != 16 {
		report.addFinding("ops: hint epoch issuer and relay bucket ids must be 16 bytes")
		passed = false
	}
	if len(provision.VerifierSecret) != 32 {
		report.addFinding("ops: hint epoch verifier secret must be 32 bytes")
		passed = false
	}
	if provision.ValidUntilUnix <= provision.ValidFromUnix {
		report.addFinding("ops: hint epoch validity interval is empty")
		passed = false
	} else {
		if nowUnix < provision.ValidFromUnix || nowUnix >= provision.ValidUntilUnix {
			report.addFinding("ops: hint epoch outside validity interval")
			passed = false
		}
		if maxEpochSeconds != 0 && provision.ValidUntilUnix-provision.ValidFromUnix > maxEpochSeconds {
			report.addFinding("hint epoch validity exceeds configured maximum")
			passed = false
		}
	}
	if provision.Revoked {
		report.addFinding("ops: hint epoch is revoked")
		passed = false
	}
	if !provision.OperatorChannelAuthenticated {
		report.addFinding("hint epoch operator channel lacks mutual authentication")
		passed = false
	}
	if !provision.OperatorChannelEncrypted {
		report.addFinding("hint epoch operator channel lacks transport encryption")
		passed = false
	}
	if provision.RotationAuditID == "" {
		report.addFinding("hint epoch lacks audited rotation record")
		passed = false
	}
	if provision.UserSpecificHintTable {
		report.addFinding("hint epoch uses user-specific hint table")
		passed = false
	}
	return passed
}

func validateHintEpochProvision(provision HintEpochProvision, nowUnix, maxEpochSeconds uint64) error {
	if len(provision.IssuerID) != 16 || len(provision.RelayBucketID) != 16 {
		return fmt.Errorf("ops: hint epoch issuer and relay bucket ids must be 16 bytes")
	}
	if len(provision.VerifierSecret) != 32 {
		return fmt.Errorf("ops: hint epoch verifier secret must be 32 bytes")
	}
	if provision.ValidUntilUnix <= provision.ValidFromUnix {
		return fmt.Errorf("ops: hint epoch validity interval is empty")
	}
	if nowUnix < provision.ValidFromUnix || nowUnix >= provision.ValidUntilUnix {
		return fmt.Errorf("ops: hint epoch outside validity interval")
	}
	if provision.Revoked {
		return fmt.Errorf("ops: hint epoch is revoked")
	}
	if !provision.OperatorChannelAuthenticated {
		return fmt.Errorf("hint epoch operator channel lacks mutual authentication")
	}
	if !provision.OperatorChannelEncrypted {
		return fmt.Errorf("hint epoch operator channel lacks transport encryption")
	}
	if provision.RotationAuditID == "" {
		return fmt.Errorf("hint epoch lacks audited rotation record")
	}
	if provision.UserSpecificHintTable {
		return fmt.Errorf("hint epoch uses user-specific hint table")
	}
	if maxEpochSeconds != 0 && provision.ValidUntilUnix-provision.ValidFromUnix > maxEpochSeconds {
		return fmt.Errorf("hint epoch validity exceeds configured maximum")
	}
	return nil
}

func verifyVerifierOperations(profile IssuerOperationsProfile, report *IssuerOperationsReport) bool {
	if len(profile.Metadata.VerifierServices) == 0 {
		return true
	}
	passed := true
	if !profile.VerifierOutageFailsClosed {
		report.addFinding("verifier service outages do not fail closed")
		passed = false
	}
	maxRTT := profile.MaxVerifierServiceRTTMillis
	if maxRTT == 0 {
		maxRTT = 250
	}
	if profile.VerifierServiceRTTMillis > maxRTT {
		report.addFinding("verifier service latency exceeds configured budget")
		passed = false
	}
	for _, service := range profile.Metadata.VerifierServices {
		if !profile.ImplementedVerifierRequestAuthPolicyIDs[service.RequestAuthPolicyID] {
			report.addFinding("verifier service request auth policy is not implemented")
			passed = false
		}
	}
	return passed
}

func verifyPublicRelayProofPolicy(profile IssuerOperationsProfile, report *IssuerOperationsReport) bool {
	if !profile.PublicRelay || profile.IssuerCoordinatedVOPRF {
		return true
	}
	if metadataHasUsableProof(profile.Metadata, registry.ProofBlindRSA2048, profile.NowUnix) {
		return true
	}
	report.addFinding("public relay without issuer coordination must advertise Blind RSA")
	return false
}

func metadataHasUsableProof(metadata protocol.IssuerMetadata, proofType uint64, nowUnix uint64) bool {
	var supported bool
	for _, supportedProof := range metadata.SupportedProofTypes {
		if supportedProof == proofType {
			supported = true
			break
		}
	}
	if !supported {
		return false
	}
	for _, key := range metadata.TokenKeyMappings {
		if key.ProofType != proofType {
			continue
		}
		if key.Validate(nowUnix) == nil {
			return true
		}
	}
	return false
}

func activeRelayBucketScopes(metadata protocol.IssuerMetadata, nowUnix uint64) []protocol.RelayBucketScope {
	var out []protocol.RelayBucketScope
	for _, scope := range metadata.RelayBucketScopes {
		if nowUnix >= scope.ValidFromUnix && nowUnix < scope.ValidUntilUnix {
			out = append(out, scope)
		}
	}
	return out
}

func (r *IssuerOperationsReport) addFinding(finding string) {
	r.Findings = append(r.Findings, finding)
}

func repeatedOpsByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
