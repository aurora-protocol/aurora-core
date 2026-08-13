package issuerd

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
)

type ProductionBlindRSAServiceOptions struct {
	Metadata           protocol.IssuerMetadata
	AuthorityKeys      []protocol.AuthorityKeyRecord
	BlindRSAKey        *rsa.PrivateKey
	SpentTokenCache    admission.ReplayCache
	RelayBucketID      []byte
	OriginInfoPolicyID uint64
	NowUnix            func() uint64
}

func NewProductionBlindRSAService(options ProductionBlindRSAServiceOptions) (*Service, error) {
	if options.NowUnix == nil {
		return nil, fmt.Errorf("issuerd: production clock is required")
	}
	nowUnix := options.NowUnix()
	if nowUnix == 0 {
		return nil, fmt.Errorf("issuerd: production clock returned an invalid time")
	}
	if options.BlindRSAKey == nil {
		return nil, fmt.Errorf("issuerd: Blind RSA private key is required")
	}
	if err := options.BlindRSAKey.Validate(); err != nil {
		return nil, fmt.Errorf("issuerd: validate Blind RSA private key: %w", err)
	}
	metadata, err := cloneIssuerMetadata(options.Metadata)
	if err != nil {
		return nil, err
	}
	authorityKeys, err := cloneAuthorityKeyRecords(options.AuthorityKeys)
	if err != nil {
		return nil, err
	}
	if err := auroratrust.VerifyIssuerMetadataSignature(metadata, authorityKeys, nowUnix); err != nil {
		return nil, fmt.Errorf("issuerd: verify production issuer metadata: %w", err)
	}
	if err := validateProductionBlindRSAMetadata(metadata); err != nil {
		return nil, err
	}
	retentionCache, ok := options.SpentTokenCache.(admission.RetentionReplayCache)
	if !ok {
		return nil, fmt.Errorf("issuerd: spent-token cache does not support retention")
	}
	blindRSAKey, err := cloneRSAPrivateKey(options.BlindRSAKey)
	if err != nil {
		return nil, err
	}
	blindRSAKeyDER, err := marshalRSAPSSPublicKey(&blindRSAKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("issuerd: encode Blind RSA public key: %w", err)
	}
	if err := validateProductionBlindRSAKey(metadata, blindRSAKeyDER, nowUnix); err != nil {
		return nil, err
	}
	issuanceScope, originInfo, err := selectProductionIssuanceScope(metadata, options.RelayBucketID, options.OriginInfoPolicyID, nowUnix)
	if err != nil {
		return nil, err
	}
	return &Service{
		now:                        options.NowUnix,
		metadata:                   metadata,
		authorityKeys:              authorityKeys,
		blindRSAKey:                blindRSAKey,
		blindRSATokenKeyDER:        blindRSAKeyDER,
		spentTokens:                retentionCache,
		issuanceScope:              issuanceScope,
		issuanceOriginInfo:         originInfo,
		issuanceOriginInfoPolicyID: options.OriginInfoPolicyID,
		authorizedRelayKeys:        make(map[uint64][]protocol.PublicKeyRecord),
		voprfVerifierAvailable:     false,
	}, nil
}

func cloneRSAPrivateKey(key *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	keyCopy := *key
	encoded := x509.MarshalPKCS1PrivateKey(&keyCopy)
	cloned, err := x509.ParsePKCS1PrivateKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("issuerd: clone Blind RSA private key: %w", err)
	}
	if err := cloned.Validate(); err != nil {
		return nil, fmt.Errorf("issuerd: validate cloned Blind RSA private key: %w", err)
	}
	return cloned, nil
}

func cloneIssuerMetadata(metadata protocol.IssuerMetadata) (protocol.IssuerMetadata, error) {
	encoded, err := protocol.Encode(metadata)
	if err != nil {
		return protocol.IssuerMetadata{}, fmt.Errorf("issuerd: encode issuer metadata: %w", err)
	}
	reader := wire.NewReader(encoded)
	cloned := protocol.DecodeIssuerMetadata(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.IssuerMetadata{}, fmt.Errorf("issuerd: clone issuer metadata failed")
	}
	return cloned, nil
}

func cloneAuthorityKeyRecords(records []protocol.AuthorityKeyRecord) ([]protocol.AuthorityKeyRecord, error) {
	cloned := make([]protocol.AuthorityKeyRecord, len(records))
	for i, record := range records {
		encoded, err := protocol.Encode(record)
		if err != nil {
			return nil, fmt.Errorf("issuerd: encode authority key %d: %w", i, err)
		}
		reader := wire.NewReader(encoded)
		cloned[i] = protocol.DecodeAuthorityKeyRecord(reader)
		if reader.Err() != nil || !reader.EOF() {
			return nil, fmt.Errorf("issuerd: clone authority key %d failed", i)
		}
	}
	return cloned, nil
}

func validateProductionBlindRSAMetadata(metadata protocol.IssuerMetadata) error {
	if len(metadata.VerifierServices) != 0 {
		return fmt.Errorf("issuerd: production Blind RSA metadata must not advertise VOPRF verifier services")
	}
	if len(metadata.SupportedProofTypes) != 1 || metadata.SupportedProofTypes[0] != registry.ProofBlindRSA2048 {
		for _, proofType := range metadata.SupportedProofTypes {
			if proofType == registry.ProofVOPRFP384SHA384 {
				return fmt.Errorf("issuerd: production Blind RSA metadata must not advertise VOPRF")
			}
		}
		return fmt.Errorf("issuerd: production issuer must support only Blind RSA")
	}
	for _, key := range metadata.TokenKeyMappings {
		if key.ProofType != registry.ProofBlindRSA2048 {
			return fmt.Errorf("issuerd: production Blind RSA metadata contains unsupported proof type 0x%x", key.ProofType)
		}
	}
	return nil
}

func validateProductionBlindRSAKey(metadata protocol.IssuerMetadata, encodedPublicKey []byte, nowUnix uint64) error {
	keyID := sha256.Sum256(encodedPublicKey)
	var matches int
	for _, key := range metadata.TokenKeyMappings {
		if key.ProofType != registry.ProofBlindRSA2048 || key.KeyStatus != registry.IssuerStatusActive {
			continue
		}
		if !bytes.Equal(key.TokenKeyID, keyID[:]) || !bytes.Equal(key.TokenVerificationKey.TokenVerificationKey, encodedPublicKey) {
			continue
		}
		if err := key.Validate(nowUnix); err != nil {
			continue
		}
		matches++
	}
	if matches != 1 {
		return fmt.Errorf("issuerd: Blind RSA private key does not match exactly one active issuer token key")
	}
	return nil
}

func selectProductionIssuanceScope(metadata protocol.IssuerMetadata, relayBucketID []byte, originInfoPolicyID, nowUnix uint64) (protocol.RelayBucketScope, []byte, error) {
	if len(relayBucketID) != 16 {
		return protocol.RelayBucketScope{}, nil, fmt.Errorf("issuerd: production relay bucket id must be 16 bytes")
	}
	if originInfoPolicyID == 0 {
		return protocol.RelayBucketScope{}, nil, fmt.Errorf("issuerd: production origin-info policy id is required")
	}
	var scopes []protocol.RelayBucketScope
	for _, scope := range metadata.RelayBucketScopes {
		if !bytes.Equal(scope.RelayBucketID, relayBucketID) || nowUnix < scope.ValidFromUnix || nowUnix >= scope.ValidUntilUnix {
			continue
		}
		for _, policyID := range scope.AllowedOriginPolicyID {
			if policyID == originInfoPolicyID {
				scopes = append(scopes, scope)
				break
			}
		}
	}
	if len(scopes) != 1 {
		return protocol.RelayBucketScope{}, nil, fmt.Errorf("issuerd: production issuance scope selection returned %d matches", len(scopes))
	}
	var policies []protocol.OriginInfoPolicy
	for _, policy := range metadata.OriginInfoPolicies {
		if policy.PolicyID == originInfoPolicyID && nowUnix >= policy.ValidFromUnix && nowUnix < policy.ValidUntilUnix {
			policies = append(policies, policy)
		}
	}
	if len(policies) != 1 {
		return protocol.RelayBucketScope{}, nil, fmt.Errorf("issuerd: production origin-info policy selection returned %d matches", len(policies))
	}
	return cloneRelayBucketScope(scopes[0]), append([]byte(nil), policies[0].OriginInfo...), nil
}

func validateCurrentIssuanceScope(metadata protocol.IssuerMetadata, scope protocol.RelayBucketScope, originInfoPolicyID, nowUnix uint64) error {
	if nowUnix < scope.ValidFromUnix || nowUnix >= scope.ValidUntilUnix {
		return fmt.Errorf("issuerd: issuance scope is outside validity")
	}
	allowed := false
	for _, policyID := range scope.AllowedOriginPolicyID {
		if policyID == originInfoPolicyID {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("issuerd: issuance scope does not authorize origin-info policy")
	}
	var matches int
	for _, policy := range metadata.OriginInfoPolicies {
		if policy.PolicyID == originInfoPolicyID && nowUnix >= policy.ValidFromUnix && nowUnix < policy.ValidUntilUnix {
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("issuerd: issuance origin-info policy selection returned %d matches", matches)
	}
	return nil
}

func cloneRelayBucketScope(scope protocol.RelayBucketScope) protocol.RelayBucketScope {
	return protocol.RelayBucketScope{
		RelayBucketID:         append([]byte(nil), scope.RelayBucketID...),
		TokenScopeID:          append([]byte(nil), scope.TokenScopeID...),
		AllowedOriginPolicyID: append([]uint64(nil), scope.AllowedOriginPolicyID...),
		ValidFromUnix:         scope.ValidFromUnix,
		ValidUntilUnix:        scope.ValidUntilUnix,
	}
}
