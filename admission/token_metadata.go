package admission

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"math/big"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
)

func RFC9577RedemptionContext(redemptionContextHash []byte) ([]byte, error) {
	if len(redemptionContextHash) != 48 {
		return nil, fmt.Errorf("admission: redemption context hash length %d, want 48", len(redemptionContextHash))
	}
	h := sha256.New()
	h.Write([]byte("aurora v2.0 token redemption context"))
	h.Write(redemptionContextHash)
	return h.Sum(nil), nil
}

func RFC9577TokenChallengeDigest(proofType uint64, issuerName, originInfo, redemptionContextHash []byte) ([]byte, error) {
	if proofType > 0xffff {
		return nil, fmt.Errorf("admission: proof type 0x%x does not fit RFC token type", proofType)
	}
	if len(issuerName) == 0 {
		return nil, fmt.Errorf("admission: issuer name is empty")
	}
	redemptionContext, err := RFC9577RedemptionContext(redemptionContextHash)
	if err != nil {
		return nil, err
	}
	e := wire.NewEncoder()
	e.WriteUint16(uint16(proofType))
	e.WriteOpaque16(issuerName)
	e.WriteOpaque8(redemptionContext)
	e.WriteOpaque16(originInfo)
	encoded, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	return sum[:], nil
}

func RFC9577AuthenticatorInputHash(proof protocol.AdmissionProof, challengeDigest []byte) ([]byte, error) {
	authenticatorInput, err := RFC9577AuthenticatorInput(proof, challengeDigest)
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 authenticator input", authenticatorInput), nil
}

func RFC9577AuthenticatorInput(proof protocol.AdmissionProof, challengeDigest []byte) ([]byte, error) {
	if proof.ProofType > 0xffff {
		return nil, fmt.Errorf("admission: proof type 0x%x does not fit RFC token type", proof.ProofType)
	}
	e := wire.NewEncoder()
	e.WriteUint16(uint16(proof.ProofType))
	e.WriteOpaqueFixed(proof.TokenNonce, 32)
	e.WriteOpaqueFixed(challengeDigest, 32)
	e.WriteOpaqueFixed(proof.TokenKeyID, 32)
	authenticatorInput, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return authenticatorInput, nil
}

type BlindRSA2048Verifier struct {
	TokenVerificationKeyDER []byte
}

func (v BlindRSA2048Verifier) VerifyBlindRSA2048(proof protocol.AdmissionProof) error {
	return VerifyBlindRSA2048(proof, v.TokenVerificationKeyDER)
}

func VerifyBlindRSA2048WithIssuerMetadata(proof protocol.AdmissionProof, metadata protocol.IssuerMetadata, now uint64) error {
	if proof.ProofType != registry.ProofBlindRSA2048 {
		return fmt.Errorf("admission: issuer metadata verifier cannot verify proof type 0x%x", proof.ProofType)
	}
	if err := metadata.ValidateStructural(now, false); err != nil {
		return err
	}
	if !bytes.Equal(proof.IssuerID, metadata.IssuerID) {
		return fmt.Errorf("admission: issuer metadata id mismatch")
	}
	if !containsVarint(metadata.SupportedProofTypes, proof.ProofType) {
		return fmt.Errorf("admission: issuer metadata does not support proof type 0x%x", proof.ProofType)
	}
	metadataHash, err := auroratrust.IssuerMetadataHash(metadata)
	if err != nil {
		return err
	}
	tokenMetadata, err := protocol.DecodeAuroraTokenMetadataBytes(proof.TokenPublicMetadata)
	if err != nil {
		return err
	}
	if err := tokenMetadata.ValidateForProof(proof, metadataHash); err != nil {
		return err
	}
	if !bytes.Equal(tokenMetadata.IssuerName, metadata.IssuerName) {
		return fmt.Errorf("admission: token metadata issuer name mismatch")
	}
	key, err := issuerTokenKeyForProof(metadata, proof, now)
	if err != nil {
		return err
	}
	if err := requireOriginAllowed(metadata, proof, tokenMetadata.OriginInfo, now); err != nil {
		return err
	}
	if err := requireBindingPolicyAllowsProof(metadata, proof); err != nil {
		return err
	}
	return VerifyBlindRSA2048(proof, key.TokenVerificationKey.TokenVerificationKey)
}

func VerifyBlindRSA2048(proof protocol.AdmissionProof, tokenVerificationKeyDER []byte) error {
	if proof.ProofType != registry.ProofBlindRSA2048 {
		return fmt.Errorf("admission: Blind RSA verifier cannot verify proof type 0x%x", proof.ProofType)
	}
	if err := proof.ValidateStructural(0, false); err != nil {
		return err
	}
	key, err := parseBlindRSA2048PublicKey(tokenVerificationKeyDER)
	if err != nil {
		return err
	}
	keyID := sha256.Sum256(tokenVerificationKeyDER)
	if !bytes.Equal(proof.TokenKeyID, keyID[:]) {
		return fmt.Errorf("admission: Blind RSA token key id mismatch")
	}
	if len(proof.TokenAuthenticator) != 256 {
		return fmt.Errorf("admission: Blind RSA authenticator length %d, want 256", len(proof.TokenAuthenticator))
	}
	metadata, err := protocol.DecodeAuroraTokenMetadataBytes(proof.TokenPublicMetadata)
	if err != nil {
		return err
	}
	challengeDigest, err := RFC9577TokenChallengeDigest(proof.ProofType, metadata.IssuerName, metadata.OriginInfo, proof.RedemptionContextHash)
	if err != nil {
		return err
	}
	if err := metadata.ValidateForProof(proof, metadata.IssuerMetadataHash); err != nil {
		return err
	}
	if !bytes.Equal(metadata.RFC9577ChallengeDigest, challengeDigest) {
		return fmt.Errorf("admission: token metadata challenge digest mismatch")
	}
	authenticatorInput, err := RFC9577AuthenticatorInput(proof, challengeDigest)
	if err != nil {
		return err
	}
	digest := sha512.Sum384(authenticatorInput)
	if err := rsa.VerifyPSS(key, crypto.SHA384, digest[:], proof.TokenAuthenticator, &rsa.PSSOptions{
		SaltLength: 48,
		Hash:       crypto.SHA384,
	}); err != nil {
		return fmt.Errorf("admission: Blind RSA authenticator verification failed: %w", err)
	}
	return nil
}

func issuerTokenKeyForProof(metadata protocol.IssuerMetadata, proof protocol.AdmissionProof, now uint64) (protocol.IssuerTokenKeyRecord, error) {
	var matches []protocol.IssuerTokenKeyRecord
	for _, key := range metadata.TokenKeyMappings {
		if key.ProofType == proof.ProofType && bytes.Equal(key.TokenKeyID, proof.TokenKeyID) {
			matches = append(matches, key)
		}
	}
	if len(matches) != 1 {
		return protocol.IssuerTokenKeyRecord{}, fmt.Errorf("admission: issuer token key lookup returned %d matches", len(matches))
	}
	if err := matches[0].Validate(now); err != nil {
		return protocol.IssuerTokenKeyRecord{}, err
	}
	return matches[0], nil
}

func requireOriginAllowed(metadata protocol.IssuerMetadata, proof protocol.AdmissionProof, originInfo []byte, now uint64) error {
	for _, scope := range metadata.RelayBucketScopes {
		if !bytes.Equal(scope.RelayBucketID, proof.RelayBucketID) || !bytes.Equal(scope.TokenScopeID, proof.TokenScopeID) {
			continue
		}
		if now < scope.ValidFromUnix || now >= scope.ValidUntilUnix {
			continue
		}
		if originAllowedByScope(metadata.OriginInfoPolicies, scope.AllowedOriginPolicyID, originInfo, now) {
			return nil
		}
	}
	return fmt.Errorf("admission: origin info not authorized for relay bucket scope")
}

func originAllowedByScope(policies []protocol.OriginInfoPolicy, allowedPolicyIDs []uint64, originInfo []byte, now uint64) bool {
	for _, policy := range policies {
		if !containsVarint(allowedPolicyIDs, policy.PolicyID) {
			continue
		}
		if now < policy.ValidFromUnix || now >= policy.ValidUntilUnix {
			continue
		}
		if len(originInfo) == 0 && policy.AllowEmptyOriginInfo {
			return true
		}
		if bytes.Equal(policy.OriginInfo, originInfo) {
			return true
		}
	}
	return false
}

func requireBindingPolicyAllowsProof(metadata protocol.IssuerMetadata, proof protocol.AdmissionProof) error {
	for _, policy := range metadata.AuxiliaryBindingPolicies {
		if policy.ProofType != proof.ProofType {
			continue
		}
		if policy.BindingProofRequired && len(proof.BindingProof) == 0 {
			return fmt.Errorf("admission: binding proof required by issuer metadata")
		}
		if len(proof.BindingProof) > int(policy.MaxBindingProofLen) {
			return fmt.Errorf("admission: binding proof exceeds issuer metadata limit")
		}
	}
	return nil
}

func containsVarint(values []uint64, want uint64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func parseBlindRSA2048PublicKey(encoded []byte) (*rsa.PublicKey, error) {
	var spki struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(encoded, &spki)
	if err != nil {
		return nil, fmt.Errorf("admission: invalid Blind RSA public key: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("admission: trailing Blind RSA public key bytes")
	}
	if !spki.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}) {
		return nil, fmt.Errorf("admission: Blind RSA public key must use RSASSA-PSS OID")
	}
	var raw struct {
		N *big.Int
		E int
	}
	rest, err = asn1.Unmarshal(spki.SubjectPublicKey.RightAlign(), &raw)
	if err != nil {
		return nil, fmt.Errorf("admission: invalid Blind RSA key body: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("admission: trailing Blind RSA key body bytes")
	}
	if raw.N == nil || raw.N.BitLen() != 2048 {
		return nil, fmt.Errorf("admission: Blind RSA key must be 2048 bits")
	}
	if raw.E < 3 || raw.E%2 == 0 {
		return nil, fmt.Errorf("admission: invalid Blind RSA public exponent")
	}
	return &rsa.PublicKey{N: raw.N, E: raw.E}, nil
}
