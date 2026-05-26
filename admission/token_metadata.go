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
