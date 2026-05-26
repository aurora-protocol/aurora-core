package admission

import (
	"crypto/sha256"
	"fmt"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
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
	return auroracrypto.PreHashLabel("aurora v2.0 authenticator input", authenticatorInput), nil
}
