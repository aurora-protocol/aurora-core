package handshake

import (
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/failure"
	"github.com/aurora-protocol/aurora-core/protocol"
)

func ValidatePreludeHybridShares(suite uint64, p0 protocol.CoverPrelude0, p1 protocol.CoverPrelude1) error {
	if _, err := auroracrypto.NewECDHPublicKeyForSuite(suite, p0.ClientClassicalEphPub); err != nil {
		return failureError(failure.MalformedHybridShare, "handshake: malformed client classical share")
	}
	if _, err := auroracrypto.NewECDHPublicKeyForSuite(suite, p1.ServerClassicalEphPub); err != nil {
		return failureError(failure.MalformedHybridShare, "handshake: malformed server classical share")
	}
	if err := auroracrypto.ValidateMLKEMEncapsulationKeyForSuite(suite, p0.ClientMLKEMEncapsulationKey); err != nil {
		return failureError(failure.MalformedHybridShare, "handshake: malformed client ML-KEM share")
	}
	if err := auroracrypto.ValidateMLKEMCiphertextForSuite(suite, p1.ServerMLKEMCiphertextToClient); err != nil {
		return failureError(failure.MalformedHybridShare, "handshake: malformed server ML-KEM share")
	}
	return nil
}
