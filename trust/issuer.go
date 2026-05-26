package trust

import (
	"bytes"
	"fmt"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

func IssuerMetadataHash(m protocol.IssuerMetadata) ([]byte, error) {
	encoded, err := protocol.Encode(m.Unsigned())
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 issuer metadata hash", encoded), nil
}

func IssuerMetadataSignatureInput(m protocol.IssuerMetadata) ([]byte, error) {
	h, err := IssuerMetadataHash(m)
	if err != nil {
		return nil, err
	}
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 issuer metadata signature"))
	e.WritePreHash(h)
	e.WriteOpaqueFixed(m.IssuerID, 16)
	e.WriteOpaqueFixed(m.MetadataSigningKeyID, 16)
	e.WriteVarint(m.SignatureScheme)
	e.WriteVarint(m.KeyEncoding)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func AuthenticatorInputHash(authenticatorInput []byte) []byte {
	return auroracrypto.PreHashLabel("aurora v2.0 authenticator input", authenticatorInput)
}

func IssuerVerifierRequestHash(r protocol.IssuerVerifierRequest) ([]byte, error) {
	encoded, err := protocol.Encode(r)
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 issuer verifier request", encoded), nil
}

func IssuerVerifierResponseSignatureInput(requestHash []byte, r protocol.IssuerVerifierResponse) ([]byte, error) {
	if len(requestHash) != 48 {
		return nil, fmt.Errorf("trust: issuer verifier request hash length %d, want 48", len(requestHash))
	}
	encoded, err := protocol.Encode(r.Unsigned())
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 issuer verifier response", requestHash, encoded), nil
}

func ValidateIssuerVerifierResponseFreshness(req protocol.IssuerVerifierRequest, service protocol.IssuerVerifierServiceRecord, resp protocol.IssuerVerifierResponse, now uint64, maxFreshnessSeconds uint64) error {
	if resp.ResponseVersion != registry.Version20 {
		return fmt.Errorf("trust: unsupported issuer verifier response version 0x%x", resp.ResponseVersion)
	}
	if !bytes.Equal(resp.ServiceID, req.ServiceID) || !bytes.Equal(resp.ServiceID, service.ServiceID) {
		return fmt.Errorf("trust: issuer verifier service id mismatch")
	}
	requestHash, err := IssuerVerifierRequestHash(req)
	if err != nil {
		return err
	}
	if !bytes.Equal(resp.RequestHash, requestHash) {
		return fmt.Errorf("trust: issuer verifier request hash mismatch")
	}
	if !bytes.Equal(resp.TokenSpentKey, req.TokenSpentKey) {
		return fmt.Errorf("trust: issuer verifier token spent key mismatch")
	}
	if now > resp.ValidUntilUnix {
		return fmt.Errorf("trust: issuer verifier response expired")
	}
	latest := req.ReplayEpochValidUntilUnix
	if service.ValidUntilUnix < latest {
		latest = service.ValidUntilUnix
	}
	if resp.ValidUntilUnix > latest {
		return fmt.Errorf("trust: issuer verifier response exceeds service or replay validity")
	}
	if maxFreshnessSeconds == 0 {
		maxFreshnessSeconds = 300
	}
	if resp.ValidUntilUnix > req.RequestTimeUnix+maxFreshnessSeconds {
		return fmt.Errorf("trust: issuer verifier response freshness window too long")
	}
	return nil
}
