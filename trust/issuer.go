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

func VerifyIssuerMetadataSignature(m protocol.IssuerMetadata, keys []protocol.AuthorityKeyRecord, now uint64) error {
	if err := m.ValidateStructural(now, false); err != nil {
		return err
	}
	if err := ValidateIssuerServiceAuthKeySeparation(m, keys, now); err != nil {
		return err
	}
	key, err := LocateAuthorityKeyByID(keys, m.MetadataSigningKeyID, m.SignatureScheme, m.KeyEncoding, now, registry.UsageMaySignIssuerMetadata)
	if err != nil {
		return err
	}
	input, err := IssuerMetadataSignatureInput(m)
	if err != nil {
		return err
	}
	if err := auroracrypto.VerifySignature(m.SignatureScheme, m.KeyEncoding, key.PublicKey.PublicKey, input, m.MetadataSignature); err != nil {
		return err
	}
	return nil
}

func LocateAuthorityKeyByID(keys []protocol.AuthorityKeyRecord, keyID []byte, signatureScheme, keyEncoding uint64, now uint64, requiredUsage uint32) (protocol.AuthorityKeyRecord, error) {
	var matches []protocol.AuthorityKeyRecord
	for _, key := range keys {
		if !bytes.Equal(key.AuthorityKeyID, keyID) {
			continue
		}
		if key.PublicKey.SignatureScheme != signatureScheme || key.PublicKey.KeyEncoding != keyEncoding {
			continue
		}
		if err := key.Validate(now, requiredUsage); err != nil {
			continue
		}
		matches = append(matches, key)
	}
	if len(matches) != 1 {
		return protocol.AuthorityKeyRecord{}, fmt.Errorf("trust: authority key-id lookup returned %d matches", len(matches))
	}
	return matches[0], nil
}

func ValidateIssuerServiceAuthKeySeparation(m protocol.IssuerMetadata, keys []protocol.AuthorityKeyRecord, now uint64) error {
	for _, service := range m.VerifierServices {
		if err := service.ServiceAuthKey.ValidateCompatibility(); err != nil {
			return err
		}
		for _, key := range keys {
			if err := key.Validate(now, 0); err != nil {
				continue
			}
			if bytes.Equal(service.ServiceAuthKey.PublicKey, key.PublicKey.PublicKey) {
				return fmt.Errorf("trust: issuer verifier service auth key reuses authority key material")
			}
		}
	}
	return nil
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
	if now < service.ValidFromUnix || now >= service.ValidUntilUnix {
		return fmt.Errorf("trust: issuer verifier service outside validity interval")
	}
	if service.ServiceStatus != registry.IssuerStatusActive && service.ServiceStatus != registry.IssuerStatusRetiring {
		return fmt.Errorf("trust: issuer verifier service status not usable")
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

func VerifyIssuerVerifierResponse(req protocol.IssuerVerifierRequest, service protocol.IssuerVerifierServiceRecord, resp protocol.IssuerVerifierResponse, now uint64, maxFreshnessSeconds uint64) error {
	if err := ValidateIssuerVerifierResponseFreshness(req, service, resp, now, maxFreshnessSeconds); err != nil {
		return err
	}
	input, err := IssuerVerifierResponseSignatureInput(resp.RequestHash, resp)
	if err != nil {
		return err
	}
	if err := auroracrypto.VerifySignature(service.ServiceAuthKey.SignatureScheme, service.ServiceAuthKey.KeyEncoding, service.ServiceAuthKey.PublicKey, input, resp.ServiceSignature); err != nil {
		return err
	}
	return nil
}
