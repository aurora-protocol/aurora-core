package trust

import (
	"bytes"
	"fmt"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

func DirectoryConsensusHash(c protocol.DirectoryConsensus) ([]byte, error) {
	encoded, err := protocol.Encode(c.Unsigned())
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 directory consensus hash", encoded), nil
}

func DirectoryConsensusSignatureInput(c protocol.DirectoryConsensus, entry protocol.SignatureEntry) ([]byte, error) {
	consensusHash, err := DirectoryConsensusHash(c)
	if err != nil {
		return nil, err
	}
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 directory consensus signature"))
	e.WritePreHash(consensusHash)
	e.WriteOpaqueFixed(entry.AuthorityID, 16)
	e.WriteOpaqueFixed(entry.AuthorityKeyID, 16)
	e.WriteVarint(entry.SignatureScheme)
	e.WriteVarint(entry.KeyEncoding)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func LocateAuthorityKey(keys []protocol.AuthorityKeyRecord, entry protocol.SignatureEntry, now uint64, requiredUsage uint32) (protocol.AuthorityKeyRecord, error) {
	var matches []protocol.AuthorityKeyRecord
	for _, key := range keys {
		if !bytes.Equal(key.AuthorityID, entry.AuthorityID) || !bytes.Equal(key.AuthorityKeyID, entry.AuthorityKeyID) {
			continue
		}
		if key.PublicKey.SignatureScheme != entry.SignatureScheme || key.PublicKey.KeyEncoding != entry.KeyEncoding {
			continue
		}
		if err := key.Validate(now, requiredUsage); err != nil {
			continue
		}
		matches = append(matches, key)
	}
	if len(matches) != 1 {
		return protocol.AuthorityKeyRecord{}, fmt.Errorf("trust: authority key lookup returned %d matches", len(matches))
	}
	return matches[0], nil
}

func VerifyDirectoryConsensusSignatures(c protocol.DirectoryConsensus, keys []protocol.AuthorityKeyRecord, now uint64, minValidDistinctAuthorities int) error {
	if minValidDistinctAuthorities <= 0 {
		minValidDistinctAuthorities = 1
	}
	if len(c.AuthoritySignatures) == 0 {
		return fmt.Errorf("trust: directory consensus has no authority signatures")
	}
	validAuthorities := make(map[string]struct{}, len(c.AuthoritySignatures))
	for _, entry := range c.AuthoritySignatures {
		key, err := LocateAuthorityKey(keys, entry, now, registry.UsageMaySignDirectoryConsensus)
		if err != nil {
			return err
		}
		input, err := DirectoryConsensusSignatureInput(c, entry)
		if err != nil {
			return err
		}
		if err := auroracrypto.VerifySignature(entry.SignatureScheme, entry.KeyEncoding, key.PublicKey.PublicKey, input, entry.Signature); err != nil {
			return err
		}
		validAuthorities[string(entry.AuthorityID)] = struct{}{}
	}
	if len(validAuthorities) < minValidDistinctAuthorities {
		return fmt.Errorf("trust: directory consensus has %d valid authority signatures, want %d", len(validAuthorities), minValidDistinctAuthorities)
	}
	return nil
}

func RelayDescriptorHash(d protocol.RelayDescriptor) ([]byte, error) {
	encoded, err := protocol.Encode(d.Unsigned())
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 relay descriptor hash", encoded), nil
}

func RelayDescriptorSignatureInput(d protocol.RelayDescriptor) ([]byte, error) {
	h, err := RelayDescriptorHash(d)
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 relay descriptor signature", h), nil
}

func CoverOriginCommitment(t protocol.CoverTemplate) ([]byte, error) {
	gateway, err := encodePreHashVector(t.GatewayOwnedSlotCommitments)
	if err != nil {
		return nil, err
	}
	passThrough, err := encodePreHashVector(t.OriginPassThroughSlotCommitments)
	if err != nil {
		return nil, err
	}
	e := wire.NewEncoder()
	e.WritePreHash(t.OriginSPKIHash)
	e.WritePreHash(t.PublicNameHash)
	e.WriteOpaque16(t.TemplateFamilyID)
	e.WriteUint64(t.ValidFromUnix)
	e.WriteUint64(t.ValidUntilUnix)
	e.WriteBytes(gateway)
	e.WriteBytes(passThrough)
	e.WriteVarint(t.H2Profile.ProfileID)
	e.WriteVarint(t.H3Profile.ProfileID)
	e.WriteVarint(t.WebSocketProfile.ProfileID)
	e.WriteVarint(t.CacheCookiePolicy.PolicyID)
	e.WriteVarint(t.TimingEnvelope.TimingPolicyID)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func CoverTemplateHash(t protocol.CoverTemplate) ([]byte, error) {
	encoded, err := protocol.Encode(t.Unsigned())
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 cover template hash", encoded), nil
}

func CoverTemplateFamilySignatureInput(t protocol.CoverTemplate) ([]byte, error) {
	h, err := CoverTemplateHash(t)
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 cover template family signature", h), nil
}

func CoverTemplateInstanceSignatureInput(relayDescriptorHash []byte, t protocol.CoverTemplate) ([]byte, error) {
	if len(relayDescriptorHash) != 48 {
		return nil, fmt.Errorf("trust: relay descriptor hash length %d, want 48", len(relayDescriptorHash))
	}
	h, err := CoverTemplateHash(t)
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 cover template instance signature", relayDescriptorHash, h), nil
}

func ValidateCoverTemplateTime(t protocol.CoverTemplate, now uint64, maxFutureSkew uint64) error {
	if t.ValidUntilUnix <= t.ValidFromUnix {
		return fmt.Errorf("trust: invalid cover-template interval")
	}
	if now+maxFutureSkew < t.ValidFromUnix {
		return fmt.Errorf("trust: cover template is not yet valid")
	}
	if now >= t.ValidUntilUnix {
		return fmt.Errorf("trust: cover template expired")
	}
	return nil
}

func ValidateRequestClass(c protocol.RequestClass) error {
	if c.ClassType == registry.RequestOriginPassThrough && (c.MayCarryPrelude || c.MayCarryCapsule) {
		return fmt.Errorf("trust: origin-pass-through class cannot carry protocol material")
	}
	return nil
}

func encodePreHashVector(values [][]byte) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteVarint(uint64(len(values)))
	for _, value := range values {
		e.WritePreHash(value)
	}
	return e.Bytes()
}
