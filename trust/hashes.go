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
	return verifyDirectoryConsensusSignaturesWithUsage(c, keys, now, minValidDistinctAuthorities, registry.UsageMaySignDirectoryConsensus, false)
}

func VerifyStrictDirectoryConsensusSignatures(c protocol.DirectoryConsensus, keys []protocol.AuthorityKeyRecord, now uint64, minValidDistinctAuthorities int) error {
	return verifyDirectoryConsensusSignaturesWithUsage(c, keys, now, minValidDistinctAuthorities, registry.UsageMaySignDirectoryConsensus, true)
}

func verifyDirectoryConsensusSignaturesWithUsage(c protocol.DirectoryConsensus, keys []protocol.AuthorityKeyRecord, now uint64, minValidDistinctAuthorities int, requiredUsage uint32, requireMLDSAQuorum bool) error {
	if minValidDistinctAuthorities <= 0 {
		minValidDistinctAuthorities = 1
	}
	if c.Version != registry.Version20 {
		return fmt.Errorf("trust: unsupported directory consensus version 0x%x", c.Version)
	}
	// A consensus signed by still-valid authority keys must not outlive its
	// own window: accepting it would allow rollback to a stale relay set,
	// revocation root, or policy root.
	if c.ValidUntilUnix <= c.ValidFromUnix || now < c.ValidFromUnix || now >= c.ValidUntilUnix {
		return fmt.Errorf("trust: directory consensus outside validity interval")
	}
	if len(c.AuthoritySignatures) == 0 {
		return fmt.Errorf("trust: directory consensus has no authority signatures")
	}
	validAuthorities := make(map[string]struct{}, len(c.AuthoritySignatures))
	validMLDSAAuthorities := make(map[string]struct{}, len(c.AuthoritySignatures))
	for _, entry := range c.AuthoritySignatures {
		key, err := LocateAuthorityKey(keys, entry, now, requiredUsage)
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
		authority := string(entry.AuthorityID)
		validAuthorities[authority] = struct{}{}
		if isMLDSASignatureScheme(entry.SignatureScheme) {
			validMLDSAAuthorities[authority] = struct{}{}
		}
	}
	if len(validAuthorities) < minValidDistinctAuthorities {
		return fmt.Errorf("trust: directory consensus has %d valid authority signatures, want %d", len(validAuthorities), minValidDistinctAuthorities)
	}
	if requireMLDSAQuorum && len(validMLDSAAuthorities) < minValidDistinctAuthorities {
		return fmt.Errorf("trust: directory consensus has %d valid ML-DSA authority signatures, want %d", len(validMLDSAAuthorities), minValidDistinctAuthorities)
	}
	return nil
}

func isMLDSASignatureScheme(scheme uint64) bool {
	return scheme == registry.SigMLDSA65 || scheme == registry.SigMLDSA87
}

type AuthorityKeyRotationInput struct {
	PreviousKeys                  []protocol.AuthorityKeyRecord
	NextKeys                      []protocol.AuthorityKeyRecord
	NextConsensus                 protocol.DirectoryConsensus
	NowUnix                       uint64
	MinValidDistinctAuthorities   int
	PinnedBootstrapRootAuthorized bool
}

func ValidateAuthorityKeyRotation(in AuthorityKeyRotationInput) error {
	if len(in.NextKeys) == 0 {
		return fmt.Errorf("trust: authority rotation produced empty next key set")
	}
	for _, key := range in.NextKeys {
		if err := key.Validate(in.NowUnix, 0); err != nil {
			return fmt.Errorf("trust: next authority key invalid: %w", err)
		}
	}
	if in.PinnedBootstrapRootAuthorized {
		return nil
	}
	requiredUsage := registry.UsageMaySignDirectoryConsensus | registry.UsageMayRotateDirectoryAuthority
	if err := verifyDirectoryConsensusSignaturesWithUsage(in.NextConsensus, in.PreviousKeys, in.NowUnix, in.MinValidDistinctAuthorities, requiredUsage, false); err != nil {
		return fmt.Errorf("trust: authority rotation lacks previous quorum path: %w", err)
	}
	for _, previous := range currentPreviousDirectoryKeys(in.PreviousKeys, in.NowUnix) {
		if !authorityKeySetContains(in.NextKeys, previous) {
			return fmt.Errorf("trust: authority rotation removed previous key without pinned root authorization")
		}
	}
	return nil
}

func currentPreviousDirectoryKeys(keys []protocol.AuthorityKeyRecord, now uint64) []protocol.AuthorityKeyRecord {
	out := make([]protocol.AuthorityKeyRecord, 0, len(keys))
	for _, key := range keys {
		if err := key.Validate(now, registry.UsageMaySignDirectoryConsensus); err == nil {
			out = append(out, key)
		}
	}
	return out
}

func authorityKeySetContains(keys []protocol.AuthorityKeyRecord, want protocol.AuthorityKeyRecord) bool {
	for _, key := range keys {
		if bytes.Equal(key.AuthorityID, want.AuthorityID) &&
			bytes.Equal(key.AuthorityKeyID, want.AuthorityKeyID) &&
			key.PublicKey.SignatureScheme == want.PublicKey.SignatureScheme &&
			key.PublicKey.KeyEncoding == want.PublicKey.KeyEncoding {
			return true
		}
	}
	return false
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
	switch c.ClassType {
	case registry.RequestOriginPassThrough, registry.RequestGatewayOwnedSlot, registry.RequestSidecarOriginSlot:
	default:
		return fmt.Errorf("trust: unknown request class type 0x%x", c.ClassType)
	}
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
