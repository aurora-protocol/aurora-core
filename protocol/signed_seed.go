package protocol

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

const maximumSignedSeedAuthorityKeys = 64

// SignedSeedRecord is the signed bootstrap state distributed with a client update.
type SignedSeedRecord struct {
	SeedVersion                uint64
	SeedID                     []byte
	ValidFromUnix              uint64
	ValidUntilUnix             uint64
	DirectoryConsensusHint     []byte
	BridgeBucketHint           []byte
	TokenIssuerHint            []byte
	IssuerMetadataHash         []byte
	BootstrapAuthorityKeys     []AuthorityKeyRecord
	BootstrapCoverTemplateHash []byte
	AuthorityKeyUpdates        []AuthorityKeyRecord
	NextSeedCommitment         []byte
	SoftwareUpdateEpoch        uint64
	SeedSignature              ObjectSignature
}

func (s SignedSeedRecord) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(s.SeedVersion)
	e.WriteOpaqueFixed(s.SeedID, 16)
	e.WriteUint64(s.ValidFromUnix)
	e.WriteUint64(s.ValidUntilUnix)
	e.WriteOpaque16(s.DirectoryConsensusHint)
	e.WriteOpaque16(s.BridgeBucketHint)
	e.WriteOpaque16(s.TokenIssuerHint)
	e.WritePreHash(s.IssuerMetadataHash)
	e.WriteVarint(uint64(len(s.BootstrapAuthorityKeys)))
	for _, key := range s.BootstrapAuthorityKeys {
		key.EncodeTo(e)
	}
	e.WritePreHash(s.BootstrapCoverTemplateHash)
	e.WriteVarint(uint64(len(s.AuthorityKeyUpdates)))
	for _, key := range s.AuthorityKeyUpdates {
		key.EncodeTo(e)
	}
	e.WritePreHash(s.NextSeedCommitment)
	e.WriteUint64(s.SoftwareUpdateEpoch)
	s.SeedSignature.EncodeTo(e)
}

func DecodeSignedSeedRecord(r *wire.Reader) SignedSeedRecord {
	seed := SignedSeedRecord{
		SeedVersion:                r.ReadVarint(),
		SeedID:                     r.ReadOpaqueFixed(16),
		ValidFromUnix:              r.ReadUint64(),
		ValidUntilUnix:             r.ReadUint64(),
		DirectoryConsensusHint:     r.ReadOpaque16(),
		BridgeBucketHint:           r.ReadOpaque16(),
		TokenIssuerHint:            r.ReadOpaque16(),
		IssuerMetadataHash:         r.ReadPreHash(),
		BootstrapAuthorityKeys:     decodeSignedSeedAuthorityKeys(r, "bootstrap authority key"),
		BootstrapCoverTemplateHash: r.ReadPreHash(),
		AuthorityKeyUpdates:        decodeSignedSeedAuthorityKeys(r, "authority key update"),
		NextSeedCommitment:         r.ReadPreHash(),
		SoftwareUpdateEpoch:        r.ReadUint64(),
		SeedSignature:              DecodeObjectSignature(r),
	}
	return seed
}

func (s SignedSeedRecord) Unsigned() SignedSeedRecord {
	s.SeedID = append([]byte(nil), s.SeedID...)
	s.DirectoryConsensusHint = append([]byte(nil), s.DirectoryConsensusHint...)
	s.BridgeBucketHint = append([]byte(nil), s.BridgeBucketHint...)
	s.TokenIssuerHint = append([]byte(nil), s.TokenIssuerHint...)
	s.IssuerMetadataHash = append([]byte(nil), s.IssuerMetadataHash...)
	s.BootstrapAuthorityKeys = cloneSignedSeedAuthorityKeys(s.BootstrapAuthorityKeys)
	s.BootstrapCoverTemplateHash = append([]byte(nil), s.BootstrapCoverTemplateHash...)
	s.AuthorityKeyUpdates = cloneSignedSeedAuthorityKeys(s.AuthorityKeyUpdates)
	s.NextSeedCommitment = append([]byte(nil), s.NextSeedCommitment...)
	s.SeedSignature = s.SeedSignature.Unsigned()
	return s
}

// ValidateStructural verifies local record invariants before trust-chain verification.
func (s SignedSeedRecord) ValidateStructural(now uint64) error {
	if s.SeedVersion != registry.Version20 {
		return fmt.Errorf("protocol: unsupported signed seed version 0x%x", s.SeedVersion)
	}
	if len(s.SeedID) != 16 {
		return fmt.Errorf("protocol: signed seed id must be 16 bytes")
	}
	if s.ValidUntilUnix <= s.ValidFromUnix || now < s.ValidFromUnix || now >= s.ValidUntilUnix {
		return fmt.Errorf("protocol: signed seed outside validity interval")
	}
	if len(s.DirectoryConsensusHint) > 0xffff || len(s.BridgeBucketHint) > 0xffff || len(s.TokenIssuerHint) > 0xffff {
		return fmt.Errorf("protocol: signed seed hint exceeds size limit")
	}
	for _, field := range []struct {
		label string
		value []byte
	}{
		{"issuer metadata hash", s.IssuerMetadataHash},
		{"bootstrap cover template hash", s.BootstrapCoverTemplateHash},
		{"next seed commitment", s.NextSeedCommitment},
	} {
		if len(field.value) != 48 {
			return fmt.Errorf("protocol: signed seed %s must be 48 bytes", field.label)
		}
	}
	if len(s.BootstrapAuthorityKeys) > maximumSignedSeedAuthorityKeys || len(s.AuthorityKeyUpdates) > maximumSignedSeedAuthorityKeys {
		return fmt.Errorf("protocol: signed seed authority key count is invalid")
	}
	if err := validateSignedSeedAuthorityKeySet(s.BootstrapAuthorityKeys, nil); err != nil {
		return err
	}
	if err := validateSignedSeedAuthorityKeySet(s.AuthorityKeyUpdates, s.BootstrapAuthorityKeys); err != nil {
		return err
	}
	if len(s.SeedSignature.SignerKeyID) != 16 || len(s.SeedSignature.Signature) == 0 {
		return fmt.Errorf("protocol: signed seed signature is incomplete")
	}
	if s.SeedSignature.SignatureScheme == registry.SigEd25519Lab {
		return fmt.Errorf("protocol: signed seed lab signature scheme disabled")
	}
	if err := validateSignatureKeyEncodingCompatibility(s.SeedSignature.SignatureScheme, s.SeedSignature.KeyEncoding); err != nil {
		return err
	}
	return nil
}

func decodeSignedSeedAuthorityKeys(r *wire.Reader, label string) []AuthorityKeyRecord {
	count := r.ReadVectorCount(label)
	if r.Err() != nil || count > maximumSignedSeedAuthorityKeys {
		r.SetErr(fmt.Errorf("protocol: signed seed %s count is invalid", label))
		return nil
	}
	keys := make([]AuthorityKeyRecord, 0, count)
	for index := uint64(0); index < count; index++ {
		keys = append(keys, DecodeAuthorityKeyRecord(r))
	}
	return keys
}

func validateSignedSeedAuthorityKeySet(keys, existing []AuthorityKeyRecord) error {
	seen := make(map[string]struct{}, len(keys)+len(existing))
	for _, key := range existing {
		seen[signedSeedAuthoritySignerIdentity(key)] = struct{}{}
	}
	for _, key := range keys {
		if err := key.ValidateStructural(); err != nil {
			return fmt.Errorf("protocol: signed seed authority key: %w", err)
		}
		if key.PublicKey.SignatureScheme == registry.SigEd25519Lab {
			return fmt.Errorf("protocol: signed seed lab authority key disabled")
		}
		identity := signedSeedAuthoritySignerIdentity(key)
		if _, duplicate := seen[identity]; duplicate {
			return fmt.Errorf("protocol: signed seed contains duplicate authority key")
		}
		seen[identity] = struct{}{}
	}
	return nil
}

func signedSeedAuthoritySignerIdentity(key AuthorityKeyRecord) string {
	encoder := wire.NewEncoder()
	encoder.WriteOpaqueFixed(key.AuthorityKeyID, 16)
	encoder.WriteVarint(key.PublicKey.SignatureScheme)
	encoder.WriteVarint(key.PublicKey.KeyEncoding)
	encoded, err := encoder.Bytes()
	if err != nil {
		return ""
	}
	return string(encoded)
}

func cloneSignedSeedAuthorityKeys(keys []AuthorityKeyRecord) []AuthorityKeyRecord {
	cloned := make([]AuthorityKeyRecord, len(keys))
	for index, key := range keys {
		cloned[index] = key
		cloned[index].AuthorityID = append([]byte(nil), key.AuthorityID...)
		cloned[index].AuthorityKeyID = append([]byte(nil), key.AuthorityKeyID...)
		cloned[index].PublicKey.PublicKey = append([]byte(nil), key.PublicKey.PublicKey...)
	}
	return cloned
}
