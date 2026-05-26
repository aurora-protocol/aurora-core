package protocol

import (
	"bytes"
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type PublicKeyRecord struct {
	SignatureScheme uint64
	KeyEncoding     uint64
	PublicKey       []byte
}

func (r PublicKeyRecord) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(r.SignatureScheme)
	e.WriteVarint(r.KeyEncoding)
	e.WriteOpaque16(r.PublicKey)
}

func DecodePublicKeyRecord(r *wire.Reader) PublicKeyRecord {
	return PublicKeyRecord{
		SignatureScheme: r.ReadVarint(),
		KeyEncoding:     r.ReadVarint(),
		PublicKey:       r.ReadOpaque16(),
	}
}

func (r PublicKeyRecord) ValidateCompatibility() error {
	switch r.SignatureScheme {
	case registry.SigECDSAP256SHA256DER, registry.SigECDSAP256SHA384DER:
		if r.KeyEncoding != registry.KeyP256SEC1Uncompressed && r.KeyEncoding != registry.KeyP256SPKI {
			return fmt.Errorf("protocol: ECDSA P-256 signature incompatible with key encoding 0x%x", r.KeyEncoding)
		}
	case registry.SigECDSAP384SHA384DER:
		if r.KeyEncoding != registry.KeyP384SEC1Uncompressed && r.KeyEncoding != registry.KeyP384SPKI {
			return fmt.Errorf("protocol: ECDSA P-384 signature incompatible with key encoding 0x%x", r.KeyEncoding)
		}
	case registry.SigMLDSA65:
		if r.KeyEncoding != registry.KeyMLDSA65RawPublic {
			return fmt.Errorf("protocol: ML-DSA-65 signature incompatible with key encoding 0x%x", r.KeyEncoding)
		}
	case registry.SigMLDSA87:
		if r.KeyEncoding != registry.KeyMLDSA87RawPublic {
			return fmt.Errorf("protocol: ML-DSA-87 signature incompatible with key encoding 0x%x", r.KeyEncoding)
		}
	case registry.SigEd25519Lab:
		if r.KeyEncoding != registry.KeyEd25519RawPublic {
			return fmt.Errorf("protocol: Ed25519 lab signature incompatible with key encoding 0x%x", r.KeyEncoding)
		}
	default:
		return fmt.Errorf("protocol: unknown signature scheme 0x%x", r.SignatureScheme)
	}
	return nil
}

type AuthorityKeyRecord struct {
	AuthorityID    []byte
	AuthorityKeyID []byte
	AuthorityRole  uint64
	PublicKey      PublicKeyRecord
	ValidFromUnix  uint64
	ValidUntilUnix uint64
	KeyStatus      uint8
	UsageFlags     uint32
}

func (r AuthorityKeyRecord) EncodeTo(e *wire.Encoder) {
	e.WriteOpaqueFixed(r.AuthorityID, 16)
	e.WriteOpaqueFixed(r.AuthorityKeyID, 16)
	e.WriteVarint(r.AuthorityRole)
	r.PublicKey.EncodeTo(e)
	e.WriteUint64(r.ValidFromUnix)
	e.WriteUint64(r.ValidUntilUnix)
	e.WriteUint8(r.KeyStatus)
	e.WriteUint32(r.UsageFlags)
}

func DecodeAuthorityKeyRecord(r *wire.Reader) AuthorityKeyRecord {
	return AuthorityKeyRecord{
		AuthorityID:    r.ReadOpaqueFixed(16),
		AuthorityKeyID: r.ReadOpaqueFixed(16),
		AuthorityRole:  r.ReadVarint(),
		PublicKey:      DecodePublicKeyRecord(r),
		ValidFromUnix:  r.ReadUint64(),
		ValidUntilUnix: r.ReadUint64(),
		KeyStatus:      r.ReadUint8(),
		UsageFlags:     r.ReadUint32(),
	}
}

func (r AuthorityKeyRecord) Validate(now uint64, requiredUsage uint32) error {
	if len(r.AuthorityID) != 16 || len(r.AuthorityKeyID) != 16 {
		return fmt.Errorf("protocol: authority IDs must be 16 bytes")
	}
	if r.ValidFromUnix > now || now >= r.ValidUntilUnix {
		return fmt.Errorf("protocol: authority key outside validity interval")
	}
	if r.KeyStatus != registry.AuthorityActive && r.KeyStatus != registry.AuthorityRetiringVerifyOnly {
		return fmt.Errorf("protocol: authority key status not usable")
	}
	if r.UsageFlags&^registry.UsageAllKnownAuthority != 0 {
		return fmt.Errorf("protocol: authority usage has reserved bits set")
	}
	if requiredUsage != 0 && r.UsageFlags&requiredUsage == 0 {
		return fmt.Errorf("protocol: authority key lacks required usage 0x%x", requiredUsage)
	}
	if err := r.PublicKey.ValidateCompatibility(); err != nil {
		return err
	}
	return nil
}

func (r AuthorityKeyRecord) MatchesSignature(sig ObjectSignature) bool {
	return bytes.Equal(r.AuthorityKeyID, sig.SignerKeyID) &&
		r.PublicKey.SignatureScheme == sig.SignatureScheme &&
		r.PublicKey.KeyEncoding == sig.KeyEncoding
}

type ObjectSignature struct {
	SignerKeyID     []byte
	SignatureScheme uint64
	KeyEncoding     uint64
	Signature       []byte
}

func (s ObjectSignature) EncodeTo(e *wire.Encoder) {
	e.WriteOpaqueFixed(s.SignerKeyID, 16)
	e.WriteVarint(s.SignatureScheme)
	e.WriteVarint(s.KeyEncoding)
	e.WriteOpaque16(s.Signature)
}

func (s ObjectSignature) Unsigned() ObjectSignature {
	return ObjectSignature{
		SignerKeyID:     append([]byte(nil), s.SignerKeyID...),
		SignatureScheme: s.SignatureScheme,
		KeyEncoding:     s.KeyEncoding,
		Signature:       nil,
	}
}

func DecodeObjectSignature(r *wire.Reader) ObjectSignature {
	return ObjectSignature{
		SignerKeyID:     r.ReadOpaqueFixed(16),
		SignatureScheme: r.ReadVarint(),
		KeyEncoding:     r.ReadVarint(),
		Signature:       r.ReadOpaque16(),
	}
}

type TokenVerificationKeyRecord struct {
	TokenVerificationKeyScheme uint64
	TokenVerificationKey       []byte
}

func (r TokenVerificationKeyRecord) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(r.TokenVerificationKeyScheme)
	e.WriteOpaque16(r.TokenVerificationKey)
}

func DecodeTokenVerificationKeyRecord(r *wire.Reader) TokenVerificationKeyRecord {
	return TokenVerificationKeyRecord{
		TokenVerificationKeyScheme: r.ReadVarint(),
		TokenVerificationKey:       r.ReadOpaque16(),
	}
}
