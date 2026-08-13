package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
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
	if err := validateSignatureKeyEncodingCompatibility(r.SignatureScheme, r.KeyEncoding); err != nil {
		return err
	}
	switch r.SignatureScheme {
	case registry.SigECDSAP256SHA256DER, registry.SigECDSAP256SHA384DER:
		if r.KeyEncoding == registry.KeyP256SEC1Uncompressed {
			return validatePublicKeyLength(r.PublicKey, 65, "P-256 SEC1 public key")
		}
		return validateECDSASPKIPublicKey(r.PublicKey, elliptic.P256(), "P-256 SPKI public key")
	case registry.SigECDSAP384SHA384DER:
		if r.KeyEncoding == registry.KeyP384SEC1Uncompressed {
			return validatePublicKeyLength(r.PublicKey, 97, "P-384 SEC1 public key")
		}
		return validateECDSASPKIPublicKey(r.PublicKey, elliptic.P384(), "P-384 SPKI public key")
	case registry.SigMLDSA65:
		return validatePublicKeyLength(r.PublicKey, mldsa65.PublicKeySize, "ML-DSA-65 public key")
	case registry.SigMLDSA87:
		return validatePublicKeyLength(r.PublicKey, mldsa87.PublicKeySize, "ML-DSA-87 public key")
	case registry.SigEd25519Lab:
		return validatePublicKeyLength(r.PublicKey, ed25519.PublicKeySize, "Ed25519 public key")
	}
	if len(r.PublicKey) == 0 {
		return fmt.Errorf("protocol: public key is empty")
	}
	return nil
}

func validateSignatureKeyEncodingCompatibility(signatureScheme, keyEncoding uint64) error {
	switch signatureScheme {
	case registry.SigECDSAP256SHA256DER, registry.SigECDSAP256SHA384DER:
		if keyEncoding != registry.KeyP256SEC1Uncompressed && keyEncoding != registry.KeyP256SPKI {
			return fmt.Errorf("protocol: ECDSA P-256 signature incompatible with key encoding 0x%x", keyEncoding)
		}
	case registry.SigECDSAP384SHA384DER:
		if keyEncoding != registry.KeyP384SEC1Uncompressed && keyEncoding != registry.KeyP384SPKI {
			return fmt.Errorf("protocol: ECDSA P-384 signature incompatible with key encoding 0x%x", keyEncoding)
		}
	case registry.SigMLDSA65:
		if keyEncoding != registry.KeyMLDSA65RawPublic {
			return fmt.Errorf("protocol: ML-DSA-65 signature incompatible with key encoding 0x%x", keyEncoding)
		}
	case registry.SigMLDSA87:
		if keyEncoding != registry.KeyMLDSA87RawPublic {
			return fmt.Errorf("protocol: ML-DSA-87 signature incompatible with key encoding 0x%x", keyEncoding)
		}
	case registry.SigEd25519Lab:
		if keyEncoding != registry.KeyEd25519RawPublic {
			return fmt.Errorf("protocol: Ed25519 lab signature incompatible with key encoding 0x%x", keyEncoding)
		}
	default:
		return fmt.Errorf("protocol: unknown signature scheme 0x%x", signatureScheme)
	}
	return nil
}

func validateECDSASPKIPublicKey(publicKey []byte, curve elliptic.Curve, label string) error {
	parsed, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("protocol: invalid %s: %w", label, err)
	}
	pk, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("protocol: %s is not ECDSA", label)
	}
	if pk.Curve != curve {
		return fmt.Errorf("protocol: %s curve mismatch", label)
	}
	return nil
}

func validatePublicKeyLength(publicKey []byte, want int, label string) error {
	if len(publicKey) != want {
		return fmt.Errorf("protocol: %s length %d, want %d", label, len(publicKey), want)
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
	if err := r.ValidateStructural(); err != nil {
		return err
	}
	if r.ValidFromUnix > now || now >= r.ValidUntilUnix {
		return fmt.Errorf("protocol: authority key outside validity interval")
	}
	if r.KeyStatus != registry.AuthorityActive && r.KeyStatus != registry.AuthorityRetiringVerifyOnly {
		return fmt.Errorf("protocol: authority key status not usable")
	}
	if requiredUsage != 0 && r.UsageFlags&requiredUsage != requiredUsage {
		return fmt.Errorf("protocol: authority key lacks required usage 0x%x", requiredUsage)
	}
	return nil
}

// ValidateStructural verifies authority-key fields that do not depend on the current time.
func (r AuthorityKeyRecord) ValidateStructural() error {
	if len(r.AuthorityID) != 16 || len(r.AuthorityKeyID) != 16 {
		return fmt.Errorf("protocol: authority IDs must be 16 bytes")
	}
	if r.ValidUntilUnix <= r.ValidFromUnix {
		return fmt.Errorf("protocol: authority key validity interval is empty")
	}
	if r.KeyStatus != registry.AuthorityActive && r.KeyStatus != registry.AuthorityRetiringVerifyOnly && r.KeyStatus != registry.AuthorityRevoked {
		return fmt.Errorf("protocol: authority key status is reserved")
	}
	if r.UsageFlags&^registry.UsageAllKnownAuthority != 0 {
		return fmt.Errorf("protocol: authority usage has reserved bits set")
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
