package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fill(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestAppendixB5AuthorityKeyRecordAndObjectSignature(t *testing.T) {
	pk := PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       fill(0x04, 65),
	}
	encodedPK, err := wire.Encode(pk)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "PublicKeyRecord", encodedPK, "41020100410404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404")

	keyID := auroracrypto.Truncate128(auroracrypto.PreHashLabel("aurora v2.0 authority key id", encodedPK))
	assertHex(t, "authority_key_id", keyID, "0bd8059272ddb7c314a04a7c6a8c9375")

	akr := AuthorityKeyRecord{
		AuthorityID:    fill(0x11, 16),
		AuthorityKeyID: keyID,
		AuthorityRole:  0x01,
		PublicKey:      pk,
		ValidFromUnix:  1700000000,
		ValidUntilUnix: 1800000000,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageAllKnownAuthority,
	}
	encodedAKR, err := wire.Encode(akr)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "AuthorityKeyRecord", encodedAKR, "111111111111111111111111111111110bd8059272ddb7c314a04a7c6a8c93750141020100410404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404000000006553f100000000006b49d200000000003f")

	recordHash := auroracrypto.PreHashLabel("aurora v2.0 structural authority key record", encodedAKR)
	assertHex(t, "AuthorityKeyRecord structural hash", recordHash, "600a3bcb961059cd47f4e5c69ebde089b9785abcedbe7d83140f0d137bba258efe99c16ed6276f3b326f951662133dfe")

	objSig := ObjectSignature{
		SignerKeyID:     keyID,
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		Signature:       fill(0x55, 8),
	}
	encodedSig, err := wire.Encode(objSig)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "ObjectSignature", encodedSig, "0bd8059272ddb7c314a04a7c6a8c937541020100085555555555555555")

	unsignedSig, err := wire.Encode(objSig.Unsigned())
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "ObjectSignature unsigned", unsignedSig, "0bd8059272ddb7c314a04a7c6a8c93754102010000")

	sigHash := auroracrypto.PreHashLabel("aurora v2.0 structural object signature", unsignedSig)
	assertHex(t, "ObjectSignature structural hash", sigHash, "c1e422a891bccf2deb21a7192d5d185ae5388daaeb4b986eb5eb3b915f3082ef1dd565c2b74a1b5460b589d5030b9c98")
}

func TestPublicKeyCompatibilityRejectsMismatches(t *testing.T) {
	err := (PublicKeyRecord{
		SignatureScheme: registry.SigMLDSA65,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       fill(0, 32),
	}).ValidateCompatibility()
	if err == nil {
		t.Fatalf("expected incompatible ML-DSA key encoding to fail")
	}
}

func TestPublicKeyCompatibilityRejectsFixedLengthMismatches(t *testing.T) {
	cases := []PublicKeyRecord{{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       fill(0x04, 64),
	}, {
		SignatureScheme: registry.SigECDSAP384SHA384DER,
		KeyEncoding:     registry.KeyP384SEC1Uncompressed,
		PublicKey:       fill(0x04, 96),
	}, {
		SignatureScheme: registry.SigMLDSA65,
		KeyEncoding:     registry.KeyMLDSA65RawPublic,
		PublicKey:       fill(0x11, 1),
	}, {
		SignatureScheme: registry.SigMLDSA87,
		KeyEncoding:     registry.KeyMLDSA87RawPublic,
		PublicKey:       fill(0x12, 1),
	}, {
		SignatureScheme: registry.SigEd25519Lab,
		KeyEncoding:     registry.KeyEd25519RawPublic,
		PublicKey:       fill(0x13, 31),
	}}
	for _, record := range cases {
		if err := record.ValidateCompatibility(); err == nil {
			t.Fatalf("fixed-length public key accepted with %d bytes: %+v", len(record.PublicKey), record)
		}
	}
}

func TestAuthorityKeyValidateRequiresAllRequestedUsageBits(t *testing.T) {
	key := AuthorityKeyRecord{
		AuthorityID:    fill(0x01, 16),
		AuthorityKeyID: fill(0x02, 16),
		PublicKey: PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP256SHA384DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			PublicKey:       fill(0x04, 65),
		},
		ValidFromUnix:  10,
		ValidUntilUnix: 30,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignDirectoryConsensus,
	}
	required := registry.UsageMaySignDirectoryConsensus | registry.UsageMayRotateDirectoryAuthority
	if err := key.Validate(20, required); err == nil {
		t.Fatalf("authority key with only one requested usage bit accepted")
	}
	key.UsageFlags |= registry.UsageMayRotateDirectoryAuthority
	if err := key.Validate(20, required); err != nil {
		t.Fatalf("authority key with all requested usage bits rejected: %v", err)
	}
}

func TestValidateExtensionsRejectsUnknownCritical(t *testing.T) {
	known := map[uint64]bool{0x7001: true}
	if err := ValidateExtensions([]Extension{{ExtensionType: 0x7001, Critical: true}}, known); err != nil {
		t.Fatalf("known critical extension rejected: %v", err)
	}
	if err := ValidateExtensions([]Extension{{ExtensionType: 0x7002, Critical: false}}, known); err != nil {
		t.Fatalf("unknown non-critical extension rejected: %v", err)
	}
	if err := ValidateExtensions([]Extension{{ExtensionType: 0x7002, Critical: true}}, known); err == nil {
		t.Fatalf("unknown critical extension accepted")
	}
}

func assertHex(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	want := hexBytes(t, wantHex)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %x, want %x", name, got, want)
	}
}
