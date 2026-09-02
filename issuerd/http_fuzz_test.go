package issuerd

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

// FuzzDecodeAdmissionProofBytes drives the wire decode of the AdmissionProof
// that arrives hex-encoded in a /token/spend request body, i.e. bytes supplied
// by an unauthenticated client before any credential verification. Beyond not
// panicking, the decoder is fail-closed on trailing bytes, so an accepted
// encoding must re-encode to the exact input: a second wire form for one proof
// would make the spend transcript malleable.
func FuzzDecodeAdmissionProofBytes(f *testing.F) {
	// Structurally-valid (crypto-invalid) proof with exact fixed-opaque lengths,
	// mirroring the fixture in TestDecodeAdmissionProofBytesRejectsTrailingBytes.
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              bytes.Repeat([]byte{0x11}, 16),
		TokenKeyID:            bytes.Repeat([]byte{0x12}, 32),
		RelayBucketID:         bytes.Repeat([]byte{0x13}, 16),
		TokenScopeID:          bytes.Repeat([]byte{0x14}, 16),
		ExpiryUnix:            300,
		TokenNonce:            bytes.Repeat([]byte{0x15}, 32),
		RedemptionContextHash: bytes.Repeat([]byte{0x16}, 48),
		TokenPublicMetadata:   []byte{0x01, 0x02},
		TokenAuthenticator:    bytes.Repeat([]byte{0x17}, 384),
	}
	valid, err := wire.Encode(proof)
	if err != nil {
		f.Fatal(err)
	}
	withExtension := proof
	withExtension.Extensions = []protocol.Extension{{ExtensionType: 0x401, Critical: true, Body: []byte{0xaa, 0xbb}}}
	validWithExtension, err := wire.Encode(withExtension)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(validWithExtension)
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(valid[:len(valid)-1])                        // truncated mid-field
	f.Add(append(append([]byte(nil), valid...), 0xab)) // trailing byte
	f.Add([]byte{0x40, 0x00})                          // non-canonical varint version

	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeAdmissionProofBytes(raw)
		if err != nil {
			return
		}
		reencoded, err := wire.Encode(decoded)
		if err != nil {
			t.Fatalf("decoded admission proof failed to re-encode: %v", err)
		}
		if !bytes.Equal(reencoded, raw) {
			t.Fatalf("admission proof re-encoded to %x, want %x", reencoded, raw)
		}
	})
}
