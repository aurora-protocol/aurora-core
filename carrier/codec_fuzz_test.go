package carrier

import (
	"bytes"
	"testing"
)

// FuzzDecodeIssueRequest drives the fixed-width issue-request decoder that runs
// on BlindRSAIssueRequest payloads carried over the opaque cover surface, i.e.
// bytes supplied by an unauthenticated peer. Beyond not panicking, an accepted
// payload must re-encode to the exact input bytes: the decoder is total and
// fixed-width, so any drift would mean two wire forms carry one request.
func FuzzDecodeIssueRequest(f *testing.F) {
	valid, err := EncodeIssueRequest(bytes.Repeat([]byte{0x11}, TokenNonceLength), bytes.Repeat([]byte{0x22}, RedemptionContextLength), 1234)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add(valid[:len(valid)-1])                        // one byte short
	f.Add(append(append([]byte(nil), valid...), 0xff)) // trailing byte
	f.Add(bytes.Repeat([]byte{0xaa}, issueRequestLength))

	f.Fuzz(func(t *testing.T, payload []byte) {
		tokenNonce, redemptionContextHash, expiryUnix, err := DecodeIssueRequest(payload)
		if err != nil {
			return
		}
		if len(payload) != issueRequestLength || len(tokenNonce) != TokenNonceLength || len(redemptionContextHash) != RedemptionContextLength {
			t.Fatalf("accepted payload of %d bytes with nonce %d, context %d", len(payload), len(tokenNonce), len(redemptionContextHash))
		}
		reencoded, err := EncodeIssueRequest(tokenNonce, redemptionContextHash, expiryUnix)
		if err != nil {
			t.Fatalf("decoded issue request failed to re-encode: %v", err)
		}
		if !bytes.Equal(reencoded, payload) {
			t.Fatalf("issue request re-encoded to %x, want %x", reencoded, payload)
		}
	})
}

// FuzzDecodeMetadataResponse drives the length-prefixed metadata-response
// decoder, which is the fail-closed side of the issuer metadata fetch: it must
// accept only payloads whose declared length accounts for every byte. A
// successful decode must therefore re-encode to the exact input and always
// carry a full 48-byte metadata hash.
func FuzzDecodeMetadataResponse(f *testing.F) {
	valid, err := EncodeMetadataResponse([]byte{0x01, 0x02, 0x03}, bytes.Repeat([]byte{0x44}, metadataHashLength))
	if err != nil {
		f.Fatal(err)
	}
	emptyMetadata, err := EncodeMetadataResponse(nil, bytes.Repeat([]byte{0x55}, metadataHashLength))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(emptyMetadata)
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00})                         // shorter than the length prefix
	f.Add([]byte{0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}) // declared length but no hash
	f.Add(append(append([]byte(nil), valid...), 0xff))      // trailing byte

	f.Fuzz(func(t *testing.T, payload []byte) {
		encoded, hash, err := DecodeMetadataResponse(payload)
		if err != nil {
			return
		}
		if len(hash) != metadataHashLength {
			t.Fatalf("accepted metadata response with %d-byte hash", len(hash))
		}
		if len(payload) != 4+len(encoded)+metadataHashLength {
			t.Fatalf("accepted payload of %d bytes with %d-byte metadata", len(payload), len(encoded))
		}
		reencoded, err := EncodeMetadataResponse(encoded, hash)
		if err != nil {
			t.Fatalf("decoded metadata response failed to re-encode: %v", err)
		}
		if !bytes.Equal(reencoded, payload) {
			t.Fatalf("metadata response re-encoded to %x, want %x", reencoded, payload)
		}
	})
}
