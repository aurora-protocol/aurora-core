package carrier

import (
	"bytes"
	"testing"
)

func TestIssueRequestCarrierRoundTrip(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x11}, TokenNonceLength)
	contextHash := bytes.Repeat([]byte{0x22}, RedemptionContextLength)
	payload, err := EncodeIssueRequest(nonce, contextHash, 1234)
	if err != nil {
		t.Fatal(err)
	}
	encoded := Encode(BlindRSAIssueRequest, payload)
	kind, decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if kind != BlindRSAIssueRequest {
		t.Fatalf("carrier kind = %d, want %d", kind, BlindRSAIssueRequest)
	}
	decodedNonce, decodedContextHash, expiry, err := DecodeIssueRequest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedNonce, nonce) || !bytes.Equal(decodedContextHash, contextHash) || expiry != 1234 {
		t.Fatalf("issue request round trip = nonce=%x context=%x expiry=%d", decodedNonce, decodedContextHash, expiry)
	}
}

func TestMetadataResponseUsesFixedLengthPrefix(t *testing.T) {
	metadata := []byte{0x01, 0x02, 0x03}
	hash := bytes.Repeat([]byte{0x44}, 48)
	encoded, err := EncodeMetadataResponse(metadata, hash)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}, hash...)
	if !bytes.Equal(encoded, want) {
		t.Fatalf("metadata response = %x, want %x", encoded, want)
	}
	decodedMetadata, decodedHash, err := DecodeMetadataResponse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedMetadata, metadata) || !bytes.Equal(decodedHash, hash) {
		t.Fatalf("metadata response round trip = metadata=%x hash=%x", decodedMetadata, decodedHash)
	}
}
