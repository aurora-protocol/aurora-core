package carrier

import (
	"bytes"
	"testing"
)

// TestDecodeAdversarial covers the Decode error path (previously uncovered):
// an empty body is rejected.
func TestDecodeAdversarial(t *testing.T) {
	if _, _, err := Decode(nil); err == nil {
		t.Fatal("empty body accepted by Decode")
	}
	if _, _, err := Decode([]byte{}); err == nil {
		t.Fatal("zero-length body accepted by Decode")
	}
}

// TestEncodeIssueRequestAdversarial covers the two EncodeIssueRequest length
// guards (previously uncovered): wrong token-nonce length and wrong
// redemption-context length.
func TestEncodeIssueRequestAdversarial(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x11}, TokenNonceLength)
	contextHash := bytes.Repeat([]byte{0x22}, RedemptionContextLength)

	if _, err := EncodeIssueRequest(nonce[:TokenNonceLength-1], contextHash, 1); err == nil {
		t.Fatal("EncodeIssueRequest accepted short token nonce")
	}
	if _, err := EncodeIssueRequest(append(nonce, 0x33), contextHash, 1); err == nil {
		t.Fatal("EncodeIssueRequest accepted long token nonce")
	}
	if _, err := EncodeIssueRequest(nonce, contextHash[:RedemptionContextLength-1], 1); err == nil {
		t.Fatal("EncodeIssueRequest accepted short redemption context")
	}
	if _, err := EncodeIssueRequest(nonce, append(contextHash, 0x33), 1); err == nil {
		t.Fatal("EncodeIssueRequest accepted long redemption context")
	}
}

// TestDecodeIssueRequestAdversarial covers the DecodeIssueRequest length
// guard (previously uncovered).
func TestDecodeIssueRequestAdversarial(t *testing.T) {
	if _, _, _, err := DecodeIssueRequest(nil); err == nil {
		t.Fatal("DecodeIssueRequest accepted empty payload")
	}
	valid, err := EncodeIssueRequest(bytes.Repeat([]byte{0x11}, TokenNonceLength), bytes.Repeat([]byte{0x22}, RedemptionContextLength), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := DecodeIssueRequest(append(valid, 0x00)); err == nil {
		t.Fatal("DecodeIssueRequest accepted over-long payload")
	}
}

// TestEncodeMetadataResponseAdversarial covers the EncodeMetadataResponse hash
// length guard (previously uncovered).
func TestEncodeMetadataResponseAdversarial(t *testing.T) {
	if _, err := EncodeMetadataResponse([]byte{0x01}, bytes.Repeat([]byte{0x44}, metadataHashLength-1)); err == nil {
		t.Fatal("EncodeMetadataResponse accepted short hash")
	}
	if _, err := EncodeMetadataResponse([]byte{0x01}, append(bytes.Repeat([]byte{0x44}, metadataHashLength), 0x55)); err == nil {
		t.Fatal("EncodeMetadataResponse accepted long hash")
	}
}

// TestDecodeMetadataResponseAdversarial covers the two DecodeMetadataResponse
// error paths (previously uncovered): a payload too short to hold the length
// prefix, and a payload whose declared length does not match the trailing hash.
func TestDecodeMetadataResponseAdversarial(t *testing.T) {
	if _, _, err := DecodeMetadataResponse(bytes.Repeat([]byte{0x00}, 3)); err == nil {
		t.Fatal("DecodeMetadataResponse accepted payload shorter than length prefix")
	}
	// Declared length claims 1 byte of encoded body, but only a 48-byte hash
	// follows the prefix (missing the 1 body byte) -> length mismatch.
	short := append([]byte{0x00, 0x00, 0x00, 0x01}, bytes.Repeat([]byte{0x44}, metadataHashLength)...)
	if _, _, err := DecodeMetadataResponse(short); err == nil {
		t.Fatal("DecodeMetadataResponse accepted payload with mismatched length")
	}

	// On 32-bit targets, converting this prefix to int used to wrap to -1.
	// A 51-byte payload then passed the length check and panicked while slicing.
	overflow := bytes.Repeat([]byte{0xff}, 4+metadataHashLength-1)
	if _, _, err := DecodeMetadataResponse(overflow); err == nil {
		t.Fatal("DecodeMetadataResponse accepted an unrepresentable length")
	}
}
