//go:build cgo

package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

// validProofWire returns the wire encoding of a fixture admission proof,
// suitable as input to parseAdmissionProof.
func validProofWire(t *testing.T) []byte {
	t.Helper()
	wire, err := protocol.Encode(nativeBridgeAdmissionProof(t))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// TestParseAdmissionProofRoundTripsValidProof covers the end-to-end happy path
// (wire -> decode -> validate -> JSON) and asserts the credential-bearing
// fields surface as hex in the parsed JSON.
func TestParseAdmissionProofRoundTripsValidProof(t *testing.T) {
	out, err := parseAdmissionProof(validProofWire(t))
	if err != nil {
		t.Fatalf("parseAdmissionProof valid: %v", err)
	}
	if !strings.Contains(string(out), hex.EncodeToString(bytes.Repeat([]byte{0x13}, 16))) {
		t.Fatalf("parsed proof JSON missing relay bucket id hex: %s", out)
	}
	if !strings.Contains(string(out), hex.EncodeToString([]byte("authenticator"))) {
		t.Fatalf("parsed proof JSON missing token authenticator hex: %s", out)
	}
}

// TestParseAdmissionProofRejectsTrailingBytes covers the !reader.EOF() guard:
// a valid proof followed by an extra byte is rejected as trailing.
func TestParseAdmissionProofRejectsTrailingBytes(t *testing.T) {
	wire := append(validProofWire(t), 0x00)
	_, err := parseAdmissionProof(wire)
	if err == nil {
		t.Fatal("parseAdmissionProof with trailing bytes unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "trailing admission proof bytes") {
		t.Fatalf("err = %q, want substring %q", err, "trailing admission proof bytes")
	}
}

// TestParseAdmissionProofRejectsMalformedWire covers the reader.Err() guard:
// garbage too short for the proof structure surfaces a wire short-read error
// (not the trailing-bytes message) and zeroes the decoded proof.
func TestParseAdmissionProofRejectsMalformedWire(t *testing.T) {
	_, err := parseAdmissionProof([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Fatal("parseAdmissionProof with malformed wire unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "trailing admission proof bytes") {
		t.Fatalf("malformed wire returned trailing-bytes error: %v", err)
	}
}

// TestEncodeParsedAdmissionProofRejectsEmptyAuthenticator covers the
// empty-token-authenticator guard that fires after metadata validation.
func TestEncodeParsedAdmissionProofRejectsEmptyAuthenticator(t *testing.T) {
	proof := nativeBridgeAdmissionProof(t)
	proof.TokenAuthenticator = nil
	_, err := encodeParsedAdmissionProof(proof)
	if err == nil {
		t.Fatal("encodeParsedAdmissionProof with empty authenticator unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "empty token authenticator") {
		t.Fatalf("err = %q, want substring %q", err, "empty token authenticator")
	}
}

// TestEncodeParsedAdmissionProofRejectsTrailingMetadataBytes covers the
// metadata !reader.EOF() guard.
func TestEncodeParsedAdmissionProofRejectsTrailingMetadataBytes(t *testing.T) {
	proof := nativeBridgeAdmissionProof(t)
	proof.TokenPublicMetadata = append(proof.TokenPublicMetadata, 0x00)
	_, err := encodeParsedAdmissionProof(proof)
	if err == nil {
		t.Fatal("trailing metadata bytes unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "trailing token metadata bytes") {
		t.Fatalf("err = %q, want substring %q", err, "trailing token metadata bytes")
	}
}

// TestEncodeParsedAdmissionProofRejectsMalformedMetadata covers the metadata
// reader.Err() guard: a too-short metadata blob surfaces a wire short-read
// error rather than a validation message.
func TestEncodeParsedAdmissionProofRejectsMalformedMetadata(t *testing.T) {
	proof := nativeBridgeAdmissionProof(t)
	proof.TokenPublicMetadata = []byte{0x00, 0x01}
	_, err := encodeParsedAdmissionProof(proof)
	if err == nil {
		t.Fatal("malformed metadata unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "trailing token metadata bytes") {
		t.Fatalf("malformed metadata returned trailing-bytes error: %v", err)
	}
}

// TestEncodeParsedAdmissionProofRejectsTokenKeyIDMismatch covers the
// ValidateForProof token-key-id consistency check: mutating the struct field
// after the metadata is encoded creates a mismatch the validator detects.
func TestEncodeParsedAdmissionProofRejectsTokenKeyIDMismatch(t *testing.T) {
	proof := nativeBridgeAdmissionProof(t)
	proof.TokenKeyID[0] ^= 0xff
	_, err := encodeParsedAdmissionProof(proof)
	if err == nil {
		t.Fatal("token key id mismatch unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "token metadata token key id mismatch") {
		t.Fatalf("err = %q, want substring %q", err, "token metadata token key id mismatch")
	}
}

// TestEncodeParsedAdmissionProofRejectsProofTypeMismatch covers the
// ValidateForProof proof-type consistency check.
func TestEncodeParsedAdmissionProofRejectsProofTypeMismatch(t *testing.T) {
	proof := nativeBridgeAdmissionProof(t)
	proof.ProofType ^= 1
	_, err := encodeParsedAdmissionProof(proof)
	if err == nil {
		t.Fatal("proof type mismatch unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "token metadata proof type mismatch") {
		t.Fatalf("err = %q, want substring %q", err, "token metadata proof type mismatch")
	}
}
