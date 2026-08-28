package client

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestNativeProvisioningImportEnvelopeRoundTrip(t *testing.T) {
	source := bytes.Repeat([]byte{0x5a}, 1024)
	keys := [][]byte{
		bytes.Repeat([]byte{0x11}, NativeProvisioningImportSpentHintKeyBytes),
		bytes.Repeat([]byte{0x22}, NativeProvisioningImportSpentHintKeyBytes),
	}
	encoded, err := EncodeNativeProvisioningImportEnvelope(source, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(encoded)
	if len(encoded) != 4+len(source)+1+2*NativeProvisioningImportSpentHintKeyBytes {
		t.Fatalf("envelope length = %d", len(encoded))
	}
	decodedSource, decodedKeys, err := DecodeNativeProvisioningImportEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedSource, source) {
		t.Fatal("envelope source did not round-trip")
	}
	if len(decodedKeys) != len(keys) {
		t.Fatalf("envelope spent hint keys = %d, want %d", len(decodedKeys), len(keys))
	}
	for index := range keys {
		if !bytes.Equal(decodedKeys[index], keys[index]) {
			t.Fatalf("spent hint key %d did not round-trip", index)
		}
	}
	// Decoded values must be caller-owned copies, not aliases of encoded.
	encoded[4] ^= 0xff
	encoded[4+len(source)+1] ^= 0xff
	if !bytes.Equal(decodedSource, source) || !bytes.Equal(decodedKeys[0], keys[0]) {
		t.Fatal("decoded envelope values alias the input buffer")
	}
}

func TestNativeProvisioningImportEnvelopeEmptySpentKeys(t *testing.T) {
	source := []byte("wallet bytes")
	encoded, err := EncodeNativeProvisioningImportEnvelope(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	decodedSource, decodedKeys, err := DecodeNativeProvisioningImportEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedSource, source) || len(decodedKeys) != 0 {
		t.Fatal("envelope with zero spent keys did not round-trip")
	}
}

func TestNativeProvisioningImportEnvelopeBoundaries(t *testing.T) {
	// Source length boundaries.
	if _, err := EncodeNativeProvisioningImportEnvelope(nil, nil); err == nil {
		t.Fatal("empty source was accepted")
	}
	if _, err := EncodeNativeProvisioningImportEnvelope(make([]byte, MaximumNativeProvisioningWalletBytes+1), nil); err == nil {
		t.Fatal("oversized source was accepted")
	}
	// Spent-key count boundaries.
	maxKeys := make([][]byte, MaximumNativeProvisioningImportSpentHintKeys)
	for index := range maxKeys {
		maxKeys[index] = bytes.Repeat([]byte{byte(index)}, NativeProvisioningImportSpentHintKeyBytes)
	}
	encoded, err := EncodeNativeProvisioningImportEnvelope([]byte{0x01}, maxKeys)
	if err != nil {
		t.Fatalf("maximum spent-key count rejected: %v", err)
	}
	if _, keys, err := DecodeNativeProvisioningImportEnvelope(encoded); err != nil || len(keys) != MaximumNativeProvisioningImportSpentHintKeys {
		t.Fatalf("maximum spent-key envelope decode = keys %d err %v", len(keys), err)
	}
	tooManyKeys := append(maxKeys, bytes.Repeat([]byte{0x77}, NativeProvisioningImportSpentHintKeyBytes))
	if _, err := EncodeNativeProvisioningImportEnvelope([]byte{0x01}, tooManyKeys); err == nil {
		t.Fatal("more than the maximum spent-key count was accepted")
	}
	// Spent-key length strictness.
	if _, err := EncodeNativeProvisioningImportEnvelope([]byte{0x01}, [][]byte{make([]byte, NativeProvisioningImportSpentHintKeyBytes-1)}); err == nil {
		t.Fatal("short spent hint key was accepted")
	}
	if _, err := EncodeNativeProvisioningImportEnvelope([]byte{0x01}, [][]byte{make([]byte, NativeProvisioningImportSpentHintKeyBytes+1)}); err == nil {
		t.Fatal("long spent hint key was accepted")
	}
}

func TestDecodeNativeProvisioningImportEnvelopeRejectsMalformed(t *testing.T) {
	valid, err := EncodeNativeProvisioningImportEnvelope(bytes.Repeat([]byte{0x33}, 64), [][]byte{bytes.Repeat([]byte{0x44}, NativeProvisioningImportSpentHintKeyBytes)})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(valid)
	for _, testCase := range []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"shorter than header", []byte{0, 0, 0}},
		{"zero source length", make([]byte, 5)},
		{"oversized source length", append([]byte{0xff, 0xff, 0xff, 0xff}, 0)},
		{"truncated source", valid[:4+32]},
		{"trailing garbage", append(append([]byte(nil), valid...), 0x00)},
		{"missing spent key bytes", valid[:len(valid)-10]},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			source, keys, err := DecodeNativeProvisioningImportEnvelope(testCase.input)
			if err == nil {
				zeroNativeProvisioningBytes(source)
				for _, key := range keys {
					zeroNativeProvisioningBytes(key)
				}
				t.Fatal("malformed envelope was accepted")
			}
		})
	}
	// An oversized envelope must be rejected before any field is trusted.
	if _, _, err := DecodeNativeProvisioningImportEnvelope(make([]byte, MaximumNativeProvisioningImportEnvelopeBytes+1)); err == nil {
		t.Fatal("oversized envelope was accepted")
	}
}

// TestNativeProvisioningImportEnvelopeUnrepresentableSourceLength mirrors the
// mobile reservation guard: a uint32 source length beyond the wallet ceiling
// must not decode.
func TestNativeProvisioningImportEnvelopeUnrepresentableSourceLength(t *testing.T) {
	request := make([]byte, 4+1)
	binary.BigEndian.PutUint32(request, ^uint32(0))
	if _, _, err := DecodeNativeProvisioningImportEnvelope(request); err == nil {
		t.Fatal("envelope accepted an unrepresentable source length")
	}
}
