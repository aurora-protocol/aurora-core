//go:build cgo

package main

// Adversarial coverage for the pure validation/encode/decode helpers in
// auroracore.go that the existing integration-style tests (which drive the C
// ABI through dispatch with a live first-hop fixture) do not reach directly.
// Each case crafts a minimal in-memory input with no TCP/UDP fixture, no live
// provisioning trust, and no C ABI caller, asserting the error/boolean
// response where the rejection branch fires before any of that.
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs).
//
// Dead by design (documented, not contrived):
//   - encodeNativeProvisioningReservationJSON:582-583 (json.Marshal error):
//     marshalling a struct of base64 strings + a uint64 cannot fail.
//   - encodeNativeProvisioningReservationJSON:586-588 (JSON size limit): the
//     limit is base64.EncodedLen(client.MaximumNativeProvisioningWalletBytes)+384,
//     and a valid provisioning is at most MaximumNativeProvisioningWalletBytes,
//     so the base64 payload plus the ~170 bytes of the other fields always fits
//     within the limit. Unreachable for any provisioning that
//     client.EncodeNativeProvisioning accepts.
//   - encodeNativeLocalPacketsJSON:693-694 (json.Marshal error): marshalling a
//     struct of a base64-string slice cannot fail.
//   The genuinely reachable size-limit branch of encodeNativeLocalPacketsJSON
//   (696-698) IS covered below (64 x 65535-byte packets -> ~5.3MB base64 > the
//   2MB cap).

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/aurora-protocol/aurora-core/client"
)

func TestValidateNativeProvisioningReservation(t *testing.T) {
	t.Run("spent hint key wrong length", func(t *testing.T) {
		r := client.NativeProvisioningReservation{
			SpentHintKey:         make([]byte, nativeProvisioningReservationSpentHintKeyBytes-1),
			RelayBucketID:        make([]byte, nativeProvisioningReservationRelayBucketBytes),
			AccessHintExpiryUnix: 1,
		}
		if err := validateNativeProvisioningReservation(r); err == nil {
			t.Fatal("validateNativeProvisioningReservation accepted a short spent hint key")
		}
	})
	t.Run("relay bucket id wrong length", func(t *testing.T) {
		r := client.NativeProvisioningReservation{
			SpentHintKey:         make([]byte, nativeProvisioningReservationSpentHintKeyBytes),
			RelayBucketID:        make([]byte, nativeProvisioningReservationRelayBucketBytes+1),
			AccessHintExpiryUnix: 1,
		}
		if err := validateNativeProvisioningReservation(r); err == nil {
			t.Fatal("validateNativeProvisioningReservation accepted an overlong relay bucket id")
		}
	})
	t.Run("zero access hint expiry", func(t *testing.T) {
		r := client.NativeProvisioningReservation{
			SpentHintKey:         make([]byte, nativeProvisioningReservationSpentHintKeyBytes),
			RelayBucketID:        make([]byte, nativeProvisioningReservationRelayBucketBytes),
			AccessHintExpiryUnix: 0,
		}
		if err := validateNativeProvisioningReservation(r); err == nil {
			t.Fatal("validateNativeProvisioningReservation accepted a zero expiry")
		}
	})
	t.Run("valid", func(t *testing.T) {
		r := client.NativeProvisioningReservation{
			SpentHintKey:         make([]byte, nativeProvisioningReservationSpentHintKeyBytes),
			RelayBucketID:        make([]byte, nativeProvisioningReservationRelayBucketBytes),
			AccessHintExpiryUnix: 1,
		}
		if err := validateNativeProvisioningReservation(r); err != nil {
			t.Fatalf("valid reservation rejected: %v", err)
		}
	})
}

// encodeReservationResultForCoverage builds the binary reservation result
// envelope (3-byte provisioning length, provisioning, 48-byte spent hint key,
// 16-byte relay bucket id, 8-byte big-endian expiry) so decodeNativeProvisioningReservation
// can be exercised without a live provisioning source.
func encodeReservationResultForCoverage(provisioningLength int, expiryUnix uint64) []byte {
	encoded := make([]byte, 3+provisioningLength+nativeProvisioningReservationSpentHintKeyBytes+nativeProvisioningReservationRelayBucketBytes+8)
	encoded[0] = byte(provisioningLength >> 16)
	encoded[1] = byte(provisioningLength >> 8)
	encoded[2] = byte(provisioningLength)
	offset := 3 + provisioningLength + nativeProvisioningReservationSpentHintKeyBytes + nativeProvisioningReservationRelayBucketBytes
	binary.BigEndian.PutUint64(encoded[offset:], expiryUnix)
	return encoded
}

func TestDecodeNativeProvisioningReservationRejectsMalformed(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		// 3 bytes is below the minimum envelope (3 + 48 + 16 + 8 = 75).
		if _, err := decodeNativeProvisioningReservation([]byte{0, 0, 1}); err == nil {
			t.Fatal("decodeNativeProvisioningReservation accepted a too-short envelope")
		}
	})
	t.Run("zero provisioning length", func(t *testing.T) {
		// 75 bytes with a zero provisioning length -> line 606-607.
		envelope := encodeReservationResultForCoverage(0, 1)
		if _, err := decodeNativeProvisioningReservation(envelope); err == nil {
			t.Fatal("decodeNativeProvisioningReservation accepted a zero provisioning length")
		}
	})
	t.Run("provisioning length does not match trailing bytes", func(t *testing.T) {
		// Declare a 1-byte provisioning but add an extra byte so the trailing
		// size check fails -> line 606-607.
		envelope := append(encodeReservationResultForCoverage(1, 1), 0xff)
		if _, err := decodeNativeProvisioningReservation(envelope); err == nil {
			t.Fatal("decodeNativeProvisioningReservation accepted a mismatched provisioning length")
		}
	})
	t.Run("zero expiry", func(t *testing.T) {
		// Well-formed envelope but the expiry field is zero -> line 618-622.
		envelope := encodeReservationResultForCoverage(1, 0)
		if _, err := decodeNativeProvisioningReservation(envelope); err == nil {
			t.Fatal("decodeNativeProvisioningReservation accepted a zero expiry")
		}
	})
}

func TestDecodeNativeProvisioningReservationAcceptsWellFormed(t *testing.T) {
	provisioning := []byte{0xab, 0xcd}
	envelope := encodeReservationResultForCoverage(len(provisioning), 0x1122334455667788)
	// Overwrite the synthetic provisioning bytes with a known value.
	copy(envelope[3:3+len(provisioning)], provisioning)
	reservation, err := decodeNativeProvisioningReservation(envelope)
	if err != nil {
		t.Fatalf("well-formed envelope rejected: %v", err)
	}
	if !bytes.Equal(reservation.Provisioning, provisioning) {
		t.Fatalf("provisioning = %x, want %x", reservation.Provisioning, provisioning)
	}
	if len(reservation.SpentHintKey) != nativeProvisioningReservationSpentHintKeyBytes {
		t.Fatalf("spent hint key length = %d, want %d", len(reservation.SpentHintKey), nativeProvisioningReservationSpentHintKeyBytes)
	}
	if len(reservation.RelayBucketID) != nativeProvisioningReservationRelayBucketBytes {
		t.Fatalf("relay bucket id length = %d, want %d", len(reservation.RelayBucketID), nativeProvisioningReservationRelayBucketBytes)
	}
	if reservation.AccessHintExpiryUnix != 0x1122334455667788 {
		t.Fatalf("expiry = %#x, want %#x", reservation.AccessHintExpiryUnix, uint64(0x1122334455667788))
	}
	defer zeroNativeBytes(reservation.Provisioning)
	defer zeroNativeBytes(reservation.SpentHintKey)
	defer zeroNativeBytes(reservation.RelayBucketID)
}

func TestEncodeNativeIssuerWorkJSONRejectsInvalid(t *testing.T) {
	valid := nativeIssuerWork{Handle: 1, IssuerURL: "https://issuer", IssuerCarrierPath: "/issue", RequestBody: []byte("request-body")}
	cases := []struct {
		name   string
		mutate func(work *nativeIssuerWork)
	}{
		{"zero handle", func(w *nativeIssuerWork) { w.Handle = 0 }},
		{"empty issuer url", func(w *nativeIssuerWork) { w.IssuerURL = "" }},
		{"empty carrier path", func(w *nativeIssuerWork) { w.IssuerCarrierPath = "" }},
		{"empty request body", func(w *nativeIssuerWork) { w.RequestBody = nil }},
		{"oversized request body", func(w *nativeIssuerWork) { w.RequestBody = make([]byte, maximumNativeIssuerWorkBytes+1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			work := valid
			tc.mutate(&work)
			if _, err := encodeNativeIssuerWorkJSON(work); err == nil {
				t.Fatalf("encodeNativeIssuerWorkJSON accepted %s", tc.name)
			}
		})
	}
}

func TestEncodeNativeIssuerWorkJSONAcceptsValid(t *testing.T) {
	work := nativeIssuerWork{Handle: 42, IssuerURL: "https://issuer.example", IssuerCarrierPath: "/issue", RequestBody: []byte("request-body")}
	encoded, err := encodeNativeIssuerWorkJSON(work)
	if err != nil {
		t.Fatalf("valid issuer work rejected: %v", err)
	}
	if !bytes.Contains(encoded, []byte("https://issuer.example")) {
		t.Fatalf("issuer work JSON missing issuer url: %s", encoded)
	}
}

func TestEncodeNativeLocalPacketsJSONRejectsInvalid(t *testing.T) {
	t.Run("too many packets", func(t *testing.T) {
		packets := make([][]byte, maximumNativeLocalPacketQueue+1)
		for i := range packets {
			packets[i] = []byte{0x01}
		}
		if _, err := encodeNativeLocalPacketsJSON(packets); err == nil {
			t.Fatal("encodeNativeLocalPacketsJSON accepted too many packets")
		}
	})
	t.Run("empty packet", func(t *testing.T) {
		if _, err := encodeNativeLocalPacketsJSON([][]byte{[]byte{0x01}, {}}); err == nil {
			t.Fatal("encodeNativeLocalPacketsJSON accepted an empty packet")
		}
	})
	t.Run("oversized packet", func(t *testing.T) {
		if _, err := encodeNativeLocalPacketsJSON([][]byte{make([]byte, maximumNativeLocalPacketBytes+1)}); err == nil {
			t.Fatal("encodeNativeLocalPacketsJSON accepted an oversized packet")
		}
	})
	t.Run("result exceeds size limit", func(t *testing.T) {
		// 64 packets of maximumNativeLocalPacketBytes each base64-encode to
		// ~5.3MB, which exceeds the 2MB result cap -> line 696-698.
		packets := make([][]byte, maximumNativeLocalPacketQueue)
		for i := range packets {
			packets[i] = make([]byte, maximumNativeLocalPacketBytes)
		}
		if _, err := encodeNativeLocalPacketsJSON(packets); err == nil {
			t.Fatal("encodeNativeLocalPacketsJSON accepted a result exceeding the size limit")
		}
	})
}

func TestEncodeNativeLocalPacketsJSONAcceptsValid(t *testing.T) {
	encoded, err := encodeNativeLocalPacketsJSON([][]byte{[]byte("first"), []byte("second")})
	if err != nil {
		t.Fatalf("valid local packets rejected: %v", err)
	}
	if !bytes.Contains(encoded, []byte("Zmlyc3Q=")) { // base64("first")
		t.Fatalf("local packets JSON missing first packet base64: %s", encoded)
	}
}

func TestEncodeNativeProvisioningReservationJSONRejectsInvalid(t *testing.T) {
	t.Run("reservation fails validation", func(t *testing.T) {
		// SpentHintKey is the wrong length, so validateNativeProvisioningReservation
		// rejects before any provisioning encoding -> line 568-569.
		reservation := client.NativeProvisioningReservation{
			SpentHintKey:         make([]byte, nativeProvisioningReservationSpentHintKeyBytes-1),
			RelayBucketID:        make([]byte, nativeProvisioningReservationRelayBucketBytes),
			AccessHintExpiryUnix: 1,
		}
		if _, err := encodeNativeProvisioningReservationJSON(reservation); err == nil {
			t.Fatal("encodeNativeProvisioningReservationJSON accepted a reservation that fails validation")
		}
	})
	t.Run("provisioning encoding fails", func(t *testing.T) {
		// The reservation fields pass validation, but a zero provisioning fails
		// client.EncodeNativeProvisioning (validateContainer) -> line 571-573.
		reservation := client.NativeProvisioningReservation{
			SpentHintKey:         make([]byte, nativeProvisioningReservationSpentHintKeyBytes),
			RelayBucketID:        make([]byte, nativeProvisioningReservationRelayBucketBytes),
			AccessHintExpiryUnix: 1,
			Provisioning:         client.NativeProvisioning{},
		}
		if _, err := encodeNativeProvisioningReservationJSON(reservation); err == nil {
			t.Fatal("encodeNativeProvisioningReservationJSON accepted a provisioning that fails to encode")
		}
	})
}