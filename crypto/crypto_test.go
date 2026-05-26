package auroracrypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func repeated(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestControlAADAppendixB4(t *testing.T) {
	in := ControlAADInput{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   registry.SuiteHybrid768AESGCM,
		MsgType:                         registry.MsgCoverCapsule1,
		RouteInstanceID:                 0x01,
		HopIndex:                        0x00,
		ControlDirection:                0x00,
		HandshakeBindingContext:         repeated(0xaa, 48),
		PreludeTranscriptHashForThisHop: repeated(0xbb, 48),
	}
	preimage, err := ControlAADPreimage(in)
	if err != nil {
		t.Fatal(err)
	}
	wantPreimage := mustHex(t, "6175726f72612076322e3020636f6e74726f6c2061616442000141030100000030aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0030bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if !bytes.Equal(preimage, wantPreimage) {
		t.Fatalf("control preimage = %x, want %x", preimage, wantPreimage)
	}
	aad, err := ControlAAD(in)
	if err != nil {
		t.Fatal(err)
	}
	wantAAD := mustHex(t, "e0b1176d0ba89cc3a0b5ebfc14f532bf71abfc7d21d75e903c8ac8f7017a3e03baff38ecd7322754ca43f1ce4dcb0ed7")
	if !bytes.Equal(aad, wantAAD) {
		t.Fatalf("control aad = %x, want %x", aad, wantAAD)
	}
}

func TestRouteWrapAppendixB4(t *testing.T) {
	in := RouteWrapInput{
		RouteInstanceID:                0x01,
		HopIndex:                       0x01,
		PreviousHopRelayDescriptorHash: repeated(0x41, 48),
		NextRelayDescriptorHash:        repeated(0x42, 48),
		HintIssuerID:                   repeated(0x34, 16),
		RelayBucketID:                  repeated(0x35, 16),
		HintEpochID:                    7,
		HintSelector:                   repeated(0x31, 16),
		WrapSuiteID:                    registry.WrapSuiteRouteV1,
		WrapNonce:                      repeated(0x32, 16),
		HintSecret:                     repeated(0x33, 32),
	}
	context, key, iv, aad, sealed, err := SealRoutePrelude(in, repeated(0x44, 16))
	if err != nil {
		t.Fatal(err)
	}
	assertHex := func(name string, got []byte, want string) {
		t.Helper()
		w := mustHex(t, want)
		if !bytes.Equal(got, w) {
			t.Fatalf("%s = %x, want %x", name, got, w)
		}
	}
	assertHex("context", context, "c91843189c8e3636da1d009c319726da0520e35c88a336f6b1798d1bdad2b35aa209bb71fe84122cc31a8e95eb8dbea6")
	assertHex("key", key, "fcf30419c9a22171928f2e08119493f637bda6eef8b0c4de25b4e7ca87808302")
	assertHex("iv", iv, "1886058795a4659f42f16a7c")
	assertHex("aad", aad, "ebc29f57ada23315f21bde701286e0db909710b06cb82bda3f971984fa29d92bc2053e8ec52c96b22e20c6c510b99ef7")
	assertHex("sealed", sealed, "b73e204336a08b51754241e828b6ff076643ec428d18c8a2c52245d0dce16c34")

	opened, err := OpenRoutePrelude(in, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, repeated(0x44, 16)) {
		t.Fatalf("opened = %x", opened)
	}
}

func TestMLKEM768RoundTrip(t *testing.T) {
	decap, err := GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}
	clientShared, ciphertext, err := EncapsulateMLKEM768(decap.EncapsulationKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	serverShared, err := decap.Decapsulate(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientShared, serverShared) {
		t.Fatalf("ML-KEM shared secret mismatch")
	}
}
