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

func TestControlAADRejectsReservedOrMismatchedDirection(t *testing.T) {
	base := ControlAADInput{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   registry.SuiteHybrid768AESGCM,
		MsgType:                         registry.MsgCoverCapsule1,
		RouteInstanceID:                 1,
		HandshakeBindingContext:         repeated(0xaa, 48),
		PreludeTranscriptHashForThisHop: repeated(0xbb, 48),
	}
	cases := map[string]ControlAADInput{
		"reserved direction": func() ControlAADInput {
			in := base
			in.ControlDirection = 2
			return in
		}(),
		"cover capsule 1 backward": func() ControlAADInput {
			in := base
			in.MsgType = registry.MsgCoverCapsule1
			in.ControlDirection = 1
			return in
		}(),
		"cover capsule 2 forward": func() ControlAADInput {
			in := base
			in.MsgType = registry.MsgCoverCapsule2
			in.ControlDirection = 0
			return in
		}(),
		"route capsule 1 backward": func() ControlAADInput {
			in := base
			in.MsgType = registry.MsgRouteCapsule1
			in.ControlDirection = 1
			return in
		}(),
		"route capsule 2 forward": func() ControlAADInput {
			in := base
			in.MsgType = registry.MsgRouteCapsule2
			in.ControlDirection = 0
			return in
		}(),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ControlAADPreimage(in); err == nil {
				t.Fatalf("invalid control AAD input accepted: %+v", in)
			}
		})
	}
}

func TestPacketADRejectsReservedDirection(t *testing.T) {
	if _, err := PacketAD(registry.SuiteHybrid768AESGCM, 1, 0, 2, 0, 0); err == nil {
		t.Fatalf("reserved packet direction accepted")
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

func TestMLKEM1024SeedConstructorIsDeterministic(t *testing.T) {
	seed := repeated(0x42, 64)
	decap1, err := NewMLKEM1024DecapsulationKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	decap2, err := NewMLKEM1024DecapsulationKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decap1.EncapsulationKeyBytes(), decap2.EncapsulationKeyBytes()) {
		t.Fatalf("ML-KEM-1024 seed constructor produced different encapsulation keys")
	}
	clientShared, ciphertext, err := EncapsulateMLKEM1024(decap1.EncapsulationKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	serverShared, err := decap2.Decapsulate(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientShared, serverShared) {
		t.Fatalf("ML-KEM-1024 shared secret mismatch")
	}
}

func TestMLKEMBackendAgreementChecksStdlibAndCIRCL(t *testing.T) {
	results, err := CheckMLKEMBackendAgreement()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("backend agreement result count = %d, want 2", len(results))
	}
	for _, result := range results {
		if !result.Passed {
			t.Fatalf("%s backend agreement did not pass: %+v", result.Scheme, result)
		}
		if result.StandardLibraryBackend != "crypto/mlkem" {
			t.Fatalf("%s stdlib backend = %q", result.Scheme, result.StandardLibraryBackend)
		}
		if result.CrossCheckBackend != "github.com/cloudflare/circl/kem/mlkem" {
			t.Fatalf("%s cross-check backend = %q", result.Scheme, result.CrossCheckBackend)
		}
		switch result.Scheme {
		case "ML-KEM-768":
			if result.PublicKeyBytes != 1184 || result.CiphertextBytes != 1088 || result.SharedSecretBytes != 32 {
				t.Fatalf("ML-KEM-768 sizes = %+v", result)
			}
		case "ML-KEM-1024":
			if result.PublicKeyBytes != 1568 || result.CiphertextBytes != 1568 || result.SharedSecretBytes != 32 {
				t.Fatalf("ML-KEM-1024 sizes = %+v", result)
			}
		default:
			t.Fatalf("unexpected backend agreement scheme %q", result.Scheme)
		}
	}
}

func TestChaCha20Poly1305RFCVector(t *testing.T) {
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex(t, "070000004041424344454647")
	aad := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	plaintext := mustHex(t, "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
	want := mustHex(t, "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")
	sealed, err := ChaCha20Poly1305Seal(key, nonce, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sealed, want) {
		t.Fatalf("ChaCha20-Poly1305 sealed bytes = %x, want %x", sealed, want)
	}
	opened, err := ChaCha20Poly1305Open(key, nonce, aad, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("ChaCha20-Poly1305 opened bytes = %x, want %x", opened, plaintext)
	}
}

func TestLabClassicalSuiteUsesChaChaAEAD(t *testing.T) {
	key := repeated(0x51, 32)
	nonce := repeated(0x52, 12)
	aad := []byte("aad")
	plaintext := []byte("lab packet")
	want, err := ChaCha20Poly1305Seal(key, nonce, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := SealForSuite(registry.SuiteLabClassical, key, nonce, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("lab suite did not use ChaCha20-Poly1305")
	}
}
