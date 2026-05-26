package vectors

import (
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestStructuralBundleMatchesSpecAnchors(t *testing.T) {
	bundle, err := GenerateStructuralBundle()
	if err != nil {
		t.Fatal(err)
	}
	if bundle.ControlAAD != "e0b1176d0ba89cc3a0b5ebfc14f532bf71abfc7d21d75e903c8ac8f7017a3e03baff38ecd7322754ca43f1ce4dcb0ed7" {
		t.Fatalf("control AAD drifted: %s", bundle.ControlAAD)
	}
	if bundle.RouteWrapCiphertextTag != "b73e204336a08b51754241e828b6ff076643ec428d18c8a2c52245d0dce16c34" {
		t.Fatalf("route wrap vector drifted: %s", bundle.RouteWrapCiphertextTag)
	}
	if bundle.PreviousHopFullTranscriptHash != "6c44e2137d2e5eefaaa4e48f981416e200938ded1e124a334295623fb8b802946d97ccd4bf5c28765c6e2844b9d9508b" {
		t.Fatalf("previous-hop full transcript vector drifted: %s", bundle.PreviousHopFullTranscriptHash)
	}
	if bundle.AuthorityKeyID != "0bd8059272ddb7c314a04a7c6a8c9375" {
		t.Fatalf("authority key id drifted: %s", bundle.AuthorityKeyID)
	}
	if bundle.FlowOpen != "420007020100045db8d82201bb01515151515151515151515151515151510000525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252020300" {
		t.Fatalf("flow open vector drifted: %s", bundle.FlowOpen)
	}
	if bundle.UDPTargetConfirm != "070100045db8d82201bb5252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252520000003c0100" {
		t.Fatalf("UDP target confirm vector drifted: %s", bundle.UDPTargetConfirm)
	}
	if bundle.FlowClose != "07000100000000000000630004646f6e6500" {
		t.Fatalf("flow close vector drifted: %s", bundle.FlowClose)
	}
}

func TestFirstHopRealCryptoBundleIsDeterministicAndVerifiable(t *testing.T) {
	first, err := GenerateFirstHopRealCryptoBundle()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateFirstHopRealCryptoBundle()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("first-hop real crypto vector is not deterministic:\nfirst=%+v\nsecond=%+v", first, second)
	}
	assertHexLen := func(name, value string, wantBytes int) {
		t.Helper()
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatalf("%s is not hex: %v", name, err)
		}
		if len(decoded) != wantBytes {
			t.Fatalf("%s length = %d, want %d", name, len(decoded), wantBytes)
		}
	}
	assertHexLen("client_mlkem_encapsulation_key", first.ClientMLKEMEncapsulationKey, mlkem768.PublicKeySize)
	assertHexLen("server_mlkem_ciphertext_to_client", first.ServerMLKEMCiphertextToClient, mlkem768.CiphertextSize)
	assertHexLen("mlkem_shared_secret", first.MLKEMSharedSecret, mlkem768.SharedKeySize)
	assertHexLen("server_pq_public_key", first.ServerPQPublicKey, mldsa65.PublicKeySize)
	assertHexLen("server_prelude_signature_pq", first.ServerPreludeSignaturePQ, mldsa65.SignatureSize)
	assertHexLen("prelude_transcript_hash", first.PreludeTranscriptHash, 48)
	if first.CoverPrelude0 == "" || first.CoverPrelude1 == "" || first.ServerPreludeSignatureClassical == "" || first.ClassicalSharedSecret == "" {
		t.Fatalf("first-hop real crypto vector omitted required first-hop fields: %+v", first)
	}
}

func TestRoutePreludeRealCryptoBundleIsDeterministicAndVerifiable(t *testing.T) {
	first, err := GenerateRoutePreludeRealCryptoBundle()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateRoutePreludeRealCryptoBundle()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("route-prelude real crypto vector is not deterministic:\nfirst=%+v\nsecond=%+v", first, second)
	}
	assertHexLen := func(name, value string, wantBytes int) {
		t.Helper()
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatalf("%s is not hex: %v", name, err)
		}
		if len(decoded) != wantBytes {
			t.Fatalf("%s length = %d, want %d", name, len(decoded), wantBytes)
		}
	}
	assertHexLen("route_hop_binding", first.RouteHopBinding, 48)
	assertHexLen("route_prelude_transcript_hash", first.RoutePreludeTranscriptHash, 48)
	assertHexLen("route_mlkem_shared_secret", first.RouteMLKEMSharedSecret, mlkem768.SharedKeySize)
	assertHexLen("route_server_pq_public_key", first.RouteServerPQPublicKey, mldsa65.PublicKeySize)
	assertHexLen("route_server_prelude_signature_pq", first.RouteServerPreludeSignaturePQ, mldsa65.SignatureSize)
	if first.RoutePreludeEnvelope == "" || first.RoutePrelude0Plaintext == "" || first.RoutePrelude1 == "" || first.RouteClassicalSharedSecret == "" {
		t.Fatalf("route-prelude real crypto vector omitted required fields: %+v", first)
	}
}
