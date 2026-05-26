package vectors

import "testing"

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
