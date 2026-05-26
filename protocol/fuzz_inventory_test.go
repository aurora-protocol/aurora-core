package protocol

import "testing"

func TestDecodeFuzzTargetsCoverProtocolStructs(t *testing.T) {
	want := []string{
		"PublicKeyRecord",
		"AuthorityKeyRecord",
		"ObjectSignature",
		"TokenVerificationKeyRecord",
		"SignatureEntry",
		"DirectoryConsensus",
		"RoutingRecord",
		"RelayDescriptor",
		"RequestClass",
		"PreludeEnvelope",
		"CapsuleEnvelope",
		"H2CoverProfile",
		"H3CoverProfile",
		"WebSocketCoverProfile",
		"CacheCookiePolicy",
		"TimingEnvelope",
		"CoverTemplate",
		"IssuerTokenKeyRecord",
		"OriginInfoPolicy",
		"RelayBucketScope",
		"AuxiliaryBindingPolicy",
		"IssuerVerifierServiceRecord",
		"IssuerMetadata",
		"IssuerVerifierRequest",
		"IssuerVerifierResponse",
		"AdmissionProof",
		"AuroraTokenMetadata",
		"ReplayProof",
		"ClientTransportHints",
		"PolicyOffer",
		"VirtualAddressAssignment",
		"PolicyAccept",
		"CoverPrelude0",
		"CoverPrelude1",
		"CoverCapsule1Plain",
		"CoverCapsule2Plain",
		"RouteCapsule1Plain",
		"RouteCapsule2Plain",
		"RoutePrelude1",
		"AuroraFrame",
		"FrameBlock",
		"KeyUpdate",
		"KeyUpdateACK",
		"KeyUpdateRequest",
		"FlowOpen",
		"UDPTargetConfirm",
		"FlowClose",
		"RouteForwardFrame",
		"RoutePreludeEnvelope",
	}

	got := DecodeFuzzTargetNames()
	seen := make(map[string]bool, len(got))
	for _, name := range got {
		if seen[name] {
			t.Fatalf("duplicate fuzz target %q", name)
		}
		seen[name] = true
	}
	for _, name := range want {
		if !seen[name] {
			t.Fatalf("missing decode fuzz target %q; got %v", name, got)
		}
	}
}
