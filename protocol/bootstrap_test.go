package protocol

import (
	"reflect"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestCoverBootstrapMessagesRoundTrip(t *testing.T) {
	p0 := CoverPrelude0{
		MsgType:                     registry.MsgCoverPrelude0,
		Version:                     registry.Version20,
		SuiteOffers:                 []uint64{registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM},
		ClientNonce:                 fill(0x01, 32),
		ClientClassicalEphPub:       []byte("client-ecdh"),
		ClientMLKEMEncapsulationKey: []byte("client-kem"),
		RelayDescriptorHash:         fill(0x02, 48),
		CoverTemplateHash:           fill(0x03, 48),
		RequestClassID:              7,
		HintIssuerID:                fill(0x04, 16),
		RelayBucketID:               fill(0x05, 16),
		HintEpochID:                 1700000000,
		HintSelector:                fill(0x06, 16),
		AccessHint:                  fill(0x07, 16),
		ClientCoverRandom:           fill(0x08, 32),
		Padding:                     []byte("pad"),
		Extensions:                  []Extension{{ExtensionType: 0x7001, Body: []byte("p0")}},
	}
	encodedP0, err := Encode(p0)
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeCoverPrelude0(bytesReader(encodedP0)); !reflect.DeepEqual(got, p0) {
		t.Fatalf("CoverPrelude0 round trip mismatch:\n got=%+v\nwant=%+v", got, p0)
	}

	p1 := CoverPrelude1{
		MsgType:                         registry.MsgCoverPrelude1,
		Version:                         registry.Version20,
		SelectedSuite:                   registry.SuiteHybrid768AESGCM,
		RelayDescriptorHash:             fill(0x09, 48),
		CoverTemplateHash:               fill(0x0a, 48),
		RelayEpochID:                    22,
		ServerNonce:                     fill(0x0b, 32),
		ServerClassicalEphPub:           []byte("server-ecdh"),
		ServerMLKEMCiphertextToClient:   []byte("server-kem"),
		SelectedCoverProfileID:          fill(0x0c, 16),
		SelectedBootstrapEnvelopeID:     fill(0x0d, 16),
		ServerPreludeSignatureClassical: []byte("sig-classical"),
		ServerPreludeSignaturePQ:        []byte("sig-pq"),
		ResponsePadding:                 []byte("response-pad"),
		Extensions:                      []Extension{{ExtensionType: 0x7002, Body: []byte("p1")}},
	}
	encodedP1, err := Encode(p1)
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeCoverPrelude1(bytesReader(encodedP1)); !reflect.DeepEqual(got, p1) {
		t.Fatalf("CoverPrelude1 round trip mismatch:\n got=%+v\nwant=%+v", got, p1)
	}

	c1 := CoverCapsule1Plain{
		MsgType:              registry.MsgCoverCapsule1,
		RouteInstanceID:      33,
		AdmissionProof:       sampleAdmissionProof(),
		ReplayProof:          sampleReplayProof(),
		PolicyOffer:          samplePolicyOffer(),
		ClientTransportHints: sampleClientTransportHints(),
		ClientFinished:       []byte("client-finished"),
		Padding:              []byte("capsule1-pad"),
		Extensions:           []Extension{{ExtensionType: 0x7003, Body: []byte("c1")}},
	}
	encodedC1, err := Encode(c1)
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeCoverCapsule1Plain(bytesReader(encodedC1)); !reflect.DeepEqual(got, c1) {
		t.Fatalf("CoverCapsule1Plain round trip mismatch:\n got=%+v\nwant=%+v", got, c1)
	}

	c2 := CoverCapsule2Plain{
		MsgType:         registry.MsgCoverCapsule2,
		RouteInstanceID: 44,
		PolicyAccept:    samplePolicyAccept(),
		ServerFinished:  []byte("server-finished"),
		Padding:         []byte("capsule2-pad"),
		Extensions:      []Extension{{ExtensionType: 0x7004, Body: []byte("c2")}},
	}
	encodedC2, err := Encode(c2)
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeCoverCapsule2Plain(bytesReader(encodedC2)); !reflect.DeepEqual(got, c2) {
		t.Fatalf("CoverCapsule2Plain round trip mismatch:\n got=%+v\nwant=%+v", got, c2)
	}

	rc1 := RouteCapsule1Plain{
		MsgType:         registry.MsgRouteCapsule1,
		RouteInstanceID: 55,
		HopIndex:        1,
		AdmissionProof:  sampleAdmissionProof(),
		ReplayProof:     sampleReplayProof(),
		PolicyOffer:     samplePolicyOffer(),
		ClientFinished:  []byte("route-client-finished"),
		Padding:         []byte("route-capsule1-pad"),
		Extensions:      []Extension{{ExtensionType: 0x700a, Body: []byte("rc1")}},
	}
	encodedRC1, err := Encode(rc1)
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeRouteCapsule1Plain(bytesReader(encodedRC1)); !reflect.DeepEqual(got, rc1) {
		t.Fatalf("RouteCapsule1Plain round trip mismatch:\n got=%+v\nwant=%+v", got, rc1)
	}

	rc2 := RouteCapsule2Plain{
		MsgType:         registry.MsgRouteCapsule2,
		RouteInstanceID: 66,
		HopIndex:        2,
		PolicyAccept:    samplePolicyAccept(),
		ServerFinished:  []byte("route-server-finished"),
		Padding:         []byte("route-capsule2-pad"),
		Extensions:      []Extension{{ExtensionType: 0x700b, Body: []byte("rc2")}},
	}
	encodedRC2, err := Encode(rc2)
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeRouteCapsule2Plain(bytesReader(encodedRC2)); !reflect.DeepEqual(got, rc2) {
		t.Fatalf("RouteCapsule2Plain round trip mismatch:\n got=%+v\nwant=%+v", got, rc2)
	}
}

func TestVirtualAddressAssignmentWireGrammar(t *testing.T) {
	assignment := VirtualAddressAssignment{
		LeaseID:         fill(0xa0, 16),
		AddressFamily:   1,
		ClientAddress:   []byte{10, 0, 0, 2},
		PrefixLength:    24,
		DNSServerHint:   []byte{9, 9, 9, 9},
		LeaseExpiryUnix: 1700000600,
	}
	encoded, err := Encode(assignment)
	if err != nil {
		t.Fatal(err)
	}
	assertProtocolHex(t, encoded, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a001040a00000218010409090909000000006553f358")
	if got := DecodeVirtualAddressAssignment(bytesReader(encoded)); !reflect.DeepEqual(got, assignment) {
		t.Fatalf("VirtualAddressAssignment round trip mismatch:\n got=%+v\nwant=%+v", got, assignment)
	}
}

func sampleAdmissionProof() AdmissionProof {
	return AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              fill(0x10, 16),
		TokenKeyID:            fill(0x11, 32),
		RelayBucketID:         fill(0x12, 16),
		TokenScopeID:          fill(0x13, 16),
		ExpiryUnix:            1700000600,
		TokenNonce:            fill(0x14, 32),
		RedemptionContextHash: fill(0x15, 48),
		TokenPublicMetadata:   []byte("metadata"),
		TokenAuthenticator:    []byte("authenticator"),
		BindingProof:          []byte("binding"),
		Extensions:            []Extension{{ExtensionType: 0x7005, Body: []byte("admission")}},
	}
}

func sampleReplayProof() ReplayProof {
	return ReplayProof{
		ProofVersion:        registry.Version20,
		ReplayEpochID:       55,
		TokenRedemptionHash: fill(0x16, 48),
		ClientReplayNonce:   fill(0x17, 32),
		ReplayContextHash:   fill(0x18, 48),
		ReplayWindowID:      fill(0x19, 16),
		Extensions:          []Extension{{ExtensionType: 0x7006, Body: []byte("replay")}},
	}
}

func sampleClientTransportHints() ClientTransportHints {
	return ClientTransportHints{
		ObservedPathMTUBucket:  1,
		RecentQUICResult:       2,
		RecentH2Result:         3,
		CongestionClass:        4,
		MaxDatagramPayloadHint: 1200,
		NetworkCohortHint:      []byte("cohort"),
		Padding:                []byte("hint-pad"),
		Extensions:             []Extension{{ExtensionType: 0x7007, Body: []byte("hints")}},
	}
}

func samplePolicyOffer() PolicyOffer {
	return PolicyOffer{
		OfferedVersions:         []uint64{registry.Version20},
		OfferedSuites:           []uint64{registry.SuiteHybrid768AESGCM},
		OfferedMethods:          []uint64{registry.MethodWebH2Stream, registry.MethodWebH1WS},
		MinimumPolicyID:         registry.PolicyFastWeb,
		RequestedPolicyID:       registry.PolicyBalancedWeb,
		RequestedRouteModeID:    registry.RouteSplit2,
		RequestedShapeID:        registry.ShapeNormal,
		TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
		FlowCapabilities:        0x03,
		MaxPaddingOverheadPct:   15,
		Extensions:              []Extension{{ExtensionType: 0x7008, Body: []byte("offer")}},
	}
}

func samplePolicyAccept() PolicyAccept {
	return PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             registry.SuiteHybrid768AESGCM,
		SelectedMethod:            registry.MethodWebH2Stream,
		SelectedPolicy:            registry.PolicyBalancedWeb,
		SelectedRouteModeID:       registry.RouteSplit2,
		SelectedShape:             registry.ShapeNormal,
		SelectedTunnelPersonality: registry.PersonalityProxyFlow,
		FallbackMethods:           []uint64{registry.MethodWebH1WS},
		RetryPolicyID:             4,
		PathValidationPolicyID:    5,
		Extensions:                []Extension{{ExtensionType: 0x7009, Body: []byte("accept")}},
	}
}
