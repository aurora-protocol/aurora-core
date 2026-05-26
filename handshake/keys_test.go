package handshake

import (
	"bytes"
	"testing"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

func hx(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestDeriveHandshakeSecretsBindsContext(t *testing.T) {
	a, err := DeriveHandshakeSecrets(registry.SuiteHybrid768AESGCM, hx(1, 32), hx(2, 32), hx(3, 48), hx(4, 48))
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveHandshakeSecrets(registry.SuiteHybrid768AESGCM, hx(1, 32), hx(2, 32), hx(9, 48), hx(4, 48))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.ClientHSKey) != 32 || len(a.ClientHSIV) != 12 || len(a.ClientFinishedKey) != 48 {
		t.Fatalf("unexpected key lengths: %+v", a)
	}
	if bytes.Equal(a.HandshakeSecret, b.HandshakeSecret) {
		t.Fatalf("handshake secret did not bind handshake context")
	}
}

func TestCoverStreamBindingMatchesCanonicalPreimage(t *testing.T) {
	in := CoverStreamBindingInput{
		OuterExporterValue:       hx(0x11, 48),
		HTTPVersion:              []byte("h2"),
		ConnectionIDHash:         hx(0x12, 48),
		StreamIDOrRequestID:      7,
		MethodFamilyID:           registry.MethodWebH2Stream,
		NormalizedAuthorityHash:  hx(0x13, 48),
		NormalizedPathTemplateID: hx(0x14, 16),
		RequestClassID:           3,
		ClientCoverRandom:        hx(0x15, 32),
	}
	got, err := CoverStreamBinding(in)
	if err != nil {
		t.Fatal(err)
	}
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 cover stream binding"))
	e.WriteOpaqueFixed(in.OuterExporterValue, 48)
	e.WriteOpaque8(in.HTTPVersion)
	e.WritePreHash(in.ConnectionIDHash)
	e.WriteVarint(in.StreamIDOrRequestID)
	e.WriteVarint(in.MethodFamilyID)
	e.WritePreHash(in.NormalizedAuthorityHash)
	e.WriteOpaqueFixed(in.NormalizedPathTemplateID, 16)
	e.WriteVarint(in.RequestClassID)
	e.WriteOpaqueFixed(in.ClientCoverRandom, 32)
	preimage, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := auroracrypto.PreHash(preimage)
	if !bytes.Equal(got, want) {
		t.Fatalf("cover stream binding mismatch\n got %x\nwant %x", got, want)
	}
	in.RequestClassID = 4
	changed, err := CoverStreamBinding(in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, changed) {
		t.Fatalf("cover stream binding did not bind request class")
	}
}

func TestFirstHopBindingContextFeedsHandshakeSecrets(t *testing.T) {
	coverBinding, err := CoverStreamBinding(CoverStreamBindingInput{
		OuterExporterValue:       hx(0x21, 48),
		HTTPVersion:              []byte("h2"),
		ConnectionIDHash:         hx(0x22, 48),
		StreamIDOrRequestID:      5,
		MethodFamilyID:           registry.MethodWebH2Stream,
		NormalizedAuthorityHash:  hx(0x23, 48),
		NormalizedPathTemplateID: hx(0x24, 16),
		RequestClassID:           1,
		ClientCoverRandom:        hx(0x25, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := FirstHopBindingContext(hx(0x21, 48), coverBinding)
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx) != 48 {
		t.Fatalf("first-hop binding length = %d", len(ctx))
	}
	a, err := DeriveHandshakeSecrets(registry.SuiteHybrid768AESGCM, hx(1, 32), hx(2, 32), ctx, hx(4, 48))
	if err != nil {
		t.Fatal(err)
	}
	changedCtx, err := FirstHopBindingContext(hx(0x99, 48), coverBinding)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveHandshakeSecrets(registry.SuiteHybrid768AESGCM, hx(1, 32), hx(2, 32), changedCtx, hx(4, 48))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.HandshakeSecret, b.HandshakeSecret) {
		t.Fatalf("handshake secret did not bind first-hop context")
	}
}

func TestFinishedAndApplicationSecrets(t *testing.T) {
	secrets, err := DeriveHandshakeSecrets(registry.SuiteHybrid768AESGCM, hx(1, 32), hx(2, 32), hx(3, 48), hx(4, 48))
	if err != nil {
		t.Fatal(err)
	}
	capsule1 := protocol.CoverCapsule1Plain{
		MsgType:         registry.MsgCoverCapsule1,
		RouteInstanceID: 5,
		AdmissionProof: protocol.AdmissionProof{
			ProofVersion:          registry.Version20,
			ProofType:             registry.ProofLabStaticToken,
			IssuerID:              hx(1, 16),
			TokenKeyID:            hx(2, 32),
			RelayBucketID:         hx(3, 16),
			TokenScopeID:          hx(4, 16),
			ExpiryUnix:            2000000000,
			TokenNonce:            hx(5, 32),
			RedemptionContextHash: hx(6, 48),
			TokenAuthenticator:    []byte("token"),
		},
		ReplayProof: protocol.ReplayProof{
			ProofVersion:        registry.Version20,
			ReplayEpochID:       1,
			TokenRedemptionHash: hx(7, 48),
			ClientReplayNonce:   hx(8, 32),
			ReplayContextHash:   hx(9, 48),
			ReplayWindowID:      hx(10, 16),
		},
		PolicyOffer: protocol.PolicyOffer{
			OfferedVersions:         []uint64{registry.Version20},
			OfferedSuites:           []uint64{registry.SuiteHybrid768AESGCM},
			OfferedMethods:          []uint64{registry.MethodWebH2Stream},
			MinimumPolicyID:         registry.PolicyAdversarialDPI,
			RequestedPolicyID:       registry.PolicyAdversarialDPI,
			RequestedRouteModeID:    registry.RouteSplit2,
			RequestedShapeID:        registry.ShapeNormal,
			TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
		},
	}
	clientFinished, err := ComputeClientFinished(registry.SuiteHybrid768AESGCM, secrets.ClientFinishedKey, hx(4, 48), capsule1)
	if err != nil {
		t.Fatal(err)
	}
	capsule1.ClientFinished = clientFinished
	accept := protocol.PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             registry.SuiteHybrid768AESGCM,
		SelectedMethod:            registry.MethodWebH2Stream,
		SelectedPolicy:            registry.PolicyAdversarialDPI,
		SelectedRouteModeID:       registry.RouteSplit2,
		SelectedShape:             registry.ShapeNormal,
		SelectedTunnelPersonality: registry.PersonalityProxyFlow,
	}
	serverFinished, capsuleHash, policyHash, err := ComputeServerFinished(registry.SuiteHybrid768AESGCM, secrets.ServerFinishedKey, hx(4, 48), capsule1, accept)
	if err != nil {
		t.Fatal(err)
	}
	app, err := DeriveApplicationSecrets(registry.SuiteHybrid768AESGCM, secrets.HandshakeSecret, hx(4, 48), capsuleHash, policyHash, serverFinished)
	if err != nil {
		t.Fatal(err)
	}
	if len(serverFinished) != 48 || len(app.ClientAppKey0) != 32 || len(app.ServerAppIV0) != 12 {
		t.Fatalf("unexpected derived lengths")
	}

	capsule1.Padding = []byte{1}
	changed, err := ComputeClientFinished(registry.SuiteHybrid768AESGCM, secrets.ClientFinishedKey, hx(4, 48), capsule1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(clientFinished, changed) {
		t.Fatalf("client finished did not bind capsule plaintext")
	}
}

func TestComputeServerFinishedRejectsPolicyAcceptVirtualAddressMismatch(t *testing.T) {
	capsule1 := protocol.CoverCapsule1Plain{
		MsgType:         registry.MsgCoverCapsule1,
		RouteInstanceID: 5,
		AdmissionProof: protocol.AdmissionProof{
			ProofVersion:          registry.Version20,
			ProofType:             registry.ProofLabStaticToken,
			IssuerID:              hx(1, 16),
			TokenKeyID:            hx(2, 32),
			RelayBucketID:         hx(3, 16),
			TokenScopeID:          hx(4, 16),
			ExpiryUnix:            2000000000,
			TokenNonce:            hx(5, 32),
			RedemptionContextHash: hx(6, 48),
			TokenAuthenticator:    []byte("token"),
		},
		ReplayProof: protocol.ReplayProof{
			ProofVersion:        registry.Version20,
			ReplayEpochID:       1,
			TokenRedemptionHash: hx(7, 48),
			ClientReplayNonce:   hx(8, 32),
			ReplayContextHash:   hx(9, 48),
			ReplayWindowID:      hx(10, 16),
		},
	}
	accept := protocol.PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             registry.SuiteHybrid768AESGCM,
		SelectedMethod:            registry.MethodWebH2Stream,
		SelectedPolicy:            registry.PolicyBalancedWeb,
		SelectedRouteModeID:       registry.RouteFast1,
		SelectedShape:             registry.ShapeNormal,
		SelectedTunnelPersonality: registry.PersonalityProxyFlow,
		VirtualAddressAssignment: &protocol.VirtualAddressAssignment{
			LeaseID:         hx(0xaa, 16),
			AddressFamily:   1,
			ClientAddress:   []byte{10, 0, 0, 2},
			PrefixLength:    24,
			LeaseExpiryUnix: 2000000600,
		},
	}
	if _, _, _, err := ComputeServerFinished(registry.SuiteHybrid768AESGCM, hx(0x33, 48), hx(0x44, 48), capsule1, accept); err == nil {
		t.Fatalf("proxy-flow PolicyAccept with virtual address assignment was signed")
	}

	accept.SelectedTunnelPersonality = registry.PersonalityIPLite
	accept.VirtualAddressAssignment = nil
	if _, _, _, err := ComputeServerFinished(registry.SuiteHybrid768AESGCM, hx(0x33, 48), hx(0x44, 48), capsule1, accept); err == nil {
		t.Fatalf("ip-lite PolicyAccept without virtual address assignment was signed")
	}
}

func TestComputeServerFinishedRejectsPolicyAcceptOutsideOffer(t *testing.T) {
	capsule1 := protocol.CoverCapsule1Plain{
		MsgType:         registry.MsgCoverCapsule1,
		RouteInstanceID: 5,
		AdmissionProof: protocol.AdmissionProof{
			ProofVersion:          registry.Version20,
			ProofType:             registry.ProofLabStaticToken,
			IssuerID:              hx(1, 16),
			TokenKeyID:            hx(2, 32),
			RelayBucketID:         hx(3, 16),
			TokenScopeID:          hx(4, 16),
			ExpiryUnix:            2000000000,
			TokenNonce:            hx(5, 32),
			RedemptionContextHash: hx(6, 48),
			TokenAuthenticator:    []byte("token"),
		},
		ReplayProof: protocol.ReplayProof{
			ProofVersion:        registry.Version20,
			ReplayEpochID:       1,
			TokenRedemptionHash: hx(7, 48),
			ClientReplayNonce:   hx(8, 32),
			ReplayContextHash:   hx(9, 48),
			ReplayWindowID:      hx(10, 16),
		},
		PolicyOffer: protocol.PolicyOffer{
			OfferedVersions:         []uint64{registry.Version20},
			OfferedSuites:           []uint64{registry.SuiteHybrid768AESGCM},
			OfferedMethods:          []uint64{registry.MethodWebH2Stream},
			MinimumPolicyID:         registry.PolicyAdversarialDPI,
			RequestedPolicyID:       registry.PolicyAdversarialDPI,
			RequestedRouteModeID:    registry.RouteSplit2,
			RequestedShapeID:        registry.ShapeNormal,
			TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
		},
	}
	base := protocol.PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             registry.SuiteHybrid768AESGCM,
		SelectedMethod:            registry.MethodWebH2Stream,
		SelectedPolicy:            registry.PolicyAdversarialDPI,
		SelectedRouteModeID:       registry.RouteSplit2,
		SelectedShape:             registry.ShapeNormal,
		SelectedTunnelPersonality: registry.PersonalityProxyFlow,
	}
	cases := map[string]func(*protocol.PolicyAccept){
		"version": func(accept *protocol.PolicyAccept) {
			accept.SelectedVersion = 0x000199
		},
		"suite": func(accept *protocol.PolicyAccept) {
			accept.SelectedSuite = registry.SuiteHybrid1024AESGCM
		},
		"method": func(accept *protocol.PolicyAccept) {
			accept.SelectedMethod = registry.MethodWebH1WS
		},
		"policy": func(accept *protocol.PolicyAccept) {
			accept.SelectedPolicy = registry.PolicyFastWeb
		},
		"personality": func(accept *protocol.PolicyAccept) {
			accept.SelectedTunnelPersonality = registry.PersonalityIPLite
			accept.VirtualAddressAssignment = &protocol.VirtualAddressAssignment{
				LeaseID:         hx(0xab, 16),
				AddressFamily:   1,
				ClientAddress:   []byte{10, 0, 0, 2},
				PrefixLength:    24,
				LeaseExpiryUnix: 2000000600,
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			accept := base
			mutate(&accept)
			if _, _, _, err := ComputeServerFinished(registry.SuiteHybrid768AESGCM, hx(0x33, 48), hx(0x44, 48), capsule1, accept); err == nil {
				t.Fatalf("PolicyAccept with non-offered %s was signed: %+v", name, accept)
			}
		})
	}
}

func TestRouteCapsuleFinishedUsesHopTranscript(t *testing.T) {
	hopTranscript := hx(0x44, 48)
	secrets, err := DeriveHandshakeSecrets(registry.SuiteHybrid768AESGCM, hx(1, 32), hx(2, 32), hx(0x43, 48), hopTranscript)
	if err != nil {
		t.Fatal(err)
	}
	capsule1 := protocol.RouteCapsule1Plain{
		MsgType:         registry.MsgRouteCapsule1,
		RouteInstanceID: 77,
		HopIndex:        1,
		AdmissionProof: protocol.AdmissionProof{
			ProofVersion:          registry.Version20,
			ProofType:             registry.ProofLabStaticToken,
			IssuerID:              hx(1, 16),
			TokenKeyID:            hx(2, 32),
			RelayBucketID:         hx(3, 16),
			TokenScopeID:          hx(4, 16),
			ExpiryUnix:            2000000000,
			TokenNonce:            hx(5, 32),
			RedemptionContextHash: hx(6, 48),
			TokenAuthenticator:    []byte("token"),
		},
		ReplayProof: protocol.ReplayProof{
			ProofVersion:        registry.Version20,
			ReplayEpochID:       1,
			TokenRedemptionHash: hx(7, 48),
			ClientReplayNonce:   hx(8, 32),
			ReplayContextHash:   hx(9, 48),
			ReplayWindowID:      hx(10, 16),
		},
		PolicyOffer: protocol.PolicyOffer{
			OfferedVersions:         []uint64{registry.Version20},
			OfferedSuites:           []uint64{registry.SuiteHybrid768AESGCM},
			OfferedMethods:          []uint64{registry.MethodWebH2Stream},
			MinimumPolicyID:         registry.PolicyAdversarialDPI,
			RequestedPolicyID:       registry.PolicyAdversarialDPI,
			RequestedRouteModeID:    registry.RouteSplit2,
			RequestedShapeID:        registry.ShapeNormal,
			TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
		},
	}
	clientFinished, err := ComputeRouteClientFinished(registry.SuiteHybrid768AESGCM, secrets.ClientFinishedKey, hopTranscript, capsule1)
	if err != nil {
		t.Fatal(err)
	}
	capsule1.ClientFinished = clientFinished
	accept := protocol.PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             registry.SuiteHybrid768AESGCM,
		SelectedMethod:            registry.MethodWebH2Stream,
		SelectedPolicy:            registry.PolicyAdversarialDPI,
		SelectedRouteModeID:       registry.RouteSplit2,
		SelectedShape:             registry.ShapeNormal,
		SelectedTunnelPersonality: registry.PersonalityProxyFlow,
	}
	serverFinished, capsuleHash, policyHash, err := ComputeRouteServerFinished(registry.SuiteHybrid768AESGCM, secrets.ServerFinishedKey, hopTranscript, capsule1, accept)
	if err != nil {
		t.Fatal(err)
	}
	app, err := DeriveApplicationSecrets(registry.SuiteHybrid768AESGCM, secrets.HandshakeSecret, hopTranscript, capsuleHash, policyHash, serverFinished)
	if err != nil {
		t.Fatal(err)
	}
	if len(clientFinished) != 48 || len(serverFinished) != 48 || len(app.ClientAppKey0) != 32 {
		t.Fatalf("unexpected route secret lengths")
	}
	changedTranscriptFinished, _, _, err := ComputeRouteServerFinished(registry.SuiteHybrid768AESGCM, secrets.ServerFinishedKey, hx(0x45, 48), capsule1, accept)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(serverFinished, changedTranscriptFinished) {
		t.Fatalf("route server finished did not bind hop transcript")
	}
	capsule1.Padding = []byte{1}
	changedClientFinished, err := ComputeRouteClientFinished(registry.SuiteHybrid768AESGCM, secrets.ClientFinishedKey, hopTranscript, capsule1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(clientFinished, changedClientFinished) {
		t.Fatalf("route client finished did not bind route capsule plaintext")
	}
}
