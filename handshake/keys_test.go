package handshake

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
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
