package cover

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/trust"
)

func cb(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func validTemplate(t *testing.T) protocol.CoverTemplate {
	t.Helper()
	tpl := protocol.CoverTemplate{
		TemplateVersion:  registry.Version20,
		TemplateID:       cb(0x01, 16),
		TemplateFamilyID: cb(0x02, 16),
		ValidFromUnix:    100,
		ValidUntilUnix:   300,
		OriginSPKIHash:   cb(0x03, 48),
		PublicNameHash:   cb(0x04, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             1,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      cb(0x05, 16),
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}, {
			ClassID:             2,
			ClassType:           registry.RequestOriginPassThrough,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      cb(0x06, 16),
		}},
		GatewayOwnedSlotCommitments:      [][]byte{cb(0x07, 48)},
		OriginPassThroughSlotCommitments: [][]byte{cb(0x08, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1200,
			MaxRequestBodySize:         1536,
			RequestSizeDistributionID:  cb(0x09, 16),
			MinResponseBodySize:        5000,
			MaxResponseBodySize:        6144,
			ResponseSizeDistributionID: cb(0x0a, 16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               cb(0x0b, 16),
			MaxCapsuleBodySize:       8192,
			BodySizeDistributionID:   cb(0x0c, 16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile: protocol.H2CoverProfile{
			ProfileID:                1,
			RecordSizeDistributionID: cb(0x0d, 16),
		},
		H3Profile: protocol.H3CoverProfile{
			ProfileID:                  2,
			DatagramSizeDistributionID: cb(0x0e, 16),
			DatagramRateDistributionID: cb(0x0f, 16),
		},
		WebSocketProfile: protocol.WebSocketCoverProfile{
			ProfileID:               3,
			FrameSizeDistributionID: cb(0x10, 16),
		},
		CacheCookiePolicy: protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope:    protocol.TimingEnvelope{TimingPolicyID: 5, JitterDistributionID: cb(0x11, 16)},
	}
	commitment, err := trust.CoverOriginCommitment(tpl)
	if err != nil {
		t.Fatal(err)
	}
	tpl.CoverOriginCommitment = commitment
	return tpl
}

func TestValidateTemplateAcceptsGatewayOwnedCarrier(t *testing.T) {
	tpl := validTemplate(t)
	if err := ValidateTemplate(tpl, ValidationOptions{NowUnix: 150, MaxFutureSkew: 120}); err != nil {
		t.Fatalf("valid cover template rejected: %v", err)
	}
	if _, err := SelectGatewayOwnedClass(tpl, 1, true); err != nil {
		t.Fatalf("gateway-owned capsule class not selected: %v", err)
	}
}

func TestValidateTemplateRejectsCarrierWithoutMethodFamily(t *testing.T) {
	tpl := validTemplate(t)
	tpl.RequestClasses[0].AllowedMethodFamily = 0
	refreshOriginCommitment(t, &tpl)
	if err := ValidateTemplate(tpl, ValidationOptions{NowUnix: 150, MaxFutureSkew: 120}); err == nil {
		t.Fatalf("protocol carrier without method family accepted")
	}
}

func TestSelectCarrierClassRequiresMatchingMethodFamily(t *testing.T) {
	tpl := validTemplate(t)
	if _, err := SelectCarrierClass(tpl, 1, registry.MethodWebH1WS, true); err == nil {
		t.Fatalf("web.h1.ws selected an H2-only carrier class")
	}
	tpl.RequestClasses[0].AllowedMethodFamily = registry.MethodWebH1WS
	refreshOriginCommitment(t, &tpl)
	class, err := SelectCarrierClass(tpl, 1, registry.MethodWebH1WS, true)
	if err != nil {
		t.Fatalf("matching method family rejected: %v", err)
	}
	if class.AllowedMethodFamily != registry.MethodWebH1WS {
		t.Fatalf("unexpected carrier class selected: %+v", class)
	}
}

func TestValidateTemplateAcceptsSidecarShadowOriginCarrier(t *testing.T) {
	tpl := validTemplate(t)
	tpl.RequestClasses[0].ClassType = registry.RequestSidecarOriginSlot
	tpl.RequestClasses[0].AllowedMethodFamily = registry.MethodShadowOrigin
	refreshOriginCommitment(t, &tpl)
	if err := ValidateTemplate(tpl, ValidationOptions{NowUnix: 150, MaxFutureSkew: 120}); err != nil {
		t.Fatalf("sidecar shadow-origin carrier rejected: %v", err)
	}
}

func TestSelectCarrierClassAllowsSidecarForShadowOrigin(t *testing.T) {
	tpl := validTemplate(t)
	tpl.RequestClasses = append(tpl.RequestClasses, protocol.RequestClass{
		ClassID:             3,
		ClassType:           registry.RequestSidecarOriginSlot,
		AllowedMethodFamily: registry.MethodShadowOrigin,
		PathTemplateID:      cb(0x12, 16),
		MayCarryPrelude:     true,
		MayCarryCapsule:     true,
	})
	refreshOriginCommitment(t, &tpl)
	class, err := SelectCarrierClass(tpl, 3, registry.MethodShadowOrigin, true)
	if err != nil {
		t.Fatalf("sidecar shadow-origin carrier not selected: %v", err)
	}
	if class.ClassType != registry.RequestSidecarOriginSlot {
		t.Fatalf("selected wrong class type: %+v", class)
	}
}

func TestValidateTemplateRejectsOriginPassThroughProtocolMaterial(t *testing.T) {
	tpl := validTemplate(t)
	tpl.RequestClasses[1].MayCarryPrelude = true
	if err := ValidateTemplate(tpl, ValidationOptions{NowUnix: 150, MaxFutureSkew: 120}); err == nil {
		t.Fatalf("origin pass-through protocol material accepted")
	}
}

func TestValidateTemplateRejectsUnknownRequestClassType(t *testing.T) {
	tpl := validTemplate(t)
	tpl.RequestClasses = append(tpl.RequestClasses, protocol.RequestClass{
		ClassID:             3,
		ClassType:           0xff,
		AllowedMethodFamily: registry.MethodWebH2Stream,
		PathTemplateID:      cb(0x13, 16),
	})
	refreshOriginCommitment(t, &tpl)
	if err := ValidateTemplate(tpl, ValidationOptions{NowUnix: 150, MaxFutureSkew: 120}); err == nil {
		t.Fatalf("unknown request class type accepted")
	}
}

func TestValidateTemplateRejectsForwardableFailedCapsules(t *testing.T) {
	tpl := validTemplate(t)
	tpl.CapsuleEnvelope.ConsumeFailedBodyLocally = false
	commitment, err := trust.CoverOriginCommitment(tpl)
	if err != nil {
		t.Fatal(err)
	}
	tpl.CoverOriginCommitment = commitment
	if err := ValidateTemplate(tpl, ValidationOptions{NowUnix: 150, MaxFutureSkew: 120}); err == nil {
		t.Fatalf("gateway-owned capsule without local failure consumption accepted")
	}
}

func TestValidateTemplateRejectsOriginCommitmentMismatch(t *testing.T) {
	tpl := validTemplate(t)
	tpl.CoverOriginCommitment = cb(0xee, 48)
	if err := ValidateTemplate(tpl, ValidationOptions{NowUnix: 150, MaxFutureSkew: 120}); err == nil {
		t.Fatalf("cover origin commitment mismatch accepted")
	}
}

func refreshOriginCommitment(t *testing.T, tpl *protocol.CoverTemplate) {
	t.Helper()
	commitment, err := trust.CoverOriginCommitment(*tpl)
	if err != nil {
		t.Fatal(err)
	}
	tpl.CoverOriginCommitment = commitment
}
