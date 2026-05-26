package transport

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestCarrierSelectionUsesH2BaselineBeforeH3UnderAdversarialProfile(t *testing.T) {
	profile, _ := policy.ProfileByID(registry.PolicyAdversarialDPI)
	caps := Capabilities{
		SupportsH2:      true,
		SupportsH1WS:    true,
		SupportsH3:      true,
		SupportsH3Dgram: true,
		H3Validated:     false,
		CoverTemplateOK: true,
	}
	carrier, err := SelectCarrier(profile, caps)
	if err != nil {
		t.Fatal(err)
	}
	if carrier.MethodID != registry.MethodWebH2Stream {
		t.Fatalf("expected h2 stream baseline, got 0x%x", carrier.MethodID)
	}
}

func TestMasqueRejectedUnderAdversarialProfile(t *testing.T) {
	profile, _ := policy.ProfileByID(registry.PolicyAdversarialDPI)
	if IsMethodAllowed(profile, registry.MethodMasqueConnectIP, Capabilities{CoverTemplateOK: true}) {
		t.Fatalf("MASQUE must not be allowed under adversarial policies")
	}
}

func TestH3ExtDgramRequiresValidation(t *testing.T) {
	profile, _ := policy.ProfileByID(registry.PolicyAdversarialDPI)
	if IsMethodAllowed(profile, registry.MethodWebH3ExtDgram, Capabilities{SupportsH3: true, SupportsH3Dgram: true, H3Validated: false, CoverTemplateOK: true}) {
		t.Fatalf("H3 ext datagram must be validation-gated")
	}
	if IsMethodAllowed(profile, registry.MethodWebH3ExtDgram, Capabilities{SupportsH3: true, SupportsH3Dgram: true, H3Validated: true, WebTransportOK: false, CoverTemplateOK: true}) {
		t.Fatalf("H3 ext datagram must require WebTransport capability validation")
	}
	if !IsMethodAllowed(profile, registry.MethodWebH3ExtDgram, Capabilities{SupportsH3: true, SupportsH3Dgram: true, H3Validated: true, WebTransportOK: true, CoverTemplateOK: true}) {
		t.Fatalf("validated H3 ext datagram should be allowed")
	}
}
