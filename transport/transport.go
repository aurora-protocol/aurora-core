package transport

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/registry"
)

type Capabilities struct {
	SupportsH2      bool
	SupportsH1WS    bool
	SupportsShadow  bool
	SupportsH3      bool
	SupportsH3Dgram bool
	H3Validated     bool
	WebTransportOK  bool
	CoverTemplateOK bool
	MASQUEAllowed   bool
}

type Carrier struct {
	MethodID uint64
	Name     string
}

type UDPMode uint8

const (
	UDPUnsupported UDPMode = iota
	UDPOverStreamFallback
	UDPNativeDatagram
)

type CarrierPlan struct {
	Carrier              Carrier
	UDPMode              UDPMode
	PerformanceDowngrade bool
}

func SelectCarrier(profile policy.Profile, caps Capabilities) (Carrier, error) {
	for _, method := range profile.MethodOrder {
		if IsMethodAllowed(profile, method, caps) {
			return Carrier{MethodID: method, Name: methodName(method)}, nil
		}
	}
	return Carrier{}, fmt.Errorf("transport: no carrier passes policy gates")
}

func SelectCarrierPlan(profile policy.Profile, caps Capabilities) (CarrierPlan, error) {
	carrier, err := SelectCarrier(profile, caps)
	if err != nil {
		return CarrierPlan{}, err
	}
	udpMode, downgrade := udpModeForMethod(carrier.MethodID)
	return CarrierPlan{
		Carrier:              carrier,
		UDPMode:              udpMode,
		PerformanceDowngrade: downgrade,
	}, nil
}

func IsMethodAllowed(profile policy.Profile, method uint64, caps Capabilities) bool {
	if !caps.CoverTemplateOK && method != registry.MethodDirectQUICLab {
		return false
	}
	switch method {
	case registry.MethodWebH2Stream:
		return caps.SupportsH2
	case registry.MethodWebH1WS:
		return caps.SupportsH1WS
	case registry.MethodShadowOrigin:
		return caps.SupportsShadow
	case registry.MethodWebH3Stream:
		if profile.QUIC == policy.QUICDisabled {
			return false
		}
		if profile.StealthGate && !caps.H3Validated {
			return false
		}
		return caps.SupportsH3
	case registry.MethodWebH3ExtDgram:
		if profile.QUIC == policy.QUICDisabled {
			return false
		}
		if profile.StealthGate && !caps.H3Validated {
			return false
		}
		return caps.SupportsH3 && caps.SupportsH3Dgram && caps.WebTransportOK
	case registry.MethodMasqueConnectIP, registry.MethodMasqueConnectUDP:
		return !profile.StealthGate && caps.MASQUEAllowed
	case registry.MethodDirectQUICLab:
		return profile.LabOnly
	default:
		return false
	}
}

func udpModeForMethod(method uint64) (UDPMode, bool) {
	switch method {
	case registry.MethodWebH3ExtDgram, registry.MethodMasqueConnectUDP, registry.MethodDirectQUICLab:
		return UDPNativeDatagram, false
	case registry.MethodWebH2Stream, registry.MethodWebH1WS, registry.MethodShadowOrigin, registry.MethodWebH3Stream:
		return UDPOverStreamFallback, true
	default:
		return UDPUnsupported, true
	}
}

func methodName(method uint64) string {
	switch method {
	case registry.MethodWebH2Stream:
		return "web.h2.stream"
	case registry.MethodWebH1WS:
		return "web.h1.ws"
	case registry.MethodShadowOrigin:
		return "web.shadow-origin"
	case registry.MethodWebH3Stream:
		return "web.h3.stream"
	case registry.MethodWebH3ExtDgram:
		return "web.h3.ext-dgram"
	case registry.MethodMasqueConnectIP:
		return "masque.connect-ip"
	case registry.MethodMasqueConnectUDP:
		return "masque.connect-udp"
	case registry.MethodDirectQUICLab:
		return "direct.quic"
	default:
		return "unknown"
	}
}
