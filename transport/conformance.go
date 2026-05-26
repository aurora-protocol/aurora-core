package transport

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

type CarrierConformanceCase struct {
	Name   string
	Passed bool
	Method string
	Detail string
}

type CarrierConformanceReport struct {
	Passed   bool
	Cases    []CarrierConformanceCase
	Findings []string
}

func RunCarrierConformance() (CarrierConformanceReport, error) {
	report := CarrierConformanceReport{Passed: true}
	if err := addH2BaselineCase(&report); err != nil {
		return CarrierConformanceReport{}, err
	}
	if err := addH1FallbackCase(&report); err != nil {
		return CarrierConformanceReport{}, err
	}
	if err := addShadowOriginSlotCase(&report); err != nil {
		return CarrierConformanceReport{}, err
	}
	if err := addH3ExtDatagramCase(&report); err != nil {
		return CarrierConformanceReport{}, err
	}
	if err := addMasqueVisibleOptInCase(&report); err != nil {
		return CarrierConformanceReport{}, err
	}
	if err := addSharedOpaqueCorePathCase(&report); err != nil {
		return CarrierConformanceReport{}, err
	}
	return report, nil
}

func (r *CarrierConformanceReport) addCase(name string, passed bool, method, detail string) {
	r.Cases = append(r.Cases, CarrierConformanceCase{
		Name:   name,
		Passed: passed,
		Method: method,
		Detail: detail,
	})
	if !passed {
		r.Passed = false
		r.Findings = append(r.Findings, name+" failed")
	}
}

func addH2BaselineCase(report *CarrierConformanceReport) error {
	profile, err := policy.ProfileByID(registry.PolicyAdversarialDPI)
	if err != nil {
		return err
	}
	plan, err := SelectCarrierPlan(profile, Capabilities{
		SupportsH2:      true,
		SupportsH1WS:    true,
		SupportsShadow:  true,
		SupportsH3:      true,
		SupportsH3Dgram: true,
		H3Validated:     true,
		WebTransportOK:  true,
		CoverTemplateOK: true,
	})
	if err != nil {
		return err
	}
	report.addCase(
		"h2_baseline_first",
		plan.Carrier.MethodID == registry.MethodWebH2Stream && plan.UDPMode == UDPOverStreamFallback,
		methodName(plan.Carrier.MethodID),
		"adversarial profile selects mandatory H2 baseline before lower-priority carriers",
	)
	return nil
}

func addH1FallbackCase(report *CarrierConformanceReport) error {
	profile, err := policy.ProfileByID(registry.PolicyAdversarialDPI)
	if err != nil {
		return err
	}
	plan, err := SelectCarrierPlan(profile, Capabilities{
		SupportsH1WS:    true,
		SupportsShadow:  true,
		SupportsH3:      true,
		SupportsH3Dgram: true,
		H3Validated:     true,
		WebTransportOK:  true,
		CoverTemplateOK: true,
	})
	if err != nil {
		return err
	}
	report.addCase(
		"h1_websocket_fallback",
		plan.Carrier.MethodID == registry.MethodWebH1WS && plan.UDPMode == UDPOverStreamFallback,
		methodName(plan.Carrier.MethodID),
		"H1 WebSocket is selected only after H2 is unavailable",
	)
	return nil
}

func addShadowOriginSlotCase(report *CarrierConformanceReport) error {
	plan := CarrierPlan{
		Carrier: Carrier{MethodID: registry.MethodShadowOrigin, Name: methodName(registry.MethodShadowOrigin)},
		UDPMode: UDPOverStreamFallback,
	}
	built, err := BuildCarrierRequest(CarrierRequestInput{
		Plan:           plan,
		Template:       conformanceTemplate(registry.MethodShadowOrigin, registry.RequestSidecarOriginSlot),
		RequestClassID: 1,
		NeedCapsule:    true,
		Scheme:         "https",
		Authority:      "origin.example",
		Path:           "/upload/media",
		Header:         http.Header{"Content-Type": []string{"application/octet-stream"}},
		Payload:        []byte{0x31, 0x32},
	})
	if err != nil {
		return err
	}
	report.addCase(
		"shadow_origin_slot",
		built.MethodID == registry.MethodShadowOrigin && built.StreamFallback && !built.NativeDatagrams,
		methodName(built.MethodID),
		"shadow-origin requires a private sidecar slot and keeps UDP on the stream path",
	)
	return nil
}

func addH3ExtDatagramCase(report *CarrierConformanceReport) error {
	profile, err := policy.ProfileByID(registry.PolicyFastWeb)
	if err != nil {
		return err
	}
	plan, err := SelectCarrierPlan(profile, Capabilities{
		SupportsH3:      true,
		SupportsH3Dgram: true,
		H3Validated:     true,
		WebTransportOK:  true,
		CoverTemplateOK: true,
	})
	if err != nil {
		return err
	}
	tpl := h3ConformanceTemplate()
	in := CarrierRequestInput{
		Plan:                     plan,
		Template:                 tpl,
		RequestClassID:           1,
		NeedCapsule:              true,
		Scheme:                   "https",
		Authority:                "cover.example",
		Path:                     "/session/42",
		Payload:                  []byte{0x41},
		H3DatagramSettingsOK:     true,
		QUICMaxDatagramFrameSize: 1200,
	}
	built, err := BuildCarrierRequest(in)
	if err != nil {
		return err
	}
	in.H3DatagramSettingsOK = false
	_, missingSettingsErr := BuildCarrierRequest(in)
	report.addCase(
		"h3_ext_datagram_gated",
		plan.Carrier.MethodID == registry.MethodWebH3ExtDgram &&
			built.NativeDatagrams &&
			!built.StreamFallback &&
			missingSettingsErr != nil,
		methodName(plan.Carrier.MethodID),
		"H3 extended datagrams require validated WebTransport and negotiated datagram settings",
	)
	return nil
}

func addMasqueVisibleOptInCase(report *CarrierConformanceReport) error {
	fast, err := policy.ProfileByID(registry.PolicyFastWeb)
	if err != nil {
		return err
	}
	balanced, err := policy.ProfileByID(registry.PolicyBalancedWeb)
	if err != nil {
		return err
	}
	lab, err := policy.ProfileByID(registry.PolicyLab)
	if err != nil {
		return err
	}
	enterprise := policy.Profile{Name: "enterprise", VisibleProxySemanticsAllowed: true}
	plan := CarrierPlan{Carrier: Carrier{MethodID: registry.MethodMasqueConnectUDP, Name: methodName(registry.MethodMasqueConnectUDP)}, UDPMode: UDPNativeDatagram}
	tpl := conformanceTemplate(registry.MethodMasqueConnectUDP, registry.RequestGatewayOwnedSlot)
	_, withoutOptInErr := BuildCarrierRequest(masqueConformanceInput(plan, tpl, false))
	built, withOptInErr := BuildCarrierRequest(masqueConformanceInput(plan, tpl, true))
	passed := IsMethodAllowed(fast, registry.MethodMasqueConnectUDP, Capabilities{CoverTemplateOK: true, MASQUEAllowed: true}) &&
		IsMethodAllowed(lab, registry.MethodMasqueConnectIP, Capabilities{CoverTemplateOK: true, MASQUEAllowed: true}) &&
		IsMethodAllowed(enterprise, registry.MethodMasqueConnectUDP, Capabilities{CoverTemplateOK: true, MASQUEAllowed: true}) &&
		!IsMethodAllowed(balanced, registry.MethodMasqueConnectUDP, Capabilities{CoverTemplateOK: true, MASQUEAllowed: true}) &&
		withoutOptInErr != nil &&
		withOptInErr == nil &&
		built.NativeDatagrams
	report.addCase(
		"masque_visible_opt_in",
		passed,
		methodName(registry.MethodMasqueConnectUDP),
		"MASQUE is limited to allowed non-stealth profiles and requires explicit visible proxy opt-in",
	)
	return nil
}

func addSharedOpaqueCorePathCase(report *CarrierConformanceReport) error {
	payload := []byte{0x90, 0x91, 0x92}
	h2, err := NewCarrierSession(BuiltCarrierRequest{MethodID: registry.MethodWebH2Stream, StreamFallback: true})
	if err != nil {
		return err
	}
	h1, err := NewCarrierSession(BuiltCarrierRequest{MethodID: registry.MethodWebH1WS, StreamFallback: true})
	if err != nil {
		return err
	}
	h3, err := NewCarrierSession(BuiltCarrierRequest{MethodID: registry.MethodWebH3ExtDgram, NativeDatagrams: true})
	if err != nil {
		return err
	}
	h2Payload, err := h2.SendDatagram(payload)
	if err != nil {
		return err
	}
	h1Payload, err := h1.SendDatagram(payload)
	if err != nil {
		return err
	}
	h3Payload, err := h3.SendDatagram(payload)
	if err != nil {
		return err
	}
	payload[0] = 0xff
	passed := h2Payload.Kind == CarrierPayloadStream &&
		h1Payload.Kind == CarrierPayloadMessage &&
		h3Payload.Kind == CarrierPayloadDatagram &&
		bytes.Equal(h2Payload.Data, []byte{0x90, 0x91, 0x92}) &&
		bytes.Equal(h1Payload.Data, []byte{0x90, 0x91, 0x92}) &&
		bytes.Equal(h3Payload.Data, []byte{0x90, 0x91, 0x92})
	report.addCase(
		"shared_opaque_core_path",
		passed,
		"shared-carrier-session",
		"all carriers move opaque core bytes without carrier-specific protocol shortcuts",
	)
	return nil
}

func conformanceTemplate(method, classType uint64) protocol.CoverTemplate {
	return protocol.CoverTemplate{
		RequestClasses: []protocol.RequestClass{{
			ClassID:             1,
			ClassType:           classType,
			AllowedMethodFamily: method,
			PathTemplateID:      bytes.Repeat([]byte{0x11}, 16),
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
	}
}

func h3ConformanceTemplate() protocol.CoverTemplate {
	tpl := conformanceTemplate(registry.MethodWebH3ExtDgram, registry.RequestGatewayOwnedSlot)
	tpl.H3Profile = protocol.H3CoverProfile{
		ProfileID:                  7,
		SupportsH3Datagram:         true,
		SupportsWebTransportH3:     true,
		WebTransportProfileID:      1,
		QUICDatagramRequired:       true,
		DatagramSizeDistributionID: bytes.Repeat([]byte{0x22}, 16),
		DatagramRateDistributionID: bytes.Repeat([]byte{0x33}, 16),
	}
	return tpl
}

func masqueConformanceInput(plan CarrierPlan, tpl protocol.CoverTemplate, allowVisible bool) CarrierRequestInput {
	return CarrierRequestInput{
		Plan:                       plan,
		Template:                   tpl,
		RequestClassID:             1,
		NeedCapsule:                true,
		Scheme:                     "https",
		Authority:                  "edge.example",
		Path:                       "/.well-known/masque/udp/192.0.2.6/443/",
		Payload:                    []byte{0xcc, 0xdd},
		AllowVisibleProxySemantics: allowVisible,
	}
}

func FormatCarrierConformanceReport(report CarrierConformanceReport) string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "transport_check passed=%t cases=%d failures=%d\n", report.Passed, len(report.Cases), len(report.Findings))
	for _, c := range report.Cases {
		fmt.Fprintf(&out, "transport_case %s passed=%t method=%s detail=%q\n", c.Name, c.Passed, c.Method, c.Detail)
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(&out, "transport_finding %s\n", finding)
	}
	return out.String()
}
