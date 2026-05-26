package transport

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/protocol"
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

func TestCarrierPlanMarksH2UDPStreamFallbackDowngrade(t *testing.T) {
	profile, _ := policy.ProfileByID(registry.PolicyAdversarialDPI)
	plan, err := SelectCarrierPlan(profile, Capabilities{SupportsH2: true, CoverTemplateOK: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Carrier.MethodID != registry.MethodWebH2Stream {
		t.Fatalf("expected H2 carrier, got %+v", plan.Carrier)
	}
	if plan.UDPMode != UDPOverStreamFallback || !plan.PerformanceDowngrade {
		t.Fatalf("H2 UDP fallback was not exposed as downgrade: %+v", plan)
	}
}

func TestCarrierPlanMarksValidatedH3DatagramNative(t *testing.T) {
	profile, _ := policy.ProfileByID(registry.PolicyFastWeb)
	plan, err := SelectCarrierPlan(profile, Capabilities{
		SupportsH3:      true,
		SupportsH3Dgram: true,
		H3Validated:     true,
		WebTransportOK:  true,
		CoverTemplateOK: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Carrier.MethodID != registry.MethodWebH3ExtDgram {
		t.Fatalf("expected H3 ext-dgram carrier, got %+v", plan.Carrier)
	}
	if plan.UDPMode != UDPNativeDatagram || plan.PerformanceDowngrade {
		t.Fatalf("validated H3 datagram should be native, got %+v", plan)
	}
}

func TestBuildH2StreamCarrierRequestUsesGatewayOwnedBody(t *testing.T) {
	tpl := transportTemplate(registry.MethodWebH2Stream)
	plan := CarrierPlan{
		Carrier:              Carrier{MethodID: registry.MethodWebH2Stream, Name: "web.h2.stream"},
		UDPMode:              UDPOverStreamFallback,
		PerformanceDowngrade: true,
	}
	built, err := BuildCarrierRequest(CarrierRequestInput{
		Plan:           plan,
		Template:       tpl,
		RequestClassID: 1,
		NeedCapsule:    true,
		Scheme:         "https",
		Authority:      "cover.example",
		Path:           "/assets/app.bin",
		Header:         http.Header{"Content-Type": []string{"application/octet-stream"}},
		Payload:        []byte{0x01, 0x02, 0x03},
	})
	if err != nil {
		t.Fatal(err)
	}
	if built.MethodID != registry.MethodWebH2Stream || built.RequestClassID != 1 {
		t.Fatalf("unexpected carrier metadata: %+v", built)
	}
	if built.Request.Method != http.MethodPost || built.Request.URL.Scheme != "https" || built.Request.URL.Host != "cover.example" || built.Request.URL.Path != "/assets/app.bin" {
		t.Fatalf("unexpected H2 request target: %+v", built.Request)
	}
	if built.Request.Host != "cover.example" {
		t.Fatalf("authority was not set as Host override: %q", built.Request.Host)
	}
	if built.Request.ContentLength != 3 {
		t.Fatalf("H2 request content length = %d, want 3", built.Request.ContentLength)
	}
	if got := built.Request.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("content type = %q", got)
	}
	if len(built.InitialMessages) != 0 {
		t.Fatalf("H2 stream must not use WebSocket initial messages: %+v", built.InitialMessages)
	}
	if !built.StreamFallback || built.NativeDatagrams {
		t.Fatalf("H2 carrier UDP fallback flags wrong: %+v", built)
	}
	if bytes.Contains([]byte(built.Request.Header.Get("Content-Type")), []byte("Aurora")) {
		t.Fatalf("carrier injected protocol-specific visible header")
	}
}

func TestBuildH1WebSocketCarrierRequestUsesUpgradeAndInitialMessage(t *testing.T) {
	tpl := transportTemplate(registry.MethodWebH1WS)
	plan := CarrierPlan{
		Carrier:              Carrier{MethodID: registry.MethodWebH1WS, Name: "web.h1.ws"},
		UDPMode:              UDPOverStreamFallback,
		PerformanceDowngrade: true,
	}
	built, err := BuildCarrierRequest(CarrierRequestInput{
		Plan:             plan,
		Template:         tpl,
		RequestClassID:   1,
		NeedCapsule:      true,
		Scheme:           "https",
		Authority:        "cover.example",
		Path:             "/chat",
		WebSocketKeySeed: bytes.Repeat([]byte{0x42}, 16),
		Payload:          []byte{0xaa, 0xbb},
	})
	if err != nil {
		t.Fatal(err)
	}
	if built.Request.Method != http.MethodGet {
		t.Fatalf("WebSocket fallback request method = %s, want GET", built.Request.Method)
	}
	if built.Request.Header.Get("Upgrade") != "websocket" || built.Request.Header.Get("Connection") != "Upgrade" {
		t.Fatalf("missing WebSocket upgrade headers: %+v", built.Request.Header)
	}
	if built.Request.Header.Get("Sec-Websocket-Version") != "13" {
		t.Fatalf("wrong WebSocket version header: %+v", built.Request.Header)
	}
	if built.Request.Header.Get("Sec-Websocket-Key") == "" {
		t.Fatalf("missing WebSocket key")
	}
	if built.Request.Body != nil || built.Request.ContentLength != 0 {
		t.Fatalf("WebSocket fallback must not put protocol payload in the upgrade body")
	}
	if len(built.InitialMessages) != 1 || !bytes.Equal(built.InitialMessages[0], []byte{0xaa, 0xbb}) {
		t.Fatalf("protocol payload was not staged as first WebSocket message: %+v", built.InitialMessages)
	}
	if !built.StreamFallback || built.NativeDatagrams {
		t.Fatalf("H1 WebSocket UDP fallback flags wrong: %+v", built)
	}
}

func TestBuildCarrierRequestRequiresMatchingPrivateCoverSlot(t *testing.T) {
	tpl := transportTemplate(registry.MethodWebH2Stream)
	plan := CarrierPlan{Carrier: Carrier{MethodID: registry.MethodWebH1WS, Name: "web.h1.ws"}, UDPMode: UDPOverStreamFallback}
	_, err := BuildCarrierRequest(CarrierRequestInput{
		Plan:           plan,
		Template:       tpl,
		RequestClassID: 1,
		NeedCapsule:    true,
		Scheme:         "https",
		Authority:      "cover.example",
		Path:           "/chat",
		Payload:        []byte{0x01},
	})
	if err == nil {
		t.Fatalf("H1 WebSocket carrier accepted an H2-only cover slot")
	}

	tpl.RequestClasses[0].ClassType = registry.RequestOriginPassThrough
	plan = CarrierPlan{Carrier: Carrier{MethodID: registry.MethodWebH2Stream, Name: "web.h2.stream"}, UDPMode: UDPOverStreamFallback}
	_, err = BuildCarrierRequest(CarrierRequestInput{
		Plan:           plan,
		Template:       tpl,
		RequestClassID: 1,
		NeedCapsule:    true,
		Scheme:         "https",
		Authority:      "cover.example",
		Path:           "/assets/app.bin",
		Payload:        []byte{0x01},
	})
	if err == nil {
		t.Fatalf("carrier accepted an origin pass-through slot for protocol material")
	}
}

func TestBuildShadowOriginCarrierRequestAllowsSidecarBodySlot(t *testing.T) {
	tpl := transportTemplate(registry.MethodShadowOrigin)
	tpl.RequestClasses[0].ClassType = registry.RequestSidecarOriginSlot
	plan := CarrierPlan{
		Carrier:              Carrier{MethodID: registry.MethodShadowOrigin, Name: "web.shadow-origin"},
		UDPMode:              UDPOverStreamFallback,
		PerformanceDowngrade: true,
	}
	built, err := BuildCarrierRequest(CarrierRequestInput{
		Plan:           plan,
		Template:       tpl,
		RequestClassID: 1,
		NeedCapsule:    true,
		Scheme:         "https",
		Authority:      "origin.example",
		Path:           "/upload/media",
		Header:         http.Header{"Content-Type": []string{"application/octet-stream"}},
		Payload:        []byte{0x44, 0x55, 0x66},
	})
	if err != nil {
		t.Fatal(err)
	}
	if built.MethodID != registry.MethodShadowOrigin || built.RequestClassID != 1 {
		t.Fatalf("unexpected shadow-origin metadata: %+v", built)
	}
	if built.Request.Method != http.MethodPost || built.Request.URL.Path != "/upload/media" || built.Request.Host != "origin.example" {
		t.Fatalf("unexpected shadow-origin request: %+v", built.Request)
	}
	body, err := io.ReadAll(built.Request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, []byte{0x44, 0x55, 0x66}) {
		t.Fatalf("shadow-origin request body = %x", body)
	}
	if len(built.InitialMessages) != 0 || !built.StreamFallback || built.NativeDatagrams {
		t.Fatalf("shadow-origin carrier flags wrong: %+v", built)
	}
}

func TestBuildShadowOriginCarrierRequestRejectsOriginPassThroughAndPublicMarkers(t *testing.T) {
	tpl := transportTemplate(registry.MethodShadowOrigin)
	tpl.RequestClasses[0].ClassType = registry.RequestOriginPassThrough
	plan := CarrierPlan{Carrier: Carrier{MethodID: registry.MethodShadowOrigin, Name: "web.shadow-origin"}, UDPMode: UDPOverStreamFallback}
	_, err := BuildCarrierRequest(CarrierRequestInput{
		Plan:           plan,
		Template:       tpl,
		RequestClassID: 1,
		NeedCapsule:    true,
		Scheme:         "https",
		Authority:      "origin.example",
		Path:           "/upload/media",
		Payload:        []byte{0x01},
	})
	if err == nil {
		t.Fatalf("shadow-origin carrier accepted origin pass-through for protocol material")
	}

	tpl.RequestClasses[0].ClassType = registry.RequestSidecarOriginSlot
	_, err = BuildCarrierRequest(CarrierRequestInput{
		Plan:           plan,
		Template:       tpl,
		RequestClassID: 1,
		NeedCapsule:    true,
		Scheme:         "https",
		Authority:      "origin.example",
		Path:           "/upload/media",
		Header:         http.Header{"X-Aurora-Mode": []string{"capsule"}},
		Payload:        []byte{0x01},
	})
	if err == nil {
		t.Fatalf("shadow-origin carrier accepted a public protocol marker header")
	}
}

func TestBuildH3ExtDatagramCarrierRequestUsesWebTransportAssociation(t *testing.T) {
	tpl := h3DatagramTemplate()
	plan := CarrierPlan{
		Carrier:              Carrier{MethodID: registry.MethodWebH3ExtDgram, Name: "web.h3.ext-dgram"},
		UDPMode:              UDPNativeDatagram,
		PerformanceDowngrade: false,
	}
	built, err := BuildCarrierRequest(CarrierRequestInput{
		Plan:                     plan,
		Template:                 tpl,
		RequestClassID:           1,
		NeedCapsule:              true,
		Scheme:                   "https",
		Authority:                "cover.example",
		Path:                     "/session/42",
		Payload:                  []byte{0x80, 0x01, 0x02},
		H3DatagramSettingsOK:     true,
		QUICMaxDatagramFrameSize: 1200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if built.MethodID != registry.MethodWebH3ExtDgram || built.RequestClassID != 1 {
		t.Fatalf("unexpected H3 metadata: %+v", built)
	}
	if built.Request.Method != http.MethodConnect || built.Request.URL.Scheme != "https" || built.Request.URL.Host != "cover.example" || built.Request.URL.Path != "/session/42" {
		t.Fatalf("unexpected H3 CONNECT request: %+v", built.Request)
	}
	if built.ProtocolToken != "webtransport-h3" {
		t.Fatalf("unexpected H3 protocol token %q", built.ProtocolToken)
	}
	if built.Request.Body != nil || built.Request.ContentLength != 0 {
		t.Fatalf("H3 datagram association must not put protocol payload in request body")
	}
	if len(built.InitialDatagrams) != 1 || !bytes.Equal(built.InitialDatagrams[0], []byte{0x80, 0x01, 0x02}) {
		t.Fatalf("H3 payload was not staged as an initial datagram: %+v", built.InitialDatagrams)
	}
	if !built.NativeDatagrams || built.StreamFallback {
		t.Fatalf("H3 datagram carrier flags wrong: %+v", built)
	}
}

func TestBuildH3ExtDatagramCarrierRequestRequiresProfileAndNegotiation(t *testing.T) {
	tpl := h3DatagramTemplate()
	plan := CarrierPlan{Carrier: Carrier{MethodID: registry.MethodWebH3ExtDgram, Name: "web.h3.ext-dgram"}, UDPMode: UDPNativeDatagram}

	tpl.H3Profile.SupportsH3Datagram = false
	if _, err := BuildCarrierRequest(h3CarrierInput(plan, tpl)); err == nil {
		t.Fatalf("H3 ext-dgram accepted a profile without datagram support")
	}

	tpl = h3DatagramTemplate()
	tpl.H3Profile.SupportsWebTransportH3 = false
	if _, err := BuildCarrierRequest(h3CarrierInput(plan, tpl)); err == nil {
		t.Fatalf("H3 ext-dgram accepted a profile without WebTransport support")
	}

	tpl = h3DatagramTemplate()
	in := h3CarrierInput(plan, tpl)
	in.H3DatagramSettingsOK = false
	if _, err := BuildCarrierRequest(in); err == nil {
		t.Fatalf("H3 ext-dgram accepted missing H3 datagram settings")
	}

	tpl = h3DatagramTemplate()
	in = h3CarrierInput(plan, tpl)
	in.QUICMaxDatagramFrameSize = 0
	if _, err := BuildCarrierRequest(in); err == nil {
		t.Fatalf("H3 ext-dgram accepted missing QUIC max_datagram_frame_size")
	}

	tpl = h3DatagramTemplate()
	tpl.H3Profile.ResetStreamAtRequired = true
	in = h3CarrierInput(plan, tpl)
	in.ResetStreamAtNegotiated = false
	if _, err := BuildCarrierRequest(in); err == nil {
		t.Fatalf("H3 ext-dgram accepted missing reset_stream_at negotiation")
	}
	in.ResetStreamAtNegotiated = true
	if _, err := BuildCarrierRequest(in); err != nil {
		t.Fatalf("H3 ext-dgram rejected negotiated reset_stream_at: %v", err)
	}
}

func transportTemplate(method uint64) protocol.CoverTemplate {
	return protocol.CoverTemplate{
		RequestClasses: []protocol.RequestClass{{
			ClassID:             1,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: method,
			PathTemplateID:      bytes.Repeat([]byte{0x11}, 16),
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
	}
}

func h3DatagramTemplate() protocol.CoverTemplate {
	tpl := transportTemplate(registry.MethodWebH3ExtDgram)
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

func h3CarrierInput(plan CarrierPlan, tpl protocol.CoverTemplate) CarrierRequestInput {
	return CarrierRequestInput{
		Plan:                     plan,
		Template:                 tpl,
		RequestClassID:           1,
		NeedCapsule:              true,
		Scheme:                   "https",
		Authority:                "cover.example",
		Path:                     "/session/42",
		Payload:                  []byte{0x80},
		H3DatagramSettingsOK:     true,
		QUICMaxDatagramFrameSize: 1200,
	}
}
