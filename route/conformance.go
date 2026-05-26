package route

import (
	"bytes"
	"fmt"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/packet"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

type SplitRouteConformanceCase struct {
	Name   string
	Passed bool
	Detail string
}

type SplitRouteConformanceReport struct {
	Passed   bool
	Cases    []SplitRouteConformanceCase
	Findings []string
}

func RunSplitRouteConformance() (SplitRouteConformanceReport, error) {
	report := SplitRouteConformanceReport{Passed: true}
	if err := addRoutePreludeWrapReplayCase(&report); err != nil {
		return SplitRouteConformanceReport{}, err
	}
	addRouteHopBindingSeparationCase(&report)
	if err := addRouteCapsuleHopPrivacyCase(&report); err != nil {
		return SplitRouteConformanceReport{}, err
	}
	if err := addSplit2ForwardOpaqueEntryCase(&report); err != nil {
		return SplitRouteConformanceReport{}, err
	}
	if err := addSplit2BackwardOpaqueEntryCase(&report); err != nil {
		return SplitRouteConformanceReport{}, err
	}
	if err := addPacketADRouteHopBindingCase(&report); err != nil {
		return SplitRouteConformanceReport{}, err
	}
	addRouteRotationDrainCase(&report)
	if err := addSplit2IndependentCountersCase(&report); err != nil {
		return SplitRouteConformanceReport{}, err
	}
	return report, nil
}

func (r *SplitRouteConformanceReport) addCase(name string, passed bool, detail string) {
	r.Cases = append(r.Cases, SplitRouteConformanceCase{
		Name:   name,
		Passed: passed,
		Detail: detail,
	})
	if !passed {
		r.Passed = false
		r.Findings = append(r.Findings, name+" failed")
	}
}

func addRoutePreludeWrapReplayCase(report *SplitRouteConformanceReport) error {
	env := splitRouteConformanceEnvelope()
	private, cred, err := splitRouteConformancePrivate(env)
	if err != nil {
		return err
	}
	envelope, err := SealPrivatePrelude(env, private)
	if err != nil {
		return err
	}
	accessCache := admission.NewMemoryReplayCache()
	wrapCache := NewWrapNonceReplayCache()
	opened, binding, openErr := OpenAndVerifyPrivatePreludeWithWrapNonceCache(accessCache, wrapCache, env, envelope, cred, 100)
	secondAccessCache := admission.NewMemoryReplayCache()
	_, _, duplicateErr := OpenAndVerifyPrivatePreludeWithWrapNonceCache(secondAccessCache, wrapCache, env, envelope, cred, 100)
	spentKey, spentErr := admission.ComputeSpentHintKey(cred)
	passed := openErr == nil &&
		spentErr == nil &&
		opened.RouteInstanceID == env.RouteInstanceID &&
		opened.HopIndex == env.HopIndex &&
		len(binding) == 48 &&
		accessCache.Has(spentKey) &&
		duplicateErr != nil &&
		!secondAccessCache.Has(spentKey)
	report.addCase(
		"route_prelude_wrap_replay",
		passed,
		"ROUTE_PRELUDE0 unwrap verifies the route-hop-bound AccessHint and rejects duplicate wrap nonces before spending a new hint",
	)
	return nil
}

func addRouteHopBindingSeparationCase(report *SplitRouteConformanceReport) {
	in := HopBindingInput{
		RouteInstanceID:                1,
		HopIndex:                       1,
		PreviousHopFullTranscriptHash:  conformanceBytes(0x10, 48),
		PreviousHopRelayDescriptorHash: conformanceBytes(0x11, 48),
		NextRelayDescriptorHash:        conformanceBytes(0x12, 48),
		RoutePreludeWrapContext:        conformanceBytes(0x13, 48),
		ClientNonceForThisHop:          conformanceBytes(0x14, 32),
	}
	first, firstErr := RouteHopBinding(in)
	in.PreviousHopFullTranscriptHash = conformanceBytes(0x15, 48)
	changedTranscript, transcriptErr := RouteHopBinding(in)
	in.PreviousHopFullTranscriptHash = conformanceBytes(0x10, 48)
	in.RoutePreludeWrapContext = conformanceBytes(0x16, 48)
	changedWrap, wrapErr := RouteHopBinding(in)
	passed := firstErr == nil &&
		transcriptErr == nil &&
		wrapErr == nil &&
		len(first) == 48 &&
		!bytes.Equal(first, changedTranscript) &&
		!bytes.Equal(first, changedWrap)
	report.addCase(
		"route_hop_binding_separation",
		passed,
		"route_hop_binding commits to previous-hop transcript and route-wrap context",
	)
}

func addRouteCapsuleHopPrivacyCase(report *SplitRouteConformanceReport) error {
	exitCtx := splitRouteControlContext(5, 1, 0x71, 0x72)
	entryCtx := splitRouteControlContext(5, 0, 0x31, 0x32)
	plain := protocol.RouteCapsule1Plain{
		AdmissionProof: protocol.AdmissionProof{
			ProofVersion:          registry.Version20,
			ProofType:             registry.ProofBlindRSA2048,
			IssuerID:              conformanceBytes(0xb1, 16),
			TokenKeyID:            conformanceBytes(0xb2, 32),
			RelayBucketID:         conformanceBytes(0xb3, 16),
			TokenScopeID:          conformanceBytes(0xb4, 16),
			ExpiryUnix:            200,
			TokenNonce:            conformanceBytes(0xb5, 32),
			RedemptionContextHash: conformanceBytes(0xb6, 48),
			TokenPublicMetadata:   []byte("exit-policy-metadata"),
			TokenAuthenticator:    []byte("exit-token-secret"),
		},
		ReplayProof: protocol.ReplayProof{
			ProofVersion:        registry.Version20,
			ReplayEpochID:       9,
			TokenRedemptionHash: conformanceBytes(0xb7, 48),
			ClientReplayNonce:   conformanceBytes(0xb8, 32),
			ReplayContextHash:   conformanceBytes(0xb9, 48),
			ReplayWindowID:      conformanceBytes(0xba, 16),
		},
		PolicyOffer: protocol.PolicyOffer{
			OfferedVersions:         []uint64{registry.Version20},
			OfferedSuites:           []uint64{registry.SuiteHybrid768AESGCM},
			OfferedMethods:          []uint64{registry.MethodWebH2Stream},
			MinimumPolicyID:         registry.PolicyFastWeb,
			RequestedPolicyID:       registry.PolicyBalancedWeb,
			RequestedRouteModeID:    registry.RouteSplit2,
			RequestedShapeID:        registry.ShapeNormal,
			TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
		},
		ClientFinished: conformanceBytes(0xc1, 48),
	}
	sealed, sealErr := handshake.SealRouteCapsule1(exitCtx, plain)
	_, entryOpenErr := handshake.OpenRouteCapsule1(entryCtx, sealed)
	opened, exitOpenErr := handshake.OpenRouteCapsule1(exitCtx, sealed)
	passed := sealErr == nil &&
		entryOpenErr != nil &&
		exitOpenErr == nil &&
		opened.RouteInstanceID == 5 &&
		opened.HopIndex == 1 &&
		bytes.Equal(opened.AdmissionProof.TokenAuthenticator, []byte("exit-token-secret")) &&
		opened.PolicyOffer.RequestedRouteModeID == registry.RouteSplit2 &&
		!bytes.Contains(sealed, []byte("exit-token-secret")) &&
		!bytes.Contains(sealed, []byte("exit-policy-metadata"))
	report.addCase(
		"route_capsule_hop_privacy",
		passed,
		"ROUTE_CAPSULE1 admission and policy material opens only with the verified exit-hop control context",
	)
	return nil
}

func addSplit2ForwardOpaqueEntryCase(report *SplitRouteConformanceReport) error {
	flowFrame, err := conformanceFlowOpenFrame(100, "secret.example")
	if err != nil {
		return err
	}
	exitBlock := protocol.FrameBlock{Frames: []protocol.AuroraFrame{flowFrame}}
	entry := splitRouteProtector(7, 0, 0, 0x31, 0x32)
	exit := splitRouteProtector(7, 1, 0, 0x41, 0x42)
	outer, err := packet.SealSplit2Onion(exitBlock, &entry, &exit, splitRouteForwardFrame(7, 1))
	if err != nil {
		return err
	}
	entryBlock, entryErr := entry.Open(outer)
	plainErr := fmt.Errorf("route: missing entry route-forward payload")
	leakedSecret := true
	if entryErr == nil && len(entryBlock.Frames) == 1 {
		_, plainErr = protocol.DecodeFrameBlock(entryBlock.Frames[0].Payload)
		leakedSecret = bytes.Contains(entryBlock.Frames[0].Payload, []byte("secret.example"))
	}
	inner, innerErr := packet.DecodeForwardedPacket(entryBlock)
	opened, exitErr := exit.Open(inner)
	passed := entryErr == nil &&
		len(entryBlock.Frames) == 1 &&
		entryBlock.Frames[0].FrameType == registry.FrameRouteForward &&
		plainErr != nil &&
		!leakedSecret &&
		innerErr == nil &&
		inner.RouteInstanceID == 7 &&
		inner.HopLayer == 1 &&
		exitErr == nil &&
		len(opened.Frames) == 1 &&
		opened.Frames[0].FrameType == registry.FrameFlowOpen &&
		opened.Frames[0].FlowID == 100
	report.addCase(
		"split2_forward_opaque_entry",
		passed,
		"entry hop sees one ROUTE_FORWARD frame while exit-only flow metadata remains encrypted for the exit hop",
	)
	return nil
}

func addSplit2BackwardOpaqueEntryCase(report *SplitRouteConformanceReport) error {
	exitBlock := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameStreamData,
		FlowID:    100,
		Payload:   []byte("exit response payload"),
	}}}
	entry := splitRouteProtector(10, 0, 1, 0x91, 0x92)
	exit := splitRouteProtector(10, 1, 1, 0xa1, 0xa2)
	outer, err := packet.SealSplit2BackwardOnion(exitBlock, &entry, &exit, splitRouteForwardFrame(10, 1))
	if err != nil {
		return err
	}
	entryBlock, entryErr := entry.Open(outer)
	inner, innerErr := packet.DecodeForwardedPacket(entryBlock)
	opened, exitErr := exit.Open(inner)
	passed := entryErr == nil &&
		len(entryBlock.Frames) == 1 &&
		entryBlock.Frames[0].FrameType == registry.FrameRouteForward &&
		!bytes.Contains(entryBlock.Frames[0].Payload, []byte("exit response payload")) &&
		innerErr == nil &&
		inner.Direction == 1 &&
		inner.HopLayer == 1 &&
		exitErr == nil &&
		len(opened.Frames) == 1 &&
		bytes.Equal(opened.Frames[0].Payload, []byte("exit response payload"))
	report.addCase(
		"split2_backward_opaque_entry",
		passed,
		"backward split-2 packets remain opaque at the entry layer and recover only after the exit layer is opened",
	)
	return nil
}

func addPacketADRouteHopBindingCase(report *SplitRouteConformanceReport) error {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	p := splitRouteProtector(12, 1, 0, 0x53, 0x54)
	pkt, err := p.Seal(block)
	if err != nil {
		return err
	}
	wrongRouteProtector := p
	wrongRouteProtector.RouteInstanceID = 13
	wrongRoutePacket := pkt
	wrongRoutePacket.RouteInstanceID = 13
	_, wrongRouteErr := wrongRouteProtector.Open(wrongRoutePacket)

	wrongHopProtector := p
	wrongHopProtector.HopLayer = 2
	wrongHopPacket := pkt
	wrongHopPacket.HopLayer = 2
	_, wrongHopErr := wrongHopProtector.Open(wrongHopPacket)

	passed := wrongRouteErr != nil &&
		wrongHopErr != nil &&
		p.NextPacket == 1
	report.addCase(
		"packet_ad_route_hop_binding",
		passed,
		"packet associated data binds route_instance_id and hop_layer so retagged packets fail authentication",
	)
	return nil
}

func addRouteRotationDrainCase(report *SplitRouteConformanceReport) {
	session := NewClientSession()
	session.ActivateRoute(100, 1)
	firstActive := session.AcceptsRouteInstance(100, 10)
	rotateErr := session.RotateRoute(200, 1, 20, 5)
	newActive := session.AcceptsRouteInstance(200, 21)
	oldDuringDrain := session.AcceptsRouteInstance(100, 24)
	oldAfterDrain := session.AcceptsRouteInstance(100, 25)
	passed := firstActive &&
		rotateErr == nil &&
		newActive &&
		oldDuringDrain &&
		!oldAfterDrain
	report.addCase(
		"route_rotation_drain_window",
		passed,
		"route instances accept the old instance during bounded drain and reject it after expiry",
	)
}

func addSplit2IndependentCountersCase(report *SplitRouteConformanceReport) error {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	entry := splitRouteProtector(8, 0, 0, 0x61, 0x62)
	exit := splitRouteProtector(8, 1, 0, 0x71, 0x72)
	firstErr := func() error {
		_, err := packet.SealSplit2Onion(block, &entry, &exit, splitRouteForwardFrame(8, 1))
		return err
	}()
	secondErr := func() error {
		_, err := packet.SealSplit2Onion(block, &entry, &exit, splitRouteForwardFrame(8, 1))
		return err
	}()
	passed := firstErr == nil &&
		secondErr == nil &&
		entry.NextPacket == 2 &&
		exit.NextPacket == 2
	report.addCase(
		"split2_independent_counters",
		passed,
		"entry and exit packet-number counters advance independently for the same route instance",
	)
	return nil
}

func splitRouteConformanceEnvelope() EnvelopeInput {
	return EnvelopeInput{
		RouteInstanceID:                1,
		HopIndex:                       1,
		PreviousHopRelayDescriptorHash: conformanceBytes(0x41, 48),
		NextRelayDescriptorHash:        conformanceBytes(0x42, 48),
		HintIssuerID:                   conformanceBytes(0x34, 16),
		RelayBucketID:                  conformanceBytes(0x35, 16),
		HintEpochID:                    7,
		HintSelector:                   conformanceBytes(0x31, 16),
		WrapSuiteID:                    registry.WrapSuiteRouteV1,
		WrapNonce:                      conformanceBytes(0x32, 16),
		HintSecret:                     conformanceBytes(0x33, 32),
	}
}

func splitRouteConformancePrivate(env EnvelopeInput) (PrivatePrelude, admission.AccessHintCredential, error) {
	classical, err := auroracrypto.GenerateECDHForSuite(registry.SuiteHybrid768AESGCM)
	if err != nil {
		return PrivatePrelude{}, admission.AccessHintCredential{}, err
	}
	kem, err := auroracrypto.GenerateMLKEM768()
	if err != nil {
		return PrivatePrelude{}, admission.AccessHintCredential{}, err
	}
	context, err := auroracrypto.RoutePreludeWrapContext(env.routeWrapInput())
	if err != nil {
		return PrivatePrelude{}, admission.AccessHintCredential{}, err
	}
	private := PrivatePrelude{
		PreviousHopFullTranscriptHash: conformanceBytes(0x44, 48),
		ClientNonceForThisHop:         conformanceBytes(0x45, 32),
		OfferedSuites:                 []uint64{registry.SuiteHybrid768AESGCM},
		ClientClassicalEphPub:         classical.PublicKeyBytes(),
		ClientMLKEMEncapsulationKey:   kem.EncapsulationKeyBytes(),
		RequestedRouteModeID:          registry.RouteSplit2,
		CoverShapeHintID:              registry.ShapeNormal,
	}
	private.RouteInstanceID = env.RouteInstanceID
	private.HopIndex = env.HopIndex
	private.PreviousHopRelayDescriptorHash = append([]byte(nil), env.PreviousHopRelayDescriptorHash...)
	private.NextRelayDescriptorHash = append([]byte(nil), env.NextRelayDescriptorHash...)
	private.RoutePreludeWrapContext = context
	private.HintIssuerID = append([]byte(nil), env.HintIssuerID...)
	private.RelayBucketID = append([]byte(nil), env.RelayBucketID...)
	private.HintEpochID = env.HintEpochID
	private.HintSelector = append([]byte(nil), env.HintSelector...)
	cred := admission.AccessHintCredential{
		HintIssuerID:  append([]byte(nil), env.HintIssuerID...),
		RelayBucketID: append([]byte(nil), env.RelayBucketID...),
		HintEpochID:   env.HintEpochID,
		HintSelector:  append([]byte(nil), env.HintSelector...),
		HintSecret:    append([]byte(nil), env.HintSecret...),
		ExpiryUnix:    200,
		MaxUses:       1,
	}
	binding, err := RouteHopBinding(HopBindingInput{
		RouteInstanceID:                private.RouteInstanceID,
		HopIndex:                       private.HopIndex,
		PreviousHopFullTranscriptHash:  private.PreviousHopFullTranscriptHash,
		PreviousHopRelayDescriptorHash: private.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        private.NextRelayDescriptorHash,
		RoutePreludeWrapContext:        private.RoutePreludeWrapContext,
		ClientNonceForThisHop:          private.ClientNonceForThisHop,
	})
	if err != nil {
		return PrivatePrelude{}, admission.AccessHintCredential{}, err
	}
	private.AccessHint, err = admission.ComputeAccessHint(cred, binding, private.ClientNonceForThisHop)
	if err != nil {
		return PrivatePrelude{}, admission.AccessHintCredential{}, err
	}
	return private, cred, nil
}

func splitRouteProtector(routeInstanceID uint64, hopLayer uint8, direction uint8, keyByte byte, ivByte byte) packet.Protector {
	return packet.Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: routeInstanceID,
		HopLayer:        hopLayer,
		Direction:       direction,
		KeyPhase:        0,
		Key:             conformanceBytes(keyByte, 32),
		StaticIV:        conformanceBytes(ivByte, 12),
	}
}

func splitRouteControlContext(routeInstanceID uint64, hopIndex uint8, keyByte byte, ivByte byte) handshake.ControlCapsuleContext {
	return handshake.ControlCapsuleContext{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   registry.SuiteHybrid768AESGCM,
		RouteInstanceID:                 routeInstanceID,
		HopIndex:                        hopIndex,
		HandshakeBindingContext:         conformanceBytes(0xd1, 48),
		PreludeTranscriptHashForThisHop: conformanceBytes(byte(0xd2+hopIndex), 48),
		ClientHSKey:                     conformanceBytes(keyByte, 32),
		ClientHSIV:                      conformanceBytes(ivByte, 12),
		ServerHSKey:                     conformanceBytes(keyByte+1, 32),
		ServerHSIV:                      conformanceBytes(ivByte+1, 12),
	}
}

func splitRouteForwardFrame(routeInstanceID uint64, hopIndex uint8) protocol.RouteForwardFrame {
	return protocol.RouteForwardFrame{
		RouteInstanceID:                routeInstanceID,
		HopIndex:                       hopIndex,
		NextRelayDescriptorHash:        conformanceBytes(0x81, 48),
		PreviousHopRelayDescriptorHash: conformanceBytes(0x82, 48),
		NextRelayRoutingRecordID:       conformanceBytes(0x83, 16),
		NextRelayLocatorType:           registry.LocatorIPv4Port,
		NextRelayLocator:               []byte{203, 0, 113, 8, 0x01, 0xbb},
	}
}

func conformanceFlowOpenFrame(flowID uint64, domain string) (protocol.AuroraFrame, error) {
	return protocol.NewFlowOpenFrame(protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           flowID,
		FlowKind:         0x01,
		TargetKind:       0x03,
		TargetHost:       []byte(domain),
		TargetPort:       443,
		NameBindingID:    conformanceBytes(0x11, 16),
		DNSAnswerSetHash: conformanceBytes(0x22, 48),
	})
}

func conformanceBytes(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func FormatSplitRouteConformanceReport(report SplitRouteConformanceReport) string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "route_check passed=%t cases=%d failures=%d\n", report.Passed, len(report.Cases), len(report.Findings))
	for _, c := range report.Cases {
		fmt.Fprintf(&out, "route_case %s passed=%t detail=%q\n", c.Name, c.Passed, c.Detail)
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(&out, "route_finding %s\n", finding)
	}
	return out.String()
}
