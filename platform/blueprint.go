package platform

import "fmt"

type AdapterBlueprint struct {
	Kind                Kind
	PacketMode          string
	LocalModes          []string
	NoEntitlementOnly   bool
	ContainsCryptoState bool
	CoreBoundaryMethods []string
}

type AdapterConformanceReport struct {
	Passed    bool
	Platforms []AdapterPlatformReport
	Failures  []AdapterConformanceFailure
}

type AdapterPlatformReport struct {
	Kind               Kind
	Passed             bool
	PacketMode         string
	LocalProxyFallback bool
	NoCryptoState      bool
	BoundaryComplete   bool
}

type AdapterConformanceFailure struct {
	Kind  Kind
	Field string
}

func AdapterBlueprints() []AdapterBlueprint {
	kinds := []Kind{KindLinux, KindWindows, KindApple, KindAndroid, KindFreeBSD, KindOpenWrt, KindCI}
	blueprints := make([]AdapterBlueprint, 0, len(kinds))
	for _, kind := range kinds {
		profile := ProfileFor(kind)
		blueprints = append(blueprints, AdapterBlueprint{
			Kind:                profile.Kind,
			PacketMode:          profile.PacketMode,
			LocalModes:          append([]string(nil), profile.LocalModes...),
			NoEntitlementOnly:   profile.NoEntitlementOnly,
			ContainsCryptoState: profile.ContainsCryptoState,
			CoreBoundaryMethods: coreBoundaryMethods(),
		})
	}
	return blueprints
}

func VerifyAdapterBlueprints(blueprints []AdapterBlueprint) (AdapterConformanceReport, error) {
	if len(blueprints) == 0 {
		return AdapterConformanceReport{}, fmt.Errorf("platform: no adapter blueprints")
	}
	report := AdapterConformanceReport{
		Passed:    true,
		Platforms: make([]AdapterPlatformReport, 0, len(blueprints)),
	}
	seen := make(map[Kind]struct{}, len(blueprints))
	for _, blueprint := range blueprints {
		if blueprint.Kind == "" {
			return AdapterConformanceReport{}, fmt.Errorf("platform: adapter blueprint kind is empty")
		}
		if _, ok := seen[blueprint.Kind]; ok {
			return AdapterConformanceReport{}, fmt.Errorf("platform: duplicate adapter blueprint for %s", blueprint.Kind)
		}
		seen[blueprint.Kind] = struct{}{}
		platformReport := AdapterPlatformReport{
			Kind:               blueprint.Kind,
			Passed:             true,
			PacketMode:         blueprint.PacketMode,
			LocalProxyFallback: hasLocalProxyFallback(blueprint.LocalModes),
			NoCryptoState:      !blueprint.ContainsCryptoState,
			BoundaryComplete:   boundaryComplete(blueprint.CoreBoundaryMethods),
		}
		if !packetModeMatchesProfile(blueprint) {
			reportFailure(&report, &platformReport, "packet_mode")
		}
		if !platformReport.LocalProxyFallback {
			reportFailure(&report, &platformReport, "local_proxy_fallback")
		}
		if !platformReport.NoCryptoState {
			reportFailure(&report, &platformReport, "no_crypto_state")
		}
		if !platformReport.BoundaryComplete {
			reportFailure(&report, &platformReport, "core_boundary")
		}
		report.Platforms = append(report.Platforms, platformReport)
	}
	for _, kind := range []Kind{KindLinux, KindWindows, KindApple, KindAndroid, KindFreeBSD, KindOpenWrt, KindCI} {
		if _, ok := seen[kind]; !ok {
			report.Passed = false
			report.Failures = append(report.Failures, AdapterConformanceFailure{Kind: kind, Field: "missing"})
		}
	}
	return report, nil
}

func reportFailure(report *AdapterConformanceReport, platformReport *AdapterPlatformReport, field string) {
	report.Passed = false
	platformReport.Passed = false
	report.Failures = append(report.Failures, AdapterConformanceFailure{Kind: platformReport.Kind, Field: field})
}

func hasLocalProxyFallback(modes []string) bool {
	hasSOCKS := false
	hasHTTPConnect := false
	for _, mode := range modes {
		hasSOCKS = hasSOCKS || mode == LocalSOCKS5
		hasHTTPConnect = hasHTTPConnect || mode == LocalHTTPConnect
	}
	return hasSOCKS && hasHTTPConnect
}

func packetModeMatchesProfile(blueprint AdapterBlueprint) bool {
	return blueprint.PacketMode == ProfileFor(blueprint.Kind).PacketMode
}

func boundaryComplete(methods []string) bool {
	seen := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		seen[method] = struct{}{}
	}
	for _, method := range coreBoundaryMethods() {
		if _, ok := seen[method]; !ok {
			return false
		}
	}
	return true
}

func coreBoundaryMethods() []string {
	return []string{
		"open-session",
		"close-session",
		"submit-tcp-flow",
		"submit-udp-datagram",
		"submit-dns-message",
		"submit-packet",
		"submit-socket-event",
		"read-packet-or-frame",
		"notify-network-change",
		"export-redacted-diagnostics",
	}
}
