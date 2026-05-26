package platform

import "fmt"

type PackagingTarget struct {
	Name                  string
	Kind                  Kind
	Release               bool
	CI                    bool
	PacketMode            string
	RequiredEntitlements  []string
	NoEntitlementOnly     bool
	UsesMockPacketFlow    bool
	UsesThinAdapter       bool
	ContainsCryptoState   bool
	HasLocalProxyFallback bool
}

type PackagingConformanceReport struct {
	Passed                   bool
	Targets                  []PackagingTargetReport
	Failures                 []PackagingConformanceFailure
	ReleaseTargets           int
	EntitlementFreeCITargets int
	ThinAdapterTargets       int
	NoCryptoTargets          int
	MockPacketFlowTargets    int
}

type PackagingTargetReport struct {
	Name               string
	Kind               Kind
	Passed             bool
	Release            bool
	CI                 bool
	PacketMode         string
	EntitlementFree    bool
	UsesMockPacketFlow bool
	UsesThinAdapter    bool
	NoCryptoState      bool
	LocalProxyFallback bool
}

type PackagingConformanceFailure struct {
	TargetName string
	Field      string
}

func PackagingBlueprints() []PackagingTarget {
	return []PackagingTarget{
		releasePackagingTarget("linux-release", KindLinux, []string{"tun-device"}),
		releasePackagingTarget("windows-release", KindWindows, []string{"wintun-driver"}),
		releasePackagingTarget("apple-release", KindApple, []string{"network-extension", "app-group", "keychain-sharing"}),
		ciPackagingTarget("apple-ci", KindApple),
		releasePackagingTarget("android-release", KindAndroid, []string{"vpn-service"}),
		ciPackagingTarget("android-ci", KindAndroid),
		releasePackagingTarget("freebsd-release", KindFreeBSD, []string{"tun-device"}),
		releasePackagingTarget("openwrt-release", KindOpenWrt, []string{"tun-device"}),
		ciPackagingTarget("portable-ci", KindCI),
	}
}

func VerifyPackagingBlueprints(targets []PackagingTarget) (PackagingConformanceReport, error) {
	if len(targets) == 0 {
		return PackagingConformanceReport{}, fmt.Errorf("platform: no packaging targets")
	}
	report := PackagingConformanceReport{
		Passed:  true,
		Targets: make([]PackagingTargetReport, 0, len(targets)),
	}
	seenNames := make(map[string]struct{}, len(targets))
	releaseKinds := make(map[Kind]struct{})
	ciKinds := make(map[Kind]struct{})
	for _, target := range targets {
		if target.Name == "" {
			return PackagingConformanceReport{}, fmt.Errorf("platform: packaging target name is empty")
		}
		if _, ok := seenNames[target.Name]; ok {
			return PackagingConformanceReport{}, fmt.Errorf("platform: duplicate packaging target %s", target.Name)
		}
		seenNames[target.Name] = struct{}{}

		targetReport := PackagingTargetReport{
			Name:               target.Name,
			Kind:               target.Kind,
			Passed:             true,
			Release:            target.Release,
			CI:                 target.CI,
			PacketMode:         target.PacketMode,
			EntitlementFree:    len(target.RequiredEntitlements) == 0 && target.NoEntitlementOnly,
			UsesMockPacketFlow: target.UsesMockPacketFlow,
			UsesThinAdapter:    target.UsesThinAdapter,
			NoCryptoState:      !target.ContainsCryptoState,
			LocalProxyFallback: target.HasLocalProxyFallback,
		}
		if target.Release {
			report.ReleaseTargets++
			releaseKinds[target.Kind] = struct{}{}
			verifyReleasePackagingTarget(target, &report, &targetReport)
		}
		if target.CI {
			ciKinds[target.Kind] = struct{}{}
			verifyCIPackagingTarget(target, &report, &targetReport)
			if targetReport.EntitlementFree {
				report.EntitlementFreeCITargets++
			}
			if target.UsesMockPacketFlow {
				report.MockPacketFlowTargets++
			}
		}
		if !target.HasLocalProxyFallback {
			addPackagingFailure(&report, &targetReport, "local_proxy_fallback")
		}
		if !target.UsesThinAdapter {
			addPackagingFailure(&report, &targetReport, "thin_adapter")
		} else {
			report.ThinAdapterTargets++
		}
		if target.ContainsCryptoState {
			addPackagingFailure(&report, &targetReport, "no_crypto_state")
		} else {
			report.NoCryptoTargets++
		}
		report.Targets = append(report.Targets, targetReport)
	}
	for _, kind := range []Kind{KindLinux, KindWindows, KindApple, KindAndroid, KindFreeBSD, KindOpenWrt} {
		if _, ok := releaseKinds[kind]; !ok {
			addPackagingMissingFailure(&report, string(kind)+"-release", "missing_release_target")
		}
	}
	for _, kind := range []Kind{KindApple, KindAndroid, KindCI} {
		if _, ok := ciKinds[kind]; !ok {
			addPackagingMissingFailure(&report, string(kind)+"-ci", "missing_ci_target")
		}
	}
	return report, nil
}

func releasePackagingTarget(name string, kind Kind, entitlements []string) PackagingTarget {
	profile := ProfileFor(kind)
	return PackagingTarget{
		Name:                  name,
		Kind:                  kind,
		Release:               true,
		PacketMode:            profile.PacketMode,
		RequiredEntitlements:  append([]string(nil), entitlements...),
		UsesThinAdapter:       true,
		HasLocalProxyFallback: profile.HasNoKernelLocalInterface(),
	}
}

func ciPackagingTarget(name string, kind Kind) PackagingTarget {
	return PackagingTarget{
		Name:                  name,
		Kind:                  kind,
		CI:                    true,
		PacketMode:            PacketNone,
		NoEntitlementOnly:     true,
		UsesMockPacketFlow:    true,
		UsesThinAdapter:       true,
		HasLocalProxyFallback: true,
	}
}

func verifyReleasePackagingTarget(target PackagingTarget, report *PackagingConformanceReport, targetReport *PackagingTargetReport) {
	if target.PacketMode != ProfileFor(target.Kind).PacketMode {
		addPackagingFailure(report, targetReport, "packet_mode")
	}
	if target.NoEntitlementOnly {
		addPackagingFailure(report, targetReport, "release_no_entitlement")
	}
	for _, required := range requiredReleaseEntitlements(target.Kind) {
		if !hasEntitlement(target.RequiredEntitlements, required) {
			addPackagingFailure(report, targetReport, "required_entitlement")
		}
	}
}

func verifyCIPackagingTarget(target PackagingTarget, report *PackagingConformanceReport, targetReport *PackagingTargetReport) {
	if len(target.RequiredEntitlements) != 0 {
		addPackagingFailure(report, targetReport, "ci_entitlements")
	}
	if !target.NoEntitlementOnly {
		addPackagingFailure(report, targetReport, "ci_no_entitlement")
	}
	if !target.UsesMockPacketFlow {
		addPackagingFailure(report, targetReport, "mock_packet_flow")
	}
}

func requiredReleaseEntitlements(kind Kind) []string {
	switch kind {
	case KindLinux, KindFreeBSD, KindOpenWrt:
		return []string{"tun-device"}
	case KindWindows:
		return []string{"wintun-driver"}
	case KindApple:
		return []string{"network-extension", "app-group", "keychain-sharing"}
	case KindAndroid:
		return []string{"vpn-service"}
	default:
		return nil
	}
}

func hasEntitlement(entitlements []string, want string) bool {
	for _, entitlement := range entitlements {
		if entitlement == want {
			return true
		}
	}
	return false
}

func addPackagingFailure(report *PackagingConformanceReport, targetReport *PackagingTargetReport, field string) {
	report.Passed = false
	targetReport.Passed = false
	report.Failures = append(report.Failures, PackagingConformanceFailure{TargetName: targetReport.Name, Field: field})
}

func addPackagingMissingFailure(report *PackagingConformanceReport, targetName string, field string) {
	report.Passed = false
	report.Failures = append(report.Failures, PackagingConformanceFailure{TargetName: targetName, Field: field})
}
