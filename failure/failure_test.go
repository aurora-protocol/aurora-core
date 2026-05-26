package failure

import (
	"reflect"
	"strings"
	"testing"
)

func TestKindsHaveStableInternalCodes(t *testing.T) {
	cases := []struct {
		kind Kind
		code uint16
		key  string
	}{
		{BadAccessHint, 0x0001, "f0001"},
		{ReplayedAccessHint, 0x0002, "f0002"},
		{MalformedPrelude, 0x0003, "f0003"},
		{WrongSignature, 0x0004, "f0004"},
		{WrongSuite, 0x0005, "f0005"},
		{BadAEADTag, 0x0006, "f0006"},
		{ReplayedAdmission, 0x0007, "f0007"},
		{MalformedFlowOpen, 0x0008, "f0008"},
		{MalformedKeyUpdate, 0x0009, "f0009"},
		{InvalidCoverSlot, 0x000a, "f000a"},
		{UnsupportedMethod, 0x000b, "f000b"},
		{PolicyGate, 0x000c, "f000c"},
		{VerifierUnavailable, 0x000d, "f000d"},
		{ReplayCacheFailure, 0x000e, "f000e"},
		{WrongH3Settings, 0x000f, "f000f"},
		{UnsupportedVersion, 0x0010, "f0010"},
		{MalformedHybridShare, 0x0011, "f0011"},
	}
	seen := make(map[uint16]bool, len(cases))
	for _, tc := range cases {
		if got := tc.kind.Code(); got != tc.code {
			t.Fatalf("%v code = 0x%04x, want 0x%04x", tc.kind, got, tc.code)
		}
		if seen[tc.code] {
			t.Fatalf("duplicate code 0x%04x", tc.code)
		}
		seen[tc.code] = true
		if got := tc.kind.LogKey(); got != tc.key {
			t.Fatalf("%v log key = %q, want %q", tc.kind, got, tc.key)
		}
	}
}

func TestProbeSensitiveFailuresUseCoverOriginAction(t *testing.T) {
	kinds := []Kind{
		BadAccessHint,
		ReplayedAccessHint,
		MalformedPrelude,
		WrongSignature,
		WrongSuite,
		BadAEADTag,
		ReplayedAdmission,
		MalformedFlowOpen,
		MalformedKeyUpdate,
		InvalidCoverSlot,
		UnsupportedMethod,
		WrongH3Settings,
		UnsupportedVersion,
		MalformedHybridShare,
		PolicyGate,
		VerifierUnavailable,
		ReplayCacheFailure,
	}
	first := Classify(kinds[0])
	for _, kind := range kinds {
		got := Classify(kind)
		if got.Action != CoverOrigin {
			t.Fatalf("%v action = %v, want cover-origin", kind, got.Action)
		}
		if got.Action != first.Action || got.PublicStatus != first.PublicStatus || len(got.PublicBody) != 0 || got.CloseCode != first.CloseCode {
			t.Fatalf("%v produced distinguishable public classification: %+v vs %+v", kind, got, first)
		}
		assertSafeLogKey(t, got.LogKey)
	}
}

func TestUnknownFailureFailsClosedToCoverOrigin(t *testing.T) {
	got := Classify(Kind(0xffff))
	if got.Action != CoverOrigin || got.LogKey != "f0000" {
		t.Fatalf("unknown failure classification = %+v", got)
	}
	assertSafeLogKey(t, got.LogKey)
}

func TestActiveProbeCasesCoverSpecChecklist(t *testing.T) {
	want := map[string]Kind{
		"bad-access-hint":           BadAccessHint,
		"replayed-access-hint":      ReplayedAccessHint,
		"malformed-cover-prelude0":  MalformedPrelude,
		"invalid-prelude-signature": WrongSignature,
		"wrong-suite":               WrongSuite,
		"bad-aead-tag":              BadAEADTag,
		"replayed-admission-proof":  ReplayedAdmission,
		"unsupported-method":        UnsupportedMethod,
		"unsupported-version":       UnsupportedVersion,
		"malformed-hybrid-share":    MalformedHybridShare,
		"wrong-h3-settings":         WrongH3Settings,
		"malformed-flow-open":       MalformedFlowOpen,
		"malformed-key-update":      MalformedKeyUpdate,
	}
	got := ActiveProbeCases()
	if len(got) != len(want) {
		t.Fatalf("probe case count = %d, want %d: %+v", len(got), len(want), got)
	}
	for _, tc := range got {
		kind, ok := want[tc.Name]
		if !ok {
			t.Fatalf("unexpected probe case %q", tc.Name)
		}
		if tc.Kind != kind {
			t.Fatalf("probe case %q kind = %v, want %v", tc.Name, tc.Kind, kind)
		}
		delete(want, tc.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing probe cases: %+v", want)
	}
}

func TestActiveProbeCasesArePubliclyIndistinguishable(t *testing.T) {
	if err := VerifyProbeNeutrality(ActiveProbeCases()); err != nil {
		t.Fatal(err)
	}
}

func TestActiveProbeHarnessReportIncludesAllCasesAndCanonicalSurface(t *testing.T) {
	report, err := RunActiveProbeHarness(ActiveProbeCases())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("active-probe report did not pass: %+v", report)
	}
	if len(report.Cases) != len(ActiveProbeCases()) {
		t.Fatalf("reported case count = %d, want %d", len(report.Cases), len(ActiveProbeCases()))
	}
	canonical, err := PublicProbeSurface(ActiveProbeCases()[0].Kind)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.CanonicalSurface, canonical) {
		t.Fatalf("canonical surface mismatch: %+v vs %+v", report.CanonicalSurface, canonical)
	}
	for i, tc := range ActiveProbeCases() {
		got := report.Cases[i]
		if got.Name != tc.Name || got.Kind != tc.Kind || !got.Passed {
			t.Fatalf("reported case mismatch at %d: %+v vs %+v", i, got, tc)
		}
		if !reflect.DeepEqual(got.Surface, canonical) {
			t.Fatalf("case %q surface drifted: %+v vs %+v", got.Name, got.Surface, canonical)
		}
	}
}

func TestActiveProbeSurfacesDoNotExposeProtocolSpecificSignals(t *testing.T) {
	first, err := PublicProbeSurface(ActiveProbeCases()[0].Kind)
	if err != nil {
		t.Fatal(err)
	}
	assertSafeReflectedLog(t, first.ReflectedLog)
	for _, tc := range ActiveProbeCases()[1:] {
		got, err := PublicProbeSurface(tc.Kind)
		if err != nil {
			t.Fatalf("%s surface failed: %v", tc.Name, err)
		}
		if got.HTTPStatus != first.HTTPStatus ||
			got.CloseCode != first.CloseCode ||
			got.TLSAlertClass != first.TLSAlertClass ||
			got.QUICCloseCode != first.QUICCloseCode ||
			got.WebSocketCloseCode != first.WebSocketCloseCode ||
			got.TimingClass != first.TimingClass ||
			string(got.Body) != string(first.Body) ||
			got.ReflectedLog != first.ReflectedLog {
			t.Fatalf("%s produced distinguishable public surface: %+v vs %+v", tc.Name, got, first)
		}
		assertSafeReflectedLog(t, got.ReflectedLog)
	}
}

func assertSafeLogKey(t *testing.T, key string) {
	t.Helper()
	forbidden := []string{"aurora", "admission", "token", "hint", "capsule", "proof", "relay", "bridge"}
	lower := strings.ToLower(key)
	for _, word := range forbidden {
		if strings.Contains(lower, word) {
			t.Fatalf("log key %q contains forbidden diagnostic word %q", key, word)
		}
	}
}

func assertSafeReflectedLog(t *testing.T, value string) {
	t.Helper()
	forbidden := []string{"aurora", "admission", "token", "hint", "capsule", "proof", "relay", "bridge", "proxy"}
	lower := strings.ToLower(value)
	for _, word := range forbidden {
		if strings.Contains(lower, word) {
			t.Fatalf("reflected log value %q contains forbidden diagnostic word %q", value, word)
		}
	}
}
