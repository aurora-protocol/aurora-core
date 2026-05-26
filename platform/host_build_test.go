package platform

import (
	"errors"
	"reflect"
	"testing"
)

func TestHostBuildTargetsCoverP0Toolchains(t *testing.T) {
	portable := PortableHostBuildTargets()
	for _, want := range []HostBuildTarget{
		{Name: "linux-amd64", GOOS: "linux", GOARCH: "amd64", CGOEnabled: "0"},
		{Name: "windows-amd64", GOOS: "windows", GOARCH: "amd64", CGOEnabled: "0"},
		{Name: "macos-arm64", GOOS: "darwin", GOARCH: "arm64", CGOEnabled: "0"},
		{Name: "android-arm64", GOOS: "android", GOARCH: "arm64", CGOEnabled: "0"},
	} {
		if !hostBuildTargetsContain(portable, want) {
			t.Fatalf("portable host build targets missing %+v: %+v", want, portable)
		}
	}

	apple := AppleSimulatorHostBuildTargets()
	if len(apple) != 1 || apple[0].Name != "ios-simulator-arm64" || apple[0].GOOS != "ios" || apple[0].GOARCH != "arm64" || apple[0].CGOEnabled != "1" {
		t.Fatalf("apple simulator host target is incomplete: %+v", apple)
	}
}

func TestVerifyHostBuildMatrixRunsCompileOnlyGoTests(t *testing.T) {
	runner := &recordingHostBuildRunner{}
	report := VerifyHostBuildMatrix([]HostBuildTarget{{
		Name:       "linux-amd64",
		GOOS:       "linux",
		GOARCH:     "amd64",
		CGOEnabled: "0",
	}}, []string{"./wire"}, runner)
	if !report.Passed || report.Targets != 1 || len(report.Results) != 1 {
		t.Fatalf("unexpected host build report: %+v", report)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	wantArgs := []string{"test", "-run", "^$", "-exec=true", "./wire"}
	if !reflect.DeepEqual(runner.calls[0].Args, wantArgs) {
		t.Fatalf("host build args = %v, want %v", runner.calls[0].Args, wantArgs)
	}
	if runner.calls[0].Target.GOOS != "linux" || runner.calls[0].Target.GOARCH != "amd64" || runner.calls[0].Target.CGOEnabled != "0" {
		t.Fatalf("host build target env not passed: %+v", runner.calls[0].Target)
	}
}

func TestVerifyHostBuildMatrixReportsCompileFailure(t *testing.T) {
	runner := &recordingHostBuildRunner{err: errors.New("compile failed")}
	report := VerifyHostBuildMatrix([]HostBuildTarget{{
		Name:       "windows-amd64",
		GOOS:       "windows",
		GOARCH:     "amd64",
		CGOEnabled: "0",
	}}, []string{"./..."}, runner)
	if report.Passed || len(report.Findings) != 1 || report.Results[0].Passed {
		t.Fatalf("host build failure was not reported: %+v", report)
	}
}

func hostBuildTargetsContain(targets []HostBuildTarget, want HostBuildTarget) bool {
	for _, target := range targets {
		if target == want {
			return true
		}
	}
	return false
}

type recordingHostBuildRunner struct {
	err   error
	calls []hostBuildRunnerCall
}

type hostBuildRunnerCall struct {
	Target HostBuildTarget
	Args   []string
}

func (r *recordingHostBuildRunner) RunHostBuild(target HostBuildTarget, args []string) ([]byte, error) {
	r.calls = append(r.calls, hostBuildRunnerCall{
		Target: target,
		Args:   append([]string(nil), args...),
	})
	if r.err != nil {
		return []byte(r.err.Error()), r.err
	}
	return []byte("ok"), nil
}
