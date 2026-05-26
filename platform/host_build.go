package platform

import "fmt"

type HostBuildTarget struct {
	Name       string
	GOOS       string
	GOARCH     string
	CGOEnabled string
}

type HostBuildRunner interface {
	RunHostBuild(target HostBuildTarget, args []string) ([]byte, error)
}

type HostBuildResult struct {
	Target HostBuildTarget
	Passed bool
	Output string
}

type HostBuildReport struct {
	Passed   bool
	Targets  int
	Results  []HostBuildResult
	Findings []string
}

func PortableHostBuildTargets() []HostBuildTarget {
	return []HostBuildTarget{
		{Name: "linux-amd64", GOOS: "linux", GOARCH: "amd64", CGOEnabled: "0"},
		{Name: "windows-amd64", GOOS: "windows", GOARCH: "amd64", CGOEnabled: "0"},
		{Name: "macos-arm64", GOOS: "darwin", GOARCH: "arm64", CGOEnabled: "0"},
		{Name: "android-arm64", GOOS: "android", GOARCH: "arm64", CGOEnabled: "0"},
	}
}

func AppleSimulatorHostBuildTargets() []HostBuildTarget {
	return []HostBuildTarget{
		{Name: "ios-simulator-arm64", GOOS: "ios", GOARCH: "arm64", CGOEnabled: "1"},
	}
}

func VerifyHostBuildMatrix(targets []HostBuildTarget, packages []string, runner HostBuildRunner) HostBuildReport {
	if len(packages) == 0 {
		packages = []string{"./..."}
	}
	report := HostBuildReport{Passed: true, Targets: len(targets)}
	args := append([]string{"test", "-run", "^$", "-exec=true"}, packages...)
	if runner == nil {
		report.Passed = false
		report.Findings = append(report.Findings, "host build runner is missing")
		return report
	}
	if len(targets) == 0 {
		report.Passed = false
		report.Findings = append(report.Findings, "host build target matrix is empty")
		return report
	}
	for _, target := range targets {
		output, err := runner.RunHostBuild(target, args)
		result := HostBuildResult{
			Target: target,
			Passed: err == nil,
			Output: string(output),
		}
		report.Results = append(report.Results, result)
		if err != nil {
			report.Passed = false
			report.Findings = append(report.Findings, fmt.Sprintf("%s: %v", target.Name, err))
		}
	}
	return report
}
