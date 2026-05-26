//go:build !aurora_lab

package logging

func LabBuildEnabled() bool {
	return false
}
