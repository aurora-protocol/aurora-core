//go:build !linux && !darwin

package perf

func processRSSBytes() (uint64, bool) {
	return 0, false
}
