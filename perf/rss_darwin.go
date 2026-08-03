//go:build darwin

package perf

import "syscall"

func processRSSBytes() (uint64, bool) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil || usage.Maxrss < 0 {
		return 0, false
	}
	return uint64(usage.Maxrss), true
}
