//go:build linux

package perf

import (
	"fmt"
	"os"
)

func processRSSBytes() (uint64, bool) {
	file, err := os.Open("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	var totalPages, residentPages uint64
	_, scanErr := fmt.Fscan(file, &totalPages, &residentPages)
	closeErr := file.Close()
	if scanErr != nil || closeErr != nil {
		return 0, false
	}
	return residentPages * uint64(os.Getpagesize()), true
}
