//go:build linux

package perf

import (
	"fmt"
	"io"
	"math"
	"os"
)

func processRSSBytes() (uint64, bool) {
	file, err := os.Open("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	bytes, scanErr := parseLinuxRSS(file, uint64(os.Getpagesize()))
	closeErr := file.Close()
	if scanErr != nil || closeErr != nil {
		return 0, false
	}
	return bytes, true
}

func parseLinuxRSS(reader io.Reader, pageSize uint64) (uint64, error) {
	var totalPages, residentPages uint64
	if _, err := fmt.Fscan(reader, &totalPages, &residentPages); err != nil {
		return 0, err
	}
	if pageSize == 0 || residentPages > math.MaxUint64/pageSize {
		return 0, fmt.Errorf("perf: invalid Linux RSS values")
	}
	return residentPages * pageSize, nil
}
