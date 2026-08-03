//go:build linux

package perf

import (
	"math"
	"strings"
	"testing"
)

func TestParseLinuxRSS(t *testing.T) {
	got, err := parseLinuxRSS(strings.NewReader("10 3"), 4096)
	if err != nil || got != 12288 {
		t.Fatalf("RSS bytes=%d error=%v", got, err)
	}
}

func TestParseLinuxRSSRejectsMalformedOrOverflowingValues(t *testing.T) {
	for name, input := range map[string]struct {
		statm    string
		pageSize uint64
	}{
		"malformed": {statm: "invalid", pageSize: 4096},
		"zero page": {statm: "10 3", pageSize: 0},
		"overflow":  {statm: "10 2", pageSize: math.MaxUint64},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseLinuxRSS(strings.NewReader(input.statm), input.pageSize); err == nil {
				t.Fatal("invalid RSS values accepted")
			}
		})
	}
}
