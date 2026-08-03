//go:build !(aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris)

package main

import (
	"fmt"
	"os"
)

func openCoverageProfile(path string) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("coverage profile open failed")
	}
	return validateCoverageProfile(file)
}
