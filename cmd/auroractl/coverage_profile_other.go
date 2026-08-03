//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris || windows)

package main

import (
	"fmt"
	"os"
)

func openCoverageProfile(path string) (*os.File, error) {
	return nil, fmt.Errorf("coverage profiles unsupported")
}
