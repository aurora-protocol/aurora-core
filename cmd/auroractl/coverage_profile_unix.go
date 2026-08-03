//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openCoverageProfile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("coverage profile open failed")
	}
	file := os.NewFile(uintptr(fd), "")
	if file == nil {
		if err := unix.Close(fd); err != nil {
			return nil, fmt.Errorf("coverage profile close failed")
		}
		return nil, fmt.Errorf("coverage profile open failed")
	}
	return validateCoverageProfile(file)
}
