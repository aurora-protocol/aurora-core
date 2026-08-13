//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

import (
	"fmt"
	"os"
	"syscall"
)

func validateProductionFileOwner(info os.FileInfo) error {
	if info == nil {
		return fmt.Errorf("production file owner is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("production file owner is unavailable")
	}
	return validateProductionFileOwnerUID(stat.Uid)
}

func validateProductionFileOwnerUID(uid uint32) error {
	if uid != uint32(os.Geteuid()) {
		return fmt.Errorf("production file owner does not match the current user")
	}
	return nil
}
