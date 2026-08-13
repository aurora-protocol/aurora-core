//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

import (
	"fmt"
	"os"
	"syscall"
)

func validateRestrictedOwnerFileOwner(info os.FileInfo) error {
	if info == nil {
		return fmt.Errorf("restricted file owner is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("restricted file owner is unavailable")
	}
	return validateRestrictedOwnerFileUID(stat.Uid)
}

func validateRestrictedOwnerFileUID(uid uint32) error {
	if uid != uint32(os.Geteuid()) {
		return fmt.Errorf("restricted file owner does not match the current user")
	}
	return nil
}
