//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package admission

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func lockReplayCacheFile(file *os.File) error {
	if file == nil {
		return fmt.Errorf("admission: replay cache is closed")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("admission: lock replay cache: %w", err)
	}
	return nil
}

func unlockReplayCacheFile(file *os.File) error {
	if file == nil {
		return fmt.Errorf("admission: replay cache is closed")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		return fmt.Errorf("admission: unlock replay cache: %w", err)
	}
	return nil
}
