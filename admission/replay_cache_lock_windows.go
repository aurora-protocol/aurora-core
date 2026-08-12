//go:build windows

package admission

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func replayCacheFileDurable() bool { return true }

func lockReplayCacheFile(file *os.File) error {
	if file == nil {
		return fmt.Errorf("admission: replay cache is closed")
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, ^uint32(0), ^uint32(0), overlapped); err != nil {
		return fmt.Errorf("admission: lock replay cache: %w", err)
	}
	return nil
}

func unlockReplayCacheFile(file *os.File) error {
	if file == nil {
		return fmt.Errorf("admission: replay cache is closed")
	}
	overlapped := new(windows.Overlapped)
	if err := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, ^uint32(0), ^uint32(0), overlapped); err != nil {
		return fmt.Errorf("admission: unlock replay cache: %w", err)
	}
	return nil
}
