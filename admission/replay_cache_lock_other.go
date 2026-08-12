//go:build !(aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris || windows)

package admission

import (
	"fmt"
	"os"
)

func replayCacheFileDurable() bool { return false }

func lockReplayCacheFile(file *os.File) error {
	if file == nil {
		return fmt.Errorf("admission: replay cache is closed")
	}
	return fmt.Errorf("admission: replay cache file locking is unsupported")
}

func unlockReplayCacheFile(file *os.File) error {
	if file == nil {
		return fmt.Errorf("admission: replay cache is closed")
	}
	return fmt.Errorf("admission: replay cache file locking is unsupported")
}
