//go:build !(aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris)

package admission

import (
	"fmt"
	"os"
)

func lockReplayCacheFile(file *os.File) error {
	if file == nil {
		return fmt.Errorf("admission: replay cache is closed")
	}
	return nil
}

func unlockReplayCacheFile(file *os.File) error {
	if file == nil {
		return fmt.Errorf("admission: replay cache is closed")
	}
	return nil
}
