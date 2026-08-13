//go:build windows

package admission

import (
	"os"
	"path/filepath"
)

func openReplayCacheFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
}

func openReplayCacheFileAt(directory *os.File, name string) (*os.File, error) {
	return openReplayCacheFile(filepath.Join(directory.Name(), name))
}
