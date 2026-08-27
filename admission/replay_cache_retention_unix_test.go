//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package admission

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRetentionFileReplayCacheRejectsSymlinkEntries(t *testing.T) {
	for _, name := range []string{"replay.log", "replay.log.lock", "replay.log.generation"} {
		t.Run(name, func(t *testing.T) {
			directoryPath := t.TempDir()
			target := filepath.Join(directoryPath, "target")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(directoryPath, name)); err != nil {
				t.Fatal(err)
			}
			directory, err := os.Open(directoryPath)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			if cache, err := NewRetentionFileReplayCacheAt(directory, "replay.log", 100); err == nil || cache != nil {
				if cache != nil {
					_ = cache.Close()
				}
				t.Fatal("retention replay cache accepted symlink entry")
			}
		})
	}
}
