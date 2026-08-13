//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package admission

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileReplayCacheRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.log")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "replay-cache.log")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if cache, err := NewFileReplayCache(path); err == nil || cache != nil {
		if cache != nil {
			_ = cache.Close()
		}
		t.Fatal("replay cache followed a symlink")
	}
	openedDirectory, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer openedDirectory.Close()
	if cache, err := NewFileReplayCacheAt(openedDirectory, "replay-cache.log"); err == nil || cache != nil {
		if cache != nil {
			_ = cache.Close()
		}
		t.Fatal("replay cache followed a symlink through an opened directory")
	}
}

func TestFileReplayCacheAtRejectsDirectoryTraversal(t *testing.T) {
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	for _, name := range []string{".", "..", "nested/cache.log"} {
		if cache, err := NewFileReplayCacheAt(directory, name); err == nil || cache != nil {
			if cache != nil {
				_ = cache.Close()
			}
			t.Fatalf("replay cache accepted unsafe directory entry %q", name)
		}
	}
}
