//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package admission

// Adversarial white-box coverage for the two count-0 non-regular-file guards
// of the replay-cache openers in admission/replay_cache_open_unix.go. Both
// defend against the opened fd resolving to a non-regular file (a device, pipe,
// socket, ...) which the append-based replay cache cannot safely use:
//
//   - :27 if !info.Mode().IsRegular()  (openReplayCacheFile)
//     -> /dev/null is a char device: unix.Open succeeds on it (O_RDWR|O_APPEND|
//        O_CLOEXEC|O_NOFOLLOW|O_CREAT; it is not a symlink and already exists so
//        O_CREAT is a no-op), os.NewFile returns a non-nil handle (:18 skipped),
//        Stat succeeds (:23 skipped), and :27 rejects the non-regular file.
//   - :49 if !info.Mode().IsRegular()  (openReplayCacheFileAt)
//     -> a FIFO (named pipe) created in a temp dir and opened via openat is a
//        non-regular file. unix.Openat succeeds on a FIFO with O_RDWR (opening a
//        FIFO O_RDWR never blocks), os.NewFile returns a non-nil handle (:40
//        skipped), Stat succeeds (:45 skipped), and :49 rejects it.
//
// Coverage targets (baseline measured on main; both bodies COUNT 0 while their
// conditions were already evaluated):
//   - replay_cache_open_unix.go:27.30,30.3 0
//   - replay_cache_open_unix.go:49.30,52.3 0
//
// The four sibling count-0 guards are deliberately NOT covered (dead-by-design):
//   - :18 / :40 (file == nil) — os.NewFile only returns nil for an invalid fd,
//     which unix.Open / unix.Openat never return on success; unreachable.
//   - :23 / :45 (file.Stat() err) — fstat on a valid fd effectively always
//     succeeds; the only way to fail is a TOCTOU delete between open and stat,
//     which is not reliably triggerable; dead-by-design.
// (replay_cache_retention_unix.go:26/:35 are the same dead-by-design shapes:
//  :26 file == nil after Openat; :35 IsRegular after O_CREAT|O_EXCL, which always
//  creates a fresh regular file — confirmed count-0 and not pillars.)
//
// The existing replay_cache_symlink_unix_test.go covers a DIFFERENT guard
// (O_NOFOLLOW rejects a symlink at the unix.Open error, before NewFile/Stat),
// so :27 / :49 remain count-0. In-package (package admission, same unix build
// tag) because openReplayCacheFile / openReplayCacheFileAt are unexported. No
// network, no goroutine, no cgo. This file adds only TestXxx entry points and
// references existing in-package symbols + stdlib os/path/filepath/strings/
// /testing and golang.org/x/sys/unix (all used) -> no U1000 surface.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenReplayCacheFileRejectsNonRegularFile(t *testing.T) {
	// :27 !info.Mode().IsRegular(): /dev/null is a char device, so a successful
	// open yields a non-regular file and the :27 guard rejects it. unix.Open
	// succeeds on /dev/null (it is not a symlink and already exists, so O_CREAT
	// is a no-op) and os.NewFile returns a non-nil handle, so :18 and :23 are
	// skipped and :27 fires.
	file, err := openReplayCacheFile("/dev/null")
	if file != nil {
		_ = file.Close()
		t.Fatal("openReplayCacheFile(/dev/null) file != nil, want nil (:27 should reject non-regular)")
	}
	if err == nil {
		t.Fatal("openReplayCacheFile(/dev/null) err = nil, want non-nil (:27)")
	}
	if !strings.Contains(err.Error(), "must be regular") {
		t.Fatalf("openReplayCacheFile(/dev/null) err = %q, want substring \"must be regular\" (:27)", err.Error())
	}
}

func TestOpenReplayCacheFileAtRejectsNonRegularFile(t *testing.T) {
	// :49 !info.Mode().IsRegular(): a FIFO (named pipe) opened via openat is a
	// non-regular file. Create a FIFO in a temp dir, open the dir, then
	// openReplayCacheFileAt(dir, fifoName): unix.Openat succeeds on a FIFO with
	// O_RDWR (opening a FIFO O_RDWR never blocks), os.NewFile returns a non-nil
	// handle (:40 skipped), Stat succeeds (:45 skipped), and :49 fires.
	directory := t.TempDir()
	fifoPath := filepath.Join(directory, "fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	openedDirectory, err := os.Open(directory)
	if err != nil {
		t.Fatalf("open dir: %v", err)
	}
	defer openedDirectory.Close()
	file, err := openReplayCacheFileAt(openedDirectory, "fifo")
	if file != nil {
		_ = file.Close()
		t.Fatal("openReplayCacheFileAt(fifo) file != nil, want nil (:49 should reject non-regular)")
	}
	if err == nil {
		t.Fatal("openReplayCacheFileAt(fifo) err = nil, want non-nil (:49)")
	}
	if !strings.Contains(err.Error(), "must be regular") {
		t.Fatalf("openReplayCacheFileAt(fifo) err = %q, want substring \"must be regular\" (:49)", err.Error())
	}
}
