package admission

// Adversarial white-box coverage for two count-0 nil-file guards in
// FileReplayCache. A FileReplayCache holds an open replay-cache *os.File; both
// InsertIfAbsent and Close guard against a nil file (the post-Close /
// never-opened state) before touching it.
//
//   - replay_cache.go:202 (*FileReplayCache).InsertIfAbsent
//     c.file == nil -> return false, "admission: replay cache is closed"
//     (fires after the :197 nil-receiver guard and the :200 mu.Lock, before the
//     :205 lockReplayCacheFile call and the :209 load).
//   - replay_cache.go:250 (*FileReplayCache).Close
//     c.file == nil -> c.seen = nil; return nil (fires after the :245
//     nil-receiver guard and the :248 mu.Lock, before the :254 file.Close path).
//
// The existing admission tests drive InsertIfAbsent / Close only on a cache that
// was opened via NewFileReplayCache (file != nil), so :202 and :250 stayed
// count-0 even though each is plainly reachable on a zero-value FileReplayCache
// whose file is still nil.
//
// Proof technique:
//
//   - :202 (nil-file clean return): a zero-value &FileReplayCache{} has file ==
//     nil and a usable zero-value mu. The :197 c == nil guard is skipped (the
//     receiver is non-nil), :200 locks the mu, and :202 sees file == nil and
//     returns "admission: replay cache is closed". The non-nil receiver
//     uniquely identifies :202 as the source: the only other site that returns
//     the same message is the :197 nil-receiver guard, which a non-nil receiver
//     cannot take. Pure (no IO; it returns before lockReplayCacheFile / load).
//
//   - :250 (nil-file clean return): construct &FileReplayCache{seen:
//     map[string]struct{}{"k": {}}} (file == nil, seen non-nil). The :245 c ==
//     nil guard is skipped (non-nil receiver), :248 locks the mu, :250 sees
//     file == nil, :251 nils out seen, and :252 returns nil. c.seen == nil
//     afterward uniquely proves :251 ran: seen was non-nil on input, :251 is
//     the only site on this path that nils it (the :245 nil-receiver guard
//     returns before touching seen, and the :254 file != nil branch is
//     unreachable with file == nil). Pure (no IO; the file path is guarded
//     out).
//
// Neither guard involves a context at the guard site, so there is no SA1012
// surface. In-package (package admission) because FileReplayCache and its
// unexported fields (file, seen) are accessed directly.
//
// This test file adds only TestXxx entry points and references existing
// in-package (FileReplayCache, InsertIfAbsent, Close) symbols and the strings
// package, so it adds no U1000 surface.

import (
	"strings"
	"testing"
)

func TestFileReplayCacheInsertIfAbsentNilFileGuard(t *testing.T) {
	// 202: a zero-value FileReplayCache has file == nil; the non-nil receiver
	// skips the :197 nil-receiver guard, so :202 is the only site that can
	// return "replay cache is closed" here.
	c := &FileReplayCache{}
	_, err := c.InsertIfAbsent([]byte("k"))
	if err == nil {
		t.Fatal("InsertIfAbsent on a nil-file cache returned nil err, want non-nil (:203 returns the closed error)")
	}
	if !strings.Contains(err.Error(), "replay cache is closed") {
		t.Fatalf("InsertIfAbsent nil-file err = %q, want it to contain \"replay cache is closed\" (:203)", err.Error())
	}
}

func TestFileReplayCacheCloseNilFileGuard(t *testing.T) {
	// 250: a FileReplayCache with file == nil and a non-nil seen map takes the
	// :250 guard, nils out seen at :251, and returns nil. seen == nil afterward
	// uniquely proves :251 ran (it was non-nil on input; :251 is the only site
	// on this path that nils it).
	c := &FileReplayCache{seen: map[string]struct{}{"k": {}}}
	if err := c.Close(); err != nil {
		t.Fatalf("Close nil-file err = %v, want nil (:252 returns nil)", err)
	}
	if c.seen != nil {
		t.Fatal("Close left seen non-nil, want nil (:251 nils out seen on the nil-file path)")
	}
}
