# Replay Cache Retention Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound production replay-cache memory and disk state to authenticated retention windows without weakening one-time credential protection.

**Architecture:** Keep the existing `ReplayCache` compatibility surface and add an optional retention-aware capability that admission code requires for security-critical inserts. Production will use a new durable cache with expiry-bearing records, a stable sidecar lock, safe atomic compaction, and legacy-record handling that remains fail-closed. The relay passes only verified descriptor deadlines to admission code; clients never supply retention timestamps.

**Tech Stack:** Go standard library, `golang.org/x/sys/unix` for Unix descriptor-relative operations, existing admission and handshake packages.

**Spec:** `aurora-spec` replay-cache retention and one-time credential rules.

## Global Constraints

- Preserve canonical wire encodings and public protocol behavior.
- Retain spent hints through `max(hint expiry, relay epoch expiry) + 10 minutes`.
- Retain spent tokens through `token expiry + 10 minutes`.
- Retain bootstrap deduplication through `max(token expiry, replay epoch expiry, relay epoch expiry) + 10 minutes`.
- Treat a cache that cannot honor explicit retention as unavailable and fail closed.
- Treat legacy key-only durable records as permanent, never as expired.
- Use only authenticated relay descriptor and credential values for retention calculations.
- Preserve cross-process duplicate detection and reject unsafe filesystem entries.
- Do not add protocol-version strings, external project references, or copied external code.

---

### Task 1: Add Retention-Aware Cache Semantics

**Files:**
- Modify: `admission/replay_cache.go`
- Modify: `admission/replay_cache_test.go`

**Interfaces:**
- Produces: `RetentionReplayCache` with `InsertIfAbsentUntil(key []byte, retainUntilUnix, nowUnix uint64) (bool, error)`.
- Produces: `InsertIfAbsentRetained(cache ReplayCache, key []byte, retainUntilUnix, nowUnix uint64) (bool, error)`.
- Produces: `RetentionDeadline(baseUnix uint64) (uint64, error)` and `MaximumRetentionDeadline(values ...uint64) (uint64, error)`.
- Produces: `MemoryReplayCache.InsertIfAbsentUntil` using per-key retention deadlines.

- [ ] **Step 1: Write the failing memory-retention tests**

```go
func TestMemoryReplayCacheExpiresRetainedEntry(t *testing.T) {
    cache := NewMemoryReplayCache()
    if inserted, err := cache.InsertIfAbsentUntil([]byte("key"), 110, 100); err != nil || !inserted {
        t.Fatalf("insert retained key: inserted=%t err=%v", inserted, err)
    }
    if inserted, err := cache.InsertIfAbsentUntil([]byte("key"), 120, 109); err != nil || inserted {
        t.Fatalf("duplicate before expiry: inserted=%t err=%v", inserted, err)
    }
    if inserted, err := cache.InsertIfAbsentUntil([]byte("key"), 130, 110); err != nil || !inserted {
        t.Fatalf("expired key was retained: inserted=%t err=%v", inserted, err)
    }
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `GOCACHE=/private/tmp/aurora-gocache go test -count=1 -run '^TestMemoryReplayCacheExpiresRetainedEntry$' ./admission`

Expected: FAIL because the retention capability does not exist.

- [ ] **Step 3: Implement the bounded in-memory capability**

```go
type RetentionReplayCache interface {
    InsertIfAbsentUntil(key []byte, retainUntilUnix, nowUnix uint64) (bool, error)
}

func InsertIfAbsentRetained(cache ReplayCache, key []byte, retainUntilUnix, nowUnix uint64) (bool, error) {
    retained, ok := cache.(RetentionReplayCache)
    if !ok {
        return false, fmt.Errorf("admission: replay cache does not support retention")
    }
    return retained.InsertIfAbsentUntil(key, retainUntilUnix, nowUnix)
}
```

Store entries as `map[string]uint64`, remove an entry when its nonzero deadline is at or before `nowUnix`, and retain `InsertIfAbsent` as permanent compatibility behavior. Add `replayCacheRetentionGraceSeconds = 10 * 60`; reject zero and overflowed deadline inputs.

- [ ] **Step 4: Run package tests**

Run: `GOCACHE=/private/tmp/aurora-gocache go test -count=1 ./admission`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add admission/replay_cache.go admission/replay_cache_test.go
git commit -m "Add replay cache retention contract"
```

### Task 2: Implement a Durable Retention Cache

**Files:**
- Create: `admission/replay_cache_retention.go`
- Create: `admission/replay_cache_retention_unix.go`
- Create: `admission/replay_cache_retention_windows.go`
- Create: `admission/replay_cache_retention_test.go`

**Interfaces:**
- Consumes: `RetentionReplayCache`, `ReplayCache`, and deadline helpers.
- Produces: `RetentionFileReplayCache` implementing `ReplayCache`, `RetentionReplayCache`, `io.Closer`, and `Durable() bool`.
- Produces: `NewRetentionFileReplayCacheAt(directory *os.File, name string, nowUnix uint64) (*RetentionFileReplayCache, error)`; ownership of `directory` transfers on success.

- [ ] **Step 1: Write failing durable-cache tests**

```go
func TestRetentionFileReplayCacheCompactsExpiredEntries(t *testing.T) {
    cache := openRetentionCacheAt(t, "replay.log", 100)
    defer cache.Close()
    mustInsertRetained(t, cache, []byte("expired"), 101, 100)
    mustInsertRetained(t, cache, []byte("live"), 200, 101)
    mustInsertRetained(t, cache, []byte("next"), 300, 102)
    if cache.Has([]byte("expired")) { t.Fatal("expired key remained resident") }
    if !cache.Has([]byte("live")) || !cache.Has([]byte("next")) {
        t.Fatal("live keys were lost")
    }
}
```

Also add tests that a legacy one-field record remains duplicate, malformed expiry data prevents opening, and two live cache instances reject the same inserted key.

- [ ] **Step 2: Run the durable-cache tests to verify they fail**

Run: `GOCACHE=/private/tmp/aurora-gocache go test -count=1 -run '^TestRetentionFileReplayCache' ./admission`

Expected: FAIL because `RetentionFileReplayCache` does not exist.

- [ ] **Step 3: Implement expiry-bearing records**

Use `hex-key<TAB>retain-until-unix<NEWLINE>`. Parse legacy one-field records as `math.MaxUint64`. Reject malformed keys, noncanonical timestamps, zero timestamps, and unsafe files. Keep a `map[string]uint64` of active entries. `InsertIfAbsentUntil` must reject retention at or before the supplied current time.

- [ ] **Step 4: Implement stable locking and compaction**

Hold an exclusive lock on `<name>.lock` for every reload, duplicate decision, append, and compaction. Reopen the data file only after locking. When expired records exist, write active entries to `<name>.compact` using descriptor-relative no-follow creation, sync it, rename it over the data entry, and sync the parent directory. Unix helpers must use `openat`, `renameat`, `unlinkat`, `O_NOFOLLOW`, and `O_CLOEXEC`; Windows helpers use the existing locking abstraction without Unix permission claims.

- [ ] **Step 5: Run durable tests with race detection**

Run: `GOCACHE=/private/tmp/aurora-gocache go test -race -count=1 ./admission`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add admission/replay_cache_retention.go admission/replay_cache_retention_unix.go admission/replay_cache_retention_windows.go admission/replay_cache_retention_test.go
git commit -m "Bound durable replay cache retention"
```

### Task 3: Propagate Authenticated Retention Deadlines

**Files:**
- Modify: `admission/access_hint.go`
- Modify: `admission/replay.go`
- Modify: `admission/admission_test.go`
- Modify: `admission/replay_cache_test.go`
- Modify: `handshake/relay.go`
- Modify: `handshake/relay_test.go`

**Interfaces:**
- Consumes: `InsertIfAbsentRetained`, `RetentionDeadline`, and `MaximumRetentionDeadline`.
- Changes: `VerifyAndSpendAccessHintAt` adds `epochValidUntilUnix uint64` after `nowUnix`.
- Changes: `ReplayVerificationInput` adds `ReplayEpochValidUntilUnix uint64` and `RelayEpochValidUntilUnix uint64`.

- [ ] **Step 1: Write failing deadline-propagation tests**

```go
func TestVerifyAndSpendAccessHintUsesEpochRetention(t *testing.T) {
    cache := &recordingRetentionCache{}
    credential := validAccessHintCredential(200)
    if err := VerifyAndSpendAccessHintAt(cache, credential, binding, nonce, hint, 100, 300); err != nil {
        t.Fatal(err)
    }
    if cache.retainUntil != 900 {
        t.Fatalf("hint retention = %d, want 900", cache.retainUntil)
    }
}
```

Add a replay test with token expiry 200, replay epoch expiry 300, relay epoch expiry 400, and current time 100; assert the token insert retains through 800 and the bootstrap insert retains through 1000.

- [ ] **Step 2: Run focused tests to verify they fail**

Run: `GOCACHE=/private/tmp/aurora-gocache go test -count=1 -run '^(TestVerifyAndSpendAccessHintUsesEpochRetention|TestVerifyAndSpendReplayUsesMaximumRetention)$' ./admission`

Expected: FAIL because admission still calls unbounded inserts.

- [ ] **Step 3: Replace security-critical unbounded inserts**

Call `InsertIfAbsentRetained` only after all MAC, structural, and context validation succeeds. Use `MaximumRetentionDeadline(credential.ExpiryUnix, epochValidUntilUnix)` for hints, `RetentionDeadline(proof.ExpiryUnix)` for tokens, and `MaximumRetentionDeadline(proof.ExpiryUnix, replayEpochValidUntilUnix, relayEpochValidUntilUnix)` for bootstrap keys.

- [ ] **Step 4: Pass descriptor deadlines from the relay**

In `RelayDriver.Begin`, pass `descriptor.EpochValidUntilUnix` to access-hint spending. In `RelayHandshake.Finish`, populate both replay and relay epoch deadlines from the verified descriptor. Reject zero or expired deadline inputs before cache mutation.

- [ ] **Step 5: Update test cache implementations and run tests**

Make recording and failing caches implement `InsertIfAbsentUntil` while preserving intended error behavior. Update direct `ReplayVerificationInput` fixtures with future verified deadlines.

Run: `GOCACHE=/private/tmp/aurora-gocache go test -count=1 ./admission ./handshake`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add admission/access_hint.go admission/replay.go admission/admission_test.go admission/replay_cache_test.go handshake/relay.go handshake/relay_test.go
git commit -m "Retain replay state through verified deadlines"
```

### Task 4: Wire Bounded Caches Into the Linux Production Server

**Files:**
- Modify: `cmd/aurorad/production.go`
- Modify: `cmd/aurorad/production_test.go`
- Modify: `cmd/aurorad/command_test.go`

**Interfaces:**
- Consumes: `NewRetentionFileReplayCacheAt`.
- Produces: `openProductionCaches` creating three `*admission.RetentionFileReplayCache` values.

- [ ] **Step 1: Write the failing production wiring test**

```go
func TestNewProductionServiceUsesRetentionReplayCaches(t *testing.T) {
    service, caches, err := newProductionService(newProductionCommandFixture(t))
    if err != nil || service == nil { t.Fatalf("new production service: service=%v err=%v", service, err) }
    defer closeProductionCaches(caches)
    for _, cache := range caches {
        if _, ok := cache.(*admission.RetentionFileReplayCache); !ok {
            t.Fatalf("production cache type = %T", cache)
        }
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `GOCACHE=/private/tmp/aurora-gocache go test -count=1 -run '^TestNewProductionServiceUsesRetentionReplayCaches$' ./cmd/aurorad`

Expected: FAIL because production opens the unbounded file cache.

- [ ] **Step 3: Transfer directory-descriptor ownership safely**

Keep the validated parent directory descriptor open only after cache construction succeeds; transfer it to `RetentionFileReplayCache`. On every error path, close the directory and all previously opened caches. Replace production relay-driver assertions with the retention cache type.

- [ ] **Step 4: Add legacy-startup coverage and run package tests**

Create a fixture with a one-field legacy record in each cache, build the service, and assert startup succeeds. The legacy entry must remain unexpired.

Run: `GOCACHE=/private/tmp/aurora-gocache go test -count=1 ./cmd/aurorad`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/aurorad/production.go cmd/aurorad/production_test.go cmd/aurorad/command_test.go
git commit -m "Use bounded replay caches in production"
```

### Task 5: Full Verification and Review

**Files:**
- Review: all files modified by Tasks 1-4

- [ ] **Step 1: Run full standard tests**

Run: `GOCACHE=/private/tmp/aurora-gocache go test -count=1 -p 1 ./...`

Expected: PASS.

- [ ] **Step 2: Run laboratory tests**

Run: `GOCACHE=/private/tmp/aurora-gocache go test -count=1 -tags lab -p 1 ./...`

Expected: PASS.

- [ ] **Step 3: Run race, static, and Linux checks**

Run: `GOCACHE=/private/tmp/aurora-gocache go test -race -count=1 ./admission ./handshake ./cmd/aurorad`

Run: `GOCACHE=/private/tmp/aurora-gocache go vet ./...`

Run: `GOCACHE=/private/tmp/aurora-gocache GOOS=linux GOARCH=amd64 go build -o /private/tmp/aurorad-replay-cache-check ./cmd/aurorad`

Expected: PASS.

- [ ] **Step 4: Run acceptance gates**

Run: `GOCACHE=/private/tmp/aurora-gocache go run ./cmd/auroractl p0-p11-check`

Expected: all gates pass.

- [ ] **Step 5: Review and publish**

Run: `git diff --check main...HEAD`

Verify that every deadline derives from verified credential or descriptor data, unsupported caches fail closed, legacy entries remain permanent, and no filesystem operation follows an unvalidated link.

```bash
git push --set-upstream origin feature/replay-cache-retention
gh pr create --repo aurora-protocol/aurora-core --draft --base main --head feature/replay-cache-retention --title "Bound durable replay cache retention"
```

Wait for the Ubuntu, Windows, macOS, and production-evidence jobs. Merge only after every job is successful and the pull request reports a clean merge state.

## Self-Review

- [x] The plan covers authenticated spent-hint, spent-token, and bootstrap retention windows.
- [x] The plan preserves token-spent replay authority and keeps bootstrap state secondary.
- [x] The plan covers migration from key-only files without reopening spent credentials.
- [x] The plan covers atomic filesystem behavior, descriptor ownership, unsafe-link rejection, and cross-process duplicate decisions.
- [x] The plan uses consistent retention-cache interface names and contains no placeholder steps or protocol-version text.
