# Aurora Evidence Floor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add repeatable latency, allocation, memory, load, coverage, race, fuzz, and vulnerability evidence for the current Linux server and portable protocol hot paths.

**Architecture:** Benchmarks remain next to the packages they measure so they can use representative package fixtures without exporting test-only APIs. A new `perf` load runner drives the existing live packet carrier through `net/http`, returns a JSON-safe report, and samples process resource use through small platform files. `auroractl` exposes the load and coverage gates, while a dedicated Linux CI job executes expensive evidence independently of the cross-platform conformance matrix.

**Tech Stack:** Go toolchain, `testing` benchmarks and fuzzing, `net/http`, `runtime.MemStats`, OS process metrics, GitHub Actions, official Go vulnerability tooling.

## Global Constraints

- Do not write a protocol specification version outside the specification repository.
- Do not include names, code, comments, or documentation references from external implementations.
- Do not include user-specific names, paths, credentials, endpoints, or account data.
- Keep all queues, request counts, response bodies, and execution times bounded.
- Benchmark fixtures must exercise canonical production APIs and fail on unexpected errors.
- Metrics and diagnostics must not contain keys, tokens, packet contents, or endpoint URLs.
- Preserve the existing untracked `route/zz_dump_conf_test.go` file without modification.

---

## File Map

- `wire/benchmark_test.go`: canonical varint and reader/encoder microbenchmarks.
- `protocol/benchmark_test.go`: representative frame-block encode/decode benchmarks.
- `crypto/benchmark_test.go`: selected AEAD seal/open benchmarks.
- `packet/benchmark_test.go`: complete packet protector seal/open benchmarks.
- `flow/scheduler_benchmark_test.go`: scheduler enqueue/dequeue allocation benchmark.
- `admission/replay_cache_benchmark_test.go`: in-memory replay insert and duplicate lookup benchmarks.
- `server/benchmark_test.go`: packet-batch/carrier codec and handler exchange benchmarks.
- `perf/load.go`: bounded concurrent live-carrier runner and percentile calculation.
- `perf/load_test.go`: option, success, error, percentile, and cancellation tests.
- `perf/rss_linux.go`: current Linux RSS reader.
- `perf/rss_darwin.go`: current Darwin RSS reader.
- `perf/rss_other.go`: explicit unsupported fallback for other build targets.
- `evidence/coverage.go`: coverage-profile parser and threshold verifier.
- `evidence/coverage_test.go`: malformed, weighted, and threshold tests.
- `cmd/auroractl/main.go`: `load-check` and `coverage-check` command dispatch.
- `cmd/auroractl/main_test.go`: command parsing and output tests.
- `.github/workflows/ci.yml`: isolated production-evidence CI job.

### Task 1: Representative Hot-Path Benchmarks

**Files:**
- Create: `wire/benchmark_test.go`
- Create: `protocol/benchmark_test.go`
- Create: `crypto/benchmark_test.go`
- Create: `packet/benchmark_test.go`
- Create: `flow/scheduler_benchmark_test.go`
- Create: `admission/replay_cache_benchmark_test.go`
- Create: `server/benchmark_test.go`

**Interfaces:**
- Consumes: existing `wire.EncodeVarint`, `wire.DecodeVarint`, `protocol.Encode`, `protocol.DecodeFrameBlock`, `crypto.SealForSuite`, `crypto.OpenForSuite`, `packet.Protector`, `flow.Scheduler`, `admission.MemoryReplayCache`, `server.EncodePacketBatch`, `server.DecodePacketBatch`, and `server.NewHarnessHandler` APIs.
- Produces: named `Benchmark*` entry points consumable by `go test -bench` and CI.

- [ ] **Step 1: Add the wire and protocol benchmarks**

Use table sub-benchmarks with stable sizes and report allocations:

```go
func BenchmarkVarintRoundTrip(b *testing.B) {
    for _, value := range []uint64{63, 16383, 1073741823, 4611686018427387903} {
        b.Run(fmt.Sprintf("value_%d", value), func(b *testing.B) {
            b.ReportAllocs()
            for i := 0; i < b.N; i++ {
                encoded, err := EncodeVarint(value)
                if err != nil { b.Fatal(err) }
                decoded, n, err := DecodeVarint(encoded)
                if err != nil || decoded != value || n != len(encoded) { b.Fatal("round trip failed") }
            }
        })
    }
}
```

Build the protocol fixture with `NewStreamDataFrame(7, bytes.Repeat([]byte{0x5a}, 1200), 0)` inside a one-frame `FrameBlock`; benchmark encode and decode separately.

- [ ] **Step 2: Run the wire and protocol benchmarks**

Run: `go test -run '^$' -bench . -benchmem ./wire ./protocol`

Expected: every new benchmark passes and prints `ns/op`, `B/op`, and `allocs/op`.

- [ ] **Step 3: Add crypto and packet benchmarks**

Benchmark AES-GCM and ChaCha seal/open with a 1200-byte payload. Reuse the key, nonce, AAD, and pre-sealed ciphertext outside the measured loop. For packet sealing, reset only `Protector.NextPacket` when a stable packet number is required and validate every returned error.

```go
b.Run("seal_1200", func(b *testing.B) {
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        if _, err := SealForSuite(suite, key, nonce, aad, plaintext); err != nil {
            b.Fatal(err)
        }
    }
})
```

- [ ] **Step 4: Add scheduler, replay, and server benchmarks**

For scheduler iterations, construct a bounded scheduler, enqueue one 1200-byte chunk, and dequeue it. For replay inserts, derive a unique 32-byte key from the iteration counter; benchmark duplicate `Has` separately. For the server, benchmark packet-batch encode/decode and an in-process packet carrier request using a prebuilt valid IPv4 packet.

- [ ] **Step 5: Run all benchmarks once as a health gate**

Run: `go test -run '^$' -bench . -benchtime=1x -benchmem ./...`

Expected: at least one benchmark runs in each of the seven target packages and the command exits successfully.

- [ ] **Step 6: Commit the benchmark suite**

```bash
git add wire/benchmark_test.go protocol/benchmark_test.go crypto/benchmark_test.go packet/benchmark_test.go flow/scheduler_benchmark_test.go admission/replay_cache_benchmark_test.go server/benchmark_test.go
git commit -m "test: add protocol performance baselines"
```

### Task 2: Bounded Live Carrier Load Runner

**Files:**
- Create: `perf/load.go`
- Create: `perf/load_test.go`
- Create: `perf/rss_linux.go`
- Create: `perf/rss_darwin.go`
- Create: `perf/rss_other.go`

**Interfaces:**
- Consumes: `server.DefaultPacketExchangePath`, `server.EncodeCarrier`, `server.DecodeCarrier`, `server.EncodePacketBatch`, and `server.DecodePacketBatch`.
- Produces: `func RunCarrierLoad(context.Context, *http.Client, string, LoadOptions) (LoadReport, error)` and JSON-safe `LoadOptions`/`LoadReport` types.

- [ ] **Step 1: Write failing option and percentile tests**

```go
func TestRunCarrierLoadRejectsUnboundedOptions(t *testing.T) {
    _, err := RunCarrierLoad(context.Background(), http.DefaultClient, "http://127.0.0.1", LoadOptions{})
    if err == nil || !strings.Contains(err.Error(), "requests") { t.Fatalf("unexpected error: %v", err) }
}

func TestLatencyPercentilesUseNearestRank(t *testing.T) {
    got := latencyPercentiles([]time.Duration{5, 1, 4, 2, 3})
    if got.P50 != 3 || got.P95 != 5 || got.P99 != 5 { t.Fatalf("percentiles = %+v", got) }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./perf -run 'TestRunCarrierLoadRejectsUnboundedOptions|TestLatencyPercentilesUseNearestRank'`

Expected: FAIL because the load types and functions do not exist.

- [ ] **Step 3: Implement options, report, validation, and percentiles**

```go
type LoadOptions struct {
    Requests     int           `json:"requests"`
    Concurrency  int           `json:"concurrency"`
    PacketBytes  int           `json:"packet_bytes"`
    RequestLimit time.Duration `json:"request_limit"`
}

type LoadReport struct {
    Passed             bool          `json:"passed"`
    Requested          int           `json:"requested"`
    Completed          int           `json:"completed"`
    Errors             int           `json:"errors"`
    BytesSent          uint64        `json:"bytes_sent"`
    BytesReceived      uint64        `json:"bytes_received"`
    Duration           time.Duration `json:"duration_ns"`
    RequestsPerSecond  float64       `json:"requests_per_second"`
    LatencyP50         time.Duration `json:"latency_p50_ns"`
    LatencyP95         time.Duration `json:"latency_p95_ns"`
    LatencyP99         time.Duration `json:"latency_p99_ns"`
    HeapAllocBefore    uint64        `json:"heap_alloc_before"`
    HeapAllocAfter     uint64        `json:"heap_alloc_after"`
    TotalAllocated     uint64        `json:"total_allocated"`
    GoroutinesBefore   int           `json:"goroutines_before"`
    GoroutinesAfter    int           `json:"goroutines_after"`
    PeakRSSBytes       uint64        `json:"peak_rss_bytes"`
    RSSAvailable       bool          `json:"rss_available"`
}
```

Reject requests outside `1..1_000_000`, concurrency outside `1..1024`, packet sizes outside `20..65535`, non-positive request limits, nil clients, and non-HTTP(S) endpoints.

- [ ] **Step 4: Write the failing successful-load and cancellation tests**

Start an `httptest.Server` with `server.NewHarnessHandler`, execute 32 requests at concurrency 4, and assert `Passed`, `Completed == 32`, `Errors == 0`, positive byte counts, ordered percentiles, and no endpoint or packet data in marshaled JSON. Add a canceled-context case and assert prompt return with a non-nil error.

- [ ] **Step 5: Implement the bounded worker pool and resource sampler**

Prebuild one valid carrier body. Feed exactly `Requests` indices through a buffered jobs channel capped at `Concurrency`. Each worker creates a request with `http.NewRequestWithContext`, applies `RequestLimit`, limits the response body, validates status/content type/carrier type/packet response, and emits one fixed-size result. Sample RSS every 10 milliseconds until all workers stop. Never retain response bodies after validation.

- [ ] **Step 6: Add platform RSS readers**

On Linux, parse the resident-page field from `/proc/self/statm` and multiply by `os.Getpagesize()`. On Darwin, call `syscall.Getrusage(syscall.RUSAGE_SELF, &usage)` and read `usage.Maxrss`. Other targets return `(0, false)` without failing the load run.

- [ ] **Step 7: Run load tests with race detection**

Run: `go test -race ./perf`

Expected: PASS with no race report and no leaked server request.

- [ ] **Step 8: Commit the load runner**

```bash
git add perf/load.go perf/load_test.go perf/rss_linux.go perf/rss_darwin.go perf/rss_other.go
git commit -m "feat: add bounded carrier load evidence"
```

### Task 3: Load and Coverage Commands

**Files:**
- Create: `evidence/coverage.go`
- Create: `evidence/coverage_test.go`
- Modify: `cmd/auroractl/main.go`
- Modify: `cmd/auroractl/main_test.go`

**Interfaces:**
- Consumes: `perf.RunCarrierLoad` and standard Go `coverprofile` files.
- Produces: `auroractl load-check` JSON output, `auroractl coverage-check`, and `func VerifyCoverage(io.Reader, float64) (CoverageReport, error)`.

- [ ] **Step 1: Write failing weighted coverage tests**

```go
func TestVerifyCoverageWeightsStatementCounts(t *testing.T) {
    profile := "mode: atomic\na.go:1.1,2.1 8 1\na.go:3.1,4.1 2 0\n"
    report, err := VerifyCoverage(strings.NewReader(profile), 79)
    if err != nil { t.Fatal(err) }
    if !report.Passed || report.CoveredStatements != 8 || report.TotalStatements != 10 || report.Percent != 80 { t.Fatalf("report = %+v", report) }
}
```

Add malformed-header, malformed-row, zero-statement, and below-threshold cases.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./evidence`

Expected: FAIL because `VerifyCoverage` is undefined.

- [ ] **Step 3: Implement the coverage parser**

Parse the mode header exactly, scan each row with `fmt.Sscanf` or a focused field parser, weight covered and total counts by each row's statement count, reject negative/invalid counts, and return:

```go
type CoverageReport struct {
    Passed            bool    `json:"passed"`
    CoveredStatements uint64  `json:"covered_statements"`
    TotalStatements   uint64  `json:"total_statements"`
    Percent           float64 `json:"percent"`
    MinimumPercent    float64 `json:"minimum_percent"`
}
```

- [ ] **Step 4: Write failing command tests**

For `load-check`, use an `httptest.Server` and assert valid JSON with `passed=true`, plus rejection of missing `--url`. For `coverage-check`, write a temporary profile and assert one concise machine-readable line for pass and a returned error below threshold.

- [ ] **Step 5: Implement command parsing and output**

Add `load-check` and `coverage-check` to dispatch and usage. Parse each command with a private `flag.FlagSet`. Defaults are 200 requests, concurrency 8, 1200 packet bytes, 5-second per-request limit, and a 70 percent coverage floor. `load-check` uses a 30-second parent context and `coverage-check` never modifies the profile.

- [ ] **Step 6: Run command and package tests**

Run: `go test -race ./evidence ./perf ./cmd/auroractl`

Expected: PASS.

- [ ] **Step 7: Commit the evidence commands**

```bash
git add evidence/coverage.go evidence/coverage_test.go cmd/auroractl/main.go cmd/auroractl/main_test.go
git commit -m "feat: expose load and coverage evidence gates"
```

### Task 4: Production Evidence CI Job

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: benchmarks from Task 1, `auroractl load-check`, `auroractl coverage-check`, the protocol fuzz target, and the official vulnerability action.
- Produces: a dedicated `production-evidence` job with uploaded coverage and benchmark artifacts.

- [ ] **Step 1: Add the isolated Linux evidence job**

Use `ubuntu-latest`, `actions/checkout`, and `actions/setup-go` matching the existing workflow. Add steps in this order:

```yaml
- name: Race test
  run: go test -race ./...
- name: Coverage floor
  run: |
    go test -covermode=atomic -coverprofile=coverage.out ./...
    go run ./cmd/auroractl coverage-check --profile coverage.out --minimum 70
- name: Protocol fuzz smoke
  run: go test ./protocol -run '^$' -fuzz '^FuzzDecodeProtocolStructs$' -fuzztime=10s
- name: Benchmark health
  run: go test -run '^$' -bench . -benchtime=1x -benchmem ./... | tee benchmarks.txt
```

- [ ] **Step 2: Add a real-process load smoke**

Build `aurorad` and `auroractl`, start `aurorad` on `127.0.0.1:19443`, poll an ordinary cover path until it is reachable, run 200 requests with concurrency 8 and 1200-byte packets, and always terminate the server with a shell trap.

```yaml
- name: Live server load smoke
  shell: bash
  run: |
    go build -o "$RUNNER_TEMP/aurorad" ./cmd/aurorad
    go build -o "$RUNNER_TEMP/auroractl" ./cmd/auroractl
    "$RUNNER_TEMP/aurorad" --listen 127.0.0.1:19443 >"$RUNNER_TEMP/aurorad.log" 2>&1 &
    server_pid=$!
    trap 'kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true' EXIT
    for attempt in $(seq 1 50); do
      curl --fail --silent http://127.0.0.1:19443/cover >/dev/null && break
      sleep 0.1
    done
    "$RUNNER_TEMP/auroractl" load-check --url http://127.0.0.1:19443/assets/app.bin --requests 200 --concurrency 8 --packet-bytes 1200 --request-limit 5s
```

- [ ] **Step 3: Add vulnerability scanning and evidence artifacts**

Pin the official Go vulnerability action to its reviewed commit. Upload `coverage.out` and `benchmarks.txt` with a short retention period using a pinned official artifact action. Do not upload server logs unless the job fails, and keep the log free of carrier bodies.

- [ ] **Step 4: Validate workflow syntax and all local gates**

Run:

```bash
go test ./...
go test -race ./...
go test -covermode=atomic -coverprofile=/tmp/aurora-coverage.out ./...
go run ./cmd/auroractl coverage-check --profile /tmp/aurora-coverage.out --minimum 70
go test ./protocol -run '^$' -fuzz '^FuzzDecodeProtocolStructs$' -fuzztime=10s
go test -run '^$' -bench . -benchtime=1x -benchmem ./...
```

Expected: every command exits zero, coverage is at least 70 percent, the fuzz target completes its bounded run, and benchmarks execute in all seven target packages.

- [ ] **Step 5: Review and commit CI evidence**

Review the full diff for unbounded work, secrets, endpoint leakage, ignored errors, build-tag gaps, race hazards, and prohibited references. Then commit:

```bash
git add .github/workflows/ci.yml
git commit -m "ci: enforce production evidence gates"
```

### Task 5: Stage Verification and Baseline Capture

**Files:**
- Modify only files requiring fixes discovered by verification.

**Interfaces:**
- Consumes: all Stage 1 evidence commands.
- Produces: a clean reviewed branch whose current metrics are visible in command output and CI artifacts.

- [ ] **Step 1: Run formatting and static analysis**

Run: `gofmt -w` on every changed Go file, then `go vet ./...` and `git diff --check`.

Expected: no output from `git diff --check`; vet exits zero.

- [ ] **Step 2: Run full functional and race verification**

Run: `go test ./...` and `go test -race ./...`.

Expected: PASS across every package.

- [ ] **Step 3: Run the local live-process load gate**

Build both commands into a temporary directory, start the server on a loopback ephemeral port selected before launch, wait for readiness, execute `load-check`, save only the JSON report, and terminate the process. Verify `passed=true`, `completed=requested`, `errors=0`, positive throughput, ordered percentiles, and available RSS on Linux or Darwin.

- [ ] **Step 4: Perform a P3+ code review**

Inspect every changed line and the complete command paths. Fix any correctness, security, compatibility, resource-bound, race, or missing-test issue of P3 or higher, then rerun the affected package and full suite.

- [ ] **Step 5: Commit verification fixes if any**

```bash
git add <only-files-fixed-during-review>
git commit -m "fix: harden production evidence gates"
```

- [ ] **Step 6: Push the completed commits**

Run: `git push origin main`

Expected: the public core repository receives only the reviewed design and Stage 1 evidence commits; the preserved untracked route test remains local and uncommitted.
