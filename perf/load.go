package perf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/server"
)

const rssSampleInterval = 10 * time.Millisecond

type LoadOptions struct {
	Requests     int           `json:"requests"`
	Concurrency  int           `json:"concurrency"`
	PacketBytes  int           `json:"packet_bytes"`
	RequestLimit time.Duration `json:"request_limit"`
}

type LoadReport struct {
	Passed    bool `json:"passed"`
	Requested int  `json:"requested"`
	Completed int  `json:"completed"`
	Errors    int  `json:"errors"`
	// BytesSent is the number of request-body bytes consumed by the HTTP
	// transport. It does not claim kernel or peer delivery.
	BytesSent         uint64        `json:"bytes_sent"`
	BytesReceived     uint64        `json:"bytes_received"`
	Duration          time.Duration `json:"duration_ns"`
	RequestsPerSecond float64       `json:"requests_per_second"`
	LatencyP50        time.Duration `json:"latency_p50_ns"`
	LatencyP95        time.Duration `json:"latency_p95_ns"`
	LatencyP99        time.Duration `json:"latency_p99_ns"`
	HeapAllocBefore   uint64        `json:"heap_alloc_before"`
	HeapAllocAfter    uint64        `json:"heap_alloc_after"`
	TotalAllocated    uint64        `json:"total_allocated"`
	GoroutinesBefore  int           `json:"goroutines_before"`
	GoroutinesAfter   int           `json:"goroutines_after"`
	PeakRSSBytes      uint64        `json:"peak_rss_bytes"`
	RSSAvailable      bool          `json:"rss_available"`
}

type latencySummary struct {
	P50 time.Duration
	P95 time.Duration
	P99 time.Duration
}

func RunCarrierLoad(ctx context.Context, client *http.Client, endpoint string, options LoadOptions) (LoadReport, error) {
	if err := validateLoadInputs(client, endpoint, options); err != nil {
		return LoadReport{}, err
	}
	if ctx == nil {
		return LoadReport{}, fmt.Errorf("perf: context is required")
	}

	requestBody, err := carrierLoadRequest(options.PacketBytes)
	if err != nil {
		return LoadReport{}, err
	}

	var memoryBefore runtime.MemStats
	runtime.ReadMemStats(&memoryBefore)
	report := LoadReport{
		Requested:        options.Requests,
		HeapAllocBefore:  memoryBefore.HeapAlloc,
		GoroutinesBefore: runtime.NumGoroutine(),
	}
	stopRSS := startRSSSampler()
	started := time.Now()

	workerCount := min(options.Concurrency, options.Requests)
	jobs := make(chan int, workerCount)
	results := make(chan carrierLoadResult, workerCount)
	loadClient := *client
	loadClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for range jobs {
				if ctx.Err() != nil {
					return
				}
				result := executeCarrierLoadRequest(ctx, &loadClient, endpoint, requestBody, options.RequestLimit)
				results <- result
			}
		}()
	}
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		defer close(jobs)
		for requestIndex := 0; requestIndex < options.Requests; requestIndex++ {
			select {
			case jobs <- requestIndex:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		<-producerDone
		close(results)
	}()

	latencies := make([]time.Duration, 0, options.Requests)
	for result := range results {
		report.Completed++
		report.BytesSent += result.bytesSent
		report.BytesReceived += result.bytesReceived
		latencies = append(latencies, result.latency)
		if result.err != nil {
			report.Errors++
		}
	}

	report.Duration = measuredDuration(time.Since(started))
	report.PeakRSSBytes, report.RSSAvailable = stopRSS()
	var memoryAfter runtime.MemStats
	runtime.ReadMemStats(&memoryAfter)
	report.HeapAllocAfter = memoryAfter.HeapAlloc
	report.TotalAllocated = memoryAfter.TotalAlloc - memoryBefore.TotalAlloc
	report.GoroutinesAfter = runtime.NumGoroutine()
	percentiles := latencyPercentiles(latencies)
	report.LatencyP50 = percentiles.P50
	report.LatencyP95 = percentiles.P95
	report.LatencyP99 = percentiles.P99
	if report.Duration > 0 {
		report.RequestsPerSecond = float64(report.Completed) / report.Duration.Seconds()
	}
	runErr := ctx.Err()
	report.Passed = report.Completed == report.Requested && report.Errors == 0 && runErr == nil
	if runErr != nil {
		return report, runErr
	}
	if !report.Passed {
		return report, fmt.Errorf("perf: carrier load failed: %d of %d completed requests failed", report.Errors, report.Completed)
	}
	return report, nil
}

func validateLoadInputs(client *http.Client, endpoint string, options LoadOptions) error {
	if client == nil {
		return fmt.Errorf("perf: HTTP client is required")
	}
	if options.Requests < 1 || options.Requests > 1_000_000 {
		return fmt.Errorf("perf: requests must be between 1 and 1000000")
	}
	if options.Concurrency < 1 || options.Concurrency > 1024 {
		return fmt.Errorf("perf: concurrency must be between 1 and 1024")
	}
	if options.PacketBytes < 20 || options.PacketBytes > 65535 {
		return fmt.Errorf("perf: packet bytes must be between 20 and 65535")
	}
	if options.RequestLimit <= 0 {
		return fmt.Errorf("perf: request limit must be positive")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("perf: endpoint must be an HTTP(S) URL")
	}
	return nil
}

type carrierLoadResult struct {
	latency       time.Duration
	bytesSent     uint64
	bytesReceived uint64
	err           error
}

func carrierLoadRequest(packetBytes int) ([]byte, error) {
	packet := make([]byte, packetBytes)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(packetBytes))
	packet[8] = 64
	packet[9] = 17
	batch, err := server.EncodePacketBatch(server.PacketBatch{
		Packets:         [][]byte{packet},
		ProtocolNumbers: []uint16{2},
	})
	if err != nil {
		return nil, fmt.Errorf("perf: encode load packet batch: %w", err)
	}
	return server.EncodeCarrier(server.CarrierPacketBatch, batch), nil
}

func executeCarrierLoadRequest(ctx context.Context, client *http.Client, endpoint string, requestBody []byte, requestLimit time.Duration) (result carrierLoadResult) {
	started := time.Now()
	requestCtx, cancel := context.WithTimeout(ctx, requestLimit)
	defer cancel()
	body := newCountingBody(requestBody)
	defer func() {
		result.bytesSent = body.BytesRead()
	}()

	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, body)
	if err != nil {
		_ = body.Close()
		result.err = fmt.Errorf("create request")
		result.latency = measuredDuration(time.Since(started))
		return result
	}
	request.ContentLength = int64(len(requestBody))
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := client.Do(request)
	bodyErr := body.WaitClosed(requestCtx)
	if err != nil {
		result.err = fmt.Errorf("execute request")
		result.latency = measuredDuration(time.Since(started))
		return result
	}
	if bodyErr != nil {
		_ = response.Body.Close()
		result.err = fmt.Errorf("finish request body")
		result.latency = measuredDuration(time.Since(started))
		return result
	}

	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, int64(len(requestBody)+1)))
	result.bytesReceived = uint64(len(responseBody))
	closeErr := response.Body.Close()
	result.latency = measuredDuration(time.Since(started))
	if readErr != nil {
		result.err = fmt.Errorf("read response")
		return result
	}
	if closeErr != nil {
		result.err = fmt.Errorf("close response")
		return result
	}
	if len(responseBody) > len(requestBody) {
		result.err = fmt.Errorf("response exceeds limit")
		return result
	}
	if response.StatusCode != http.StatusOK {
		result.err = fmt.Errorf("unexpected response status")
		return result
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		result.err = fmt.Errorf("unexpected response content type")
		return result
	}
	carrierType, payload, err := server.DecodeCarrier(responseBody)
	if err != nil || carrierType != server.CarrierPacketBatch {
		result.err = fmt.Errorf("invalid carrier response")
		return result
	}
	batch, err := server.DecodePacketBatch(payload)
	if err != nil || len(batch.Packets) != 1 || len(batch.ProtocolNumbers) != 1 || batch.ProtocolNumbers[0] != 2 {
		result.err = fmt.Errorf("invalid packet response")
		return result
	}
	if !bytes.Equal(batch.Packets[0], requestBody[9:]) {
		result.err = fmt.Errorf("packet response mismatch")
	}
	return result
}

type countingBody struct {
	mu        sync.Mutex
	reader    *bytes.Reader
	bytesRead uint64
	closed    bool
	closedCh  chan struct{}
}

func newCountingBody(data []byte) *countingBody {
	return &countingBody{
		reader:   bytes.NewReader(data),
		closedCh: make(chan struct{}),
	}
}

func (b *countingBody) Read(buffer []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, http.ErrBodyReadAfterClose
	}
	n, err := b.reader.Read(buffer)
	b.bytesRead += uint64(n)
	return n, err
}

func (b *countingBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		close(b.closedCh)
	}
	return nil
}

func (b *countingBody) BytesRead() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bytesRead
}

func (b *countingBody) WaitClosed(ctx context.Context) error {
	select {
	case <-b.closedCh:
		return nil
	case <-ctx.Done():
		_ = b.Close()
		return ctx.Err()
	}
}

func startRSSSampler() func() (uint64, bool) {
	stop := make(chan struct{})
	done := make(chan rssSample, 1)
	go func() {
		ticker := time.NewTicker(rssSampleInterval)
		defer ticker.Stop()
		peak, available := processRSSBytes()
		for {
			select {
			case <-ticker.C:
				current, ok := processRSSBytes()
				available = available || ok
				if ok && current > peak {
					peak = current
				}
			case <-stop:
				current, ok := processRSSBytes()
				available = available || ok
				if ok && current > peak {
					peak = current
				}
				done <- rssSample{bytes: peak, available: available}
				return
			}
		}
	}()
	var once sync.Once
	var sample rssSample
	return func() (uint64, bool) {
		once.Do(func() {
			close(stop)
			sample = <-done
		})
		return sample.bytes, sample.available
	}
}

type rssSample struct {
	bytes     uint64
	available bool
}

func measuredDuration(elapsed time.Duration) time.Duration {
	if elapsed <= 0 {
		return time.Nanosecond
	}
	return elapsed
}

func latencyPercentiles(samples []time.Duration) latencySummary {
	if len(samples) == 0 {
		return latencySummary{}
	}
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	return latencySummary{
		P50: nearestRank(ordered, 50),
		P95: nearestRank(ordered, 95),
		P99: nearestRank(ordered, 99),
	}
}

func nearestRank(ordered []time.Duration, percentile int) time.Duration {
	rank := (percentile*len(ordered) + 99) / 100
	return ordered[rank-1]
}
