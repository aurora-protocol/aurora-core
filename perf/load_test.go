package perf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/server"
)

func TestRunCarrierLoadRejectsUnboundedOptions(t *testing.T) {
	_, err := RunCarrierLoad(context.Background(), http.DefaultClient, "http://127.0.0.1", LoadOptions{})
	if err == nil || !strings.Contains(err.Error(), "requests") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunCarrierLoadValidatesInputs(t *testing.T) {
	valid := LoadOptions{
		Requests:     1,
		Concurrency:  1,
		PacketBytes:  20,
		RequestLimit: time.Second,
	}
	tests := []struct {
		name     string
		client   *http.Client
		endpoint string
		options  LoadOptions
		want     string
	}{
		{name: "nil client", endpoint: "http://127.0.0.1", options: valid, want: "client"},
		{name: "too many requests", client: http.DefaultClient, endpoint: "http://127.0.0.1", options: withRequests(valid, 1_000_001), want: "requests"},
		{name: "zero concurrency", client: http.DefaultClient, endpoint: "http://127.0.0.1", options: withConcurrency(valid, 0), want: "concurrency"},
		{name: "too much concurrency", client: http.DefaultClient, endpoint: "http://127.0.0.1", options: withConcurrency(valid, 1025), want: "concurrency"},
		{name: "packet too small", client: http.DefaultClient, endpoint: "http://127.0.0.1", options: withPacketBytes(valid, 19), want: "packet bytes"},
		{name: "packet too large", client: http.DefaultClient, endpoint: "http://127.0.0.1", options: withPacketBytes(valid, 65536), want: "packet bytes"},
		{name: "non-positive request limit", client: http.DefaultClient, endpoint: "http://127.0.0.1", options: withRequestLimit(valid, 0), want: "request limit"},
		{name: "non-http endpoint", client: http.DefaultClient, endpoint: "ftp://127.0.0.1", options: valid, want: "endpoint"},
		{name: "missing endpoint host", client: http.DefaultClient, endpoint: "https://", options: valid, want: "endpoint"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RunCarrierLoad(context.Background(), tc.client, tc.endpoint, tc.options)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestLatencyPercentilesUseNearestRank(t *testing.T) {
	got := latencyPercentiles([]time.Duration{5, 1, 4, 2, 3})
	if got.P50 != 3 || got.P95 != 5 || got.P99 != 5 {
		t.Fatalf("percentiles = %+v", got)
	}
}

func TestRunCarrierLoadCompletesBoundedHarnessLoad(t *testing.T) {
	harness, err := server.NewHarnessHandler(server.HarnessOptions{NowUnix: 1_700_000_000})
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	var active atomic.Int32
	var peakActive atomic.Int32
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for {
			peak := peakActive.Load()
			if current <= peak || peakActive.CompareAndSwap(peak, current) {
				break
			}
		}
		harness.ServeHTTP(w, r)
	}))
	defer testServer.Close()

	report, err := RunCarrierLoad(context.Background(), testServer.Client(), testServer.URL+server.DefaultPacketExchangePath, LoadOptions{
		Requests:     32,
		Concurrency:  4,
		PacketBytes:  128,
		RequestLimit: time.Second,
	})
	if err != nil {
		t.Fatalf("RunCarrierLoad failed: %v", err)
	}
	if !report.Passed || report.Completed != 32 || report.Errors != 0 {
		t.Fatalf("load report = %+v", report)
	}
	if report.Requested != 32 || requests.Load() != 32 {
		t.Fatalf("requested=%d server_requests=%d", report.Requested, requests.Load())
	}
	if peakActive.Load() > 4 {
		t.Fatalf("peak concurrency = %d", peakActive.Load())
	}
	if report.BytesSent == 0 || report.BytesReceived == 0 {
		t.Fatalf("byte counts = sent %d received %d", report.BytesSent, report.BytesReceived)
	}
	if report.LatencyP50 <= 0 || report.LatencyP50 > report.LatencyP95 || report.LatencyP95 > report.LatencyP99 {
		t.Fatalf("latencies = p50 %s p95 %s p99 %s", report.LatencyP50, report.LatencyP95, report.LatencyP99)
	}
	if report.Duration <= 0 || report.RequestsPerSecond <= 0 {
		t.Fatalf("duration=%s requests_per_second=%f", report.Duration, report.RequestsPerSecond)
	}
	if report.HeapAllocBefore == 0 || report.HeapAllocAfter == 0 || report.TotalAllocated == 0 {
		t.Fatalf("heap metrics = before %d after %d total %d", report.HeapAllocBefore, report.HeapAllocAfter, report.TotalAllocated)
	}
	if report.GoroutinesBefore <= 0 || report.GoroutinesAfter <= 0 {
		t.Fatalf("goroutine metrics = before %d after %d", report.GoroutinesBefore, report.GoroutinesAfter)
	}
	if report.RSSAvailable && report.PeakRSSBytes == 0 {
		t.Fatalf("RSS metrics = available %t peak %d", report.RSSAvailable, report.PeakRSSBytes)
	}
	if !report.RSSAvailable && report.PeakRSSBytes != 0 {
		t.Fatalf("unavailable RSS reported peak %d", report.PeakRSSBytes)
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), testServer.URL) {
		t.Fatalf("report leaked endpoint: %s", encoded)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"endpoint", "packet", "packet_data", "request_body", "response_body"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("report leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestRunCarrierLoadAcceptsFullCarrierEndpoint(t *testing.T) {
	harness, err := server.NewHarnessHandler(server.HarnessOptions{NowUnix: 1_700_000_000})
	if err != nil {
		t.Fatal(err)
	}
	testServer := httptest.NewServer(harness)
	defer testServer.Close()

	report, err := RunCarrierLoad(context.Background(), testServer.Client(), testServer.URL+server.DefaultPacketExchangePath, LoadOptions{
		Requests:     1,
		Concurrency:  1,
		PacketBytes:  20,
		RequestLimit: time.Second,
	})
	if err != nil || !report.Passed || report.Completed != 1 {
		t.Fatalf("report=%+v error=%v", report, err)
	}
}

func TestRunCarrierLoadReturnsPromptlyWhenCanceled(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer testServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, err := RunCarrierLoad(ctx, testServer.Client(), testServer.URL, LoadOptions{
		Requests:     32,
		Concurrency:  4,
		PacketBytes:  128,
		RequestLimit: 5 * time.Second,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation error, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("canceled load returned after %s", elapsed)
	}
}

func TestRunCarrierLoadCancelsInFlightWorkers(t *testing.T) {
	const concurrency = 4
	started := make(chan struct{}, concurrency)
	var active atomic.Int32
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer testServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		report LoadReport
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		report, err := RunCarrierLoad(ctx, testServer.Client(), testServer.URL, LoadOptions{
			Requests:     1_000,
			Concurrency:  concurrency,
			PacketBytes:  128,
			RequestLimit: 5 * time.Second,
		})
		done <- outcome{report: report, err: err}
	}()

	for i := 0; i < concurrency; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("workers did not reach the server")
		}
	}
	cancel()

	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("report=%+v error=%v", got.report, got.err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("canceled load did not return promptly")
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := active.Load(); got != 0 {
		t.Fatalf("active server requests after return = %d", got)
	}
}

func TestRunCarrierLoadAppliesRequestLimit(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer testServer.Close()

	started := time.Now()
	report, err := RunCarrierLoad(context.Background(), testServer.Client(), testServer.URL, LoadOptions{
		Requests:     1,
		Concurrency:  1,
		PacketBytes:  20,
		RequestLimit: 20 * time.Millisecond,
	})
	if err == nil || report.Errors != 1 {
		t.Fatalf("report=%+v error=%v", report, err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("limited request returned after %s", elapsed)
	}
}

func TestRunCarrierLoadCancellationCannotReturnPassingReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/octet-stream"}},
			Body: cancelOnCloseBody{
				ReadCloser: io.NopCloser(bytes.NewReader(body)),
				cancel:     cancel,
			},
			Request: request,
		}, nil
	})}

	report, err := RunCarrierLoad(ctx, client, "http://127.0.0.1/assets/app.bin", LoadOptions{
		Requests:     1,
		Concurrency:  1,
		PacketBytes:  20,
		RequestLimit: time.Second,
	})
	if !errors.Is(err, context.Canceled) || report.Passed {
		t.Fatalf("report=%+v error=%v", report, err)
	}
}

func TestRunCarrierLoadCountsBytesConsumedByTransport(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		buffer := make([]byte, 5)
		if _, err := io.ReadFull(request.Body, buffer); err != nil {
			return nil, err
		}
		return nil, errors.New("transport failure")
	})}

	report, err := RunCarrierLoad(context.Background(), client, "http://127.0.0.1/assets/app.bin", LoadOptions{
		Requests:     1,
		Concurrency:  1,
		PacketBytes:  20,
		RequestLimit: time.Second,
	})
	if err == nil || report.BytesSent != 5 {
		t.Fatalf("report=%+v error=%v", report, err)
	}
}

func TestRunCarrierLoadBoundsResponseRead(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(make([]byte, 1<<20))
	}))
	defer testServer.Close()

	report, err := RunCarrierLoad(context.Background(), testServer.Client(), testServer.URL, LoadOptions{
		Requests:     1,
		Concurrency:  1,
		PacketBytes:  20,
		RequestLimit: time.Second,
	})
	if err == nil || report.Errors != 1 || report.Passed {
		t.Fatalf("report=%+v error=%v", report, err)
	}
	const requestBodyBytes = 20 + 9
	if report.BytesReceived > requestBodyBytes+1 {
		t.Fatalf("read %d response bytes", report.BytesReceived)
	}
}

func TestRunCarrierLoadRejectsInvalidResponses(t *testing.T) {
	wrongPacket := make([]byte, 20)
	wrongPacket[0] = 0x45
	wrongPacket[1] = 1
	encodedBatch, err := server.EncodePacketBatch(server.PacketBatch{
		Packets:         [][]byte{wrongPacket},
		ProtocolNumbers: []uint16{2},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(http.StatusServiceUnavailable)
			},
		},
		{
			name: "content type",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("cover"))
			},
		},
		{
			name: "carrier type",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(server.EncodeCarrier(server.CarrierIssuerMetadataResp, nil))
			},
		},
		{
			name: "packet batch",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(server.EncodeCarrier(server.CarrierPacketBatch, []byte{0}))
			},
		},
		{
			name: "packet mismatch",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(server.EncodeCarrier(server.CarrierPacketBatch, encodedBatch))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testServer := httptest.NewServer(tc.handler)
			defer testServer.Close()

			report, err := RunCarrierLoad(context.Background(), testServer.Client(), testServer.URL, LoadOptions{
				Requests:     1,
				Concurrency:  1,
				PacketBytes:  20,
				RequestLimit: time.Second,
			})
			if err == nil || report.Passed || report.Completed != 1 || report.Errors != 1 {
				t.Fatalf("report=%+v error=%v", report, err)
			}
		})
	}
}

func withRequests(options LoadOptions, requests int) LoadOptions {
	options.Requests = requests
	return options
}

func withConcurrency(options LoadOptions, concurrency int) LoadOptions {
	options.Concurrency = concurrency
	return options
}

func withPacketBytes(options LoadOptions, packetBytes int) LoadOptions {
	options.PacketBytes = packetBytes
	return options
}

func withRequestLimit(options LoadOptions, requestLimit time.Duration) LoadOptions {
	options.RequestLimit = requestLimit
	return options
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b cancelOnCloseBody) Close() error {
	b.cancel()
	return b.ReadCloser.Close()
}
