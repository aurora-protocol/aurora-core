package evidence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/transport"
)

const (
	maxSessionEvidenceDuration       = time.Minute
	maxSessionEvidenceMessages       = 1_000_000
	maxSessionEvidencePayloadBytes   = 1 << 20
	maxSessionEvidenceConcurrency    = 256
	maxSessionEvidenceQueuePackets   = 4096
	maxSessionEvidenceQueueBytes     = 64 << 20
	minSessionEvidenceQueueBytes     = 8 << 10
	sessionEvidenceControlPackets    = 2
	sessionEvidenceControlBytes      = 8 << 10
	sessionEvidencePacketAllowance   = 256
	sessionEvidenceReplayWindow      = 1024
	maxSessionEvidenceRecordBodySize = 0xffffff
)

type SessionOptions struct {
	Duration     time.Duration `json:"duration_ns"`
	Messages     int           `json:"messages"`
	PayloadBytes int           `json:"payload_bytes"`
	Concurrency  int           `json:"concurrency"`
	QueuePackets int           `json:"queue_packets"`
	QueueBytes   int           `json:"queue_bytes"`
}

type SessionResult struct {
	Passed            bool          `json:"passed"`
	MessagesSent      int           `json:"messages_sent"`
	MessagesReceived  int           `json:"messages_received"`
	PayloadBytes      uint64        `json:"payload_bytes"`
	Duration          time.Duration `json:"duration_ns"`
	MessagesPerSecond float64       `json:"messages_per_second"`
	BytesPerSecond    float64       `json:"bytes_per_second"`
	LatencyP50        time.Duration `json:"latency_p50_ns"`
	LatencyP95        time.Duration `json:"latency_p95_ns"`
	PeakQueuedPackets int           `json:"peak_queued_packets"`
	PeakQueuedBytes   int           `json:"peak_queued_bytes"`
	HeapAllocBefore   uint64        `json:"heap_alloc_before"`
	HeapAllocAfter    uint64        `json:"heap_alloc_after"`
	TotalAllocated    uint64        `json:"total_allocated"`
	// AllocatedPerMessage reports how much the session allocated for each
	// message it carried, which is the figure that changes when the packet
	// path allocates differently.
	AllocatedPerMessage float64 `json:"allocated_per_message"`
	GoroutinesBefore    int     `json:"goroutines_before"`
	GoroutinesAfter   int           `json:"goroutines_after"`
	GoroutineDelta    int           `json:"goroutine_delta"`
	Errors            int           `json:"errors"`
}

func RunSession(ctx context.Context, options SessionOptions) (SessionResult, error) {
	if ctx == nil {
		return SessionResult{}, fmt.Errorf("session evidence: nil context")
	}
	if err := validateSessionOptions(options); err != nil {
		return SessionResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return SessionResult{Errors: 1}, err
	}

	var memoryBefore runtime.MemStats
	runtime.ReadMemStats(&memoryBefore)
	result := SessionResult{
		HeapAllocBefore:  memoryBefore.HeapAlloc,
		GoroutinesBefore: runtime.NumGoroutine(),
	}
	client, relay, err := newSessionEvidencePair(options)
	if err != nil {
		result.Errors = 1
		return result, err
	}
	clientToRelayReader, clientToRelayWriter := io.Pipe()
	relayToClientReader, relayToClientWriter := io.Pipe()
	runCtx, cancel := context.WithTimeout(ctx, options.Duration)
	state := newSessionEvidenceState(options)
	start := time.Now()

	recordMaximum := options.QueueBytes
	if recordMaximum > maxSessionEvidenceRecordBodySize {
		recordMaximum = maxSessionEvidenceRecordBodySize
	}
	pumpResults := make(chan error, 2)
	go func() {
		pumpResults <- transport.RunPacketDuplex(
			runCtx,
			oneByteReadCloser{ReadCloser: relayToClientReader},
			oneByteWriteCloser{WriteCloser: clientToRelayWriter},
			client,
			state.handle,
			uint32(recordMaximum),
		)
	}()
	go func() {
		pumpResults <- transport.RunPacketDuplex(
			runCtx,
			oneByteReadCloser{ReadCloser: clientToRelayReader},
			oneByteWriteCloser{WriteCloser: relayToClientWriter},
			relay,
			state.handle,
			uint32(recordMaximum),
		)
	}()

	senderError := make(chan error, 1)
	sendersDone := make(chan struct{})
	go func() {
		state.runSenders(runCtx, client, relay, senderError)
		close(sendersDone)
	}()

	completed := false
	collectedPumps := 0
	var runErr error
	select {
	case <-state.allReceived:
		completed = true
	case runErr = <-senderError:
	case runErr = <-pumpResults:
		collectedPumps = 1
	case <-runCtx.Done():
		runErr = runCtx.Err()
	}
	cancel()
	<-sendersDone
	for collectedPumps < 2 {
		<-pumpResults
		collectedPumps++
	}
	finish := time.Now()

	var memoryAfter runtime.MemStats
	runtime.ReadMemStats(&memoryAfter)
	result.HeapAllocAfter = memoryAfter.HeapAlloc
	result.TotalAllocated = memoryAfter.TotalAlloc - memoryBefore.TotalAlloc

	clientStats := client.Stats()
	relayStats := relay.Stats()
	result.MessagesSent = int(state.sent.Load())
	result.MessagesReceived = int(state.received.Load())
	result.PayloadBytes = state.receivedBytes.Load()
	result.Duration = finish.Sub(start)
	result.PeakQueuedPackets = clientStats.PeakQueuedPackets + relayStats.PeakQueuedPackets
	result.PeakQueuedBytes = clientStats.PeakQueuedBytes + relayStats.PeakQueuedBytes
	result.LatencyP50, result.LatencyP95 = state.percentiles()
	result.GoroutinesAfter = settledGoroutineCount(result.GoroutinesBefore)
	result.GoroutineDelta = result.GoroutinesAfter - result.GoroutinesBefore
	if result.Duration > 0 {
		seconds := result.Duration.Seconds()
		result.MessagesPerSecond = float64(result.MessagesReceived) / seconds
		result.BytesPerSecond = float64(result.PayloadBytes) / seconds
	}
	if result.MessagesReceived > 0 {
		result.AllocatedPerMessage = float64(result.TotalAllocated) / float64(result.MessagesReceived)
	}

	if !completed && runErr == nil {
		runErr = fmt.Errorf("session evidence: run stopped before completion")
	}
	if runErr == nil && (result.MessagesSent != options.Messages || result.MessagesReceived != options.Messages) {
		runErr = fmt.Errorf("session evidence: message count mismatch")
	}
	wantBytes := uint64(options.Messages) * uint64(options.PayloadBytes)
	if runErr == nil && result.PayloadBytes != wantBytes {
		runErr = fmt.Errorf("session evidence: payload byte count mismatch")
	}
	if runErr != nil {
		result.Errors = 1
		return result, runErr
	}
	result.Passed = true
	return result, nil
}

func validateSessionOptions(options SessionOptions) error {
	if options.Duration <= 0 || options.Duration > maxSessionEvidenceDuration {
		return fmt.Errorf("session evidence: duration must be within (0, %s]", maxSessionEvidenceDuration)
	}
	if options.Messages <= 0 || options.Messages > maxSessionEvidenceMessages {
		return fmt.Errorf("session evidence: invalid message count")
	}
	if options.PayloadBytes <= 0 || options.PayloadBytes > maxSessionEvidencePayloadBytes {
		return fmt.Errorf("session evidence: invalid payload size")
	}
	if options.Concurrency <= 0 || options.Concurrency > maxSessionEvidenceConcurrency {
		return fmt.Errorf("session evidence: invalid concurrency")
	}
	if options.QueuePackets <= sessionEvidenceControlPackets || options.QueuePackets > maxSessionEvidenceQueuePackets {
		return fmt.Errorf("session evidence: invalid queue packet limit")
	}
	if options.QueueBytes <= minSessionEvidenceQueueBytes || options.QueueBytes > maxSessionEvidenceQueueBytes {
		return fmt.Errorf("session evidence: invalid queue byte limit")
	}
	dataBytes := options.QueueBytes - sessionEvidenceControlBytes
	if options.PayloadBytes > dataBytes-sessionEvidencePacketAllowance {
		return fmt.Errorf("session evidence: payload does not fit data queue")
	}
	return nil
}

type sessionEvidenceState struct {
	options SessionOptions

	mu        sync.Mutex
	sentAt    []time.Time
	seen      []bool
	latencies []time.Duration

	sent          atomic.Int64
	received      atomic.Int64
	receivedBytes atomic.Uint64
	allReceived   chan struct{}
	completeOnce  sync.Once
}

func newSessionEvidenceState(options SessionOptions) *sessionEvidenceState {
	return &sessionEvidenceState{
		options:     options,
		sentAt:      make([]time.Time, options.Messages),
		seen:        make([]bool, options.Messages),
		latencies:   make([]time.Duration, 0, options.Messages),
		allReceived: make(chan struct{}),
	}
}

func (s *sessionEvidenceState) runSenders(ctx context.Context, client, relay *session.Application, errorsOut chan<- error) {
	var next atomic.Int64
	var workers sync.WaitGroup
	var failOnce sync.Once
	fail := func(err error) {
		failOnce.Do(func() { errorsOut <- err })
	}
	for i := 0; i < s.options.Concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				id := int(next.Add(1) - 1)
				if id >= s.options.Messages {
					return
				}
				endpoint := client
				if id%2 != 0 {
					endpoint = relay
				}
				if err := s.queueMessage(ctx, endpoint, id); err != nil {
					fail(err)
					return
				}
			}
		}()
	}
	workers.Wait()
}

func (s *sessionEvidenceState) queueMessage(ctx context.Context, endpoint *session.Application, id int) error {
	payload := bytes.Repeat([]byte{byte(id)}, s.options.PayloadBytes)
	frame, err := protocol.NewStreamDataFrame(uint64(id+1), payload, 0)
	zeroEvidenceBytes(payload)
	if err != nil {
		return err
	}
	defer zeroEvidenceBytes(frame.Payload)
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}
	started := time.Now()
	s.mu.Lock()
	s.sentAt[id] = started
	s.mu.Unlock()
	for {
		err := endpoint.QueueFrames(ctx, block)
		if err == nil {
			s.sent.Add(1)
			return nil
		}
		if !errors.Is(err, session.ErrBackpressure) {
			return err
		}
		timer := time.NewTimer(100 * time.Microsecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *sessionEvidenceState) handle(_ context.Context, block protocol.FrameBlock) error {
	if len(block.Frames) != 1 || block.Frames[0].FrameType != registry.FrameStreamData {
		return fmt.Errorf("session evidence: unexpected frame block")
	}
	frame := block.Frames[0]
	if frame.FlowID == 0 || frame.FlowID > uint64(s.options.Messages) || len(frame.Payload) != s.options.PayloadBytes {
		return fmt.Errorf("session evidence: invalid received message")
	}
	id := int(frame.FlowID - 1)
	for _, value := range frame.Payload {
		if value != byte(id) {
			return fmt.Errorf("session evidence: received payload mismatch")
		}
	}
	now := time.Now()
	s.mu.Lock()
	if s.seen[id] || s.sentAt[id].IsZero() {
		s.mu.Unlock()
		return fmt.Errorf("session evidence: duplicate or unsent message")
	}
	s.seen[id] = true
	s.latencies = append(s.latencies, now.Sub(s.sentAt[id]))
	s.mu.Unlock()
	s.receivedBytes.Add(uint64(len(frame.Payload)))
	if s.received.Add(1) == int64(s.options.Messages) {
		s.completeOnce.Do(func() { close(s.allReceived) })
	}
	return nil
}

func (s *sessionEvidenceState) percentiles() (time.Duration, time.Duration) {
	s.mu.Lock()
	samples := append([]time.Duration(nil), s.latencies...)
	s.mu.Unlock()
	return sessionLatencyPercentiles(samples)
}

func sessionLatencyPercentiles(samples []time.Duration) (time.Duration, time.Duration) {
	if len(samples) == 0 {
		return 0, 0
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return sessionNearestRank(samples, 50), sessionNearestRank(samples, 95)
}

func sessionNearestRank(ordered []time.Duration, percentile int) time.Duration {
	rank := (percentile*len(ordered) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	return ordered[rank-1]
}

func newSessionEvidencePair(options SessionOptions) (*session.Application, *session.Application, error) {
	forward := session.DirectionConfig{
		Direction: 0,
		Secret:    bytes.Repeat([]byte{0x31}, 48),
		Key:       bytes.Repeat([]byte{0x32}, 32),
		IV:        bytes.Repeat([]byte{0x33}, 12),
	}
	backward := session.DirectionConfig{
		Direction: 1,
		Secret:    bytes.Repeat([]byte{0x41}, 48),
		Key:       bytes.Repeat([]byte{0x42}, 32),
		IV:        bytes.Repeat([]byte{0x43}, 12),
	}
	defer destroyEvidenceDirection(&forward)
	defer destroyEvidenceDirection(&backward)
	limits := session.Limits{
		MaxQueuedPackets:       options.QueuePackets,
		MaxQueuedBytes:         options.QueueBytes,
		ControlReservedPackets: sessionEvidenceControlPackets,
		ControlReservedBytes:   sessionEvidenceControlBytes,
		ReplayWindow:           sessionEvidenceReplayWindow,
	}
	client, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 0x51,
		HopLayer:        1,
		Write:           forward,
		Read:            backward,
		Limits:          limits,
	})
	if err != nil {
		return nil, nil, err
	}
	relay, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 0x51,
		HopLayer:        1,
		Write:           backward,
		Read:            forward,
		Limits:          limits,
	})
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	return client, relay, nil
}

type oneByteReadCloser struct{ io.ReadCloser }

func (r oneByteReadCloser) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.ReadCloser.Read(p)
}

type oneByteWriteCloser struct{ io.WriteCloser }

func (w oneByteWriteCloser) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.WriteCloser.Write(p)
}

func destroyEvidenceDirection(direction *session.DirectionConfig) {
	zeroEvidenceBytes(direction.Secret)
	zeroEvidenceBytes(direction.Key)
	zeroEvidenceBytes(direction.IV)
	*direction = session.DirectionConfig{}
}

func zeroEvidenceBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func settledGoroutineCount(baseline int) int {
	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		current := runtime.NumGoroutine()
		if current <= baseline+2 || !time.Now().Before(deadline) {
			return current
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
}
