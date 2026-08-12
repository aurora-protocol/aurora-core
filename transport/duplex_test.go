package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
)

func TestRunPacketDuplexExchangesSimultaneousApplicationPackets(t *testing.T) {
	for _, fragmented := range []bool{false, true} {
		name := "whole writes"
		if fragmented {
			name = "one byte fragments"
		}
		t.Run(name, func(t *testing.T) {
			runPairedPacketDuplex(t, fragmented)
		})
	}
}

func TestRunPacketDuplexCancellationUnblocksIdlePumps(t *testing.T) {
	baseline := runtime.NumGoroutine()
	reader := newBlockingReadCloser()
	writer := &discardWriteCloser{}
	endpoint := newDuplexTestEndpoint()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- RunPacketDuplex(ctx, reader, writer, endpoint, discardFrameBlock, 64)
	}()
	awaitSignal(t, reader.started, "reader start")
	awaitSignal(t, endpoint.nextStarted, "endpoint writer start")
	cancel()

	if err := awaitDuplexResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunPacketDuplex cancellation error = %v, want context.Canceled", err)
	}
	requireDuplexClosedOnce(t, reader.closeCalls.Load(), writer.closeCalls.Load(), endpoint.closeCalls.Load())
	requireGoroutinesSettled(t, baseline)
}

func TestRunPacketDuplexCancellationUnblocksCarrierWrite(t *testing.T) {
	baseline := runtime.NumGoroutine()
	reader := newBlockingReadCloser()
	writer := newBlockingWriteCloser()
	endpoint := newDuplexTestEndpoint()
	endpoint.packets <- []byte("blocked packet")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- RunPacketDuplex(ctx, reader, writer, endpoint, discardFrameBlock, 64)
	}()
	awaitSignal(t, writer.started, "blocked carrier write")
	cancel()

	if err := awaitDuplexResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunPacketDuplex blocked-write cancellation error = %v, want context.Canceled", err)
	}
	requireDuplexClosedOnce(t, reader.closeCalls.Load(), writer.closeCalls.Load(), endpoint.closeCalls.Load())
	requireGoroutinesSettled(t, baseline)
}

func TestRunPacketDuplexRejectsMalformedRecordAndClosesResources(t *testing.T) {
	reader := &countingReadCloser{Reader: bytes.NewReader([]byte{0, 0, 0})}
	writer := &discardWriteCloser{}
	endpoint := newDuplexTestEndpoint()

	err := RunPacketDuplex(context.Background(), reader, writer, endpoint, discardFrameBlock, 64)
	if !errors.Is(err, ErrEmptyRecord) {
		t.Fatalf("RunPacketDuplex malformed record error = %v, want ErrEmptyRecord", err)
	}
	requireDuplexClosedOnce(t, reader.closeCalls.Load(), writer.closeCalls.Load(), endpoint.closeCalls.Load())
}

func TestRunPacketDuplexReturnsHandlerErrorAndDestroysBlocks(t *testing.T) {
	var encoded bytes.Buffer
	recordWriter, err := NewRecordWriter(&encoded, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := recordWriter.Write([]byte("authenticated packet")); err != nil {
		t.Fatal(err)
	}
	reader := &countingReadCloser{Reader: bytes.NewReader(encoded.Bytes())}
	writer := &discardWriteCloser{}
	endpoint := newDuplexTestEndpoint()
	endpoint.handle = func(packet []byte) []protocol.FrameBlock {
		return []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{{
			FrameType: registry.FramePadding,
			Payload:   append([]byte(nil), packet...),
		}}}}
	}
	wantErr := errors.New("handler rejected block")
	var retained []byte
	handler := func(_ context.Context, block protocol.FrameBlock) error {
		retained = block.Frames[0].Payload
		return wantErr
	}

	err = RunPacketDuplex(context.Background(), reader, writer, endpoint, handler, 64)
	if !errors.Is(err, wantErr) {
		t.Fatalf("RunPacketDuplex handler error = %v, want %v", err, wantErr)
	}
	for _, value := range retained {
		if value != 0 {
			t.Fatalf("duplex retained handler block payload")
		}
	}
	requireDuplexClosedOnce(t, reader.closeCalls.Load(), writer.closeCalls.Load(), endpoint.closeCalls.Load())
}

func TestRunPacketDuplexProcessesInboundRecordsInOrder(t *testing.T) {
	var encoded bytes.Buffer
	recordWriter, err := NewRecordWriter(&encoded, 64)
	if err != nil {
		t.Fatal(err)
	}
	for _, packet := range [][]byte{[]byte("first"), []byte("second")} {
		if err := recordWriter.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	reader := &countingReadCloser{Reader: bytes.NewReader(encoded.Bytes())}
	writer := &discardWriteCloser{}
	endpoint := newDuplexTestEndpoint()
	endpoint.handle = func(packet []byte) []protocol.FrameBlock {
		return []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{{
			FrameType: registry.FramePadding,
			Payload:   append([]byte(nil), packet...),
		}}}}
	}
	var got []string
	handler := func(_ context.Context, block protocol.FrameBlock) error {
		got = append(got, string(block.Frames[0].Payload))
		return nil
	}

	err = RunPacketDuplex(context.Background(), reader, writer, endpoint, handler, 64)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("RunPacketDuplex exhausted input error = %v, want io.EOF", err)
	}
	if want := []string{"first", "second"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("handler order = %v, want %v", got, want)
	}
	requireDuplexClosedOnce(t, reader.closeCalls.Load(), writer.closeCalls.Load(), endpoint.closeCalls.Load())
}

func TestRunPacketDuplexPreservesCarrierWriteError(t *testing.T) {
	reader := newBlockingReadCloser()
	wantErr := errors.New("carrier write failed")
	writer := &failingWriteCloser{err: wantErr}
	endpoint := newDuplexTestEndpoint()
	endpoint.packets <- []byte("outbound packet")

	err := RunPacketDuplex(context.Background(), reader, writer, endpoint, discardFrameBlock, 64)
	if !errors.Is(err, wantErr) {
		t.Fatalf("RunPacketDuplex carrier write error = %v, want %v", err, wantErr)
	}
	requireDuplexClosedOnce(t, reader.closeCalls.Load(), writer.closeCalls.Load(), endpoint.closeCalls.Load())
}

func TestRunPacketDuplexRejectsInvalidArgumentsWithoutStartingPumps(t *testing.T) {
	endpoint := newDuplexTestEndpoint()
	var typedNilEndpoint *duplexTestEndpoint
	reader := &countingReadCloser{Reader: bytes.NewReader(nil)}
	writer := &discardWriteCloser{}
	for name, run := range map[string]func() error{
		"nil context": func() error {
			//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
			return RunPacketDuplex(nil, reader, writer, endpoint, discardFrameBlock, 64)
		},
		"nil reader": func() error {
			return RunPacketDuplex(context.Background(), nil, writer, endpoint, discardFrameBlock, 64)
		},
		"nil writer": func() error {
			return RunPacketDuplex(context.Background(), reader, nil, endpoint, discardFrameBlock, 64)
		},
		"nil endpoint": func() error {
			return RunPacketDuplex(context.Background(), reader, writer, nil, discardFrameBlock, 64)
		},
		"typed nil endpoint": func() error {
			return RunPacketDuplex(context.Background(), reader, writer, typedNilEndpoint, discardFrameBlock, 64)
		},
		"nil handler": func() error {
			return RunPacketDuplex(context.Background(), reader, writer, endpoint, nil, 64)
		},
		"invalid maximum": func() error {
			return RunPacketDuplex(context.Background(), reader, writer, endpoint, discardFrameBlock, maxRecordBodyBytes+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); err == nil {
				t.Fatalf("RunPacketDuplex accepted %s", name)
			}
		})
	}
	if reader.closeCalls.Load() != 0 || writer.closeCalls.Load() != 0 || endpoint.closeCalls.Load() != 0 {
		t.Fatalf("invalid arguments transferred resource ownership")
	}
}

func runPairedPacketDuplex(t *testing.T, fragmented bool) {
	t.Helper()
	client, relay := newDuplexApplicationPair(t)
	defer client.Close()
	defer relay.Close()
	clientToRelayReader, clientToRelayWriter := io.Pipe()
	relayToClientReader, relayToClientWriter := io.Pipe()
	var clientReader io.ReadCloser = relayToClientReader
	var clientWriter io.WriteCloser = clientToRelayWriter
	var relayReader io.ReadCloser = clientToRelayReader
	var relayWriter io.WriteCloser = relayToClientWriter
	if fragmented {
		clientReader = fragmentReadCloser{ReadCloser: clientReader}
		clientWriter = fragmentWriteCloser{WriteCloser: clientWriter}
		relayReader = fragmentReadCloser{ReadCloser: relayReader}
		relayWriter = fragmentWriteCloser{WriteCloser: relayWriter}
	}

	clientWant := duplexFrameBlock(t, 41, []byte("client to relay"))
	relayWant := duplexFrameBlock(t, 42, []byte("relay to client"))
	if err := client.QueueFrames(context.Background(), clientWant); err != nil {
		t.Fatal(err)
	}
	if err := relay.QueueFrames(context.Background(), relayWant); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientReceived := make(chan protocol.FrameBlock, 1)
	relayReceived := make(chan protocol.FrameBlock, 1)
	clientResult := make(chan error, 1)
	relayResult := make(chan error, 1)
	go func() {
		clientResult <- RunPacketDuplex(ctx, clientReader, clientWriter, client, capturingHandler(clientReceived), 0)
	}()
	go func() {
		relayResult <- RunPacketDuplex(ctx, relayReader, relayWriter, relay, capturingHandler(relayReceived), 0)
	}()

	if got := awaitFrameBlock(t, relayReceived); !reflect.DeepEqual(got, clientWant) {
		t.Fatalf("relay block = %#v, want %#v", got, clientWant)
	}
	if got := awaitFrameBlock(t, clientReceived); !reflect.DeepEqual(got, relayWant) {
		t.Fatalf("client block = %#v, want %#v", got, relayWant)
	}
	cancel()
	for name, result := range map[string]<-chan error{"client": clientResult, "relay": relayResult} {
		if err := awaitDuplexResult(t, result); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s duplex error = %v, want context.Canceled", name, err)
		}
	}
}

func newDuplexApplicationPair(t *testing.T) (*session.Application, *session.Application) {
	t.Helper()
	forward := session.DirectionConfig{
		Direction: 0,
		Secret:    bytes.Repeat([]byte{0x11}, 48),
		Key:       bytes.Repeat([]byte{0x12}, 32),
		IV:        bytes.Repeat([]byte{0x13}, 12),
	}
	backward := session.DirectionConfig{
		Direction: 1,
		Secret:    bytes.Repeat([]byte{0x21}, 48),
		Key:       bytes.Repeat([]byte{0x22}, 32),
		IV:        bytes.Repeat([]byte{0x23}, 12),
	}
	limits := session.Limits{
		MaxQueuedPackets:       8,
		MaxQueuedBytes:         64 << 10,
		ControlReservedPackets: 2,
		ControlReservedBytes:   8 << 10,
		ReplayWindow:           64,
	}
	client, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 0x44,
		HopLayer:        1,
		Write:           cloneDuplexDirection(forward),
		Read:            cloneDuplexDirection(backward),
		Limits:          limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	relay, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 0x44,
		HopLayer:        1,
		Write:           cloneDuplexDirection(backward),
		Read:            cloneDuplexDirection(forward),
		Limits:          limits,
	})
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	return client, relay
}

func duplexFrameBlock(t *testing.T, flowID uint64, payload []byte) protocol.FrameBlock {
	t.Helper()
	frame, err := protocol.NewStreamDataFrame(flowID, payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}
}

func cloneDuplexDirection(in session.DirectionConfig) session.DirectionConfig {
	return session.DirectionConfig{
		Direction: in.Direction,
		Secret:    append([]byte(nil), in.Secret...),
		Key:       append([]byte(nil), in.Key...),
		IV:        append([]byte(nil), in.IV...),
	}
}

func capturingHandler(result chan<- protocol.FrameBlock) FrameBlockHandler {
	return func(_ context.Context, block protocol.FrameBlock) error {
		result <- cloneDuplexFrameBlock(block)
		return nil
	}
}

func cloneDuplexFrameBlock(in protocol.FrameBlock) protocol.FrameBlock {
	out := protocol.FrameBlock{Frames: make([]protocol.AuroraFrame, len(in.Frames))}
	for i, frame := range in.Frames {
		out.Frames[i] = protocol.AuroraFrame{
			FrameType: frame.FrameType,
			FlowID:    frame.FlowID,
			Flags:     frame.Flags,
			Payload:   append([]byte(nil), frame.Payload...),
		}
	}
	return out
}

func discardFrameBlock(context.Context, protocol.FrameBlock) error { return nil }

type fragmentReadCloser struct{ io.ReadCloser }

func (r fragmentReadCloser) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.ReadCloser.Read(p)
}

type fragmentWriteCloser struct{ io.WriteCloser }

func (w fragmentWriteCloser) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.WriteCloser.Write(p)
}

type blockingReadCloser struct {
	started    chan struct{}
	closed     chan struct{}
	startOnce  sync.Once
	closeOnce  sync.Once
	closeCalls atomic.Int32
}

func newBlockingReadCloser() *blockingReadCloser {
	return &blockingReadCloser{started: make(chan struct{}), closed: make(chan struct{})}
}

func (r *blockingReadCloser) Read([]byte) (int, error) {
	r.startOnce.Do(func() { close(r.started) })
	<-r.closed
	return 0, io.ErrClosedPipe
}

func (r *blockingReadCloser) Close() error {
	r.closeCalls.Add(1)
	r.closeOnce.Do(func() { close(r.closed) })
	return nil
}

type blockingWriteCloser struct {
	started    chan struct{}
	closed     chan struct{}
	startOnce  sync.Once
	closeOnce  sync.Once
	closeCalls atomic.Int32
}

func newBlockingWriteCloser() *blockingWriteCloser {
	return &blockingWriteCloser{started: make(chan struct{}), closed: make(chan struct{})}
}

func (w *blockingWriteCloser) Write([]byte) (int, error) {
	w.startOnce.Do(func() { close(w.started) })
	<-w.closed
	return 0, io.ErrClosedPipe
}

func (w *blockingWriteCloser) Close() error {
	w.closeCalls.Add(1)
	w.closeOnce.Do(func() { close(w.closed) })
	return nil
}

type countingReadCloser struct {
	io.Reader
	closeCalls atomic.Int32
}

func (r *countingReadCloser) Close() error {
	r.closeCalls.Add(1)
	return nil
}

type discardWriteCloser struct{ closeCalls atomic.Int32 }

func (w *discardWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (w *discardWriteCloser) Close() error {
	w.closeCalls.Add(1)
	return nil
}

type failingWriteCloser struct {
	err        error
	closeCalls atomic.Int32
}

func (w *failingWriteCloser) Write([]byte) (int, error) { return 0, w.err }
func (w *failingWriteCloser) Close() error {
	w.closeCalls.Add(1)
	return nil
}

type duplexTestEndpoint struct {
	packets     chan []byte
	closed      chan struct{}
	nextStarted chan struct{}
	handle      func([]byte) []protocol.FrameBlock
	startOnce   sync.Once
	closeOnce   sync.Once
	closeCalls  atomic.Int32
}

func newDuplexTestEndpoint() *duplexTestEndpoint {
	return &duplexTestEndpoint{
		packets:     make(chan []byte, 1),
		closed:      make(chan struct{}),
		nextStarted: make(chan struct{}),
	}
}

func (e *duplexTestEndpoint) NextPacket(ctx context.Context) ([]byte, error) {
	e.startOnce.Do(func() { close(e.nextStarted) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.closed:
		return nil, session.ErrClosed
	case packet := <-e.packets:
		return append([]byte(nil), packet...), nil
	}
}

func (e *duplexTestEndpoint) HandlePacket(_ context.Context, _ time.Time, packet []byte) ([]protocol.FrameBlock, error) {
	if e.handle == nil {
		return nil, nil
	}
	return e.handle(packet), nil
}

func (e *duplexTestEndpoint) Close() error {
	e.closeCalls.Add(1)
	e.closeOnce.Do(func() { close(e.closed) })
	return nil
}

func awaitSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func awaitFrameBlock(t *testing.T, result <-chan protocol.FrameBlock) protocol.FrameBlock {
	t.Helper()
	select {
	case block := <-result:
		return block
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for frame block")
		return protocol.FrameBlock{}
	}
}

func awaitDuplexResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for duplex result")
		return nil
	}
}

func requireDuplexClosedOnce(t *testing.T, reader, writer, endpoint int32) {
	t.Helper()
	if reader != 1 || writer != 1 || endpoint != 1 {
		t.Fatalf("close calls = reader %d, writer %d, endpoint %d; want 1 each", reader, writer, endpoint)
	}
}

func requireGoroutinesSettled(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= baseline+2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutines did not settle: before %d, after %d", baseline, runtime.NumGoroutine())
}
