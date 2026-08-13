package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
)

const (
	defaultPacketTUNRuntimeReadBufferBytes = 65535
	minimumPacketTUNRuntimeReadBufferBytes = 128
	maximumPacketTUNRuntimeReadBufferBytes = 65535
)

var ErrPacketTUNRuntimeClosed = errors.New("client: packet TUN runtime is closed")

// PacketTUNRuntimeOptions bounds packet device handling for one packet adapter.
type PacketTUNRuntimeOptions struct {
	ReadBufferBytes int
	Now             func() time.Time
}

// PacketTUNRuntime owns local packet-device I/O for one encrypted packet adapter.
type PacketTUNRuntime struct {
	adapter *PacketAdapter
	device  io.ReadWriteCloser
	now     func() time.Time

	readBuffer []byte
	writeMu    sync.Mutex
	closeOnce  sync.Once
	done       chan struct{}
	closeErr   error
}

// NewPacketTUNRuntime creates bounded packet-device handling for one adapter.
func NewPacketTUNRuntime(adapter *PacketAdapter, device io.ReadWriteCloser, options PacketTUNRuntimeOptions) (*PacketTUNRuntime, error) {
	if adapter == nil {
		return nil, fmt.Errorf("client: packet TUN adapter is required")
	}
	if isNilPacketTUNDevice(device) {
		return nil, fmt.Errorf("client: packet TUN device is required")
	}
	normalized, err := normalizePacketTUNRuntimeOptions(options)
	if err != nil {
		return nil, err
	}
	return &PacketTUNRuntime{
		adapter:    adapter,
		device:     device,
		now:        normalized.Now,
		readBuffer: make([]byte, normalized.ReadBufferBytes),
		done:       make(chan struct{}),
	}, nil
}

func normalizePacketTUNRuntimeOptions(options PacketTUNRuntimeOptions) (PacketTUNRuntimeOptions, error) {
	if options.ReadBufferBytes == 0 {
		options.ReadBufferBytes = defaultPacketTUNRuntimeReadBufferBytes
	}
	if options.ReadBufferBytes < minimumPacketTUNRuntimeReadBufferBytes || options.ReadBufferBytes > maximumPacketTUNRuntimeReadBufferBytes {
		return PacketTUNRuntimeOptions{}, fmt.Errorf("client: packet TUN read buffer size is invalid")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return options, nil
}

// Serve captures local IP packets until cancellation, device failure, or Close.
func (r *PacketTUNRuntime) Serve(ctx context.Context) error {
	if r == nil {
		return fmt.Errorf("client: nil packet TUN runtime")
	}
	if ctx == nil {
		return fmt.Errorf("client: nil packet TUN context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.isClosed() {
		return ErrPacketTUNRuntimeClosed
	}

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = r.Close()
		case <-r.done:
		case <-stop:
		}
	}()
	defer close(stop)

	for {
		size, err := r.device.Read(r.readBuffer)
		if size < 0 || size > len(r.readBuffer) {
			return fmt.Errorf("client: packet TUN device returned an invalid read length")
		}
		if size > 0 {
			packet := r.readBuffer[:size]
			processErr := r.adapter.Ingress(ctx, packet, r.now())
			zeroPacketTUNBytes(packet)
			if processErr != nil {
				return processErr
			}
			if processErr := r.writePackets(ctx, r.adapter.DrainLocalPackets()); processErr != nil {
				return processErr
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("client: read packet TUN device: %w", err)
		}
		if size == 0 {
			return fmt.Errorf("client: packet TUN device returned an empty packet")
		}
	}
}

// HandleFrameBlock converts one authenticated relay frame block into local IP packets.
// Cancellation closes the device because packet-device writes cannot observe a context directly.
func (r *PacketTUNRuntime) HandleFrameBlock(ctx context.Context, block protocol.FrameBlock) error {
	if r == nil {
		return fmt.Errorf("client: nil packet TUN runtime")
	}
	if ctx == nil {
		return fmt.Errorf("client: nil packet TUN frame context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.isClosed() {
		return ErrPacketTUNRuntimeClosed
	}
	stopClose := context.AfterFunc(ctx, func() {
		_ = r.Close()
	})
	defer stopClose()
	packets, err := r.adapter.HandleFrameBlocks(ctx, []protocol.FrameBlock{block}, r.now())
	if err != nil {
		return err
	}
	return r.writePackets(ctx, packets)
}

func (r *PacketTUNRuntime) writePackets(ctx context.Context, packets [][]byte) error {
	defer zeroPacketTUNPacketList(packets)
	for _, packet := range packets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(packet) == 0 {
			return fmt.Errorf("client: packet TUN runtime received an empty local packet")
		}
		r.writeMu.Lock()
		if r.isClosed() {
			r.writeMu.Unlock()
			return ErrPacketTUNRuntimeClosed
		}
		size, err := r.device.Write(packet)
		r.writeMu.Unlock()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("client: write packet TUN device: %w", err)
		}
		if size != len(packet) {
			return io.ErrShortWrite
		}
	}
	return nil
}

// Close closes the packet device and unblocks any pending local packet read.
func (r *PacketTUNRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		close(r.done)
		r.closeErr = r.device.Close()
	})
	return r.closeErr
}

func (r *PacketTUNRuntime) isClosed() bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

func zeroPacketTUNPacketList(packets [][]byte) {
	for _, packet := range packets {
		zeroPacketTUNBytes(packet)
	}
}

func zeroPacketTUNBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func isNilPacketTUNDevice(device io.ReadWriteCloser) bool {
	if device == nil {
		return true
	}
	value := reflect.ValueOf(device)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
