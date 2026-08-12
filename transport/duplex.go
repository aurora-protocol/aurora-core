package transport

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
)

var (
	errNilDuplexContext       = errors.New("transport: nil duplex context")
	errNilPacketEndpoint      = errors.New("transport: nil packet endpoint")
	errNilPacketEndpointDone  = errors.New("transport: nil packet endpoint lifecycle")
	errPacketEndpointFinished = errors.New("transport: packet endpoint finished without an error")
	errNilFrameHandler        = errors.New("transport: nil frame block handler")
)

// PacketEndpoint returns owned packets, copies inbound bytes it retains, and
// closes Done on terminal failure. Err returns that failure after Done closes.
type PacketEndpoint interface {
	NextPacket(context.Context) ([]byte, error)
	HandlePacket(context.Context, time.Time, []byte) ([]protocol.FrameBlock, error)
	Done() <-chan struct{}
	Err() error
	Close() error
}

// FrameBlockHandler must honor context cancellation and copy retained payloads.
type FrameBlockHandler func(context.Context, protocol.FrameBlock) error

// RunPacketDuplex carries ordered packets until cancellation or the first pump error.
func RunPacketDuplex(ctx context.Context, readCarrier io.ReadCloser, writeCarrier io.WriteCloser, endpoint PacketEndpoint, handler FrameBlockHandler, maxRecordBodyBytes uint32) error {
	if ctx == nil {
		return errNilDuplexContext
	}
	if isNilLike(readCarrier) {
		return errNilRecordReader
	}
	if isNilLike(writeCarrier) {
		return errNilRecordWriter
	}
	if isNilLike(endpoint) {
		return errNilPacketEndpoint
	}
	if handler == nil {
		return errNilFrameHandler
	}
	endpointDone := endpoint.Done()
	if endpointDone == nil {
		return errNilPacketEndpointDone
	}
	if _, err := normalizeRecordMaximum(maxRecordBodyBytes); err != nil {
		return err
	}
	reader, err := NewRecordReader(readCarrier, maxRecordBodyBytes)
	if err != nil {
		return err
	}
	writer, err := NewRecordWriter(writeCarrier, maxRecordBodyBytes)
	if err != nil {
		return err
	}

	pumpCtx, cancel := context.WithCancel(ctx)
	results := make(chan error, 2)
	go func() {
		results <- runPacketReadPump(pumpCtx, reader, endpoint, handler)
	}()
	go func() {
		results <- runPacketWritePump(pumpCtx, writer, endpoint)
	}()

	collected := 0
	var triggerErr error
	select {
	case <-ctx.Done():
		triggerErr = ctx.Err()
	case <-endpointDone:
		triggerErr = endpoint.Err()
		if triggerErr == nil {
			triggerErr = errPacketEndpointFinished
		}
	case triggerErr = <-results:
		collected = 1
		if ctx.Err() != nil {
			triggerErr = ctx.Err()
		}
	}

	cancel()
	cleanupErr := closePacketDuplex(readCarrier, writeCarrier, endpoint)
	for collected < 2 {
		<-results
		collected++
	}
	if triggerErr != nil {
		return triggerErr
	}
	return cleanupErr
}

func runPacketReadPump(ctx context.Context, reader *RecordReader, endpoint PacketEndpoint, handler FrameBlockHandler) error {
	for {
		packet, err := reader.Read()
		if err != nil {
			return err
		}
		if err := handlePacketRecord(ctx, endpoint, handler, packet); err != nil {
			return err
		}
	}
}

func handlePacketRecord(ctx context.Context, endpoint PacketEndpoint, handler FrameBlockHandler, packet []byte) error {
	defer zeroDuplexBytes(packet)
	if err := ctx.Err(); err != nil {
		return err
	}
	blocks, err := endpoint.HandlePacket(ctx, time.Now(), packet)
	if err != nil {
		destroyDuplexFrameBlocks(blocks)
		return err
	}
	defer destroyDuplexFrameBlocks(blocks)
	for _, block := range blocks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := handler(ctx, block); err != nil {
			return err
		}
	}
	return nil
}

func runPacketWritePump(ctx context.Context, writer *RecordWriter, endpoint PacketEndpoint) error {
	for {
		packet, err := endpoint.NextPacket(ctx)
		if err != nil {
			return err
		}
		writeErr := func() error {
			defer zeroDuplexBytes(packet)
			if err := ctx.Err(); err != nil {
				return err
			}
			return writer.Write(packet)
		}()
		if writeErr != nil {
			return writeErr
		}
	}
}

func closePacketDuplex(readCarrier io.ReadCloser, writeCarrier io.WriteCloser, endpoint PacketEndpoint) error {
	var first error
	for _, close := range []func() error{endpoint.Close, readCarrier.Close, writeCarrier.Close} {
		if err := close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func destroyDuplexFrameBlocks(blocks []protocol.FrameBlock) {
	for i := range blocks {
		for j := range blocks[i].Frames {
			zeroDuplexBytes(blocks[i].Frames[j].Payload)
			blocks[i].Frames[j] = protocol.AuroraFrame{}
		}
		blocks[i] = protocol.FrameBlock{}
	}
}

func zeroDuplexBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
