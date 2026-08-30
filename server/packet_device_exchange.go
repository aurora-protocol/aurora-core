package server

import (
	"fmt"
	"io"
	"sync"
)

const (
	defaultDevicePacketMTU          = 1280
	defaultDevicePacketQueuePackets = 64
)

type DevicePacketExchangerOptions struct {
	MTU          int
	QueuePackets int
}

type DevicePacketExchanger struct {
	device   io.ReadWriteCloser
	mtu      int
	outbound chan []byte
	done     chan struct{}
	readDone chan struct{}

	closeOnce  sync.Once
	closeErr   error
	writeMu    sync.Mutex
	outboundMu sync.Mutex
	readErrMu  sync.RWMutex
	readErr    error
}

func NewDevicePacketExchanger(device io.ReadWriteCloser, opts DevicePacketExchangerOptions) (*DevicePacketExchanger, error) {
	if device == nil {
		return nil, fmt.Errorf("server: packet device is required")
	}
	mtu := opts.MTU
	if mtu == 0 {
		mtu = defaultDevicePacketMTU
	}
	if mtu < 1 || mtu > maxPacketBytes {
		return nil, fmt.Errorf("server: packet device MTU %d outside supported range", mtu)
	}
	queuePackets := opts.QueuePackets
	if queuePackets == 0 {
		queuePackets = defaultDevicePacketQueuePackets
	}
	if queuePackets < 1 || queuePackets > maxPacketBatchPackets {
		return nil, fmt.Errorf("server: packet device queue size %d outside supported range", queuePackets)
	}

	exchanger := &DevicePacketExchanger{
		device:   device,
		mtu:      mtu,
		outbound: make(chan []byte, queuePackets),
		done:     make(chan struct{}),
		readDone: make(chan struct{}),
	}
	go exchanger.readDevice()
	return exchanger, nil
}

func (e *DevicePacketExchanger) ExchangePacketBatch(batch PacketBatch) (PacketBatch, error) {
	if e == nil {
		return PacketBatch{}, fmt.Errorf("server: packet exchanger is nil")
	}
	select {
	case <-e.done:
		return PacketBatch{}, fmt.Errorf("server: packet exchanger is closed")
	default:
	}
	if err := validatePacketBatch(batch); err != nil {
		return PacketBatch{}, err
	}
	if err := e.readError(); err != nil {
		return PacketBatch{}, fmt.Errorf("server: read packet device: %w", err)
	}

	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	select {
	case <-e.done:
		return PacketBatch{}, fmt.Errorf("server: packet exchanger is closed")
	default:
	}
	if err := e.readError(); err != nil {
		return PacketBatch{}, fmt.Errorf("server: read packet device: %w", err)
	}
	// Preflight the whole batch before mutating the packet device. Otherwise a
	// late oversized packet would leave an injected prefix behind on failure.
	for _, packet := range batch.Packets {
		if len(packet) > e.mtu {
			return PacketBatch{}, fmt.Errorf("server: packet length %d exceeds device MTU %d", len(packet), e.mtu)
		}
	}
	for _, packet := range batch.Packets {
		if err := writeFullPacket(e.device, packet); err != nil {
			return PacketBatch{}, fmt.Errorf("server: write packet device: %w", err)
		}
	}

	return e.drainOutbound(), nil
}

func (e *DevicePacketExchanger) Close() error {
	if e == nil {
		return nil
	}
	e.closeOnce.Do(func() {
		close(e.done)
		e.closeErr = e.device.Close()
		e.outboundMu.Lock()
		e.zeroQueuedOutbound()
		e.outboundMu.Unlock()
	})
	return e.closeErr
}

func (e *DevicePacketExchanger) readDevice() {
	defer close(e.readDone)
	buffer := make([]byte, e.mtu)
	defer zeroDevicePacketBytes(buffer)
	for {
		n, err := e.device.Read(buffer)
		if n < 0 || n > len(buffer) {
			e.setReadError(fmt.Errorf("server: packet device returned invalid read length %d", n))
			return
		}
		if n > 0 {
			e.queueOutbound(buffer[:n])
			zeroDevicePacketBytes(buffer[:n])
		}
		if err != nil {
			e.setReadError(err)
			return
		}
		if n == 0 {
			e.setReadError(fmt.Errorf("server: packet device returned an empty read"))
			return
		}
		select {
		case <-e.done:
			return
		default:
		}
	}
}

func (e *DevicePacketExchanger) setReadError(err error) {
	if err == nil {
		return
	}
	select {
	case <-e.done:
		return
	default:
	}
	e.readErrMu.Lock()
	defer e.readErrMu.Unlock()
	select {
	case <-e.done:
		return
	default:
	}
	if e.readErr == nil {
		e.readErr = err
	}
}

func (e *DevicePacketExchanger) readError() error {
	e.readErrMu.RLock()
	defer e.readErrMu.RUnlock()
	return e.readErr
}

func (e *DevicePacketExchanger) queueOutbound(packet []byte) {
	copied := append([]byte(nil), packet...)
	e.outboundMu.Lock()
	defer e.outboundMu.Unlock()
	select {
	case <-e.done:
		zeroDevicePacketBytes(copied)
		return
	default:
	}
	select {
	case e.outbound <- copied:
		return
	default:
	}
	select {
	case evicted := <-e.outbound:
		zeroDevicePacketBytes(evicted)
	default:
	}
	select {
	case e.outbound <- copied:
		return
	default:
		zeroDevicePacketBytes(copied)
	}
}

func (e *DevicePacketExchanger) drainOutbound() PacketBatch {
	e.outboundMu.Lock()
	defer e.outboundMu.Unlock()
	outbound := PacketBatch{
		Packets:         make([][]byte, 0),
		ProtocolNumbers: make([]uint16, 0),
	}
	for len(outbound.Packets) < maxPacketBatchPackets {
		select {
		case packet := <-e.outbound:
			outbound.Packets = append(outbound.Packets, packet)
			outbound.ProtocolNumbers = append(outbound.ProtocolNumbers, packetProtocolNumber(packet))
		default:
			return outbound
		}
	}
	return outbound
}

func (e *DevicePacketExchanger) zeroQueuedOutbound() {
	for {
		select {
		case packet := <-e.outbound:
			zeroDevicePacketBytes(packet)
		default:
			return
		}
	}
}

func zeroDevicePacketBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func writeFullPacket(w io.Writer, packet []byte) error {
	n, err := w.Write(packet)
	if n < 0 || n > len(packet) {
		return fmt.Errorf("server: packet device returned invalid write length %d", n)
	}
	if err != nil {
		return err
	}
	if n != len(packet) {
		// Packet devices preserve write boundaries. Retrying the remainder would
		// inject it as a second malformed packet rather than completing the first.
		return io.ErrShortWrite
	}
	return nil
}

func packetProtocolNumber(packet []byte) uint16 {
	if len(packet) == 0 {
		return 0
	}
	switch packet[0] >> 4 {
	case 4:
		return packetFamilyIPv4
	case 6:
		return packetFamilyIPv6
	default:
		return 0
	}
}

var _ PacketExchanger = (*DevicePacketExchanger)(nil)
