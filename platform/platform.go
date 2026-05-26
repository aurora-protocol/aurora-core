package platform

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/protocol"
)

const EventNetworkChange = "network-change"

type Kind string

const (
	KindLinux   Kind = "linux"
	KindWindows Kind = "windows"
	KindApple   Kind = "apple"
	KindAndroid Kind = "android"
	KindFreeBSD Kind = "freebsd"
	KindCI      Kind = "ci"
)

const (
	PacketNone             = "none"
	PacketTUN              = "tun"
	PacketWintun           = "wintun"
	PacketNetworkExtension = "network-extension"
	PacketVpnService       = "vpn-service"
)

type Profile struct {
	Kind                Kind
	PacketMode          string
	SupportsLocalProxy  bool
	NoEntitlementOnly   bool
	ContainsCryptoState bool
}

func ProfileFor(kind Kind) Profile {
	switch kind {
	case KindLinux:
		return Profile{Kind: kind, PacketMode: PacketTUN, SupportsLocalProxy: true}
	case KindWindows:
		return Profile{Kind: kind, PacketMode: PacketWintun, SupportsLocalProxy: true}
	case KindApple:
		return Profile{Kind: kind, PacketMode: PacketNetworkExtension}
	case KindAndroid:
		return Profile{Kind: kind, PacketMode: PacketVpnService, SupportsLocalProxy: true}
	case KindFreeBSD:
		return Profile{Kind: kind, PacketMode: PacketTUN, SupportsLocalProxy: true}
	case KindCI:
		return Profile{Kind: kind, PacketMode: PacketNone, SupportsLocalProxy: true, NoEntitlementOnly: true}
	default:
		return Profile{Kind: kind, PacketMode: PacketNone, SupportsLocalProxy: true, NoEntitlementOnly: true}
	}
}

type SessionConfig struct {
	SessionID string
}

type PathInfo struct {
	Interface string
	Expensive bool
}

type Event struct {
	Type string
	Path PathInfo
}

type Adapter interface {
	Name() string
	Start(SessionConfig) error
	SubmitPacket([]byte) error
	ReadPacket() ([]byte, bool)
	NotifyNetworkChange(PathInfo)
	Events() []Event
	HasCryptoState() bool
}

type CoreSink interface {
	OpenSession(configBlob []byte) error
	CloseSession(sessionID string) error
	SubmitTCPFlow(protocol.FlowOpen) error
	SubmitUDPDatagram(flowID uint64, datagram []byte) error
	SubmitDNSMessage(flowID uint64, message []byte) error
	ReadPacketOrFrame() ([]byte, bool)
	NotifyNetworkChange(PathInfo)
	ExportRedactedDiagnostics() []byte
}

type ThinAdapter struct {
	profile Profile
	core    CoreSink
}

func NewThinAdapter(profile Profile, core CoreSink) *ThinAdapter {
	return &ThinAdapter{profile: profile, core: core}
}

func (a *ThinAdapter) Profile() Profile {
	return a.profile
}

func (a *ThinAdapter) HasCryptoState() bool {
	return false
}

func (a *ThinAdapter) OpenSession(configBlob []byte) error {
	if a.core == nil {
		return fmt.Errorf("platform: missing core sink")
	}
	return a.core.OpenSession(append([]byte(nil), configBlob...))
}

func (a *ThinAdapter) CloseSession(sessionID string) error {
	if a.core == nil {
		return fmt.Errorf("platform: missing core sink")
	}
	return a.core.CloseSession(sessionID)
}

func (a *ThinAdapter) SubmitTCPFlow(open protocol.FlowOpen) error {
	if a.core == nil {
		return fmt.Errorf("platform: missing core sink")
	}
	return a.core.SubmitTCPFlow(open)
}

func (a *ThinAdapter) SubmitUDPDatagram(flowID uint64, datagram []byte) error {
	if a.core == nil {
		return fmt.Errorf("platform: missing core sink")
	}
	return a.core.SubmitUDPDatagram(flowID, append([]byte(nil), datagram...))
}

func (a *ThinAdapter) SubmitDNSMessage(flowID uint64, message []byte) error {
	if a.core == nil {
		return fmt.Errorf("platform: missing core sink")
	}
	return a.core.SubmitDNSMessage(flowID, append([]byte(nil), message...))
}

func (a *ThinAdapter) ReadPacketOrFrame() ([]byte, bool) {
	if a.core == nil {
		return nil, false
	}
	return a.core.ReadPacketOrFrame()
}

func (a *ThinAdapter) NotifyNetworkChange(path PathInfo) {
	if a.core != nil {
		a.core.NotifyNetworkChange(path)
	}
}

func (a *ThinAdapter) ExportRedactedDiagnostics() []byte {
	if a.core == nil {
		return nil
	}
	return append([]byte(nil), a.core.ExportRedactedDiagnostics()...)
}

type MockAdapter struct {
	name    string
	started bool
	queue   [][]byte
	events  []Event
}

func NewMockAdapter(name string) *MockAdapter {
	return &MockAdapter{name: name}
}

func (a *MockAdapter) Name() string {
	return a.name
}

func (a *MockAdapter) Start(cfg SessionConfig) error {
	if cfg.SessionID == "" {
		return fmt.Errorf("platform: missing session id")
	}
	a.started = true
	return nil
}

func (a *MockAdapter) SubmitPacket(packet []byte) error {
	if !a.started {
		return fmt.Errorf("platform: adapter not started")
	}
	a.queue = append(a.queue, append([]byte(nil), packet...))
	return nil
}

func (a *MockAdapter) ReadPacket() ([]byte, bool) {
	if len(a.queue) == 0 {
		return nil, false
	}
	packet := a.queue[0]
	a.queue = a.queue[1:]
	return packet, true
}

func (a *MockAdapter) NotifyNetworkChange(path PathInfo) {
	a.events = append(a.events, Event{Type: EventNetworkChange, Path: path})
}

func (a *MockAdapter) Events() []Event {
	out := make([]Event, len(a.events))
	copy(out, a.events)
	return out
}

func (a *MockAdapter) HasCryptoState() bool {
	return false
}
