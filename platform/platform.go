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
	KindOpenWrt Kind = "openwrt"
	KindCI      Kind = "ci"
)

const (
	PacketNone             = "none"
	PacketTUN              = "tun"
	PacketWintun           = "wintun"
	PacketNetworkExtension = "network-extension"
	PacketVpnService       = "vpn-service"
)

const (
	LocalSOCKS5       = "local.socks5"
	LocalHTTPConnect  = "local.http-connect"
	LocalDNSForwarder = "local.dns-forwarder"
)

type Profile struct {
	Kind                Kind
	PacketMode          string
	SupportsLocalProxy  bool
	LocalModes          []string
	NoEntitlementOnly   bool
	ContainsCryptoState bool
}

func ProfileFor(kind Kind) Profile {
	switch kind {
	case KindLinux:
		return Profile{Kind: kind, PacketMode: PacketTUN, SupportsLocalProxy: true, LocalModes: localModes(true)}
	case KindWindows:
		return Profile{Kind: kind, PacketMode: PacketWintun, SupportsLocalProxy: true, LocalModes: localModes(true)}
	case KindApple:
		return Profile{Kind: kind, PacketMode: PacketNetworkExtension, SupportsLocalProxy: true, LocalModes: localModes(true)}
	case KindAndroid:
		return Profile{Kind: kind, PacketMode: PacketVpnService, SupportsLocalProxy: true, LocalModes: localModes(true)}
	case KindFreeBSD:
		return Profile{Kind: kind, PacketMode: PacketTUN, SupportsLocalProxy: true, LocalModes: localModes(true)}
	case KindOpenWrt:
		return Profile{Kind: kind, PacketMode: PacketTUN, SupportsLocalProxy: true, LocalModes: localModes(true)}
	case KindCI:
		return Profile{Kind: kind, PacketMode: PacketNone, SupportsLocalProxy: true, LocalModes: localModes(false), NoEntitlementOnly: true}
	default:
		return Profile{Kind: kind, PacketMode: PacketNone, SupportsLocalProxy: true, LocalModes: localModes(false), NoEntitlementOnly: true}
	}
}

func (p Profile) SupportsLocalMode(mode string) bool {
	for _, candidate := range p.LocalModes {
		if candidate == mode {
			return true
		}
	}
	return false
}

func (p Profile) HasNoKernelLocalInterface() bool {
	return p.SupportsLocalMode(LocalSOCKS5) ||
		p.SupportsLocalMode(LocalHTTPConnect) ||
		p.SupportsLocalMode(LocalDNSForwarder)
}

func localModes(includeDNSForwarder bool) []string {
	modes := []string{LocalSOCKS5, LocalHTTPConnect}
	if includeDNSForwarder {
		modes = append(modes, LocalDNSForwarder)
	}
	return modes
}

func cloneProfile(profile Profile) Profile {
	profile.LocalModes = append([]string(nil), profile.LocalModes...)
	return profile
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
	return &ThinAdapter{profile: cloneProfile(profile), core: core}
}

func (a *ThinAdapter) Profile() Profile {
	return cloneProfile(a.profile)
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
	return a.core.SubmitTCPFlow(cloneFlowOpen(open))
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

func cloneFlowOpen(open protocol.FlowOpen) protocol.FlowOpen {
	open.TargetHost = append([]byte(nil), open.TargetHost...)
	open.NameBindingID = append([]byte(nil), open.NameBindingID...)
	open.OriginalDomainHint = append([]byte(nil), open.OriginalDomainHint...)
	open.DNSAnswerSetHash = append([]byte(nil), open.DNSAnswerSetHash...)
	open.Extensions = cloneExtensions(open.Extensions)
	return open
}

func cloneExtensions(in []protocol.Extension) []protocol.Extension {
	if len(in) == 0 {
		return nil
	}
	out := make([]protocol.Extension, len(in))
	for i, ext := range in {
		out[i] = ext
		out[i].Body = append([]byte(nil), ext.Body...)
	}
	return out
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
