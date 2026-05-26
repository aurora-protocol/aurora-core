package flow

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

const (
	FlowKindTCPStream      uint8 = 0x01
	FlowKindUDPAssociation uint8 = 0x02
	FlowKindDNSExchange    uint8 = 0x03

	TargetKindIPv4       uint8 = 0x01
	TargetKindIPv6       uint8 = 0x02
	TargetKindDomainName uint8 = 0x03

	UDPFQDNNoneIPAuthoritative       uint8 = 0x00
	UDPFQDNClientResolvedNameBinding uint8 = 0x01
	UDPFQDNRelayResolvedFlowBound    uint8 = 0x02
	UDPFQDNStandardsMasqueOnly       uint8 = 0x03

	LocalBindingExplicitProxyAPI      uint8 = 0x00
	LocalBindingTransparentOriginalIP uint8 = 0x01
	LocalBindingTransparentFakeIP     uint8 = 0x02
	LocalBindingTUNPacketFlow         uint8 = 0x03

	PriorityInteractive uint8 = 0x01
	PriorityBulk        uint8 = 0x02
	PriorityRealtime    uint8 = 0x03
)

type FlowState struct {
	FlowID                    uint64
	Kind                      uint8
	TargetKind                uint8
	TargetHost                []byte
	TargetPort                uint16
	UDPFQDNMode               uint8
	NameBindingID             []byte
	DNSAnswerSetHash          []byte
	LocalBindingMode          uint8
	PriorityClass             uint8
	CreatedAtUnix             uint64
	LastActivityUnix          uint64
	TTLSeconds                uint64
	IdleTimeoutSecs           uint64
	ConfirmedHost             []byte
	ConfirmedPort             uint16
	ConfirmedDNSAnswerSetHash []byte
	ConfirmedTTLSeconds       uint32
	ConfirmedResolutionSource uint8
}

type FlowOptions struct {
	NowUnix            uint64
	TTLSeconds         uint64
	IdleTimeoutSeconds uint64
}

type Manager struct {
	mu    sync.Mutex
	flows map[uint64]FlowState
}

func NewManager() *Manager {
	return &Manager{flows: make(map[uint64]FlowState)}
}

func (m *Manager) Open(open protocol.FlowOpen) error {
	return m.OpenWithOptions(open, FlowOptions{})
}

func (m *Manager) OpenWithOptions(open protocol.FlowOpen, opts FlowOptions) error {
	if open.FlowOpenVersion != registry.Version20 {
		return fmt.Errorf("flow: unsupported flow_open_version 0x%x", open.FlowOpenVersion)
	}
	if err := validateOpen(open); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.flows[open.FlowID]; ok {
		return fmt.Errorf("flow: duplicate flow_id %d", open.FlowID)
	}
	now := opts.NowUnix
	m.flows[open.FlowID] = FlowState{
		FlowID:           open.FlowID,
		Kind:             open.FlowKind,
		TargetKind:       open.TargetKind,
		TargetHost:       append([]byte(nil), open.TargetHost...),
		TargetPort:       open.TargetPort,
		UDPFQDNMode:      open.UDPFQDNMode,
		NameBindingID:    append([]byte(nil), open.NameBindingID...),
		DNSAnswerSetHash: append([]byte(nil), open.DNSAnswerSetHash...),
		LocalBindingMode: open.LocalBindingMode,
		PriorityClass:    open.PriorityClass,
		CreatedAtUnix:    now,
		LastActivityUnix: now,
		TTLSeconds:       opts.TTLSeconds,
		IdleTimeoutSecs:  opts.IdleTimeoutSeconds,
	}
	return nil
}

func (m *Manager) ConfirmUDP(confirm protocol.UDPTargetConfirm) error {
	if err := protocol.ValidateUDPTargetConfirm(confirm); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.flows[confirm.FlowID]
	if !ok {
		return fmt.Errorf("flow: unknown flow_id %d", confirm.FlowID)
	}
	if state.Kind != FlowKindUDPAssociation {
		return fmt.Errorf("flow: target confirmation on non-UDP flow")
	}
	state.ConfirmedHost = append([]byte(nil), confirm.SelectedIP...)
	state.ConfirmedPort = confirm.SelectedPort
	state.ConfirmedDNSAnswerSetHash = append([]byte(nil), confirm.DNSAnswerSetHash...)
	state.ConfirmedTTLSeconds = confirm.TTLSeconds
	state.ConfirmedResolutionSource = confirm.ResolutionSource
	m.flows[confirm.FlowID] = state
	return nil
}

func (m *Manager) DemuxInbound(flowID uint64) (FlowState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.flows[flowID]
	return state, ok
}

func (m *Manager) AcceptDatagram(flowID uint64, now uint64) (FlowState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.flows[flowID]
	if !ok || state.Kind != FlowKindUDPAssociation {
		return FlowState{}, false
	}
	if state.expired(now) {
		delete(m.flows, flowID)
		return FlowState{}, false
	}
	state.LastActivityUnix = now
	m.flows[flowID] = state
	return state, true
}

func (m *Manager) Close(close protocol.FlowClose) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.flows[close.FlowID]; !ok {
		return fmt.Errorf("flow: unknown flow_id %d", close.FlowID)
	}
	delete(m.flows, close.FlowID)
	return nil
}

func validateOpen(open protocol.FlowOpen) error {
	switch open.FlowKind {
	case FlowKindTCPStream, FlowKindUDPAssociation, FlowKindDNSExchange:
	default:
		return fmt.Errorf("flow: reserved flow_kind 0x%x", open.FlowKind)
	}
	switch open.TargetKind {
	case TargetKindIPv4:
		if len(open.TargetHost) != 4 {
			return fmt.Errorf("flow: IPv4 target must be 4 bytes")
		}
	case TargetKindIPv6:
		if len(open.TargetHost) != 16 {
			return fmt.Errorf("flow: IPv6 target must be 16 bytes")
		}
	case TargetKindDomainName:
		if string(open.TargetHost) != canonicalDomain(string(open.TargetHost)) {
			return fmt.Errorf("flow: domain target must be lower-case A-label without trailing dot")
		}
	default:
		return fmt.Errorf("flow: reserved target_kind 0x%x", open.TargetKind)
	}
	if len(open.NameBindingID) != 16 || len(open.DNSAnswerSetHash) != 48 {
		return fmt.Errorf("flow: binding ID and DNS answer hash have invalid lengths")
	}
	if open.FlowKind == FlowKindUDPAssociation &&
		open.LocalBindingMode == LocalBindingTransparentFakeIP &&
		open.UDPFQDNMode == UDPFQDNRelayResolvedFlowBound {
		return fmt.Errorf("flow: relay-resolved UDP disabled by default for transparent fake-IP mode")
	}
	return nil
}

func (s FlowState) expired(now uint64) bool {
	if s.TTLSeconds > 0 && now >= s.CreatedAtUnix+s.TTLSeconds {
		return true
	}
	if s.IdleTimeoutSecs > 0 && now > s.LastActivityUnix+s.IdleTimeoutSecs {
		return true
	}
	return false
}

type FakeIPAllocator struct {
	network *net.IPNet
	mu      sync.Mutex
	byName  map[string]string
	byIP    map[string][]string
}

func NewFakeIPAllocator(cidr string) *FakeIPAllocator {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		_, network, _ = net.ParseCIDR("198.18.0.0/15")
	}
	return &FakeIPAllocator{network: network, byName: make(map[string]string), byIP: make(map[string][]string)}
}

func (a *FakeIPAllocator) Assign(domain string, answers []string) (fakeIP string, nameBindingID []byte, err error) {
	name := canonicalDomain(domain)
	if name == "" {
		return "", nil, fmt.Errorf("flow: empty domain")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if ip, ok := a.byName[name]; ok {
		return ip, bindingID(name, answers), nil
	}
	hash := sha256.Sum256([]byte(name))
	base := a.network.IP.To4()
	if base == nil {
		return "", nil, fmt.Errorf("flow: fake IP network must be IPv4")
	}
	ip := net.IPv4(base[0], base[1], hash[0], hash[1])
	if !a.network.Contains(ip) {
		ip = net.IPv4(198, 18, hash[0], hash[1])
	}
	fakeIP = ip.String()
	a.byName[name] = fakeIP
	a.byIP[fakeIP] = append([]string(nil), answers...)
	return fakeIP, bindingID(name, answers), nil
}

func canonicalDomain(domain string) string {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "." {
		return ""
	}
	return d
}

func bindingID(domain string, answers []string) []byte {
	h := sha256.New()
	h.Write([]byte(canonicalDomain(domain)))
	for _, answer := range answers {
		h.Write([]byte{0})
		h.Write([]byte(answer))
	}
	return auroracrypto.Truncate128(h.Sum(nil))
}

func DNSAnswerSetHash(answers []string) []byte {
	h := sha256.Sum256([]byte(strings.Join(answers, "\x00")))
	return auroracrypto.PreHash([]byte(hex.EncodeToString(h[:])))
}
