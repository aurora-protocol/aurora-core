package flow

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
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
	LocalClosed               bool
	PeerClosed                bool
	CloseCode                 uint64
	FinalSequenceHintPresent  bool
	FinalSequenceHint         uint64
	DrainUntilUnix            uint64
}

type FlowOptions struct {
	NowUnix            uint64
	TTLSeconds         uint64
	IdleTimeoutSeconds uint64
}

type DatagramOptions struct {
	NowUnix               uint64
	SentAtUnix            uint64
	MaxRealtimeAgeSeconds uint64
}

type CloseOptions struct {
	NowUnix      uint64
	DrainSeconds uint64
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
	if err := validateUDPConfirmAgainstFlow(state, confirm); err != nil {
		return err
	}
	state.ConfirmedHost = append([]byte(nil), confirm.SelectedIP...)
	state.ConfirmedPort = confirm.SelectedPort
	state.ConfirmedDNSAnswerSetHash = append([]byte(nil), confirm.DNSAnswerSetHash...)
	state.ConfirmedTTLSeconds = confirm.TTLSeconds
	state.ConfirmedResolutionSource = confirm.ResolutionSource
	m.flows[confirm.FlowID] = state
	return nil
}

func (m *Manager) ConfirmUDPFrame(frame protocol.AuroraFrame) error {
	confirm, err := decodeUDPTargetConfirmFrame(frame)
	if err != nil {
		return err
	}
	return m.ConfirmUDP(confirm)
}

func decodeUDPTargetConfirmFrame(frame protocol.AuroraFrame) (protocol.UDPTargetConfirm, error) {
	if frame.FrameType != registry.FrameUDPTargetConfirm {
		return protocol.UDPTargetConfirm{}, fmt.Errorf("flow: expected UDP_TARGET_CONFIRM frame, got 0x%x", frame.FrameType)
	}
	if err := protocol.ValidateFlowManagementFrame(frame); err != nil {
		return protocol.UDPTargetConfirm{}, err
	}
	r := wire.NewReader(frame.Payload)
	confirm := protocol.DecodeUDPTargetConfirm(r)
	if r.Err() != nil {
		return protocol.UDPTargetConfirm{}, r.Err()
	}
	return confirm, nil
}

func validateUDPConfirmAgainstFlow(state FlowState, confirm protocol.UDPTargetConfirm) error {
	switch state.UDPFQDNMode {
	case UDPFQDNNoneIPAuthoritative, UDPFQDNClientResolvedNameBinding:
	default:
		return nil
	}
	if state.TargetKind != TargetKindIPv4 && state.TargetKind != TargetKindIPv6 {
		return nil
	}
	if confirm.TargetKind != state.TargetKind || confirm.SelectedPort != state.TargetPort || !bytes.Equal(confirm.SelectedIP, state.TargetHost) {
		return fmt.Errorf("flow: UDP target confirm does not match IP-authoritative flow target")
	}
	if len(state.DNSAnswerSetHash) == 48 && !bytes.Equal(confirm.DNSAnswerSetHash, state.DNSAnswerSetHash) {
		return fmt.Errorf("flow: UDP target confirm DNS answer hash mismatch")
	}
	return nil
}

func (m *Manager) DemuxInbound(flowID uint64) (FlowState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.flows[flowID]
	return state, ok
}

func (m *Manager) AcceptDatagram(flowID uint64, now uint64) (FlowState, bool) {
	return m.AcceptDatagramWithOptions(flowID, DatagramOptions{NowUnix: now})
}

func (m *Manager) AcceptDatagramWithOptions(flowID uint64, opts DatagramOptions) (FlowState, bool) {
	now := opts.NowUnix
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.flows[flowID]
	if !ok || state.Kind != FlowKindUDPAssociation {
		return FlowState{}, false
	}
	if state.LocalClosed || state.PeerClosed {
		return FlowState{}, false
	}
	if state.expired(now) {
		delete(m.flows, flowID)
		return FlowState{}, false
	}
	if state.staleRealtimeDatagram(opts) {
		return FlowState{}, false
	}
	state.LastActivityUnix = opts.NowUnix
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

func (m *Manager) MarkLocalClose(close protocol.FlowClose, opts CloseOptions) error {
	return m.markClose(close, opts, true)
}

func (m *Manager) MarkPeerClose(close protocol.FlowClose, opts CloseOptions) error {
	return m.markClose(close, opts, false)
}

func (m *Manager) MarkLocalCloseFrame(frame protocol.AuroraFrame, opts CloseOptions) error {
	close, err := decodeFlowCloseFrame(frame)
	if err != nil {
		return err
	}
	return m.MarkLocalClose(close, opts)
}

func (m *Manager) MarkPeerCloseFrame(frame protocol.AuroraFrame, opts CloseOptions) error {
	close, err := decodeFlowCloseFrame(frame)
	if err != nil {
		return err
	}
	return m.MarkPeerClose(close, opts)
}

func decodeFlowCloseFrame(frame protocol.AuroraFrame) (protocol.FlowClose, error) {
	if frame.FrameType != registry.FrameFlowClose {
		return protocol.FlowClose{}, fmt.Errorf("flow: expected FLOW_CLOSE frame, got 0x%x", frame.FrameType)
	}
	if err := protocol.ValidateFlowManagementFrame(frame); err != nil {
		return protocol.FlowClose{}, err
	}
	r := wire.NewReader(frame.Payload)
	close := protocol.DecodeFlowClose(r)
	if r.Err() != nil {
		return protocol.FlowClose{}, r.Err()
	}
	return close, nil
}

func (m *Manager) markClose(close protocol.FlowClose, opts CloseOptions, local bool) error {
	if err := protocol.ValidateFlowClose(close); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.flows[close.FlowID]
	if !ok {
		return fmt.Errorf("flow: unknown flow_id %d", close.FlowID)
	}
	if local {
		state.LocalClosed = true
	} else {
		state.PeerClosed = true
	}
	state.CloseCode = close.CloseCode
	state.FinalSequenceHintPresent = close.FinalSequenceHintPresent
	state.FinalSequenceHint = close.FinalSequenceHint
	state.DrainUntilUnix = closeDrainUntil(opts)
	if state.LocalClosed && state.PeerClosed {
		delete(m.flows, close.FlowID)
		return nil
	}
	m.flows[close.FlowID] = state
	return nil
}

func (m *Manager) PurgeClosed(now uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for flowID, state := range m.flows {
		if (state.LocalClosed || state.PeerClosed) && now >= state.DrainUntilUnix {
			delete(m.flows, flowID)
		}
	}
}

func validateOpen(open protocol.FlowOpen) error {
	if err := protocol.ValidateFlowOpen(open); err != nil {
		return err
	}
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
	if open.FlowKind == FlowKindUDPAssociation {
		if open.TargetKind == TargetKindDomainName && open.UDPFQDNMode != UDPFQDNRelayResolvedFlowBound {
			return fmt.Errorf("flow: UDP domain targets require relay-resolved FQDN mode")
		}
		if len(open.OriginalDomainHint) != 0 && (open.TargetKind != TargetKindDomainName || open.UDPFQDNMode != UDPFQDNRelayResolvedFlowBound) {
			return fmt.Errorf("flow: raw UDP domain hints require explicit relay-resolved FQDN mode")
		}
		if open.LocalBindingMode == LocalBindingTransparentFakeIP &&
			open.UDPFQDNMode == UDPFQDNRelayResolvedFlowBound {
			return fmt.Errorf("flow: relay-resolved UDP disabled by default for transparent fake-IP mode")
		}
	}
	return nil
}

func closeDrainUntil(opts CloseOptions) uint64 {
	return opts.NowUnix + opts.DrainSeconds
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

func (s FlowState) staleRealtimeDatagram(opts DatagramOptions) bool {
	if s.PriorityClass != PriorityRealtime || opts.MaxRealtimeAgeSeconds == 0 || opts.SentAtUnix == 0 {
		return false
	}
	if opts.NowUnix <= opts.SentAtUnix {
		return false
	}
	return opts.NowUnix-opts.SentAtUnix > opts.MaxRealtimeAgeSeconds
}

type FakeIPAllocator struct {
	network *net.IPNet
	mu      sync.Mutex
	byName  map[string]string
	byIP    map[string]FakeIPMapping
}

type FakeIPMapping struct {
	Domain  string
	Answers []string
}

func NewFakeIPAllocator(cidr string) *FakeIPAllocator {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		_, network, _ = net.ParseCIDR("198.18.0.0/15")
	}
	return &FakeIPAllocator{network: network, byName: make(map[string]string), byIP: make(map[string]FakeIPMapping)}
}

func (a *FakeIPAllocator) Assign(domain string, answers []string) (fakeIP string, nameBindingID []byte, err error) {
	name := canonicalDomain(domain)
	if name == "" {
		return "", nil, fmt.Errorf("flow: empty domain")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if ip, ok := a.byName[name]; ok {
		a.byIP[ip] = newFakeIPMapping(name, answers)
		return ip, bindingID(name, answers), nil
	}
	fakeIP, err = a.nextAvailableIPLocked(name)
	if err != nil {
		return "", nil, err
	}
	a.byName[name] = fakeIP
	a.byIP[fakeIP] = newFakeIPMapping(name, answers)
	return fakeIP, bindingID(name, answers), nil
}

func (a *FakeIPAllocator) AnswersForFakeIP(fakeIP string) ([]string, bool) {
	mapping, ok := a.MappingForFakeIP(fakeIP)
	if !ok {
		return nil, false
	}
	return append([]string(nil), mapping.Answers...), true
}

func (a *FakeIPAllocator) MappingForFakeIP(fakeIP string) (FakeIPMapping, bool) {
	ip := net.ParseIP(fakeIP).To4()
	if ip == nil {
		return FakeIPMapping{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	mapping, ok := a.byIP[ip.String()]
	if !ok {
		return FakeIPMapping{}, false
	}
	return cloneFakeIPMapping(mapping), true
}

func (a *FakeIPAllocator) nextAvailableIPLocked(name string) (string, error) {
	base := a.network.IP.To4()
	if base == nil {
		return "", fmt.Errorf("flow: fake IP network must be IPv4")
	}
	ones, bits := a.network.Mask.Size()
	if bits != 32 || ones < 0 {
		return "", fmt.Errorf("flow: fake IP network must be IPv4")
	}
	span := uint64(1) << uint(32-ones)
	firstOffset, usable := uint64(0), span
	if span > 2 {
		firstOffset, usable = 1, span-2
	}
	hash := sha256.Sum256([]byte(name))
	start := uint64(binary.BigEndian.Uint32(hash[:4])) % usable
	baseInt := binary.BigEndian.Uint32(base)
	for probe := uint64(0); probe < usable; probe++ {
		offset := firstOffset + ((start + probe) % usable)
		candidate := ipv4FromUint32(baseInt + uint32(offset)).String()
		if _, exists := a.byIP[candidate]; !exists {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("flow: fake IP network exhausted")
}

func ipv4FromUint32(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
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
	for _, answer := range canonicalAnswers(answers) {
		h.Write([]byte{0})
		h.Write([]byte(answer))
	}
	return auroracrypto.Truncate128(h.Sum(nil))
}

func DNSAnswerSetHash(answers []string) []byte {
	h := sha256.Sum256([]byte(strings.Join(canonicalAnswers(answers), "\x00")))
	return auroracrypto.PreHash([]byte(hex.EncodeToString(h[:])))
}

func newFakeIPMapping(domain string, answers []string) FakeIPMapping {
	return FakeIPMapping{
		Domain:  canonicalDomain(domain),
		Answers: append([]string(nil), answers...),
	}
}

func cloneFakeIPMapping(mapping FakeIPMapping) FakeIPMapping {
	return FakeIPMapping{
		Domain:  mapping.Domain,
		Answers: append([]string(nil), mapping.Answers...),
	}
}

func canonicalAnswers(answers []string) []string {
	out := make([]string, 0, len(answers))
	for _, answer := range answers {
		answer = strings.TrimSpace(strings.ToLower(answer))
		if ip := net.ParseIP(answer); ip != nil {
			answer = ip.String()
		}
		if answer != "" {
			out = append(out, answer)
		}
	}
	sort.Strings(out)
	return out
}
