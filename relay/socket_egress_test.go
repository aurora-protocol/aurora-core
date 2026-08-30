package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	coreflow "github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type socketDialCall struct {
	network string
	address string
}

type recordingContextDialer struct {
	calls   []socketDialCall
	err     error
	conn    net.Conn
	useConn bool
	peers   []net.Conn
}

type closeErrorConn struct {
	net.Conn
	err error
}

func (c *closeErrorConn) Close() error {
	_ = c.Conn.Close()
	return c.err
}

type invalidReadSocketConn struct {
	net.Conn
	readCount int
}

func (c *invalidReadSocketConn) Read([]byte) (int, error) {
	return c.readCount, nil
}

type observingReadSocketConn struct {
	net.Conn
	payload []byte
	buffer  []byte
}

func (c *observingReadSocketConn) Read(buffer []byte) (int, error) {
	c.buffer = buffer
	copy(buffer, c.payload)
	return len(c.payload), io.EOF
}

func (d *recordingContextDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.calls = append(d.calls, socketDialCall{network: network, address: address})
	if d.err != nil {
		return nil, d.err
	}
	if d.useConn {
		return d.conn, nil
	}
	local, peer := net.Pipe()
	d.peers = append(d.peers, peer)
	return local, nil
}

func (d *recordingContextDialer) closePeers() {
	for _, peer := range d.peers {
		_ = peer.Close()
	}
}

type socketResolveCall struct {
	network string
	host    string
}

type recordingIPResolver struct {
	answers []netip.Addr
	calls   []socketResolveCall
	err     error
}

type recordingDNSMessageResolver struct {
	response []byte
	calls    [][]byte
	err      error
}

func (r *recordingDNSMessageResolver) ExchangeDNS(_ context.Context, query []byte) ([]byte, error) {
	r.calls = append(r.calls, append([]byte(nil), query...))
	return append([]byte(nil), r.response...), r.err
}

func (r *recordingIPResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls = append(r.calls, socketResolveCall{network: network, host: host})
	return append([]netip.Addr(nil), r.answers...), r.err
}

type blockingIPResolver struct {
	started  chan struct{}
	canceled chan struct{}
	release  chan struct{}
}

type channelFrameSink struct {
	blocks chan protocol.FrameBlock
}

func (s *channelFrameSink) QueueFrames(ctx context.Context, block protocol.FrameBlock) error {
	owned := protocol.FrameBlock{Frames: appendAuroraFrames(nil, block.Frames)}
	select {
	case s.blocks <- owned:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *blockingIPResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	close(r.started)
	<-ctx.Done()
	close(r.canceled)
	<-r.release
	return nil, ctx.Err()
}

func TestNewSocketEgressRejectsInvalidDependenciesAndLimits(t *testing.T) {
	ctx := context.Background()
	sink := &recordingFrameSink{}
	dialer := &recordingContextDialer{}
	resolver := &recordingIPResolver{}
	tests := []struct {
		name string
		ctx  context.Context
		opts SocketEgressOptions
	}{
		{name: "nil context", opts: SocketEgressOptions{Sink: sink, Dialer: dialer, Resolver: resolver}},
		{name: "nil sink", ctx: ctx, opts: SocketEgressOptions{Dialer: dialer, Resolver: resolver}},
		{name: "typed nil sink", ctx: ctx, opts: SocketEgressOptions{Sink: (*recordingFrameSink)(nil), Dialer: dialer, Resolver: resolver}},
		{name: "nil dialer", ctx: ctx, opts: SocketEgressOptions{Sink: sink, Resolver: resolver}},
		{name: "typed nil dialer", ctx: ctx, opts: SocketEgressOptions{Sink: sink, Dialer: (*recordingContextDialer)(nil), Resolver: resolver}},
		{name: "nil resolver", ctx: ctx, opts: SocketEgressOptions{Sink: sink, Dialer: dialer}},
		{name: "typed nil resolver", ctx: ctx, opts: SocketEgressOptions{Sink: sink, Dialer: dialer, Resolver: (*recordingIPResolver)(nil)}},
		{name: "partial limits", ctx: ctx, opts: SocketEgressOptions{
			Sink: sink, Dialer: dialer, Resolver: resolver,
			Limits: SocketEgressLimits{MaxFlows: 1},
		}},
		{name: "too many flows", ctx: ctx, opts: SocketEgressOptions{
			Sink: sink, Dialer: dialer, Resolver: resolver,
			Limits: validSocketEgressLimits(maximumSocketEgressFlows + 1),
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			egress, err := NewSocketEgress(test.ctx, test.opts)
			if err == nil {
				_ = egress.Close()
				t.Fatal("NewSocketEgress accepted invalid input")
			}
		})
	}
}

func validSocketEgressLimits(maxFlows int) SocketEgressLimits {
	return SocketEgressLimits{
		MaxFlows:            maxFlows,
		MaxBufferedBytes:    4 << 20,
		TCPReadBufferBytes:  16 << 10,
		MaxUDPDatagramBytes: 65535,
		DialTimeout:         time.Second,
		WriteTimeout:        time.Second,
		IdleTimeout:         time.Minute,
		QueueRetryInterval:  time.Millisecond,
		ResolvedTTLSeconds:  60,
	}
}

func TestSocketEgressUsesAuthoritativeIPWithoutResolution(t *testing.T) {
	dialer := &recordingContextDialer{}
	resolver := &recordingIPResolver{answers: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   dialer,
		Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() {
		_ = egress.Close()
		dialer.closePeers()
	})

	frames, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind:   ExitEventFlowOpened,
		FlowID: 71,
		Flow: coreflow.FlowState{
			FlowID:      71,
			Kind:        coreflow.FlowKindUDPAssociation,
			TargetKind:  coreflow.TargetKindIPv4,
			TargetHost:  []byte{93, 184, 216, 34},
			TargetPort:  443,
			UDPFQDNMode: coreflow.UDPFQDNClientResolvedNameBinding,
		},
	})
	if err != nil {
		t.Fatalf("HandleEvent failed: %v", err)
	}
	if len(frames) != 0 {
		t.Fatalf("HandleEvent returned %d frames, want none", len(frames))
	}
	if len(resolver.calls) != 0 {
		t.Fatalf("resolver calls = %d, want 0", len(resolver.calls))
	}
	if len(dialer.calls) != 1 || dialer.calls[0] != (socketDialCall{network: "udp4", address: "93.184.216.34:443"}) {
		t.Fatalf("dial calls = %#v", dialer.calls)
	}
}

func TestSocketEgressResolvesDNSMessageWithoutOpeningSocket(t *testing.T) {
	dialer := &recordingContextDialer{}
	resolver := &recordingIPResolver{answers: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   dialer,
		Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	query := socketEgressDNSQuery(t, "example.com", 1)
	frames, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind:   ExitEventDNSMessage,
		FlowID: 81,
		Data:   query,
	})
	if err != nil {
		t.Fatalf("HandleEvent failed: %v", err)
	}
	if len(frames) != 1 || frames[0].FrameType != registry.FrameDNSMessage || frames[0].FlowID != 81 {
		t.Fatalf("DNS response frames = %#v", frames)
	}
	response := frames[0].Payload
	if len(response) < len(query)+16 || !bytes.Equal(response[:2], query[:2]) || response[2]&0x80 == 0 || binary.BigEndian.Uint16(response[6:8]) != 1 {
		t.Fatalf("unexpected DNS response: %x", response)
	}
	if len(resolver.calls) != 1 || resolver.calls[0] != (socketResolveCall{network: "ip4", host: "example.com"}) {
		t.Fatalf("resolver calls = %#v", resolver.calls)
	}
	if len(dialer.calls) != 0 {
		t.Fatalf("DNS resolution opened sockets: %#v", dialer.calls)
	}
}

func TestSocketEgressResolvesIPv6EDNSDNSMessageWithoutOpeningSocket(t *testing.T) {
	dialer := &recordingContextDialer{}
	resolver := &recordingIPResolver{answers: []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   dialer,
		Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	query := socketEgressDNSQuery(t, "example.com", socketDNSTypeAAAA)
	binary.BigEndian.PutUint16(query[10:12], 1)
	query = append(query, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
	frames, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind:   ExitEventDNSMessage,
		FlowID: 82,
		Data:   query,
	})
	if err != nil {
		t.Fatalf("HandleEvent failed: %v", err)
	}
	if len(frames) != 1 || frames[0].FrameType != registry.FrameDNSMessage || frames[0].FlowID != 82 {
		t.Fatalf("DNS response frames = %#v", frames)
	}
	response := frames[0].Payload
	if len(response) < 28 || binary.BigEndian.Uint16(response[6:8]) != 1 || binary.BigEndian.Uint16(response[10:12]) != 0 || !bytes.Equal(response[len(response)-16:], netip.MustParseAddr("2606:4700:4700::1111").AsSlice()) {
		t.Fatalf("unexpected IPv6 DNS response: %x", response)
	}
	if len(resolver.calls) != 1 || resolver.calls[0] != (socketResolveCall{network: "ip6", host: "example.com"}) {
		t.Fatalf("resolver calls = %#v", resolver.calls)
	}
	if len(dialer.calls) != 0 {
		t.Fatalf("DNS resolution opened sockets: %#v", dialer.calls)
	}
}

func TestSocketEgressDNSMessageDoesNotReturnPolicyDeniedAddress(t *testing.T) {
	dialer := &recordingContextDialer{}
	resolver := &recordingIPResolver{answers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   dialer,
		Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	frames, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind:   ExitEventDNSMessage,
		FlowID: 83,
		Data:   socketEgressDNSQuery(t, "example.com", socketDNSTypeA),
	})
	if err != nil {
		t.Fatalf("HandleEvent failed: %v", err)
	}
	if len(frames) != 1 || len(frames[0].Payload) < 12 || frames[0].Payload[3]&0x0f != socketDNSRCodeFail || binary.BigEndian.Uint16(frames[0].Payload[6:8]) != 0 {
		t.Fatalf("policy denied DNS response = %#v", frames)
	}
	if len(dialer.calls) != 0 {
		t.Fatalf("DNS policy denial opened sockets: %#v", dialer.calls)
	}
}

func TestSocketEgressDNSMessageRejectsOversizedResolverAnswerSet(t *testing.T) {
	answers := make([]netip.Addr, 0, 33)
	for octet := byte(1); octet <= 33; octet++ {
		answers = append(answers, netip.AddrFrom4([4]byte{8, 8, 8, octet}))
	}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   &recordingContextDialer{},
		Resolver: &recordingIPResolver{answers: answers},
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	frames, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind:   ExitEventDNSMessage,
		FlowID: 84,
		Data:   socketEgressDNSQuery(t, "example.com", socketDNSTypeA),
	})
	if err != nil {
		t.Fatalf("HandleEvent failed: %v", err)
	}
	if len(frames) != 1 || len(frames[0].Payload) < 12 || frames[0].Payload[3]&0x0f != socketDNSRCodeFail || binary.BigEndian.Uint16(frames[0].Payload[6:8]) != 0 {
		t.Fatalf("oversized DNS answer set response = %#v", frames)
	}
}

func TestSocketEgressForwardsSVCBDNSMessageThroughConfiguredResolver(t *testing.T) {
	query := socketEgressDNSQuery(t, "example.com", 64)
	response := append([]byte(nil), query...)
	response[2] |= socketDNSFlagResponse >> 8
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response,
		0xc0, 0x0c,
		0x00, 0x40,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x03,
		0x00, 0x01, 0x00,
	)
	dnsResolver := &recordingDNSMessageResolver{response: response}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:        &recordingFrameSink{},
		Dialer:      &recordingContextDialer{},
		Resolver:    &recordingIPResolver{},
		DNSResolver: dnsResolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	frames, err := egress.HandleEvent(context.Background(), ExitFrameEvent{Kind: ExitEventDNSMessage, FlowID: 85, Data: query})
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || !bytes.Equal(frames[0].Payload, response) {
		t.Fatalf("forwarded DNS response = %#v, want %x", frames, response)
	}
	if len(dnsResolver.calls) != 1 || !bytes.Equal(dnsResolver.calls[0], query) {
		t.Fatalf("DNS resolver calls = %#v", dnsResolver.calls)
	}
}

func TestSocketEgressForwardsEDNSSVCBDNSMessageThroughConfiguredResolver(t *testing.T) {
	query := socketEgressDNSQuery(t, "example.com", socketDNSTypeSVCB)
	binary.BigEndian.PutUint16(query[10:12], 1)
	query = append(query, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
	response := append([]byte(nil), query...)
	response[2] |= socketDNSFlagResponse >> 8
	dnsResolver := &recordingDNSMessageResolver{response: response}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:        &recordingFrameSink{},
		Dialer:      &recordingContextDialer{},
		Resolver:    &recordingIPResolver{},
		DNSResolver: dnsResolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = egress.Close() })

	frames, err := egress.HandleEvent(context.Background(), ExitFrameEvent{Kind: ExitEventDNSMessage, FlowID: 85, Data: query})
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || !bytes.Equal(frames[0].Payload, response) {
		t.Fatalf("forwarded EDNS DNS response = %#v, want %x", frames, response)
	}
	if len(dnsResolver.calls) != 1 || !bytes.Equal(dnsResolver.calls[0], query) {
		t.Fatalf("DNS resolver calls = %#v", dnsResolver.calls)
	}
}

func TestSocketEgressRejectsPolicyDeniedSVCBAddressHints(t *testing.T) {
	query := socketEgressDNSQuery(t, "example.com", socketDNSTypeHTTPS)
	response := append([]byte(nil), query...)
	response[2] |= socketDNSFlagResponse >> 8
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response,
		0xc0, 0x0c,
		0x00, socketDNSTypeHTTPS,
		0x00, socketDNSClassIN,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x0b,
		0x00, 0x01, 0x00,
		0x00, socketDNSSvcIPv4, 0x00, 0x04,
		127, 0, 0, 1,
	)
	dnsResolver := &recordingDNSMessageResolver{response: response}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:        &recordingFrameSink{},
		Dialer:      &recordingContextDialer{},
		Resolver:    &recordingIPResolver{},
		DNSResolver: dnsResolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	frames, err := egress.HandleEvent(context.Background(), ExitFrameEvent{Kind: ExitEventDNSMessage, FlowID: 86, Data: query})
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || len(frames[0].Payload) < socketDNSHeaderBytes || frames[0].Payload[3]&0x0f != socketDNSRCodeFail || binary.BigEndian.Uint16(frames[0].Payload[6:8]) != 0 {
		t.Fatalf("policy denied SVCB response = %#v", frames)
	}
}

func TestSocketEgressDNSMessageRejectsMalformedQuestionSections(t *testing.T) {
	resolver := &recordingIPResolver{answers: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   &recordingContextDialer{},
		Resolver: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	query := socketEgressDNSQuery(t, "example.com", socketDNSTypeA)
	binary.BigEndian.PutUint16(query[6:8], 1)
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{Kind: ExitEventDNSMessage, FlowID: 85, Data: query}); !errors.Is(err, ErrExitDNSMessageInvalid) {
		t.Fatalf("answer-bearing DNS query error = %v, want ErrExitDNSMessageInvalid", err)
	}
	if len(resolver.calls) != 0 {
		t.Fatalf("resolver calls = %#v, want none", resolver.calls)
	}
}

func TestSocketEgressDNSMessageRejectsOversizedEncodedName(t *testing.T) {
	resolver := &recordingIPResolver{answers: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   &recordingContextDialer{},
		Resolver: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = egress.Close() })

	label := strings.Repeat("a", 63)
	query := socketEgressDNSQuery(t, strings.Join([]string{label, label, label, label}, "."), socketDNSTypeA)
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{Kind: ExitEventDNSMessage, FlowID: 85, Data: query}); !errors.Is(err, ErrExitDNSMessageInvalid) {
		t.Fatalf("oversized encoded DNS name error = %v, want ErrExitDNSMessageInvalid", err)
	}
	if len(resolver.calls) != 0 {
		t.Fatalf("resolver calls = %#v, want none", resolver.calls)
	}
}

func TestSocketEgressRejectsMixedPolicyResolutionBeforeDial(t *testing.T) {
	dialer := &recordingContextDialer{}
	resolver := &recordingIPResolver{answers: []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("127.0.0.1"),
	}}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   dialer,
		Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })

	_, err = egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind:   ExitEventFlowOpened,
		FlowID: 72,
		Flow: coreflow.FlowState{
			FlowID:     72,
			Kind:       coreflow.FlowKindTCPStream,
			TargetKind: coreflow.TargetKindDomainName,
			TargetHost: []byte("example.com"),
			TargetPort: 443,
		},
	})
	if !errors.Is(err, ErrExitPolicyDenied) {
		t.Fatalf("HandleEvent error = %v, want ErrExitPolicyDenied", err)
	}
	if len(dialer.calls) != 0 {
		t.Fatalf("dial calls = %#v, want none", dialer.calls)
	}
}

func TestSocketEgressRejectsTypedNilDialResult(t *testing.T) {
	dialer := &recordingContextDialer{conn: (*net.TCPConn)(nil), useConn: true}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Policy:   ExitPolicy{AllowPrivate: true},
		Dialer:   dialer,
		Resolver: &recordingIPResolver{},
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })

	_, err = egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind:   ExitEventFlowOpened,
		FlowID: 73,
		Flow: coreflow.FlowState{
			FlowID:     73,
			Kind:       coreflow.FlowKindTCPStream,
			TargetKind: coreflow.TargetKindIPv4,
			TargetHost: []byte{127, 0, 0, 1},
			TargetPort: 443,
		},
	})
	if !errors.Is(err, ErrExitDialFailed) {
		t.Fatalf("HandleEvent error = %v, want ErrExitDialFailed", err)
	}
}

func TestSocketEgressCloseWaitsForActiveResolution(t *testing.T) {
	resolver := &blockingIPResolver{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
	}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   &recordingContextDialer{},
		Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	eventResult := make(chan error, 1)
	go func() {
		_, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
			Kind:   ExitEventFlowOpened,
			FlowID: 74,
			Flow: coreflow.FlowState{
				FlowID:     74,
				Kind:       coreflow.FlowKindTCPStream,
				TargetKind: coreflow.TargetKindDomainName,
				TargetHost: []byte("example.com"),
				TargetPort: 443,
			},
		})
		eventResult <- err
	}()
	select {
	case <-resolver.started:
	case <-time.After(time.Second):
		t.Fatal("resolver did not start")
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- egress.Close() }()
	select {
	case <-resolver.canceled:
	case <-time.After(time.Second):
		close(resolver.release)
		t.Fatal("Close did not cancel resolver")
	}
	select {
	case err := <-closeResult:
		close(resolver.release)
		<-eventResult
		t.Fatalf("Close returned before active resolution completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(resolver.release)
	if err := <-eventResult; !errors.Is(err, ErrSocketEgressClosed) {
		t.Errorf("HandleEvent error = %v, want ErrSocketEgressClosed", err)
	}
	if err := <-closeResult; err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestSocketEgressSelectsCanonicalResolvedAddress(t *testing.T) {
	dialer := &recordingContextDialer{}
	resolver := &recordingIPResolver{answers: []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   dialer,
		Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() {
		_ = egress.Close()
		dialer.closePeers()
	})
	_, err = egress.HandleEvent(context.Background(), tcpDomainOpenEvent(75, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent failed: %v", err)
	}
	if len(resolver.calls) != 1 || resolver.calls[0] != (socketResolveCall{network: "ip", host: "example.com"}) {
		t.Fatalf("resolver calls = %#v", resolver.calls)
	}
	if len(dialer.calls) != 1 || dialer.calls[0] != (socketDialCall{network: "tcp4", address: "1.1.1.1:443"}) {
		t.Fatalf("dial calls = %#v", dialer.calls)
	}
}

func TestSocketEgressEnforcesFlowLimitAndReleasesFailedDial(t *testing.T) {
	dialer := &recordingContextDialer{err: errors.New("dial detail")}
	limits := validSocketEgressLimits(1)
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   dialer,
		Resolver: &recordingIPResolver{},
		Limits:   limits,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() {
		_ = egress.Close()
		dialer.closePeers()
	})
	if _, err := egress.HandleEvent(context.Background(), tcpIPOpenEvent(76, [4]byte{93, 184, 216, 34})); !errors.Is(err, ErrExitDialFailed) {
		t.Fatalf("first HandleEvent error = %v, want ErrExitDialFailed", err)
	}
	dialer.err = nil
	if _, err := egress.HandleEvent(context.Background(), tcpIPOpenEvent(77, [4]byte{93, 184, 216, 34})); err != nil {
		t.Fatalf("HandleEvent after failed dial did not reuse reservation: %v", err)
	}
	if _, err := egress.HandleEvent(context.Background(), tcpIPOpenEvent(77, [4]byte{93, 184, 216, 34})); !errors.Is(err, ErrExitDuplicateFlow) {
		t.Fatalf("duplicate HandleEvent error = %v, want ErrExitDuplicateFlow", err)
	}
	if _, err := egress.HandleEvent(context.Background(), tcpIPOpenEvent(78, [4]byte{93, 184, 216, 34})); !errors.Is(err, ErrExitFlowLimit) {
		t.Fatalf("over-limit HandleEvent error = %v, want ErrExitFlowLimit", err)
	}
}

func TestSocketEgressRedactsResolverFailure(t *testing.T) {
	resolver := &recordingIPResolver{err: errors.New("secret.example internal resolver detail")}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   &recordingContextDialer{},
		Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	_, err = egress.HandleEvent(context.Background(), tcpDomainOpenEvent(79, "secret.example"))
	if !errors.Is(err, ErrExitResolveFailed) {
		t.Fatalf("HandleEvent error = %v, want ErrExitResolveFailed", err)
	}
	if strings.Contains(err.Error(), "secret.example") || strings.Contains(err.Error(), "internal") {
		t.Fatalf("resolver detail escaped in error: %v", err)
	}
}

func TestSocketEgressRedactsCloseFailure(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	dialer := &recordingContextDialer{
		conn:    &closeErrorConn{Conn: local, err: errors.New("10.0.0.1 close detail")},
		useConn: true,
	}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   dialer,
		Resolver: &recordingIPResolver{},
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	if _, err := egress.HandleEvent(context.Background(), tcpIPOpenEvent(80, [4]byte{93, 184, 216, 34})); err != nil {
		t.Fatalf("HandleEvent failed: %v", err)
	}
	err = egress.Close()
	if !errors.Is(err, ErrExitCloseFailed) {
		t.Fatalf("Close error = %v, want ErrExitCloseFailed", err)
	}
	if strings.Contains(err.Error(), "10.0.0.1") || strings.Contains(err.Error(), "detail") {
		t.Fatalf("close detail escaped in error: %v", err)
	}
}

func tcpDomainOpenEvent(flowID uint64, domain string) ExitFrameEvent {
	return ExitFrameEvent{
		Kind:   ExitEventFlowOpened,
		FlowID: flowID,
		Flow: coreflow.FlowState{
			FlowID:     flowID,
			Kind:       coreflow.FlowKindTCPStream,
			TargetKind: coreflow.TargetKindDomainName,
			TargetHost: []byte(domain),
			TargetPort: 443,
		},
	}
}

func tcpIPOpenEvent(flowID uint64, addr [4]byte) ExitFrameEvent {
	return ExitFrameEvent{
		Kind:   ExitEventFlowOpened,
		FlowID: flowID,
		Flow: coreflow.FlowState{
			FlowID:     flowID,
			Kind:       coreflow.FlowKindTCPStream,
			TargetKind: coreflow.TargetKindIPv4,
			TargetHost: append([]byte(nil), addr[:]...),
			TargetPort: 443,
		},
	}
}

func socketEgressDNSQuery(t testing.TB, domain string, queryType uint16) []byte {
	t.Helper()
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, byte(queryType>>8), byte(queryType), 0, 1)
	return query
}

func TestSocketEgressTCPReadPumpRejectsInvalidReadLength(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Policy:   ExitPolicy{AllowPrivate: true},
		Dialer:   &recordingContextDialer{},
		Resolver: &recordingIPResolver{},
		Limits:   validSocketEgressLimits(1),
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	defer egress.Close()
	flowState := coreflow.FlowState{
		FlowID:     79,
		Kind:       coreflow.FlowKindTCPStream,
		TargetKind: coreflow.TargetKindIPv4,
		TargetHost: []byte{127, 0, 0, 1},
		TargetPort: 443,
	}
	flow, err := egress.reserveFlow(flowState)
	if err != nil {
		t.Fatalf("reserveFlow failed: %v", err)
	}
	if err := egress.installFlow(flowState.FlowID, flow, &invalidReadSocketConn{Conn: local, readCount: flow.bufferBytes + 1}, selectedSocketTarget{}, context.Background()); err != nil {
		t.Fatalf("installFlow failed: %v", err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("runTCPReadPump panicked on invalid read length: %v", recovered)
		}
	}()

	egress.runTCPReadPump(flowState.FlowID, flow)
}

func TestSocketEgressTCPReadPumpZeroesTerminatedReadBuffer(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	sink := &channelFrameSink{blocks: make(chan protocol.FrameBlock, 2)}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     sink,
		Policy:   ExitPolicy{AllowPrivate: true},
		Dialer:   &recordingContextDialer{},
		Resolver: &recordingIPResolver{},
		Limits:   validSocketEgressLimits(1),
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	defer egress.Close()
	flowState := coreflow.FlowState{
		FlowID:     80,
		Kind:       coreflow.FlowKindTCPStream,
		TargetKind: coreflow.TargetKindIPv4,
		TargetHost: []byte{127, 0, 0, 1},
		TargetPort: 443,
	}
	flow, err := egress.reserveFlow(flowState)
	if err != nil {
		t.Fatalf("reserveFlow failed: %v", err)
	}
	conn := &observingReadSocketConn{Conn: local, payload: []byte{0x45, 0x11, 0x22, 0x33}}
	if err := egress.installFlow(flowState.FlowID, flow, conn, selectedSocketTarget{}, context.Background()); err != nil {
		t.Fatalf("installFlow failed: %v", err)
	}

	egress.runTCPReadPump(flowState.FlowID, flow)

	if len(conn.buffer) != flow.bufferBytes {
		t.Fatalf("observed read buffer length = %d, want %d", len(conn.buffer), flow.bufferBytes)
	}
	for index, value := range conn.buffer {
		if value != 0 {
			t.Fatalf("terminated read buffer byte %d = %x, want zero", index, value)
		}
	}
}

func TestSocketEgressTCPRoundTripAndEOF(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		request := make([]byte, 4)
		if _, err := io.ReadFull(conn, request); err != nil {
			serverResult <- err
			return
		}
		if string(request) != "ping" {
			serverResult <- errors.New("unexpected TCP request")
			return
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			serverResult <- err
			return
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			serverResult <- tcp.CloseWrite()
			return
		}
		serverResult <- nil
	}()

	sink := &channelFrameSink{blocks: make(chan protocol.FrameBlock, 4)}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     sink,
		Policy:   ExitPolicy{AllowPrivate: true},
		Dialer:   &net.Dialer{},
		Resolver: net.DefaultResolver,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	port := listener.Addr().(*net.TCPAddr).Port
	flow := coreflow.FlowState{
		FlowID:     81,
		Kind:       coreflow.FlowKindTCPStream,
		TargetKind: coreflow.TargetKindIPv4,
		TargetHost: []byte{127, 0, 0, 1},
		TargetPort: uint16(port),
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowOpened, FlowID: flow.FlowID, Flow: flow,
	}); err != nil {
		t.Fatalf("open HandleEvent failed: %v", err)
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventStreamData, FlowID: flow.FlowID, Flow: flow, Data: []byte("ping"),
	}); err != nil {
		t.Fatalf("data HandleEvent failed: %v", err)
	}

	assertSocketFrame(t, sink.blocks, registry.FrameStreamData, flow.FlowID, "pong")
	assertSocketFrame(t, sink.blocks, registry.FrameFlowClose, flow.FlowID, "")
	if err := <-serverResult; err != nil {
		t.Fatalf("TCP server failed: %v", err)
	}
}

func assertSocketFrame(t *testing.T, blocks <-chan protocol.FrameBlock, frameType, flowID uint64, payload string) {
	t.Helper()
	select {
	case block := <-blocks:
		if len(block.Frames) != 1 {
			t.Fatalf("frame block has %d frames, want 1", len(block.Frames))
		}
		frame := block.Frames[0]
		if frame.FrameType != frameType || frame.FlowID != flowID {
			t.Fatalf("frame = type 0x%x flow %d, want type 0x%x flow %d", frame.FrameType, frame.FlowID, frameType, flowID)
		}
		if payload != "" && string(frame.Payload) != payload {
			t.Fatalf("frame payload = %q, want %q", frame.Payload, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for frame type 0x%x", frameType)
	}
}

func TestSocketEgressTCPNormalCloseDrainsDestinationRead(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		request, err := io.ReadAll(conn)
		if err != nil {
			serverResult <- err
			return
		}
		if string(request) != "request" {
			serverResult <- errors.New("unexpected half-close request")
			return
		}
		_, err = conn.Write([]byte("final"))
		serverResult <- err
	}()

	sink := &channelFrameSink{blocks: make(chan protocol.FrameBlock, 4)}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     sink,
		Policy:   ExitPolicy{AllowPrivate: true},
		Dialer:   &net.Dialer{},
		Resolver: net.DefaultResolver,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	flow := coreflow.FlowState{
		FlowID:     82,
		Kind:       coreflow.FlowKindTCPStream,
		TargetKind: coreflow.TargetKindIPv4,
		TargetHost: []byte{127, 0, 0, 1},
		TargetPort: uint16(listener.Addr().(*net.TCPAddr).Port),
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowOpened, FlowID: flow.FlowID, Flow: flow,
	}); err != nil {
		t.Fatalf("open HandleEvent failed: %v", err)
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventStreamData, FlowID: flow.FlowID, Flow: flow, Data: []byte("request"),
	}); err != nil {
		t.Fatalf("data HandleEvent failed: %v", err)
	}
	flow.PeerClosed = true
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowClosed, FlowID: flow.FlowID, Flow: flow,
		Close: protocol.FlowClose{FlowID: flow.FlowID, CloseCode: protocol.CloseNormal},
	}); err != nil {
		t.Fatalf("close HandleEvent failed: %v", err)
	}

	assertSocketFrame(t, sink.blocks, registry.FrameStreamData, flow.FlowID, "final")
	assertSocketFrame(t, sink.blocks, registry.FrameFlowClose, flow.FlowID, "")
	if err := <-serverResult; err != nil {
		t.Fatalf("TCP server failed: %v", err)
	}
}

func TestSocketEgressTCPCanceledWriteReleasesFlow(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	writeStarted := make(chan struct{}, 1)
	dialer := &recordingContextDialer{conn: &writeStartedConn{Conn: local, started: writeStarted}, useConn: true}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &channelFrameSink{blocks: make(chan protocol.FrameBlock, 4)},
		Policy:   ExitPolicy{AllowPrivate: true},
		Dialer:   dialer,
		Resolver: &recordingIPResolver{},
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	flow := coreflow.FlowState{
		FlowID:     83,
		Kind:       coreflow.FlowKindTCPStream,
		TargetKind: coreflow.TargetKindIPv4,
		TargetHost: []byte{127, 0, 0, 1},
		TargetPort: 443,
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowOpened, FlowID: flow.FlowID, Flow: flow,
	}); err != nil {
		t.Fatalf("open HandleEvent failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	writeResult := make(chan error, 1)
	go func() {
		_, err := egress.HandleEvent(ctx, ExitFrameEvent{
			Kind: ExitEventStreamData, FlowID: flow.FlowID, Flow: flow, Data: []byte("blocked"),
		})
		writeResult <- err
	}()
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("write did not start")
	}
	cancel()
	select {
	case err := <-writeResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("write error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled write did not return")
	}
	egress.mu.Lock()
	_, retained := egress.flows[flow.FlowID]
	egress.mu.Unlock()
	if retained {
		t.Fatal("canceled partial write retained the flow")
	}
}

type writeStartedConn struct {
	net.Conn
	started chan<- struct{}
}

func (c *writeStartedConn) Write(payload []byte) (int, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	return c.Conn.Write(payload)
}

func TestSocketEgressLifecycleCancellationInterruptsTCPWrite(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, peer := net.Pipe()
	defer peer.Close()
	writeStarted := make(chan struct{}, 1)
	egress, err := NewSocketEgress(parent, SocketEgressOptions{
		Sink:     &channelFrameSink{blocks: make(chan protocol.FrameBlock, 4)},
		Policy:   ExitPolicy{AllowPrivate: true},
		Dialer:   &recordingContextDialer{conn: &writeStartedConn{Conn: local, started: writeStarted}, useConn: true},
		Resolver: &recordingIPResolver{},
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	flow := coreflow.FlowState{
		FlowID:     86,
		Kind:       coreflow.FlowKindTCPStream,
		TargetKind: coreflow.TargetKindIPv4,
		TargetHost: []byte{127, 0, 0, 1},
		TargetPort: 443,
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowOpened, FlowID: flow.FlowID, Flow: flow,
	}); err != nil {
		t.Fatalf("open HandleEvent failed: %v", err)
	}
	writeResult := make(chan error, 1)
	go func() {
		_, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
			Kind: ExitEventStreamData, FlowID: flow.FlowID, Flow: flow, Data: []byte("blocked"),
		})
		writeResult <- err
	}()
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("write did not start")
	}
	cancel()
	select {
	case err := <-writeResult:
		if !errors.Is(err, ErrSocketEgressClosed) {
			t.Fatalf("write error = %v, want ErrSocketEgressClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lifecycle cancellation did not interrupt write")
	}
}

func TestSocketEgressTCPFlowCloseInterruptsBackpressure(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	sink := &blockingBackpressureSink{called: make(chan struct{}, 1)}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     sink,
		Policy:   ExitPolicy{AllowPrivate: true},
		Dialer:   &recordingContextDialer{conn: local, useConn: true},
		Resolver: &recordingIPResolver{},
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	flowState := coreflow.FlowState{
		FlowID:     84,
		Kind:       coreflow.FlowKindTCPStream,
		TargetKind: coreflow.TargetKindIPv4,
		TargetHost: []byte{127, 0, 0, 1},
		TargetPort: 443,
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowOpened, FlowID: flowState.FlowID, Flow: flowState,
	}); err != nil {
		t.Fatalf("open HandleEvent failed: %v", err)
	}
	egress.mu.Lock()
	flow := egress.flows[flowState.FlowID]
	egress.mu.Unlock()
	writeResult := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte("response"))
		writeResult <- err
	}()
	select {
	case <-sink.called:
	case <-time.After(time.Second):
		t.Fatal("read pump did not reach backpressured sink")
	}
	flowState.PeerClosed = true
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowClosed, FlowID: flowState.FlowID, Flow: flowState,
		Close: protocol.FlowClose{FlowID: flowState.FlowID, CloseCode: protocol.CloseResetByPeer},
	}); err != nil {
		t.Fatalf("close HandleEvent failed: %v", err)
	}
	select {
	case <-flow.done:
	case <-time.After(time.Second):
		t.Fatal("flow close did not stop the backpressured read pump")
	}
	if err := <-writeResult; err != nil {
		t.Fatalf("destination write failed: %v", err)
	}
}

func TestSocketEgressTCPWriteTimeoutReleasesFlow(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	limits := validSocketEgressLimits(4)
	limits.WriteTimeout = 20 * time.Millisecond
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     &channelFrameSink{blocks: make(chan protocol.FrameBlock, 4)},
		Policy:   ExitPolicy{AllowPrivate: true},
		Dialer:   &recordingContextDialer{conn: local, useConn: true},
		Resolver: &recordingIPResolver{},
		Limits:   limits,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	flow := coreflow.FlowState{
		FlowID: 85, Kind: coreflow.FlowKindTCPStream,
		TargetKind: coreflow.TargetKindIPv4, TargetHost: []byte{127, 0, 0, 1}, TargetPort: 443,
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowOpened, FlowID: flow.FlowID, Flow: flow,
	}); err != nil {
		t.Fatalf("open HandleEvent failed: %v", err)
	}
	started := time.Now()
	_, err = egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventStreamData, FlowID: flow.FlowID, Flow: flow, Data: []byte("blocked"),
	})
	if !errors.Is(err, ErrExitWriteFailed) {
		t.Fatalf("write error = %v, want ErrExitWriteFailed", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("write timeout took %v", elapsed)
	}
	egress.mu.Lock()
	_, retained := egress.flows[flow.FlowID]
	egress.mu.Unlock()
	if retained {
		t.Fatal("timed-out write retained the flow")
	}
}

func TestSocketEgressTCPIdleTimeoutQueuesClose(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
		}
		close(serverDone)
	}()
	limits := validSocketEgressLimits(4)
	limits.IdleTimeout = 30 * time.Millisecond
	sink := &channelFrameSink{blocks: make(chan protocol.FrameBlock, 4)}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink: sink, Policy: ExitPolicy{AllowPrivate: true}, Dialer: &net.Dialer{},
		Resolver: net.DefaultResolver, Limits: limits,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	flow := coreflow.FlowState{
		FlowID: 86, Kind: coreflow.FlowKindTCPStream,
		TargetKind: coreflow.TargetKindIPv4, TargetHost: []byte{127, 0, 0, 1},
		TargetPort: uint16(listener.Addr().(*net.TCPAddr).Port),
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowOpened, FlowID: flow.FlowID, Flow: flow,
	}); err != nil {
		t.Fatalf("open HandleEvent failed: %v", err)
	}
	select {
	case block := <-sink.blocks:
		if len(block.Frames) != 1 || block.Frames[0].FrameType != registry.FrameFlowClose {
			t.Fatalf("idle frame block = %#v", block)
		}
		reader := wire.NewReader(block.Frames[0].Payload)
		closeFrame := protocol.DecodeFlowClose(reader)
		if reader.Err() != nil || !reader.EOF() || closeFrame.CloseCode != protocol.CloseIdleTimeout {
			t.Fatalf("idle close = %+v, decode error %v", closeFrame, reader.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for idle close")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("idle flow did not close destination socket")
	}
}

func TestSocketEgressUDPAssociationRoundTrip(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer server.Close()
	serverResult := make(chan error, 1)
	go func() {
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 64)
		n, client, err := server.ReadFromUDP(buffer)
		if err != nil {
			serverResult <- err
			return
		}
		if string(buffer[:n]) != "ping" {
			serverResult <- errors.New("unexpected UDP request")
			return
		}
		_, err = server.WriteToUDP([]byte("pong"), client)
		serverResult <- err
	}()

	sink := &channelFrameSink{blocks: make(chan protocol.FrameBlock, 8)}
	socketEgress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink: sink, Policy: ExitPolicy{AllowPrivate: true}, Dialer: &net.Dialer{},
		Resolver: net.DefaultResolver,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	exitSession, err := NewExitSession(socketEgress, sink, ExitSessionOptions{
		Policy: ExitPolicy{AllowPrivate: true},
	})
	if err != nil {
		_ = socketEgress.Close()
		t.Fatalf("NewExitSession failed: %v", err)
	}
	t.Cleanup(func() { _ = exitSession.Close() })
	open := relayUDPFlowOpen(91, []byte{127, 0, 0, 1})
	open.TargetPort = uint16(server.LocalAddr().(*net.UDPAddr).Port)
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{
		Frames: []protocol.AuroraFrame{flowOpenFrame(t, open)},
	}); err != nil {
		t.Fatalf("FLOW_OPEN failed: %v", err)
	}
	assertSocketFrame(t, sink.blocks, registry.FrameUDPTargetConfirm, open.FlowID, "")
	datagram, err := protocol.NewDatagramDataFrame(open.FlowID, []byte("ping"), 0)
	if err != nil {
		t.Fatalf("NewDatagramDataFrame failed: %v", err)
	}
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{
		Frames: []protocol.AuroraFrame{datagram},
	}); err != nil {
		t.Fatalf("DATAGRAM_DATA failed: %v", err)
	}
	assertSocketFrame(t, sink.blocks, registry.FrameDatagramData, open.FlowID, "pong")
	if err := <-serverResult; err != nil {
		t.Fatalf("UDP server failed: %v", err)
	}
	closeFrame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: open.FlowID, CloseCode: protocol.CloseNormal})
	if err != nil {
		t.Fatalf("NewFlowCloseFrame failed: %v", err)
	}
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{
		Frames: []protocol.AuroraFrame{closeFrame},
	}); err != nil {
		t.Fatalf("FLOW_CLOSE failed: %v", err)
	}
}

func TestSocketEgressUDPRelayResolutionConfirmation(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer server.Close()
	resolver := &recordingIPResolver{answers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	limits := validSocketEgressLimits(4)
	sink := &channelFrameSink{blocks: make(chan protocol.FrameBlock, 4)}
	socketEgress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink: sink, Policy: ExitPolicy{AllowPrivate: true}, Dialer: &net.Dialer{},
		Resolver: resolver, Limits: limits,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	exitSession, err := NewExitSession(socketEgress, sink, ExitSessionOptions{
		Policy: ExitPolicy{AllowPrivate: true},
	})
	if err != nil {
		_ = socketEgress.Close()
		t.Fatalf("NewExitSession failed: %v", err)
	}
	t.Cleanup(func() { _ = exitSession.Close() })
	open := protocol.FlowOpen{
		FlowOpenVersion: registry.Version20, FlowID: 92,
		FlowKind: coreflow.FlowKindUDPAssociation, TargetKind: coreflow.TargetKindDomainName,
		TargetHost: []byte("relay.test"), TargetPort: uint16(server.LocalAddr().(*net.UDPAddr).Port),
		UDPFQDNMode:   coreflow.UDPFQDNRelayResolvedFlowBound,
		NameBindingID: bytesOf(0x31, 16), DNSAnswerSetHash: bytesOf(0x32, 48),
		LocalBindingMode: coreflow.LocalBindingExplicitProxyAPI, PriorityClass: coreflow.PriorityRealtime,
	}
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{
		Frames: []protocol.AuroraFrame{flowOpenFrame(t, open)},
	}); err != nil {
		t.Fatalf("FLOW_OPEN failed: %v", err)
	}
	select {
	case block := <-sink.blocks:
		if len(block.Frames) != 1 || block.Frames[0].FrameType != registry.FrameUDPTargetConfirm {
			t.Fatalf("confirmation block = %#v", block)
		}
		reader := wire.NewReader(block.Frames[0].Payload)
		confirm := protocol.DecodeUDPTargetConfirm(reader)
		if reader.Err() != nil || !reader.EOF() {
			t.Fatalf("decode confirmation: %v", reader.Err())
		}
		if confirm.ResolutionSource != protocol.UDPResolutionRelaySystemDNS ||
			confirm.TargetKind != coreflow.TargetKindIPv4 ||
			!bytes.Equal(confirm.SelectedIP, []byte{127, 0, 0, 1}) ||
			confirm.TTLSeconds != limits.ResolvedTTLSeconds ||
			!bytes.Equal(confirm.DNSAnswerSetHash, coreflow.DNSAnswerSetHash([]string{"127.0.0.1"})) {
			t.Fatalf("unexpected confirmation: %+v", confirm)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for relay resolution confirmation")
	}
	if len(resolver.calls) != 1 || resolver.calls[0].host != "relay.test" {
		t.Fatalf("resolver calls = %#v", resolver.calls)
	}
}

func TestSocketEgressUDPRejectsOversizeAndReleasesFlow(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	limits := validSocketEgressLimits(4)
	limits.MaxUDPDatagramBytes = 512
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:   &channelFrameSink{blocks: make(chan protocol.FrameBlock, 4)},
		Policy: ExitPolicy{AllowPrivate: true},
		Dialer: &recordingContextDialer{conn: local, useConn: true}, Resolver: &recordingIPResolver{},
		Limits: limits,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	flow := coreflow.FlowState{
		FlowID: 93, Kind: coreflow.FlowKindUDPAssociation,
		TargetKind: coreflow.TargetKindIPv4, TargetHost: []byte{127, 0, 0, 1}, TargetPort: 443,
		UDPFQDNMode: coreflow.UDPFQDNNoneIPAuthoritative,
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowOpened, FlowID: flow.FlowID, Flow: flow,
	}); err != nil {
		t.Fatalf("open HandleEvent failed: %v", err)
	}
	_, err = egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventDatagramData, FlowID: flow.FlowID, Flow: flow,
		Data: make([]byte, limits.MaxUDPDatagramBytes+1),
	})
	if !errors.Is(err, ErrExitDatagramLarge) {
		t.Fatalf("oversized datagram error = %v, want ErrExitDatagramLarge", err)
	}
	egress.mu.Lock()
	_, retained := egress.flows[flow.FlowID]
	egress.mu.Unlock()
	if retained {
		t.Fatal("oversized datagram retained the association")
	}
}

func TestSocketEgressUDPStreamFallbackAndOversizeResponse(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer server.Close()
	serverResult := make(chan error, 1)
	go func() {
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 64)
		n, client, err := server.ReadFromUDP(buffer)
		if err != nil {
			serverResult <- err
			return
		}
		if string(buffer[:n]) != "fallback" {
			serverResult <- errors.New("unexpected UDP fallback request")
			return
		}
		_, err = server.WriteToUDP(make([]byte, 513), client)
		serverResult <- err
	}()
	limits := validSocketEgressLimits(4)
	limits.MaxUDPDatagramBytes = 512
	sink := &channelFrameSink{blocks: make(chan protocol.FrameBlock, 4)}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink: sink, Policy: ExitPolicy{AllowPrivate: true}, Dialer: &net.Dialer{},
		Resolver: net.DefaultResolver, Limits: limits,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	flow := coreflow.FlowState{
		FlowID: 94, Kind: coreflow.FlowKindUDPAssociation,
		TargetKind: coreflow.TargetKindIPv4, TargetHost: []byte{127, 0, 0, 1},
		TargetPort:  uint16(server.LocalAddr().(*net.UDPAddr).Port),
		UDPFQDNMode: coreflow.UDPFQDNNoneIPAuthoritative,
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowOpened, FlowID: flow.FlowID, Flow: flow,
	}); err != nil {
		t.Fatalf("open HandleEvent failed: %v", err)
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventStreamData, FlowID: flow.FlowID, Flow: flow, Data: []byte("fallback"),
	}); err != nil {
		t.Fatalf("stream fallback HandleEvent failed: %v", err)
	}
	select {
	case block := <-sink.blocks:
		if len(block.Frames) != 1 || block.Frames[0].FrameType != registry.FrameFlowClose {
			t.Fatalf("oversize response block = %#v", block)
		}
		reader := wire.NewReader(block.Frames[0].Payload)
		closeFrame := protocol.DecodeFlowClose(reader)
		if reader.Err() != nil || closeFrame.CloseCode != protocol.CloseResourceLimit {
			t.Fatalf("oversize response close = %+v, decode error %v", closeFrame, reader.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for resource-limit close")
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("UDP server failed: %v", err)
	}
}

func TestSocketEgressUDPIdleTimeoutQueuesClose(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer server.Close()
	limits := validSocketEgressLimits(4)
	limits.IdleTimeout = 30 * time.Millisecond
	sink := &channelFrameSink{blocks: make(chan protocol.FrameBlock, 4)}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink: sink, Policy: ExitPolicy{AllowPrivate: true}, Dialer: &net.Dialer{},
		Resolver: net.DefaultResolver, Limits: limits,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	flow := coreflow.FlowState{
		FlowID: 95, Kind: coreflow.FlowKindUDPAssociation,
		TargetKind: coreflow.TargetKindIPv4, TargetHost: []byte{127, 0, 0, 1},
		TargetPort:  uint16(server.LocalAddr().(*net.UDPAddr).Port),
		UDPFQDNMode: coreflow.UDPFQDNNoneIPAuthoritative,
	}
	if _, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowOpened, FlowID: flow.FlowID, Flow: flow,
	}); err != nil {
		t.Fatalf("open HandleEvent failed: %v", err)
	}
	select {
	case block := <-sink.blocks:
		if len(block.Frames) != 1 || block.Frames[0].FrameType != registry.FrameFlowClose {
			t.Fatalf("idle block = %#v", block)
		}
		reader := wire.NewReader(block.Frames[0].Payload)
		closeFrame := protocol.DecodeFlowClose(reader)
		if reader.Err() != nil || closeFrame.CloseCode != protocol.CloseIdleTimeout {
			t.Fatalf("idle close = %+v, decode error %v", closeFrame, reader.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for UDP idle close")
	}
}

func TestResolvedUDPAssociationExpiresAtTTL(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer server.Close()
	limits := validSocketEgressLimits(4)
	limits.IdleTimeout = time.Minute
	limits.ResolvedTTLSeconds = 1
	sink := &channelFrameSink{blocks: make(chan protocol.FrameBlock, 4)}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink: sink, Policy: ExitPolicy{AllowPrivate: true}, Dialer: &net.Dialer{},
		Resolver: &recordingIPResolver{answers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		Limits:   limits,
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	flow := coreflow.FlowState{
		FlowID: 96, Kind: coreflow.FlowKindUDPAssociation,
		TargetKind: coreflow.TargetKindDomainName, TargetHost: []byte("relay.test"),
		TargetPort:  uint16(server.LocalAddr().(*net.UDPAddr).Port),
		UDPFQDNMode: coreflow.UDPFQDNRelayResolvedFlowBound,
	}
	frames, err := egress.HandleEvent(context.Background(), ExitFrameEvent{
		Kind: ExitEventFlowOpened, FlowID: flow.FlowID, Flow: flow,
	})
	if err != nil || len(frames) != 1 || frames[0].FrameType != registry.FrameUDPTargetConfirm {
		t.Fatalf("open result frames=%#v error=%v", frames, err)
	}
	select {
	case block := <-sink.blocks:
		if len(block.Frames) != 1 || block.Frames[0].FrameType != registry.FrameFlowClose {
			t.Fatalf("TTL block = %#v", block)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolved UDP association outlived TTL")
	}
}
