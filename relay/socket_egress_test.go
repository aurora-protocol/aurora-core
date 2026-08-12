package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	coreflow "github.com/aurora-protocol/aurora-core/flow"
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

func (r *recordingIPResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls = append(r.calls, socketResolveCall{network: network, host: host})
	return append([]netip.Addr(nil), r.answers...), r.err
}

type blockingIPResolver struct {
	started  chan struct{}
	canceled chan struct{}
	release  chan struct{}
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
