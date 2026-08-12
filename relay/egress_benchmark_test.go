package relay

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	coreflow "github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestSocketEgressTCPWriteAllocations(t *testing.T) {
	egress, event, closeEgress := newBenchmarkSocketEgress(t, 1, 32<<10)
	defer closeEgress()
	var runErr error
	allocations := testing.AllocsPerRun(1000, func() {
		if runErr != nil {
			return
		}
		_, runErr = egress.HandleEvent(context.Background(), event)
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if allocations > 8 {
		t.Fatalf("socket egress TCP write allocations = %.2f, want <= 8", allocations)
	}
}

func BenchmarkSocketEgressTCPWrite32K(b *testing.B) {
	for _, flowCount := range []int{1, 64, 256} {
		b.Run(fmt.Sprintf("flows=%d", flowCount), func(b *testing.B) {
			egress, event, closeEgress := newBenchmarkSocketEgress(b, flowCount, 32<<10)
			defer closeEgress()
			ctx := context.Background()
			var next atomic.Uint64
			b.SetBytes(int64(len(event.Data)))
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(iterations *testing.PB) {
				for iterations.Next() {
					flowID := (next.Add(1)-1)%uint64(flowCount) + 1
					candidate := event
					candidate.FlowID = flowID
					candidate.Flow.FlowID = flowID
					if _, err := egress.HandleEvent(ctx, candidate); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}

func newBenchmarkSocketEgress(tb testing.TB, flowCount, payloadBytes int) (*SocketEgress, ExitFrameEvent, func()) {
	tb.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	egress, err := NewSocketEgress(ctx, SocketEgressOptions{
		Sink:     benchmarkFrameSink{},
		Dialer:   benchmarkDialer{},
		Resolver: benchmarkResolver{},
		Limits:   validSocketEgressLimits(flowCount),
	})
	if err != nil {
		cancel()
		tb.Fatal(err)
	}
	for flowID := 1; flowID <= flowCount; flowID++ {
		flowContext, flowCancel := context.WithCancel(egress.ctx)
		egress.flows[uint64(flowID)] = &socketFlow{
			conn:   benchmarkSocketConn{},
			kind:   coreflow.FlowKindTCPStream,
			ctx:    flowContext,
			cancel: flowCancel,
			done:   make(chan struct{}),
		}
	}
	event := ExitFrameEvent{
		Kind:   ExitEventStreamData,
		FlowID: 1,
		Flow: coreflow.FlowState{
			FlowID: 1,
			Kind:   coreflow.FlowKindTCPStream,
		},
		Data: make([]byte, payloadBytes),
	}
	return egress, event, func() {
		_ = egress.Close()
		cancel()
	}
}

type benchmarkFrameSink struct{}

func (benchmarkFrameSink) QueueFrames(context.Context, protocol.FrameBlock) error { return nil }

type benchmarkDialer struct{}

func (benchmarkDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("benchmark dialer is not used")
}

type benchmarkResolver struct{}

func (benchmarkResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, fmt.Errorf("benchmark resolver is not used")
}

type benchmarkSocketConn struct{}

func (benchmarkSocketConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (benchmarkSocketConn) Write(data []byte) (int, error)   { return len(data), nil }
func (benchmarkSocketConn) Close() error                     { return nil }
func (benchmarkSocketConn) LocalAddr() net.Addr              { return benchmarkSocketAddr{} }
func (benchmarkSocketConn) RemoteAddr() net.Addr             { return benchmarkSocketAddr{} }
func (benchmarkSocketConn) SetDeadline(time.Time) error      { return nil }
func (benchmarkSocketConn) SetReadDeadline(time.Time) error  { return nil }
func (benchmarkSocketConn) SetWriteDeadline(time.Time) error { return nil }

type benchmarkSocketAddr struct{}

func (benchmarkSocketAddr) Network() string { return "benchmark" }
func (benchmarkSocketAddr) String() string  { return "benchmark" }
