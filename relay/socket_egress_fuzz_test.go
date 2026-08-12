package relay

import (
	"context"
	"net/netip"
	"testing"

	coreflow "github.com/aurora-protocol/aurora-core/flow"
)

func FuzzSocketEgressFlowOpen(f *testing.F) {
	f.Add(uint8(coreflow.FlowKindTCPStream), uint8(coreflow.TargetKindIPv4), uint64(1), []byte{1, 1, 1, 1}, uint16(443), uint8(0))
	f.Add(uint8(coreflow.FlowKindUDPAssociation), uint8(coreflow.TargetKindDomainName), uint64(2), []byte("example.test"), uint16(443), uint8(coreflow.UDPFQDNRelayResolvedFlowBound))
	f.Add(uint8(0xff), uint8(0xff), uint64(0), []byte{0}, uint16(0), uint8(0xff))
	f.Fuzz(func(t *testing.T, flowKind, targetKind uint8, flowID uint64, host []byte, port uint16, udpFQDNMode uint8) {
		if len(host) > 1024 {
			host = host[:1024]
		}
		dialer := &recordingContextDialer{}
		egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
			Sink:     &recordingFrameSink{},
			Policy:   ExitPolicy{AllowPrivate: true},
			Dialer:   dialer,
			Resolver: &recordingIPResolver{answers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}},
			Limits:   validSocketEgressLimits(4),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = egress.Close()
			dialer.closePeers()
		}()
		_, _ = egress.HandleEvent(context.Background(), ExitFrameEvent{
			Kind:   ExitEventFlowOpened,
			FlowID: flowID,
			Flow: coreflow.FlowState{
				FlowID:      flowID,
				Kind:        flowKind,
				TargetKind:  targetKind,
				TargetHost:  append([]byte(nil), host...),
				TargetPort:  port,
				UDPFQDNMode: udpFQDNMode,
			},
		})
	})
}
