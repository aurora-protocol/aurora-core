package main

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
)

// TestRunTUNComponentsCleansUpWhenAlreadyCancelled proves that a shutdown
// signal landing between route configuration and component start still
// removes the owned host routes and closes the tunnel device and session.
// Before the fix runTUNComponents returned ctx.Err() before touching any of
// them, leaving the relay bypass and tunnel default routes on the host.
func TestRunTUNComponentsCleansUpWhenAlreadyCancelled(t *testing.T) {
	application, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		Write:           session.DirectionConfig{Direction: 0, Secret: bytes.Repeat([]byte{0x11}, 48), Key: bytes.Repeat([]byte{0x12}, 32), IV: bytes.Repeat([]byte{0x13}, 12)},
		Read:            session.DirectionConfig{Direction: 1, Secret: bytes.Repeat([]byte{0x21}, 48), Key: bytes.Repeat([]byte{0x22}, 32), IV: bytes.Repeat([]byte{0x23}, 12)},
	})
	if err != nil {
		t.Fatal(err)
	}
	device := newTUNComponentDevice()
	adapter, err := client.NewPacketAdapter(application, client.PacketAdapterOptions{MaxFlows: 1, MaxPacketBytes: 1500})
	if err != nil {
		_ = application.Close()
		t.Fatal(err)
	}
	runtime, err := client.NewPacketTUNRuntime(adapter, device, client.PacketTUNRuntimeOptions{ReadBufferBytes: 1500})
	if err != nil {
		_ = application.Close()
		t.Fatal(err)
	}
	carrier, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	established := &handshake.EstablishedSession{Application: application, ReadCarrier: carrier, WriteCarrier: carrier}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	routesRemoved := false
	deviceOpenDuringRouteCleanup := false
	err = runTUNComponents(ctx, established, runtime, func() error {
		routesRemoved = true
		deviceOpenDuringRouteCleanup = !device.Closed()
		return nil
	})
	if err != nil {
		t.Fatalf("runTUNComponents(cancelled ctx) err = %v, want clean shutdown", err)
	}
	if !routesRemoved {
		t.Fatal("owned host routes were not removed after pre-cancelled component start")
	}
	if !deviceOpenDuringRouteCleanup {
		t.Fatal("tunnel device closed before route cleanup")
	}
	if !device.Closed() {
		t.Fatal("tunnel device remained open after pre-cancelled component start")
	}
	if _, err := application.TryNextPacket(); err == nil {
		t.Fatal("application session remained open after pre-cancelled component start")
	}
}
