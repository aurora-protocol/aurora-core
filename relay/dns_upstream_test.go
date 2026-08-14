package relay

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestUDPDNSMessageResolverExchangesBoundedMessage(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	query := socketEgressDNSQuery(t, "example.com", socketDNSTypeHTTPS)
	response := append([]byte(nil), query...)
	response[2] |= socketDNSFlagResponse >> 8
	served := make(chan error, 1)
	go func() {
		buffer := make([]byte, maximumSocketDNSBytes)
		_ = server.SetDeadline(time.Now().Add(time.Second))
		count, peer, readErr := server.ReadFromUDP(buffer)
		if readErr != nil {
			served <- readErr
			return
		}
		if !bytes.Equal(buffer[:count], query) {
			served <- ErrExitEventInvalid
			return
		}
		_, writeErr := server.WriteToUDP(response, peer)
		served <- writeErr
	}()
	_, portText, err := net.SplitHostPort(server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewUDPDNSMessageResolver(net.JoinHostPort("::ffff:127.0.0.1", portText))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	actual, err := resolver.ExchangeDNS(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, response) {
		t.Fatalf("DNS response = %x, want %x", actual, response)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}

func TestUDPDNSMessageResolverRejectsNonNumericEndpoint(t *testing.T) {
	if _, err := NewUDPDNSMessageResolver("resolver.example:53"); err == nil {
		t.Fatal("hostname DNS upstream was accepted")
	}
}

func TestUDPDNSMessageResolverNormalizesIPv4MappedAddress(t *testing.T) {
	resolver, err := NewUDPDNSMessageResolver("[::ffff:192.0.2.1]:53")
	if err != nil {
		t.Fatal(err)
	}
	if resolver.network != "udp4" {
		t.Fatalf("resolver network = %q, want udp4", resolver.network)
	}
	if resolver.address != "192.0.2.1:53" {
		t.Fatalf("resolver address = %q, want 192.0.2.1:53", resolver.address)
	}
}
