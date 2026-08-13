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
	resolver, err := NewUDPDNSMessageResolver(server.LocalAddr().String())
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
