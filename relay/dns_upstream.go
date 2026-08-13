package relay

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// UDPDNSMessageResolver exchanges bounded DNS messages with one numeric UDP resolver endpoint.
type UDPDNSMessageResolver struct {
	network string
	address string
	dialer  net.Dialer
}

// NewUDPDNSMessageResolver constructs a resolver for an IP-literal host and port.
func NewUDPDNSMessageResolver(address string) (*UDPDNSMessageResolver, error) {
	if strings.TrimSpace(address) == "" || strings.TrimSpace(address) != address {
		return nil, fmt.Errorf("relay: DNS upstream address is required")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("relay: DNS upstream address is invalid: %w", err)
	}
	endpoint, err := netip.ParseAddr(host)
	if err != nil || endpoint.Zone() != "" {
		return nil, fmt.Errorf("relay: DNS upstream host must be an IP address")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("relay: DNS upstream port is invalid")
	}
	network := "udp4"
	if endpoint.Is6() {
		network = "udp6"
	}
	return &UDPDNSMessageResolver{
		network: network,
		address: net.JoinHostPort(endpoint.String(), strconv.FormatUint(port, 10)),
	}, nil
}

// ExchangeDNS sends one DNS query and returns one bounded DNS response.
func (r *UDPDNSMessageResolver) ExchangeDNS(ctx context.Context, query []byte) ([]byte, error) {
	if r == nil || r.address == "" || r.network == "" {
		return nil, fmt.Errorf("relay: DNS upstream resolver is invalid")
	}
	if ctx == nil {
		return nil, fmt.Errorf("relay: DNS upstream context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(query) == 0 || len(query) > maximumSocketDNSBytes {
		return nil, fmt.Errorf("relay: DNS query size is invalid")
	}
	connection, err := r.dialer.DialContext(ctx, r.network, r.address)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	if err := writeSocketBytes(connection, query); err != nil {
		return nil, err
	}
	buffer := make([]byte, maximumSocketDNSBytes+1)
	defer zeroUDPDNSBytes(buffer)
	count, err := connection.Read(buffer)
	if err != nil {
		return nil, err
	}
	if count == 0 || count > maximumSocketDNSBytes {
		return nil, fmt.Errorf("relay: DNS response size is invalid")
	}
	return append([]byte(nil), buffer[:count]...), nil
}

func zeroUDPDNSBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
