package client

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/transport"
)

const (
	socksVersion5                = 0x05
	socksNoAuth                  = 0x00
	socksNoAcceptable            = 0xff
	socksCommandConnect          = 0x01
	socksCommandUDP              = 0x03
	socksReplyGeneralFailure     = 0x01
	socksReplyCommandUnsupported = 0x07
	socksReplyAddressUnsupported = 0x08
	socksATYPIPv4                = 0x01
	socksATYPDomain              = 0x03
	socksATYPIPv6                = 0x04
)

var (
	httpConnectEstablished = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
	socksSuccessResponse   = []byte{socksVersion5, 0x00, 0x00, socksATYPIPv4, 0, 0, 0, 0, 0, 0}
)

func socks5FailureResponse(reply byte) []byte {
	return []byte{socksVersion5, reply, 0x00, socksATYPIPv4, 0, 0, 0, 0, 0, 0}
}

func (p *LocalProxy) OpenHTTPConnectRequest(flowID uint64, raw []byte) ([]byte, error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, fmt.Errorf("client: invalid HTTP CONNECT request: %w", err)
	}
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	if req.Method != http.MethodConnect {
		return nil, fmt.Errorf("client: HTTP local interface requires CONNECT")
	}
	host, port, err := parseAuthority(req.Host)
	if err != nil {
		return nil, err
	}
	if err := p.OpenTCP(flowID, host, port); err != nil {
		return nil, err
	}
	return append([]byte(nil), httpConnectEstablished...), nil
}

func HandleSOCKS5Greeting(greeting []byte) ([]byte, error) {
	if len(greeting) < 2 || greeting[0] != socksVersion5 {
		return nil, fmt.Errorf("client: invalid SOCKS5 greeting")
	}
	methods := int(greeting[1])
	if len(greeting) != 2+methods {
		return nil, fmt.Errorf("client: truncated SOCKS5 greeting")
	}
	for _, method := range greeting[2:] {
		if method == socksNoAuth {
			return []byte{socksVersion5, socksNoAuth}, nil
		}
	}
	return []byte{socksVersion5, socksNoAcceptable}, fmt.Errorf("client: SOCKS5 no-auth method unavailable")
}

func (p *LocalProxy) OpenSOCKS5ConnectRequest(flowID uint64, request []byte) ([]byte, error) {
	host, port, end, err := parseSOCKS5Request(request, socksCommandConnect)
	if err != nil {
		return nil, err
	}
	if end != len(request) {
		return nil, fmt.Errorf("client: trailing SOCKS5 CONNECT bytes")
	}
	if err := p.OpenTCP(flowID, host, port); err != nil {
		return nil, err
	}
	return append([]byte(nil), socksSuccessResponse...), nil
}

func HandleSOCKS5UDPAssociateRequest(request []byte, bindHost string, bindPort uint16) ([]byte, error) {
	_, _, end, err := parseSOCKS5RequestWithOptions(request, socksCommandUDP, true)
	if err != nil {
		return nil, err
	}
	if end != len(request) {
		return nil, fmt.Errorf("client: trailing SOCKS5 UDP ASSOCIATE bytes")
	}
	response, err := socks5BindResponse(bindHost, bindPort)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (p *LocalProxy) HandleSOCKS5UDPDatagram(flowID uint64, packet []byte, now uint64, udpMode transport.UDPMode) (protocol.AuroraFrame, error) {
	frames, err := p.HandleSOCKS5UDPDatagramFrames(flowID, packet, now, udpMode)
	if err != nil {
		return protocol.AuroraFrame{}, err
	}
	return frames[len(frames)-1], nil
}

func (p *LocalProxy) HandleSOCKS5UDPDatagramFrames(flowID uint64, packet []byte, now uint64, udpMode transport.UDPMode) ([]protocol.AuroraFrame, error) {
	if udpMode != transport.UDPNativeDatagram && udpMode != transport.UDPOverStreamFallback {
		return nil, fmt.Errorf("client: UDP mode %d is unsupported", udpMode)
	}
	host, port, payloadOffset, err := parseSOCKS5UDPHeader(packet)
	if err != nil {
		return nil, err
	}
	openFrame, opened, err := p.ensureSOCKS5UDPFlowFrame(flowID, host, port, now)
	if err != nil {
		return nil, err
	}
	dataFrame, err := p.SendUDPWithOptions(flowID, packet[payloadOffset:], UDPSendOptions{NowUnix: now, UDPMode: udpMode})
	if err != nil {
		return nil, err
	}
	if !opened {
		return []protocol.AuroraFrame{dataFrame}, nil
	}
	return []protocol.AuroraFrame{openFrame, dataFrame}, nil
}

func socks5BindResponse(bindHost string, bindPort uint16) ([]byte, error) {
	if bindPort == 0 {
		return nil, fmt.Errorf("client: SOCKS5 bind port is zero")
	}
	targetKind, targetHost, err := localTarget(bindHost)
	if err != nil {
		return nil, err
	}
	response := []byte{socksVersion5, 0x00, 0x00}
	switch targetKind {
	case flow.TargetKindIPv4:
		response = append(response, socksATYPIPv4)
		response = append(response, targetHost...)
	case flow.TargetKindIPv6:
		response = append(response, socksATYPIPv6)
		response = append(response, targetHost...)
	case flow.TargetKindDomainName:
		if len(targetHost) > 255 {
			return nil, fmt.Errorf("client: SOCKS5 bind domain is too long")
		}
		response = append(response, socksATYPDomain, byte(len(targetHost)))
		response = append(response, targetHost...)
	default:
		return nil, fmt.Errorf("client: unsupported SOCKS5 bind target")
	}
	return binary.BigEndian.AppendUint16(response, bindPort), nil
}

func (p *LocalProxy) ensureSOCKS5UDPFlow(flowID uint64, host string, port uint16, now uint64) error {
	_, _, err := p.ensureSOCKS5UDPFlowFrame(flowID, host, port, now)
	return err
}

func (p *LocalProxy) ensureSOCKS5UDPFlowFrame(flowID uint64, host string, port uint16, now uint64) (protocol.AuroraFrame, bool, error) {
	state, ok := p.FlowState(flowID)
	if !ok {
		frame, err := p.OpenUDPExplicitFrame(flowID, host, port, now)
		return frame, true, err
	}
	targetKind, targetHost, err := localTarget(host)
	if err != nil {
		return protocol.AuroraFrame{}, false, err
	}
	if state.Kind != flow.FlowKindUDPAssociation || state.TargetKind != targetKind || !bytes.Equal(state.TargetHost, targetHost) || state.TargetPort != port {
		return protocol.AuroraFrame{}, false, fmt.Errorf("client: SOCKS5 UDP target changed for flow %d", flowID)
	}
	return protocol.AuroraFrame{}, false, nil
}

func parseAuthority(authority string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		return "", 0, fmt.Errorf("client: CONNECT authority must be host:port")
	}
	port64, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port64 == 0 {
		return "", 0, fmt.Errorf("client: invalid CONNECT port")
	}
	return host, uint16(port64), nil
}

func parseSOCKS5Request(request []byte, wantCommand byte) (string, uint16, int, error) {
	return parseSOCKS5RequestWithOptions(request, wantCommand, false)
}

func parseSOCKS5RequestWithOptions(request []byte, wantCommand byte, allowZeroPort bool) (string, uint16, int, error) {
	if len(request) < 4 || request[0] != socksVersion5 {
		return "", 0, 0, fmt.Errorf("client: invalid SOCKS5 request")
	}
	if request[1] != wantCommand {
		return "", 0, 0, fmt.Errorf("client: unsupported SOCKS5 command 0x%x", request[1])
	}
	if request[2] != 0 {
		return "", 0, 0, fmt.Errorf("client: invalid SOCKS5 reserved byte")
	}
	return parseSOCKS5Address(request, 3, allowZeroPort)
}

func parseSOCKS5UDPHeader(packet []byte) (string, uint16, int, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 {
		return "", 0, 0, fmt.Errorf("client: invalid SOCKS5 UDP header")
	}
	if packet[2] != 0 {
		return "", 0, 0, fmt.Errorf("client: fragmented SOCKS5 UDP datagrams are unsupported")
	}
	return parseSOCKS5Address(packet, 3, false)
}

func parseSOCKS5Address(data []byte, offset int, allowZeroPort bool) (string, uint16, int, error) {
	if offset >= len(data) {
		return "", 0, 0, fmt.Errorf("client: missing SOCKS5 address type")
	}
	atyp := data[offset]
	offset++
	var host string
	switch atyp {
	case socksATYPIPv4:
		if len(data) < offset+4+2 {
			return "", 0, 0, fmt.Errorf("client: truncated SOCKS5 IPv4 address")
		}
		host = net.IP(data[offset : offset+4]).String()
		offset += 4
	case socksATYPDomain:
		if len(data) < offset+1 {
			return "", 0, 0, fmt.Errorf("client: truncated SOCKS5 domain length")
		}
		size := int(data[offset])
		offset++
		if size == 0 || len(data) < offset+size+2 {
			return "", 0, 0, fmt.Errorf("client: truncated SOCKS5 domain address")
		}
		host = string(data[offset : offset+size])
		offset += size
	case socksATYPIPv6:
		if len(data) < offset+16+2 {
			return "", 0, 0, fmt.Errorf("client: truncated SOCKS5 IPv6 address")
		}
		host = net.IP(data[offset : offset+16]).String()
		offset += 16
	default:
		return "", 0, 0, fmt.Errorf("client: unsupported SOCKS5 address type 0x%x", atyp)
	}
	port := binary.BigEndian.Uint16(data[offset : offset+2])
	if port == 0 && !allowZeroPort {
		return "", 0, 0, fmt.Errorf("client: SOCKS5 target port is zero")
	}
	return host, port, offset + 2, nil
}
