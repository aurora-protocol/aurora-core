package transport

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/aurora-protocol/aurora-core/cover"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

type CarrierRequestInput struct {
	Plan                     CarrierPlan
	Template                 protocol.CoverTemplate
	RequestClassID           uint64
	NeedCapsule              bool
	Scheme                   string
	Authority                string
	Path                     string
	Header                   http.Header
	Payload                  []byte
	WebSocketKeySeed         []byte
	H3DatagramSettingsOK     bool
	QUICMaxDatagramFrameSize uint64
	ResetStreamAtNegotiated  bool
}

type BuiltCarrierRequest struct {
	MethodID         uint64
	RequestClassID   uint64
	Request          *http.Request
	ProtocolToken    string
	InitialMessages  [][]byte
	InitialDatagrams [][]byte
	StreamFallback   bool
	NativeDatagrams  bool
}

func BuildCarrierRequest(in CarrierRequestInput) (BuiltCarrierRequest, error) {
	method := in.Plan.Carrier.MethodID
	class, err := cover.SelectCarrierClass(in.Template, in.RequestClassID, method, in.NeedCapsule)
	if err != nil {
		return BuiltCarrierRequest{}, err
	}
	target, err := carrierURL(in.Scheme, in.Authority, in.Path)
	if err != nil {
		return BuiltCarrierRequest{}, err
	}
	if err := validateVisibleHeaders(in.Header); err != nil {
		return BuiltCarrierRequest{}, err
	}
	payload := append([]byte(nil), in.Payload...)
	switch method {
	case registry.MethodWebH2Stream:
		req, err := newCarrierHTTPRequest(http.MethodPost, target, in.Authority, cloneHeader(in.Header), bytes.NewReader(payload))
		if err != nil {
			return BuiltCarrierRequest{}, err
		}
		return BuiltCarrierRequest{
			MethodID:        method,
			RequestClassID:  class.ClassID,
			Request:         req,
			StreamFallback:  in.Plan.UDPMode == UDPOverStreamFallback,
			NativeDatagrams: in.Plan.UDPMode == UDPNativeDatagram,
		}, nil
	case registry.MethodWebH1WS:
		header := cloneHeader(in.Header)
		header.Set("Connection", "Upgrade")
		header.Set("Upgrade", "websocket")
		header.Set("Sec-WebSocket-Version", "13")
		key, err := websocketKey(in.WebSocketKeySeed)
		if err != nil {
			return BuiltCarrierRequest{}, err
		}
		header.Set("Sec-WebSocket-Key", key)
		req, err := newCarrierHTTPRequest(http.MethodGet, target, in.Authority, header, nil)
		if err != nil {
			return BuiltCarrierRequest{}, err
		}
		return BuiltCarrierRequest{
			MethodID:        method,
			RequestClassID:  class.ClassID,
			Request:         req,
			InitialMessages: [][]byte{payload},
			StreamFallback:  in.Plan.UDPMode == UDPOverStreamFallback,
			NativeDatagrams: in.Plan.UDPMode == UDPNativeDatagram,
		}, nil
	case registry.MethodShadowOrigin:
		req, err := newCarrierHTTPRequest(http.MethodPost, target, in.Authority, cloneHeader(in.Header), bytes.NewReader(payload))
		if err != nil {
			return BuiltCarrierRequest{}, err
		}
		return BuiltCarrierRequest{
			MethodID:        method,
			RequestClassID:  class.ClassID,
			Request:         req,
			StreamFallback:  in.Plan.UDPMode == UDPOverStreamFallback,
			NativeDatagrams: in.Plan.UDPMode == UDPNativeDatagram,
		}, nil
	case registry.MethodWebH3ExtDgram:
		if err := validateH3ExtDatagram(in); err != nil {
			return BuiltCarrierRequest{}, err
		}
		req, err := newCarrierHTTPRequest(http.MethodConnect, target, in.Authority, cloneHeader(in.Header), nil)
		if err != nil {
			return BuiltCarrierRequest{}, err
		}
		return BuiltCarrierRequest{
			MethodID:         method,
			RequestClassID:   class.ClassID,
			Request:          req,
			ProtocolToken:    "webtransport-h3",
			InitialDatagrams: initialDatagrams(payload),
			StreamFallback:   in.Plan.UDPMode == UDPOverStreamFallback,
			NativeDatagrams:  in.Plan.UDPMode == UDPNativeDatagram,
		}, nil
	default:
		return BuiltCarrierRequest{}, fmt.Errorf("transport: carrier request builder unsupported for method 0x%x", method)
	}
}

func validateH3ExtDatagram(in CarrierRequestInput) error {
	if in.Plan.UDPMode != UDPNativeDatagram {
		return fmt.Errorf("transport: H3 extension datagram carrier requires native datagram mode")
	}
	profile := in.Template.H3Profile
	if !profile.SupportsH3Datagram {
		return fmt.Errorf("transport: H3 cover profile does not support datagrams")
	}
	if !profile.SupportsWebTransportH3 {
		return fmt.Errorf("transport: H3 cover profile does not support WebTransport")
	}
	if profile.WebTransportProfileID == 0 {
		return fmt.Errorf("transport: H3 cover profile missing WebTransport profile id")
	}
	if !in.H3DatagramSettingsOK {
		return fmt.Errorf("transport: H3 datagram settings were not negotiated")
	}
	if in.QUICMaxDatagramFrameSize == 0 {
		return fmt.Errorf("transport: QUIC max_datagram_frame_size was not negotiated")
	}
	if profile.ResetStreamAtRequired && !in.ResetStreamAtNegotiated {
		return fmt.Errorf("transport: reset_stream_at was not negotiated")
	}
	return nil
}

func initialDatagrams(payload []byte) [][]byte {
	if len(payload) == 0 {
		return nil
	}
	return [][]byte{append([]byte(nil), payload...)}
}

func carrierURL(scheme, authority, path string) (*url.URL, error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	authority = strings.TrimSpace(authority)
	if scheme != "https" {
		return nil, fmt.Errorf("transport: carrier requests require https scheme")
	}
	if authority == "" {
		return nil, fmt.Errorf("transport: carrier request authority is empty")
	}
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("transport: carrier request path must start with /")
	}
	return &url.URL{Scheme: scheme, Host: authority, Path: path}, nil
}

func newCarrierHTTPRequest(method string, target *url.URL, authority string, header http.Header, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, target.String(), body)
	if err != nil {
		return nil, err
	}
	req.Host = authority
	req.Header = header
	return req, nil
}

func cloneHeader(in http.Header) http.Header {
	out := make(http.Header, len(in))
	for k, vs := range in {
		copied := make([]string, len(vs))
		copy(copied, vs)
		out[http.CanonicalHeaderKey(k)] = copied
	}
	return out
}

func validateVisibleHeaders(header http.Header) error {
	for k, vs := range header {
		if containsProtocolMarker(k) {
			return fmt.Errorf("transport: visible carrier header contains protocol marker")
		}
		for _, v := range vs {
			if containsProtocolMarker(v) {
				return fmt.Errorf("transport: visible carrier header value contains protocol marker")
			}
		}
	}
	return nil
}

func containsProtocolMarker(s string) bool {
	return strings.Contains(strings.ToLower(s), "aurora")
}

func websocketKey(seed []byte) (string, error) {
	if len(seed) == 0 {
		seed = make([]byte, 16)
		if _, err := rand.Read(seed); err != nil {
			return "", err
		}
	}
	if len(seed) != 16 {
		return "", fmt.Errorf("transport: WebSocket key seed length %d, want 16", len(seed))
	}
	return base64.StdEncoding.EncodeToString(append([]byte(nil), seed...)), nil
}
