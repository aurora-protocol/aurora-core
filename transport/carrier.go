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
	Plan             CarrierPlan
	Template         protocol.CoverTemplate
	RequestClassID   uint64
	NeedCapsule      bool
	Scheme           string
	Authority        string
	Path             string
	Header           http.Header
	Payload          []byte
	WebSocketKeySeed []byte
}

type BuiltCarrierRequest struct {
	MethodID        uint64
	RequestClassID  uint64
	Request         *http.Request
	InitialMessages [][]byte
	StreamFallback  bool
	NativeDatagrams bool
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
	default:
		return BuiltCarrierRequest{}, fmt.Errorf("transport: carrier request builder unsupported for method 0x%x", method)
	}
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
