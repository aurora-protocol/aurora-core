package relay

import (
	"fmt"
	"io"
	"math"
	"net/http"

	"github.com/aurora-protocol/aurora-core/failure"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

const defaultHTTPGatewayMaxBodyBytes int64 = 1 << 20

type HTTPForwardingOrigin interface {
	ForwardHTTPRequest(*http.Request, []byte) Response
}

type HTTPSidecarOrigin interface {
	ForwardSidecarHTTPRequest(*http.Request, []byte) Response
}

type HTTPGatewayRoute struct {
	Path    string
	ClassID uint64
	Kind    CoverRequestKind
	Failure FailureKind
}

type HTTPGatewayHandler struct {
	Gateway      Gateway
	Template     protocol.CoverTemplate
	Routes       []HTTPGatewayRoute
	MaxBodyBytes int64
}

func (h HTTPGatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, ok := h.matchRoute(r.URL.Path)
	if !ok {
		writeHTTPGatewayResponse(w, h.Gateway.HandleFailure(FailureInvalidCoverSlot))
		return
	}
	body, err := h.readRequestBody(r)
	if err != nil {
		writeHTTPGatewayResponse(w, h.Gateway.HandleFailure(failure.MalformedPrelude))
		return
	}
	h.serveMatchedRoute(w, r, route, body)
}

func (h HTTPGatewayHandler) matchRoute(path string) (HTTPGatewayRoute, bool) {
	for _, route := range h.Routes {
		if route.Path == path {
			return route, true
		}
	}
	return HTTPGatewayRoute{}, false
}

func (h HTTPGatewayHandler) readRequestBody(r *http.Request) ([]byte, error) {
	maxBodyBytes := h.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultHTTPGatewayMaxBodyBytes
	}
	defer r.Body.Close()
	readLimit := maxBodyBytes
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, readLimit))
	if err != nil {
		zeroHTTPGatewayBody(body)
		return nil, err
	}
	if int64(len(body)) > maxBodyBytes {
		zeroHTTPGatewayBody(body)
		return nil, fmt.Errorf("relay: cover request body exceeds envelope")
	}
	return body, nil
}

func (h HTTPGatewayHandler) serveMatchedRoute(w http.ResponseWriter, r *http.Request, route HTTPGatewayRoute, body []byte) {
	defer zeroHTTPGatewayBody(body)
	writeHTTPGatewayResponse(w, h.handleMatchedRoute(r, route, body))
}

func (h HTTPGatewayHandler) handleMatchedRoute(r *http.Request, route HTTPGatewayRoute, body []byte) Response {
	class, ok := findRequestClass(h.Template, route.ClassID)
	if !ok {
		return h.Gateway.HandleFailure(FailureInvalidCoverSlot)
	}
	switch class.ClassType {
	case registry.RequestOriginPassThrough:
		if route.Kind == CoverRequestOrdinary {
			if origin, ok := h.Gateway.Origin.(HTTPForwardingOrigin); ok {
				return origin.ForwardHTTPRequest(r.Clone(r.Context()), append([]byte(nil), body...))
			}
		}
	case registry.RequestSidecarOriginSlot:
		if route.Kind == CoverRequestOrdinary {
			if origin, ok := h.Gateway.Origin.(HTTPSidecarOrigin); ok {
				return origin.ForwardSidecarHTTPRequest(r.Clone(r.Context()), append([]byte(nil), body...))
			}
		}
	}
	return h.Gateway.HandleCoverRequest(CoverRequest{
		Template: h.Template,
		ClassID:  route.ClassID,
		Kind:     route.Kind,
		Body:     body,
		Failure:  route.Failure,
	})
}

func zeroHTTPGatewayBody(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func writeHTTPGatewayResponse(w http.ResponseWriter, resp Response) {
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(resp.Body)
}
