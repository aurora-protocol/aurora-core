package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type CoverOrigin interface {
	http.Handler
	ServeFailureHTTP(http.ResponseWriter, *http.Request)
}

// ProductionCoverOrigin identifies a cover origin constructed for production use.
type ProductionCoverOrigin interface {
	CoverOrigin
	productionFirstHopCoverOrigin()
}

type productionCoverOrigin struct {
	CoverOrigin
}

func (productionCoverOrigin) productionFirstHopCoverOrigin() {}

type reverseProxyCoverOrigin struct {
	proxy *httputil.ReverseProxy
}

func NewReverseProxyCoverOrigin(target *url.URL) (CoverOrigin, error) {
	return NewReverseProxyCoverOriginWithTransport(target, nil)
}

// NewProductionReverseProxyCoverOrigin constructs a production cover origin.
func NewProductionReverseProxyCoverOrigin(target *url.URL) (ProductionCoverOrigin, error) {
	return NewProductionReverseProxyCoverOriginWithTransport(target, nil)
}

// NewProductionReverseProxyCoverOriginWithTransport constructs a production cover origin with a fixed transport.
func NewProductionReverseProxyCoverOriginWithTransport(target *url.URL, transport http.RoundTripper) (ProductionCoverOrigin, error) {
	origin, err := NewReverseProxyCoverOriginWithTransport(target, transport)
	if err != nil {
		return nil, err
	}
	return productionCoverOrigin{CoverOrigin: origin}, nil
}

func NewReverseProxyCoverOriginWithTransport(target *url.URL, transport http.RoundTripper) (CoverOrigin, error) {
	if target == nil {
		return nil, fmt.Errorf("server: cover origin URL is required")
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("server: cover origin URL must use http or https")
	}
	if target.Host == "" {
		return nil, fmt.Errorf("server: cover origin URL host is required")
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	if transport != nil {
		proxy.Transport = transport
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}
	return reverseProxyCoverOrigin{proxy: proxy}, nil
}

func (o reverseProxyCoverOrigin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.proxy.ServeHTTP(w, r)
}

func (o reverseProxyCoverOrigin) ServeFailureHTTP(w http.ResponseWriter, r *http.Request) {
	o.proxy.ServeHTTP(w, sanitizedCoverFailureRequest(r))
}

func sanitizedCoverFailureRequest(r *http.Request) *http.Request {
	cloned := r.Clone(r.Context())
	cloned.Method = http.MethodGet
	cloned.Body = http.NoBody
	cloned.GetBody = nil
	cloned.ContentLength = 0
	cloned.TransferEncoding = nil
	cloned.Trailer = nil
	cloned.Header = cloned.Header.Clone()
	cloned.Header.Del("Content-Type")
	cloned.Header.Del("Content-Length")
	cloned.Header.Del("Transfer-Encoding")
	cloned.Header.Del("Trailer")
	cloned.Header.Del("Expect")
	return cloned
}
