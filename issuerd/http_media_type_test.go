package issuerd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJSONHTTPHandlersRejectUnexpectedMediaType(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/blind-rsa/issue", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "text/plain")
	response := httptest.NewRecorder()
	NewHTTPHandler(service).ServeHTTP(response, request)

	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("unexpected media type status = %d, want %d", response.Code, http.StatusUnsupportedMediaType)
	}
	if response.Header().Get("Content-Type") != "application/json" || !strings.Contains(response.Body.String(), "unsupported media type") {
		t.Fatalf("unexpected media type response = headers %v body %q", response.Header(), response.Body.String())
	}
}

func TestVerifierHTTPHandlerRejectsUnexpectedMediaType(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not a verifier request")))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{}},
	}
	response := httptest.NewRecorder()
	NewVerifierHTTPHandler(service).ServeHTTP(response, request)

	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("unexpected verifier media type status = %d, want %d", response.Code, http.StatusUnsupportedMediaType)
	}
}

func TestRequestMediaTypeAllowsParameters(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response := httptest.NewRecorder()

	if !requireRequestMediaType(response, request, "application/json") {
		t.Fatalf("parameterized JSON media type was rejected: status=%d body=%q", response.Code, response.Body.String())
	}
}
