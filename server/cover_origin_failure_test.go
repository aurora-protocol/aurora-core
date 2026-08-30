package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type failingCoverOriginTransport struct {
	err   error
	calls int
}

func (t *failingCoverOriginTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, t.err
}

func TestReverseProxyCoverOriginSanitizesUpstreamTransportFailure(t *testing.T) {
	sensitiveError := "dial cover.internal: secret transport detail"
	transport := &failingCoverOriginTransport{err: errors.New(sensitiveError)}
	origin, err := NewReverseProxyCoverOriginWithTransport(
		&url.URL{Scheme: "https", Host: "cover.example"},
		transport,
	)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"https://relay.example/assets/upload",
		strings.NewReader("secret request body"),
	)
	request.Header.Set("Authorization", "secret authorization")
	response := httptest.NewRecorder()
	origin.ServeHTTP(response, request)

	if transport.calls != 1 {
		t.Fatalf("upstream attempts = %d, want 1", transport.calls)
	}
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("response status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if body := response.Body.String(); body != "service unavailable\n" {
		t.Fatalf("response body = %q, want generic service-unavailable body", body)
	}
	if strings.Contains(response.Body.String(), sensitiveError) ||
		strings.Contains(response.Body.String(), "secret request body") ||
		strings.Contains(response.Body.String(), "secret authorization") {
		t.Fatal("upstream failure response exposed sensitive request or transport details")
	}
}
