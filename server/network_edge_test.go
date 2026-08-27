package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/aurora-protocol/aurora-core/relay"
)

func TestReverseProxyCoverOriginOwnsTargetURL(t *testing.T) {
	target := &url.URL{Scheme: "https", Host: "cover.example", Path: "/base"}
	var upstream *url.URL
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		cloned := *request.URL
		upstream = &cloned
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    request,
		}, nil
	})
	origin, err := NewReverseProxyCoverOriginWithTransport(target, transport)
	if err != nil {
		t.Fatal(err)
	}

	target.Scheme = "http"
	target.Host = "mutated.invalid"
	target.Path = "/changed"
	origin.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://gateway.example/asset.js", nil))

	if upstream == nil {
		t.Fatal("cover origin did not issue an upstream request")
	}
	if upstream.Scheme != "https" || upstream.Host != "cover.example" || upstream.Path != "/base/asset.js" {
		t.Fatalf("caller mutation changed cover target: %s", upstream.String())
	}
}

func TestCoverCarrierStopsAfterRequestCancellation(t *testing.T) {
	issuer := &retainingCarrierIssuer{}
	payload, err := EncodeCarrierIssueRequest(
		repeatedByte(0x41, carrierTokenNonceLen),
		repeatedByte(0x42, carrierRedemptionContextLen),
		250,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	body := &cancelWhenConsumedReader{
		reader: bytes.NewReader(EncodeCarrier(CarrierBlindRSAIssueReq, payload)),
		cancel: cancel,
	}
	request := httptest.NewRequest(http.MethodPost, DefaultPacketExchangePath, nil).WithContext(ctx)
	request.Body = io.NopCloser(body)
	response := httptest.NewRecorder()

	serveCoverCarrier(response, request, relay.StaticOrigin{Status: http.StatusOK, Body: []byte("cover")}, nil, nil, issuer)

	if response.Code != http.StatusOK || response.Body.String() != "cover" {
		t.Fatalf("canceled carrier response = %d %q, want cover response", response.Code, response.Body.String())
	}
	if issuer.issueTokenNonce != nil || issuer.issueRedemptionContext != nil || issuer.issueProof != nil {
		t.Fatal("canceled carrier request reached the issuer")
	}
}

func TestCarrierHTTPExchangeRejectsOversizedStreamingResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := io.MultiReader(
			bytes.NewReader([]byte{byte(CarrierPacketBatch)}),
			io.LimitReader(zeroNetworkReader{}, int64(maxCarrierBodyBytes)),
		)
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": {"application/octet-stream"}},
			Body:          io.NopCloser(body),
			ContentLength: -1,
			Request:       request,
		}, nil
	})}

	if _, _, err := doCarrierExchangeHTTP(client, "https://gateway.example/assets/app.bin", CarrierIssuerMetadataReq, nil); err == nil {
		t.Fatal("oversized streaming carrier response was accepted")
	}
}

func TestCarrierHTTPExchangeAppliesControlPayloadLimit(t *testing.T) {
	encoded := append(
		[]byte{byte(CarrierIssuerMetadataResp)},
		make([]byte, maxCarrierControlPayloadBytes+1)...,
	)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": {"application/octet-stream"}},
			Body:          io.NopCloser(bytes.NewReader(encoded)),
			ContentLength: int64(len(encoded)),
			Request:       request,
		}, nil
	})}

	if _, _, err := doCarrierExchangeHTTP(client, "https://gateway.example/assets/app.bin", CarrierIssuerMetadataReq, nil); err == nil {
		t.Fatal("oversized carrier control response was accepted")
	}
}

type cancelWhenConsumedReader struct {
	reader *bytes.Reader
	cancel context.CancelFunc
}

func (r *cancelWhenConsumedReader) Read(destination []byte) (int, error) {
	count, err := r.reader.Read(destination)
	if r.reader.Len() == 0 {
		r.cancel()
	}
	return count, err
}

type zeroNetworkReader struct{}

func (zeroNetworkReader) Read(destination []byte) (int, error) {
	clear(destination)
	return len(destination), nil
}
