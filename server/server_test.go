package server

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/relay"
)

func TestHarnessHandlerServesCoverAndIssuerEndpoints(t *testing.T) {
	handler, err := NewHarnessHandler(HarnessOptions{
		NowUnix:   200,
		CoverBody: []byte("<html>cover</html>"),
	})
	if err != nil {
		t.Fatalf("NewHarnessHandler failed: %v", err)
	}

	cover := serveRequest(handler, http.MethodGet, "/ordinary-origin-path", nil)
	if cover.status != http.StatusOK || string(cover.body) != "<html>cover</html>" {
		t.Fatalf("cover origin response = %d %q", cover.status, cover.body)
	}

	// The former public issuer and health paths must be byte-identical to an
	// ordinary origin probe (no distinguishable public Aurora path).
	for _, path := range []string{"/issuer/issuer-metadata", "/issuer/blind-rsa/issue", "/issuer/token/spend", "/healthz"} {
		probe := serveRequest(handler, http.MethodGet, path, nil)
		if probe.status != cover.status || !bytes.Equal(probe.body, cover.body) {
			t.Fatalf("legacy path %q is distinguishable from cover: status=%d body=%q", path, probe.status, probe.body)
		}
	}

	// Issuer metadata is reachable only over the cover carrier.
	metaType, metaPayload, resp := doCarrierExchangeHandler(handler, CarrierIssuerMetadataReq, nil)
	if metaType != CarrierIssuerMetadataResp {
		t.Fatalf("carrier metadata response type = %d status=%d", metaType, resp.status)
	}
	encoded, hash, err := DecodeCarrierMetadataResponse(metaPayload)
	if err != nil || len(encoded) == 0 || len(hash) != carrierMetadataHashLen {
		t.Fatalf("carrier metadata decode failed: err=%v encoded=%d hash=%d", err, len(encoded), len(hash))
	}

	issueReq, err := EncodeCarrierIssueRequest(repeatedByte(0x44, carrierTokenNonceLen), repeatedByte(0x45, carrierRedemptionContextLen), 250)
	if err != nil {
		t.Fatalf("EncodeCarrierIssueRequest failed: %v", err)
	}
	issueType, proof, _ := doCarrierExchangeHandler(handler, CarrierBlindRSAIssueReq, issueReq)
	if issueType != CarrierBlindRSAIssueResp || len(proof) == 0 {
		t.Fatalf("carrier issue response type=%d len=%d", issueType, len(proof))
	}
}

func TestHarnessHandlerUsesInjectedSpentTokenCacheForIssuerHTTP(t *testing.T) {
	spentTokens := admission.NewMemoryReplayCache()
	handler, err := NewHarnessHandler(HarnessOptions{
		NowUnix:         200,
		SpentTokenCache: spentTokens,
	})
	if err != nil {
		t.Fatalf("NewHarnessHandler failed: %v", err)
	}
	issueReq, err := EncodeCarrierIssueRequest(repeatedByte(0x44, carrierTokenNonceLen), repeatedByte(0x45, carrierRedemptionContextLen), 250)
	if err != nil {
		t.Fatalf("EncodeCarrierIssueRequest failed: %v", err)
	}
	issueType, proof, _ := doCarrierExchangeHandler(handler, CarrierBlindRSAIssueReq, issueReq)
	if issueType != CarrierBlindRSAIssueResp || len(proof) == 0 {
		t.Fatalf("carrier issue response type=%d len=%d", issueType, len(proof))
	}

	spendType, spentKey, _ := doCarrierExchangeHandler(handler, CarrierTokenSpendReq, proof)
	if spendType != CarrierTokenSpendResp || len(spentKey) != carrierSpentKeyLen {
		t.Fatalf("carrier spend response type=%d len=%d", spendType, len(spentKey))
	}
	if !spentTokens.Has(spentKey) {
		t.Fatalf("injected spent-token cache did not record spent key")
	}
}

func TestServeCoverCarrierScrubsIssueRequestInputsAfterDispatch(t *testing.T) {
	issuer := &retainingCarrierIssuer{}
	payload, err := EncodeCarrierIssueRequest(repeatedByte(0x41, carrierTokenNonceLen), repeatedByte(0x42, carrierRedemptionContextLen), 250)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, DefaultPacketExchangePath, bytes.NewReader(EncodeCarrier(CarrierBlindRSAIssueReq, payload)))
	response := httptest.NewRecorder()
	serveCoverCarrier(response, request, relay.StaticOrigin{}, http.NotFoundHandler(), nil, issuer)

	if response.Code != http.StatusOK {
		t.Fatalf("carrier issue response status = %d, want %d", response.Code, http.StatusOK)
	}
	for _, value := range issuer.issueTokenNonce {
		if value != 0 {
			t.Fatal("issuer retained token nonce after carrier dispatch")
		}
	}
	for _, value := range issuer.issueRedemptionContext {
		if value != 0 {
			t.Fatal("issuer retained redemption context after carrier dispatch")
		}
	}
}

func TestServeCoverCarrierScrubsSpendRequestInputAfterDispatch(t *testing.T) {
	issuer := &retainingCarrierIssuer{}
	request := httptest.NewRequest(http.MethodPost, DefaultPacketExchangePath, bytes.NewReader(EncodeCarrier(CarrierTokenSpendReq, repeatedByte(0x43, 96))))
	response := httptest.NewRecorder()
	serveCoverCarrier(response, request, relay.StaticOrigin{}, http.NotFoundHandler(), nil, issuer)

	if response.Code != http.StatusOK {
		t.Fatalf("carrier spend response status = %d, want %d", response.Code, http.StatusOK)
	}
	for _, value := range issuer.spentProof {
		if value != 0 {
			t.Fatal("issuer retained admission proof after carrier dispatch")
		}
	}
}

func TestPacketBatchCodecMatchesInteroperabilityVector(t *testing.T) {
	batch := PacketBatch{
		Packets:         [][]byte{{0x45, 0x00, 0x00, 0x14}},
		ProtocolNumbers: []uint16{2},
	}

	encoded, err := EncodePacketBatch(batch)
	if err != nil {
		t.Fatalf("EncodePacketBatch failed: %v", err)
	}
	if got, want := hex.EncodeToString(encoded), "000100020000000445000014"; got != want {
		t.Fatalf("packet batch vector = %s, want %s", got, want)
	}
	decoded, err := DecodePacketBatch(encoded)
	if err != nil {
		t.Fatalf("DecodePacketBatch failed: %v", err)
	}
	if len(decoded.Packets) != 1 || !bytes.Equal(decoded.Packets[0], batch.Packets[0]) || decoded.ProtocolNumbers[0] != 2 {
		t.Fatalf("decoded packet batch mismatch: %+v", decoded)
	}
}

type retainingCarrierIssuer struct {
	issueTokenNonce        []byte
	issueRedemptionContext []byte
	spentProof             []byte
}

func (*retainingCarrierIssuer) IssuerMetadata() ([]byte, []byte, error) {
	return nil, nil, errors.New("issuer metadata is unavailable")
}

func (c *retainingCarrierIssuer) IssueBlindRSA(tokenNonce, redemptionContextHash []byte, _ uint64) ([]byte, error) {
	c.issueTokenNonce = tokenNonce
	c.issueRedemptionContext = redemptionContextHash
	return []byte("proof"), nil
}

func (c *retainingCarrierIssuer) SpendToken(admissionProof []byte) ([]byte, error) {
	c.spentProof = admissionProof
	return repeatedByte(0x44, carrierSpentKeyLen), nil
}

func TestPacketBatchCodecRejectsEmptyPacketEntry(t *testing.T) {
	encodedEmptyPacket := []byte{
		0x00, 0x01,
		0x00, 0x02,
		0x00, 0x00, 0x00, 0x00,
	}

	if _, err := DecodePacketBatch(encodedEmptyPacket); err == nil {
		t.Fatal("DecodePacketBatch accepted an empty packet entry")
	}
}

func TestPacketBatchCodecRejectsProtocolNumberMismatch(t *testing.T) {
	encodedMismatch := []byte{
		0x00, 0x01,
		0x00, 0x1e,
		0x00, 0x00, 0x00, 0x04,
		0x45, 0x00, 0x00, 0x14,
	}

	if _, err := DecodePacketBatch(encodedMismatch); err == nil {
		t.Fatal("DecodePacketBatch accepted an IPv4 packet labeled as IPv6")
	}
	if _, err := EncodePacketBatch(PacketBatch{
		Packets:         [][]byte{{0x45, 0x00, 0x00, 0x14}},
		ProtocolNumbers: []uint16{30},
	}); err == nil {
		t.Fatal("EncodePacketBatch accepted an IPv4 packet labeled as IPv6")
	}
	if _, err := EncodePacketBatch(PacketBatch{
		Packets:         [][]byte{{0x05, 0x00, 0x00, 0x14}},
		ProtocolNumbers: []uint16{0},
	}); err == nil {
		t.Fatal("EncodePacketBatch accepted a non-IP packet")
	}
}

func TestHarnessHandlerExchangesPacketBatchesThroughPrivateCarrierSlot(t *testing.T) {
	handler, err := NewHarnessHandler(HarnessOptions{
		NowUnix:   200,
		CoverBody: []byte("<html>cover</html>"),
	})
	if err != nil {
		t.Fatalf("NewHarnessHandler failed: %v", err)
	}
	inbound, err := EncodePacketBatch(PacketBatch{
		Packets:         [][]byte{{0x45, 0x00, 0x00, 0x14}},
		ProtocolNumbers: []uint16{2},
	})
	if err != nil {
		t.Fatalf("EncodePacketBatch failed: %v", err)
	}

	exchanged := serveRequestWithContentType(handler, http.MethodPost, DefaultPacketExchangePath, EncodeCarrier(CarrierPacketBatch, inbound), "application/octet-stream")

	if exchanged.status != http.StatusOK {
		t.Fatalf("packet exchange status = %d body=%q", exchanged.status, exchanged.body)
	}
	if got := exchanged.header.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("packet exchange content type = %q", got)
	}
	respType, respPayload, err := DecodeCarrier(exchanged.body)
	if err != nil || respType != CarrierPacketBatch {
		t.Fatalf("packet exchange carrier response type=%d err=%v", respType, err)
	}
	outbound, err := DecodePacketBatch(respPayload)
	if err != nil {
		t.Fatalf("DecodePacketBatch response failed: %v", err)
	}
	if len(outbound.Packets) != 1 || !bytes.Equal(outbound.Packets[0], []byte{0x45, 0x00, 0x00, 0x14}) || outbound.ProtocolNumbers[0] != 2 {
		t.Fatalf("packet exchange response mismatch: %+v", outbound)
	}
}

func TestHarnessHandlerExchangesMaximumPacketBatchThroughCarrier(t *testing.T) {
	handler, err := NewHarnessHandler(HarnessOptions{NowUnix: 200})
	if err != nil {
		t.Fatalf("NewHarnessHandler failed: %v", err)
	}
	packet := make([]byte, maxPacketBytes)
	packet[0] = 0x45
	batch := PacketBatch{
		Packets:         make([][]byte, maxPacketBatchPackets),
		ProtocolNumbers: make([]uint16, maxPacketBatchPackets),
	}
	for index := range batch.Packets {
		batch.Packets[index] = packet
		batch.ProtocolNumbers[index] = 2
	}
	payload, err := EncodePacketBatch(batch)
	if err != nil {
		t.Fatalf("EncodePacketBatch failed: %v", err)
	}
	requestBody := EncodeCarrier(CarrierPacketBatch, payload)
	if len(requestBody) != maxCarrierBodyBytes {
		t.Fatalf("maximum carrier body length = %d, want %d", len(requestBody), maxCarrierBodyBytes)
	}

	exchanged := serveRequestWithContentType(handler, http.MethodPost, DefaultPacketExchangePath, requestBody, "application/octet-stream")
	if exchanged.status != http.StatusOK {
		t.Fatalf("maximum packet exchange status = %d", exchanged.status)
	}
	responseType, responsePayload, err := DecodeCarrier(exchanged.body)
	if err != nil || responseType != CarrierPacketBatch {
		t.Fatalf("maximum packet exchange carrier response type=%d err=%v", responseType, err)
	}
	outbound, err := DecodePacketBatch(responsePayload)
	if err != nil {
		t.Fatalf("DecodePacketBatch response failed: %v", err)
	}
	if len(outbound.Packets) != maxPacketBatchPackets || len(outbound.ProtocolNumbers) != maxPacketBatchPackets {
		t.Fatalf("maximum packet exchange response counts = packets %d protocols %d", len(outbound.Packets), len(outbound.ProtocolNumbers))
	}
	for index, returned := range outbound.Packets {
		if len(returned) != maxPacketBytes || returned[0] != 0x45 || outbound.ProtocolNumbers[index] != 2 {
			t.Fatalf("maximum packet exchange response entry %d is invalid", index)
		}
	}
}

func TestCarrierControlPayloadOverLimitFallsBackToCover(t *testing.T) {
	const coverBody = "<html>cover</html>"
	handler, err := NewHarnessHandler(HarnessOptions{
		NowUnix:   200,
		CoverBody: []byte(coverBody),
	})
	if err != nil {
		t.Fatalf("NewHarnessHandler failed: %v", err)
	}
	requestBody := append([]byte{byte(CarrierIssuerMetadataReq)}, bytes.Repeat([]byte{0x41}, maxCarrierControlPayloadBytes+1)...)

	response := serveRequestWithContentType(handler, http.MethodPost, DefaultPacketExchangePath, requestBody, "application/octet-stream")
	if response.status != http.StatusOK || string(response.body) != coverBody {
		t.Fatalf("oversized control payload response = %d %q", response.status, response.body)
	}
}

func TestPacketExchangeInvalidProbeFallsBackToCover(t *testing.T) {
	handler, err := NewHarnessHandler(HarnessOptions{
		NowUnix:   200,
		CoverBody: []byte("<html>cover</html>"),
	})
	if err != nil {
		t.Fatalf("NewHarnessHandler failed: %v", err)
	}

	probe := serveRequestWithContentType(handler, http.MethodPost, DefaultPacketExchangePath, []byte("not a packet batch"), "application/octet-stream")

	if probe.status != http.StatusOK || string(probe.body) != "<html>cover</html>" {
		t.Fatalf("invalid packet exchange did not fall back to cover: status=%d body=%q", probe.status, probe.body)
	}
}

func TestReverseProxyCoverOriginForwardsOrdinaryRequests(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "cover.example" {
			t.Fatalf("upstream origin = %s://%s", r.URL.Scheme, r.URL.Host)
		}
		if r.URL.Path != "/ordinary/path" || r.URL.RawQuery != "x=1" {
			t.Fatalf("upstream request target = %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("upstream method = %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, []byte("ordinary body")) {
			t.Fatalf("upstream body = %q", body)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header:     http.Header{"Content-Type": []string{"text/plain"}},
			Body:       io.NopCloser(bytes.NewReader([]byte("origin response"))),
			Request:    r,
		}, nil
	})
	cover, err := NewReverseProxyCoverOriginWithTransport(mustParseURL(t, "https://cover.example"), transport)
	if err != nil {
		t.Fatalf("NewReverseProxyCoverOrigin failed: %v", err)
	}
	service, err := newServerTestIssuer()
	if err != nil {
		t.Fatalf("newServerTestIssuer failed: %v", err)
	}
	handler := NewHandler(Options{
		Issuer:      service,
		CoverOrigin: cover,
	})

	response := serveRequestWithContentType(handler, http.MethodPost, "/ordinary/path?x=1", []byte("ordinary body"), "text/plain")

	if response.status != http.StatusCreated || string(response.body) != "origin response" {
		t.Fatalf("reverse-proxied cover response = %d %q", response.status, response.body)
	}
}

func TestReverseProxyCoverOriginSanitizesFailedGatewayOwnedBodies(t *testing.T) {
	var seenMethod string
	var seenPath string
	var seenBody []byte
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		if r.Body != nil {
			seenBody, _ = io.ReadAll(r.Body)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/html"}},
			Body:       io.NopCloser(bytes.NewReader([]byte("<html>origin</html>"))),
			Request:    r,
		}, nil
	})
	cover, err := NewReverseProxyCoverOriginWithTransport(mustParseURL(t, "https://cover.example"), transport)
	if err != nil {
		t.Fatalf("NewReverseProxyCoverOrigin failed: %v", err)
	}
	service, err := newServerTestIssuer()
	if err != nil {
		t.Fatalf("newServerTestIssuer failed: %v", err)
	}
	handler := NewHandler(Options{
		Issuer:          service,
		CoverOrigin:     cover,
		PacketExchanger: LoopbackPacketExchanger{},
	})

	response := serveRequestWithContentType(handler, http.MethodPost, DefaultPacketExchangePath, []byte("failed capsule body"), "application/octet-stream")

	if response.status != http.StatusOK || string(response.body) != "<html>origin</html>" {
		t.Fatalf("sanitized failure response = %d %q", response.status, response.body)
	}
	if seenMethod != http.MethodGet || seenPath != DefaultPacketExchangePath || len(seenBody) != 0 {
		t.Fatalf("failed gateway body was not sanitized before cover origin: method=%s path=%s body=%q", seenMethod, seenPath, seenBody)
	}
}

func TestSanitizedCoverFailureRequestRemovesBodyFramingAndTrailers(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://cover.example/gateway", bytes.NewReader([]byte("secret body")))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte("secret body"))), nil
	}
	request.TransferEncoding = []string{"chunked"}
	request.Trailer = http.Header{"X-Gateway-State": {"secret trailer"}}
	request.Header.Set("Trailer", "X-Gateway-State")
	request.Header.Set("Expect", "100-continue")

	sanitized := sanitizedCoverFailureRequest(request)
	if sanitized.Method != http.MethodGet || sanitized.Body != http.NoBody || sanitized.GetBody != nil || sanitized.ContentLength != 0 || len(sanitized.TransferEncoding) != 0 || len(sanitized.Trailer) != 0 {
		t.Fatalf("failure request retained body framing: %+v", sanitized)
	}
	for _, name := range []string{"Content-Type", "Content-Length", "Transfer-Encoding", "Trailer", "Expect"} {
		if sanitized.Header.Get(name) != "" {
			t.Fatalf("failure request retained %s", name)
		}
	}
}

func TestDevicePacketExchangerWritesInboundPacketsToDevice(t *testing.T) {
	device := newScriptedPacketDevice()
	exchanger, err := NewDevicePacketExchanger(device, DevicePacketExchangerOptions{
		MTU:          1280,
		QueuePackets: 4,
	})
	if err != nil {
		t.Fatalf("NewDevicePacketExchanger failed: %v", err)
	}
	defer exchanger.Close()

	_, err = exchanger.ExchangePacketBatch(PacketBatch{
		Packets:         [][]byte{{0x45, 0x00, 0x00, 0x14}},
		ProtocolNumbers: []uint16{2},
	})
	if err != nil {
		t.Fatalf("ExchangePacketBatch failed: %v", err)
	}

	writes := device.Writes()
	if len(writes) != 1 || !bytes.Equal(writes[0], []byte{0x45, 0x00, 0x00, 0x14}) {
		t.Fatalf("device writes = %x", writes)
	}
}

func TestDevicePacketExchangerDrainsOutboundDevicePackets(t *testing.T) {
	device := newScriptedPacketDevice()
	exchanger, err := NewDevicePacketExchanger(device, DevicePacketExchangerOptions{
		MTU:          1280,
		QueuePackets: 4,
	})
	if err != nil {
		t.Fatalf("NewDevicePacketExchanger failed: %v", err)
	}
	defer exchanger.Close()

	device.QueueRead([]byte{0x45, 0x00, 0x00, 0x14})
	outbound := waitForDeviceOutbound(t, exchanger)

	if len(outbound.Packets) != 1 || !bytes.Equal(outbound.Packets[0], []byte{0x45, 0x00, 0x00, 0x14}) {
		t.Fatalf("outbound device packet mismatch: %+v", outbound)
	}
	if outbound.ProtocolNumbers[0] != 2 {
		t.Fatalf("outbound protocol = %d, want IPv4 protocol number 2", outbound.ProtocolNumbers[0])
	}
}

func TestDevicePacketExchangerZeroesEvictedOutboundPacket(t *testing.T) {
	exchanger := &DevicePacketExchanger{
		outbound: make(chan []byte, 1),
		done:     make(chan struct{}),
	}
	evicted := []byte{0x45, 0x11, 0x22, 0x33}
	exchanger.outbound <- evicted

	exchanger.queueOutbound([]byte{0x45, 0x44, 0x55, 0x66})

	if !bytes.Equal(evicted, make([]byte, len(evicted))) {
		t.Fatalf("evicted outbound packet was retained: %x", evicted)
	}
	queued := <-exchanger.outbound
	for index := range queued {
		queued[index] = 0
	}
}

func TestDevicePacketExchangerCloseZeroesQueuedOutboundPackets(t *testing.T) {
	device := newScriptedPacketDevice()
	exchanger, err := NewDevicePacketExchanger(device, DevicePacketExchangerOptions{
		MTU:          1280,
		QueuePackets: 1,
	})
	if err != nil {
		t.Fatalf("NewDevicePacketExchanger failed: %v", err)
	}
	queued := []byte{0x45, 0x11, 0x22, 0x33}
	exchanger.outbound <- queued

	if err := exchanger.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !bytes.Equal(queued, make([]byte, len(queued))) {
		t.Fatalf("queued outbound packet was retained after close: %x", queued)
	}
}

func TestDevicePacketExchangerDrainTransfersOutboundPacket(t *testing.T) {
	exchanger := &DevicePacketExchanger{
		outbound: make(chan []byte, 1),
		done:     make(chan struct{}),
	}
	queued := []byte{0x45, 0x11, 0x22, 0x33}
	exchanger.outbound <- queued

	outbound := exchanger.drainOutbound()
	if len(outbound.Packets) != 1 {
		t.Fatalf("outbound packets = %d, want 1", len(outbound.Packets))
	}
	outbound.Packets[0][1] = 0x7f
	if queued[1] != 0x7f {
		t.Fatal("drained outbound packet was copied instead of transferred")
	}
	for index := range queued {
		queued[index] = 0
	}
}

func TestDevicePacketExchangerStopsOnInvalidReadLength(t *testing.T) {
	exchanger := &DevicePacketExchanger{
		device:   invalidReadPacketDevice{},
		mtu:      1280,
		outbound: make(chan []byte, 1),
		done:     make(chan struct{}),
		readDone: make(chan struct{}),
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("readDevice panicked on invalid read length: %v", recovered)
		}
	}()

	exchanger.readDevice()

	select {
	case <-exchanger.readDone:
	default:
		t.Fatal("readDevice did not terminate after an invalid read length")
	}
	if _, err := exchanger.ExchangePacketBatch(PacketBatch{}); err == nil || !strings.Contains(err.Error(), "invalid read length") {
		t.Fatalf("ExchangePacketBatch error = %v, want invalid read length", err)
	}
}

func TestDevicePacketExchangerReportsTerminalReadFailure(t *testing.T) {
	device := newScriptedPacketDevice()
	exchanger, err := NewDevicePacketExchanger(device, DevicePacketExchangerOptions{
		MTU:          1280,
		QueuePackets: 1,
	})
	if err != nil {
		t.Fatalf("NewDevicePacketExchanger failed: %v", err)
	}
	defer exchanger.Close()
	if err := device.Close(); err != nil {
		t.Fatalf("packet device close failed: %v", err)
	}
	select {
	case <-exchanger.readDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for terminal packet-device read failure")
	}

	if _, err := exchanger.ExchangePacketBatch(PacketBatch{}); !errors.Is(err, io.EOF) {
		t.Fatalf("ExchangePacketBatch error = %v, want terminal read error %v", err, io.EOF)
	}
}

func TestDevicePacketExchangerReportsEmptyRead(t *testing.T) {
	exchanger := &DevicePacketExchanger{
		device:   emptyReadPacketDevice{},
		mtu:      1280,
		outbound: make(chan []byte, 1),
		done:     make(chan struct{}),
		readDone: make(chan struct{}),
	}

	exchanger.readDevice()

	if _, err := exchanger.ExchangePacketBatch(PacketBatch{}); err == nil || !strings.Contains(err.Error(), "empty read") {
		t.Fatalf("ExchangePacketBatch error = %v, want empty read", err)
	}
}

func TestWriteFullPacketRejectsInvalidWriteLength(t *testing.T) {
	err := writeFullPacket(packetWriteFunc(func(packet []byte) (int, error) {
		return len(packet) + 1, nil
	}), []byte{0x45, 0x11, 0x22, 0x33})
	if err == nil {
		t.Fatal("writeFullPacket accepted an invalid write length")
	}
}

func TestDevicePacketExchangerCloseUnblocksWrite(t *testing.T) {
	device := newBlockingPacketDevice()
	exchanger, err := NewDevicePacketExchanger(device, DevicePacketExchangerOptions{
		MTU:          1280,
		QueuePackets: 4,
	})
	if err != nil {
		t.Fatalf("NewDevicePacketExchanger failed: %v", err)
	}

	writeResult := make(chan error, 1)
	go func() {
		_, err := exchanger.ExchangePacketBatch(PacketBatch{
			Packets:         [][]byte{{0x45, 0x00, 0x00, 0x14}},
			ProtocolNumbers: []uint16{2},
		})
		writeResult <- err
	}()

	select {
	case <-device.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for packet-device write")
	}

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- exchanger.Close()
	}()

	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	case <-time.After(time.Second):
		device.ReleaseWrite()
		<-writeResult
		<-closeResult
		t.Fatal("Close did not interrupt the blocked packet-device write")
	}

	select {
	case err := <-writeResult:
		if err == nil {
			t.Fatal("ExchangePacketBatch succeeded after its write was interrupted")
		}
	case <-time.After(time.Second):
		t.Fatal("ExchangePacketBatch did not return after device close")
	}
}

func TestDevicePacketExchangerCloseReturnsSameDeviceError(t *testing.T) {
	expected := errors.New("device close failed")
	device := &closeErrorPacketDevice{
		scriptedPacketDevice: newScriptedPacketDevice(),
		err:                  expected,
	}
	exchanger, err := NewDevicePacketExchanger(device, DevicePacketExchangerOptions{
		MTU:          1280,
		QueuePackets: 4,
	})
	if err != nil {
		t.Fatalf("NewDevicePacketExchanger failed: %v", err)
	}

	results := make(chan error, 2)
	go func() { results <- exchanger.Close() }()
	go func() { results <- exchanger.Close() }()
	for range 2 {
		if err := <-results; !errors.Is(err, expected) {
			t.Fatalf("Close error = %v, want %v", err, expected)
		}
	}
}

func TestRunReadinessHarnessCoversLinuxServerSurface(t *testing.T) {
	report, err := RunReadinessHarness(200)
	if err != nil {
		t.Fatalf("RunReadinessHarness failed: %v", err)
	}
	if !report.Passed {
		t.Fatalf("server readiness report failed: %+v", report)
	}
	if !report.CoverEndpoint || !report.CoverNeutralIssuerPath || !report.CoverNeutralHealthPath {
		t.Fatalf("server readiness report missing cover-neutrality coverage: %+v", report)
	}
	if !report.IssuerMetadataCarrier || !report.BlindRSAIssueCarrier || !report.PacketExchangeEndpoint {
		t.Fatalf("server readiness report missing carrier coverage: %+v", report)
	}
}

func TestRunReadinessHarnessUsesValidDefaultClock(t *testing.T) {
	report, err := RunReadinessHarness(0)
	if err != nil {
		t.Fatalf("RunReadinessHarness failed: %v", err)
	}
	if !report.Passed || !report.BlindRSAIssueCarrier {
		t.Fatalf("zero-value readiness report failed: %+v", report)
	}
}

func TestRunClientInteropHarnessExercisesLiveHTTPAndHTTPSBoundary(t *testing.T) {
	report, err := RunClientInteropHarness(200)
	if err != nil {
		t.Fatalf("RunClientInteropHarness failed: %v", err)
	}
	if !report.Passed {
		t.Fatalf("client interop report failed: %+v", report)
	}
	if !report.CoverNeutralIssuerPath || !report.CoverNeutralHealthPath || !report.PacketExchangeEndpoint || !report.CoverNeutralInvalidCarrier {
		t.Fatalf("client interop report missing live HTTP coverage: %+v", report)
	}
	if !report.IssuerMetadataCarrier || !report.TokenIssueCarrier || !report.TokenSpendCarrier || !report.DuplicateSpendRejected {
		t.Fatalf("client interop report missing live issuer coverage: %+v", report)
	}
	if !report.HTTPSCoverNeutralIssuerPath || !report.HTTPSCoverNeutralHealthPath || !report.HTTPSIssuerMetadataCarrier || !report.HTTPSTokenIssueCarrier ||
		!report.HTTPSTokenSpendCarrier || !report.HTTPSDuplicateSpendRejected {
		t.Fatalf("client interop report missing live HTTPS coverage: %+v", report)
	}
	formatted := FormatClientInteropReport(report)
	if !strings.Contains(formatted, "https_packet_exchange=true") {
		t.Fatalf("client interop report missing live HTTPS packet coverage:\n%s", formatted)
	}
	if !strings.Contains(formatted, "token_spend=true") || !strings.Contains(formatted, "https_token_spend=true") ||
		!strings.Contains(formatted, "duplicate_spend_rejected=true") || !strings.Contains(formatted, "https_duplicate_spend_rejected=true") {
		t.Fatalf("client interop report missing token spend coverage:\n%s", formatted)
	}
}

type servedResponse struct {
	status int
	header http.Header
	body   []byte
}

func serveRequest(handler http.Handler, method, path string, body []byte) servedResponse {
	return serveRequestWithContentType(handler, method, path, body, "application/json")
}

func serveRequestWithContentType(handler http.Handler, method, path string, body []byte, contentType string) servedResponse {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return servedResponse{status: rec.Code, header: rec.Result().Header, body: rec.Body.Bytes()}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url parse failed: %v", err)
	}
	return parsed
}

func newServerTestIssuer() (*issuerd.Service, error) {
	return issuerd.NewHarnessService(200)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type packetWriteFunc func([]byte) (int, error)

func (f packetWriteFunc) Write(packet []byte) (int, error) {
	return f(packet)
}

func waitForDeviceOutbound(t *testing.T, exchanger PacketExchanger) PacketBatch {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		outbound, err := exchanger.ExchangePacketBatch(PacketBatch{})
		if err != nil {
			t.Fatalf("ExchangePacketBatch failed while waiting for outbound packet: %v", err)
		}
		if len(outbound.Packets) > 0 {
			return outbound
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for outbound device packet")
	return PacketBatch{}
}

type scriptedPacketDevice struct {
	mu     sync.Mutex
	reads  chan []byte
	writes [][]byte
	closed bool
}

func newScriptedPacketDevice() *scriptedPacketDevice {
	return &scriptedPacketDevice{reads: make(chan []byte, 8)}
}

func (d *scriptedPacketDevice) QueueRead(packet []byte) {
	d.reads <- append([]byte(nil), packet...)
}

func (d *scriptedPacketDevice) Read(p []byte) (int, error) {
	packet, ok := <-d.reads
	if !ok {
		return 0, io.EOF
	}
	return copy(p, packet), nil
}

func (d *scriptedPacketDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.writes = append(d.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (d *scriptedPacketDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		close(d.reads)
	}
	return nil
}

func (d *scriptedPacketDevice) Writes() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, len(d.writes))
	for i, packet := range d.writes {
		out[i] = append([]byte(nil), packet...)
	}
	return out
}

type closeErrorPacketDevice struct {
	*scriptedPacketDevice
	err error
}

func (d *closeErrorPacketDevice) Close() error {
	_ = d.scriptedPacketDevice.Close()
	return d.err
}

type invalidReadPacketDevice struct{}

func (invalidReadPacketDevice) Read(packet []byte) (int, error) {
	return len(packet) + 1, nil
}

func (invalidReadPacketDevice) Write(packet []byte) (int, error) {
	return len(packet), nil
}

func (invalidReadPacketDevice) Close() error {
	return nil
}

type emptyReadPacketDevice struct{}

func (emptyReadPacketDevice) Read([]byte) (int, error) {
	return 0, nil
}

func (emptyReadPacketDevice) Write(packet []byte) (int, error) {
	return len(packet), nil
}

func (emptyReadPacketDevice) Close() error {
	return nil
}

type blockingPacketDevice struct {
	writeStarted chan struct{}
	releaseWrite chan struct{}
	closed       chan struct{}
	closeOnce    sync.Once
}

func newBlockingPacketDevice() *blockingPacketDevice {
	return &blockingPacketDevice{
		writeStarted: make(chan struct{}, 1),
		releaseWrite: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (d *blockingPacketDevice) Read([]byte) (int, error) {
	<-d.closed
	return 0, io.ErrClosedPipe
}

func (d *blockingPacketDevice) Write(p []byte) (int, error) {
	select {
	case d.writeStarted <- struct{}{}:
	default:
	}
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	case <-d.releaseWrite:
		return len(p), nil
	}
}

func (d *blockingPacketDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
	})
	return nil
}

func (d *blockingPacketDevice) ReleaseWrite() {
	close(d.releaseWrite)
}
