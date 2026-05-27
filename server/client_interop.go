package server

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"time"
)

type ClientInteropReport struct {
	Passed                      bool
	CoverNeutralIssuerPath      bool
	HTTPSCoverNeutralIssuerPath bool
	CoverNeutralHealthPath      bool
	HTTPSCoverNeutralHealthPath bool
	IssuerMetadataCarrier       bool
	HTTPSIssuerMetadataCarrier  bool
	TokenIssueCarrier           bool
	HTTPSTokenIssueCarrier      bool
	TokenSpendCarrier           bool
	HTTPSTokenSpendCarrier      bool
	DuplicateSpendRejected      bool
	HTTPSDuplicateSpendRejected bool
	PacketExchangeEndpoint      bool
	HTTPSPacketExchangeEndpoint bool
	CoverNeutralInvalidCarrier  bool
	Findings                    []string
}

func RunClientInteropHarness(nowUnix uint64) (ClientInteropReport, error) {
	nowUnix = normalizeHarnessNow(nowUnix)
	coverBody := []byte("<html>cover</html>")
	handler, err := NewHarnessHandler(HarnessOptions{
		NowUnix:   nowUnix,
		CoverBody: coverBody,
	})
	if err != nil {
		return ClientInteropReport{}, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return ClientInteropReport{}, fmt.Errorf("server: start client interop listener: %w", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	defer server.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	report := ClientInteropReport{Passed: true}

	// The former fixed public issuer and health paths MUST be byte-identical to
	// an ordinary origin probe over both HTTP and HTTPS.
	report.CoverNeutralIssuerPath = probeIsCoverNeutral(client, server.URL+"/issuer/issuer-metadata", coverBody)
	report.require(report.CoverNeutralIssuerPath, "legacy issuer path distinguishable from cover over HTTP")
	report.CoverNeutralHealthPath = probeIsCoverNeutral(client, server.URL+"/healthz", coverBody)
	report.require(report.CoverNeutralHealthPath, "legacy health path distinguishable from cover over HTTP")

	report.IssuerMetadataCarrier, report.TokenIssueCarrier, report.TokenSpendCarrier, report.DuplicateSpendRejected =
		exerciseCarrierIssuance(client, server.URL+DefaultPacketExchangePath, nowUnix, 0x10)
	report.require(report.IssuerMetadataCarrier, "issuer metadata carrier failed over HTTP")
	report.require(report.TokenIssueCarrier, "token issue carrier failed over HTTP")
	report.require(report.TokenSpendCarrier, "token spend carrier failed over HTTP")
	report.require(report.DuplicateSpendRejected, "duplicate token spend was not rejected over HTTP")

	report.PacketExchangeEndpoint = exerciseCarrierPacketExchange(client, server.URL+DefaultPacketExchangePath)
	report.require(report.PacketExchangeEndpoint, "packet exchange carrier failed over HTTP")

	report.CoverNeutralInvalidCarrier = exerciseInvalidCarrierIsCover(client, server.URL+DefaultPacketExchangePath, coverBody)
	report.require(report.CoverNeutralInvalidCarrier, "invalid carrier request did not map to cover")

	tlsServer := httptest.NewTLSServer(handler)
	defer tlsServer.Close()
	tlsClient := tlsServer.Client()
	tlsClient.Timeout = 2 * time.Second

	report.HTTPSCoverNeutralIssuerPath = probeIsCoverNeutral(tlsClient, tlsServer.URL+"/issuer/issuer-metadata", coverBody)
	report.require(report.HTTPSCoverNeutralIssuerPath, "legacy issuer path distinguishable from cover over HTTPS")
	report.HTTPSCoverNeutralHealthPath = probeIsCoverNeutral(tlsClient, tlsServer.URL+"/healthz", coverBody)
	report.require(report.HTTPSCoverNeutralHealthPath, "legacy health path distinguishable from cover over HTTPS")

	report.HTTPSIssuerMetadataCarrier, report.HTTPSTokenIssueCarrier, report.HTTPSTokenSpendCarrier, report.HTTPSDuplicateSpendRejected =
		exerciseCarrierIssuance(tlsClient, tlsServer.URL+DefaultPacketExchangePath, nowUnix, 0x20)
	report.require(report.HTTPSIssuerMetadataCarrier, "issuer metadata carrier failed over HTTPS")
	report.require(report.HTTPSTokenIssueCarrier, "token issue carrier failed over HTTPS")
	report.require(report.HTTPSTokenSpendCarrier, "token spend carrier failed over HTTPS")
	report.require(report.HTTPSDuplicateSpendRejected, "duplicate token spend was not rejected over HTTPS")

	report.HTTPSPacketExchangeEndpoint = exerciseCarrierPacketExchange(tlsClient, tlsServer.URL+DefaultPacketExchangePath)
	report.require(report.HTTPSPacketExchangeEndpoint, "packet exchange carrier failed over HTTPS")

	return report, nil
}

func (r *ClientInteropReport) require(ok bool, finding string) {
	if ok {
		return
	}
	r.Passed = false
	r.Findings = append(r.Findings, finding)
}

func FormatClientInteropReport(report ClientInteropReport) string {
	return fmt.Sprintf(
		"client_check passed=%t cover_neutral_issuer_path=%t https_cover_neutral_issuer_path=%t cover_neutral_health_path=%t https_cover_neutral_health_path=%t issuer_metadata=%t https_issuer_metadata=%t token_issue=%t https_token_issue=%t token_spend=%t https_token_spend=%t duplicate_spend_rejected=%t https_duplicate_spend_rejected=%t packet_exchange=%t https_packet_exchange=%t cover_neutral_invalid_carrier=%t findings=%d\n",
		report.Passed,
		report.CoverNeutralIssuerPath,
		report.HTTPSCoverNeutralIssuerPath,
		report.CoverNeutralHealthPath,
		report.HTTPSCoverNeutralHealthPath,
		report.IssuerMetadataCarrier,
		report.HTTPSIssuerMetadataCarrier,
		report.TokenIssueCarrier,
		report.HTTPSTokenIssueCarrier,
		report.TokenSpendCarrier,
		report.HTTPSTokenSpendCarrier,
		report.DuplicateSpendRejected,
		report.HTTPSDuplicateSpendRejected,
		report.PacketExchangeEndpoint,
		report.HTTPSPacketExchangeEndpoint,
		report.CoverNeutralInvalidCarrier,
		len(report.Findings),
	)
}

// probeIsCoverNeutral confirms a GET probe to the given URL returns a 200 with a
// body byte-identical to the configured cover body.
func probeIsCoverNeutral(client *http.Client, url string, coverBody []byte) bool {
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	return resp.StatusCode == http.StatusOK && bytes.Equal(body, coverBody)
}

// exerciseCarrierIssuance fetches metadata, issues a Blind RSA admission token,
// spends it, and confirms a replayed spend is rejected — all over the cover
// carrier. seed differentiates token material across independent runs sharing
// the same issuer spent-token state.
func exerciseCarrierIssuance(client *http.Client, carrierURL string, nowUnix uint64, seed byte) (metadataOK, issueOK, spendOK, duplicateRejected bool) {
	metaType, metaPayload, err := doCarrierExchangeHTTP(client, carrierURL, CarrierIssuerMetadataReq, nil)
	if err == nil && metaType == CarrierIssuerMetadataResp {
		if encoded, hash, decodeErr := DecodeCarrierMetadataResponse(metaPayload); decodeErr == nil && len(encoded) > 0 && len(hash) == carrierMetadataHashLen {
			metadataOK = true
		}
	}

	issueRequest, err := EncodeCarrierIssueRequest(repeatedByte(seed|0x01, carrierTokenNonceLen), repeatedByte(seed|0x02, carrierRedemptionContextLen), nowUnix+300)
	if err != nil {
		return metadataOK, false, false, false
	}
	issueType, proof, err := doCarrierExchangeHTTP(client, carrierURL, CarrierBlindRSAIssueReq, issueRequest)
	if err != nil || issueType != CarrierBlindRSAIssueResp || len(proof) == 0 {
		return metadataOK, false, false, false
	}
	issueOK = true

	spendType, spentKey, err := doCarrierExchangeHTTP(client, carrierURL, CarrierTokenSpendReq, proof)
	if err == nil && spendType == CarrierTokenSpendResp && len(spentKey) == carrierSpentKeyLen {
		spendOK = true
	}

	duplicateType, _, err := doCarrierExchangeHTTP(client, carrierURL, CarrierTokenSpendReq, proof)
	if err == nil && duplicateType == CarrierTokenSpendConflict {
		duplicateRejected = true
	}
	return metadataOK, issueOK, spendOK, duplicateRejected
}

func exerciseCarrierPacketExchange(client *http.Client, carrierURL string) bool {
	inbound, err := EncodePacketBatch(PacketBatch{
		Packets:         [][]byte{{0x45, 0x00, 0x00, 0x14}},
		ProtocolNumbers: []uint16{2},
	})
	if err != nil {
		return false
	}
	respType, payload, err := doCarrierExchangeHTTP(client, carrierURL, CarrierPacketBatch, inbound)
	if err != nil || respType != CarrierPacketBatch {
		return false
	}
	outbound, err := DecodePacketBatch(payload)
	return err == nil &&
		len(outbound.Packets) == 1 &&
		bytes.Equal(outbound.Packets[0], []byte{0x45, 0x00, 0x00, 0x14}) &&
		outbound.ProtocolNumbers[0] == 2
}

// exerciseInvalidCarrierIsCover confirms a POST of an unknown/garbage carrier
// body to the carrier surface is served as byte-identical cover.
func exerciseInvalidCarrierIsCover(client *http.Client, carrierURL string, coverBody []byte) bool {
	resp, err := client.Post(carrierURL, "application/octet-stream", bytes.NewReader([]byte("not a carrier message")))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	// A garbage carrier body must look like the ordinary origin: a plain cover
	// response, never an octet-stream carrier reply.
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return resp.StatusCode == http.StatusOK && bytes.Equal(body, coverBody) && mediaType != "application/octet-stream"
}
