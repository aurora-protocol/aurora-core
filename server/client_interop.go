package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/aurora-protocol/aurora-core/issuerd"
)

type ClientInteropReport struct {
	Passed                      bool
	HealthEndpoint              bool
	HTTPSHealthEndpoint         bool
	IssuerMetadataEndpoint      bool
	HTTPSIssuerMetadataEndpoint bool
	TokenIssueEndpoint          bool
	HTTPSTokenIssueEndpoint     bool
	TokenSpendEndpoint          bool
	HTTPSTokenSpendEndpoint     bool
	DuplicateSpendRejected      bool
	HTTPSDuplicateSpendRejected bool
	PacketExchangeEndpoint      bool
	HTTPSPacketExchangeEndpoint bool
	CoverNeutralInvalidPacket   bool
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

	health, err := client.Get(server.URL + "/healthz")
	if err == nil {
		defer health.Body.Close()
		var status struct {
			Ready  bool `json:"ready"`
			Issuer bool `json:"issuer"`
			Cover  bool `json:"cover"`
		}
		body, readErr := io.ReadAll(health.Body)
		if readErr == nil && json.Unmarshal(body, &status) == nil {
			report.HealthEndpoint = health.StatusCode == http.StatusOK && status.Ready && status.Issuer && status.Cover
		}
	}
	report.require(report.HealthEndpoint, "live health request failed")

	tlsServer := httptest.NewTLSServer(handler)
	defer tlsServer.Close()
	tlsClient := tlsServer.Client()
	tlsClient.Timeout = 2 * time.Second
	tlsHealth, err := tlsClient.Get(tlsServer.URL + "/healthz")
	if err == nil {
		defer tlsHealth.Body.Close()
		var status struct {
			Ready  bool `json:"ready"`
			Issuer bool `json:"issuer"`
			Cover  bool `json:"cover"`
		}
		body, readErr := io.ReadAll(tlsHealth.Body)
		if readErr == nil && json.Unmarshal(body, &status) == nil {
			report.HTTPSHealthEndpoint = tlsHealth.StatusCode == http.StatusOK && status.Ready && status.Issuer && status.Cover
		}
	}
	report.require(report.HTTPSHealthEndpoint, "live HTTPS health request failed")

	report.IssuerMetadataEndpoint, report.TokenIssueEndpoint, report.TokenSpendEndpoint, report.DuplicateSpendRejected =
		exerciseIssuerHTTPClient(client, server.URL, nowUnix)
	report.require(report.IssuerMetadataEndpoint, "live issuer metadata request failed")
	report.require(report.TokenIssueEndpoint, "live token issue request failed")
	report.require(report.TokenSpendEndpoint, "live token spend request failed")
	report.require(report.DuplicateSpendRejected, "live duplicate token spend was not rejected")

	report.HTTPSIssuerMetadataEndpoint, report.HTTPSTokenIssueEndpoint, report.HTTPSTokenSpendEndpoint, report.HTTPSDuplicateSpendRejected =
		exerciseIssuerHTTPClient(tlsClient, tlsServer.URL, nowUnix)
	report.require(report.HTTPSIssuerMetadataEndpoint, "live HTTPS issuer metadata request failed")
	report.require(report.HTTPSTokenIssueEndpoint, "live HTTPS token issue request failed")
	report.require(report.HTTPSTokenSpendEndpoint, "live HTTPS token spend request failed")
	report.require(report.HTTPSDuplicateSpendRejected, "live HTTPS duplicate token spend was not rejected")

	inbound, err := EncodePacketBatch(PacketBatch{
		Packets:         [][]byte{{0x45, 0x00, 0x00, 0x14}},
		ProtocolNumbers: []uint16{2},
	})
	if err != nil {
		return ClientInteropReport{}, err
	}
	packetResp, err := client.Post(server.URL+DefaultPacketExchangePath, "application/octet-stream", bytes.NewReader(inbound))
	if err == nil {
		defer packetResp.Body.Close()
		body, readErr := io.ReadAll(packetResp.Body)
		mediaType, _, mediaErr := mime.ParseMediaType(packetResp.Header.Get("Content-Type"))
		if readErr == nil && mediaErr == nil && packetResp.StatusCode == http.StatusOK && mediaType == "application/octet-stream" {
			outbound, decodeErr := DecodePacketBatch(body)
			report.PacketExchangeEndpoint = decodeErr == nil &&
				len(outbound.Packets) == 1 &&
				bytes.Equal(outbound.Packets[0], []byte{0x45, 0x00, 0x00, 0x14}) &&
				outbound.ProtocolNumbers[0] == 2
		}
	}
	report.require(report.PacketExchangeEndpoint, "live packet exchange failed")

	tlsPacketResp, err := tlsClient.Post(tlsServer.URL+DefaultPacketExchangePath, "application/octet-stream", bytes.NewReader(inbound))
	if err == nil {
		defer tlsPacketResp.Body.Close()
		body, readErr := io.ReadAll(tlsPacketResp.Body)
		mediaType, _, mediaErr := mime.ParseMediaType(tlsPacketResp.Header.Get("Content-Type"))
		if readErr == nil && mediaErr == nil && tlsPacketResp.StatusCode == http.StatusOK && mediaType == "application/octet-stream" {
			outbound, decodeErr := DecodePacketBatch(body)
			report.HTTPSPacketExchangeEndpoint = decodeErr == nil &&
				len(outbound.Packets) == 1 &&
				bytes.Equal(outbound.Packets[0], []byte{0x45, 0x00, 0x00, 0x14}) &&
				outbound.ProtocolNumbers[0] == 2
		}
	}
	report.require(report.HTTPSPacketExchangeEndpoint, "live HTTPS packet exchange failed")

	invalidResp, err := client.Post(server.URL+DefaultPacketExchangePath, "application/octet-stream", bytes.NewReader([]byte("not a packet batch")))
	if err == nil {
		defer invalidResp.Body.Close()
		body, readErr := io.ReadAll(invalidResp.Body)
		report.CoverNeutralInvalidPacket = readErr == nil &&
			invalidResp.StatusCode == http.StatusOK &&
			bytes.Equal(body, coverBody)
	}
	report.require(report.CoverNeutralInvalidPacket, "invalid packet request did not map to cover")

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
		"client_check passed=%t health=%t https_health=%t issuer_metadata=%t https_issuer_metadata=%t token_issue=%t https_token_issue=%t token_spend=%t https_token_spend=%t duplicate_spend_rejected=%t https_duplicate_spend_rejected=%t packet_exchange=%t https_packet_exchange=%t cover_neutral_invalid_packet=%t findings=%d\n",
		report.Passed,
		report.HealthEndpoint,
		report.HTTPSHealthEndpoint,
		report.IssuerMetadataEndpoint,
		report.HTTPSIssuerMetadataEndpoint,
		report.TokenIssueEndpoint,
		report.HTTPSTokenIssueEndpoint,
		report.TokenSpendEndpoint,
		report.HTTPSTokenSpendEndpoint,
		report.DuplicateSpendRejected,
		report.HTTPSDuplicateSpendRejected,
		report.PacketExchangeEndpoint,
		report.HTTPSPacketExchangeEndpoint,
		report.CoverNeutralInvalidPacket,
		len(report.Findings),
	)
}

func exerciseIssuerHTTPClient(client *http.Client, baseURL string, nowUnix uint64) (metadataOK, issueOK, spendOK, duplicateRejected bool) {
	metadataResp, err := client.Get(baseURL + "/issuer/issuer-metadata")
	if err != nil {
		return false, false, false, false
	}
	defer metadataResp.Body.Close()
	var metadata issuerd.MetadataResponse
	metadataBody, readErr := io.ReadAll(metadataResp.Body)
	if readErr == nil && json.Unmarshal(metadataBody, &metadata) == nil {
		metadataOK = metadataResp.StatusCode == http.StatusOK &&
			validHexLength(metadata.IssuerMetadataHash, 48) &&
			validNonEmptyHex(metadata.IssuerMetadata)
	}

	issueBody, err := json.Marshal(issuerd.IssueRequest{
		TokenNonce:            repeatedHex(0xa1, 32),
		RedemptionContextHash: repeatedHex(0xb2, 48),
		ExpiryUnix:            nowUnix + 300,
	})
	if err != nil {
		return metadataOK, false, false, false
	}
	issueResp, err := client.Post(baseURL+"/issuer/blind-rsa/issue", "application/json", bytes.NewReader(issueBody))
	if err != nil {
		return metadataOK, false, false, false
	}
	defer issueResp.Body.Close()
	var issued issuerd.IssueResponse
	issueRespBody, readErr := io.ReadAll(issueResp.Body)
	if readErr == nil && json.Unmarshal(issueRespBody, &issued) == nil {
		issueOK = issueResp.StatusCode == http.StatusOK && validNonEmptyHex(issued.AdmissionProof)
	}
	if !issueOK {
		return metadataOK, issueOK, false, false
	}

	spendBody, err := json.Marshal(issuerd.SpendRequest{AdmissionProof: issued.AdmissionProof})
	if err != nil {
		return metadataOK, issueOK, false, false
	}
	spendResp, err := client.Post(baseURL+"/issuer/token/spend", "application/json", bytes.NewReader(spendBody))
	if err != nil {
		return metadataOK, issueOK, false, false
	}
	defer spendResp.Body.Close()
	var spent issuerd.SpendResponse
	spendRespBody, readErr := io.ReadAll(spendResp.Body)
	if readErr == nil && json.Unmarshal(spendRespBody, &spent) == nil {
		spendOK = spendResp.StatusCode == http.StatusOK && spent.Spent && validHexLength(spent.SpentKey, 48)
	}

	duplicateResp, err := client.Post(baseURL+"/issuer/token/spend", "application/json", bytes.NewReader(spendBody))
	if err != nil {
		return metadataOK, issueOK, spendOK, false
	}
	defer duplicateResp.Body.Close()
	duplicateRejected = duplicateResp.StatusCode == http.StatusConflict
	return metadataOK, issueOK, spendOK, duplicateRejected
}

func repeatedHex(value byte, count int) string {
	return hex.EncodeToString(bytes.Repeat([]byte{value}, count))
}

func validHexLength(raw string, want int) bool {
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == want
}

func validNonEmptyHex(raw string) bool {
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) > 0
}
