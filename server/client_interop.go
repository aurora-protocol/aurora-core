package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"time"
)

type ClientInteropReport struct {
	Passed                    bool
	HealthEndpoint            bool
	PacketExchangeEndpoint    bool
	CoverNeutralInvalidPacket bool
	Findings                  []string
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
		"client_check passed=%t health=%t packet_exchange=%t cover_neutral_invalid_packet=%t findings=%d\n",
		report.Passed,
		report.HealthEndpoint,
		report.PacketExchangeEndpoint,
		report.CoverNeutralInvalidPacket,
		len(report.Findings),
	)
}
