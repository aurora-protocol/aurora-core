package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkPacketBatchEncode(b *testing.B) {
	batch := benchmarkPacketBatch()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncodePacketBatch(batch); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPacketBatchDecode(b *testing.B) {
	encoded, err := EncodePacketBatch(benchmarkPacketBatch())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch, err := DecodePacketBatch(encoded)
		if err != nil {
			b.Fatal(err)
		}
		if len(batch.Packets) != 1 || batch.ProtocolNumbers[0] != 2 {
			b.Fatal("packet batch decode failed")
		}
	}
}

func BenchmarkHarnessPacketCarrier(b *testing.B) {
	handler, err := NewHarnessHandler(HarnessOptions{NowUnix: 1700000000})
	if err != nil {
		b.Fatal(err)
	}
	encodedBatch, err := EncodePacketBatch(benchmarkPacketBatch())
	if err != nil {
		b.Fatal(err)
	}
	body := EncodeCarrier(CarrierPacketBatch, encodedBatch)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, DefaultPacketExchangePath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/octet-stream")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		resp := rec.Result()
		responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxCarrierBodyBytes+1))
		closeErr := resp.Body.Close()
		if readErr != nil {
			b.Fatal(readErr)
		}
		if closeErr != nil {
			b.Fatal(closeErr)
		}
		if len(responseBody) > maxCarrierBodyBytes {
			b.Fatalf("carrier response body length %d exceeds %d", len(responseBody), maxCarrierBodyBytes)
		}
		carrierType, payload, err := DecodeCarrier(responseBody)
		if err != nil {
			b.Fatal(err)
		}
		batch, err := DecodePacketBatch(payload)
		if err != nil {
			b.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || carrierType != CarrierPacketBatch || len(batch.Packets) != 1 || batch.ProtocolNumbers[0] != 2 {
			b.Fatal("packet carrier request failed")
		}
	}
}

func benchmarkPacketBatch() PacketBatch {
	return PacketBatch{
		Packets: [][]byte{{
			0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
			0x4e, 0xa3, 0xc0, 0x00, 0x02, 0x01, 0xc6, 0x33, 0x64, 0x01,
		}},
		ProtocolNumbers: []uint16{2},
	}
}
