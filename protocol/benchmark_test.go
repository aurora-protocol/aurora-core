package protocol

import (
	"bytes"
	"testing"
)

func BenchmarkFrameBlockEncode1200(b *testing.B) {
	block := benchmarkStreamDataFrameBlock(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Encode(block); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFrameBlockDecode1200(b *testing.B) {
	block := benchmarkStreamDataFrameBlock(b)
	encoded, err := Encode(block)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decoded, err := DecodeFrameBlock(encoded)
		if err != nil {
			b.Fatal(err)
		}
		if len(decoded.Frames) != 1 || len(decoded.Frames[0].Payload) != 1200 {
			b.Fatal("frame block decode failed")
		}
	}
}

func benchmarkStreamDataFrameBlock(b *testing.B) FrameBlock {
	b.Helper()
	frame, err := NewStreamDataFrame(7, bytes.Repeat([]byte{0x5a}, 1200), 0)
	if err != nil {
		b.Fatal(err)
	}
	return FrameBlock{Frames: []AuroraFrame{frame}}
}
