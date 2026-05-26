package protocol

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestDataFrameConstructorsCopyPayloads(t *testing.T) {
	data := []byte("hello")
	stream, err := NewStreamDataFrame(7, data, 0x01)
	if err != nil {
		t.Fatal(err)
	}
	datagram, err := NewDatagramDataFrame(8, data, 0x02)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := NewDNSMessageFrame(9, data)
	if err != nil {
		t.Fatal(err)
	}
	data[0] = 'H'
	if stream.FrameType != registry.FrameStreamData || stream.FlowID != 7 || stream.Flags != 0x01 || !bytes.Equal(stream.Payload, []byte("hello")) {
		t.Fatalf("unexpected stream frame: %+v", stream)
	}
	if datagram.FrameType != registry.FrameDatagramData || datagram.FlowID != 8 || datagram.Flags != 0x02 || !bytes.Equal(datagram.Payload, []byte("hello")) {
		t.Fatalf("unexpected datagram frame: %+v", datagram)
	}
	if dns.FrameType != registry.FrameDNSMessage || dns.FlowID != 9 || dns.Flags != 0 || !bytes.Equal(dns.Payload, []byte("hello")) {
		t.Fatalf("unexpected DNS frame: %+v", dns)
	}
}

func TestValidateFrameBlockRejectsMalformedDataFrames(t *testing.T) {
	cases := []AuroraFrame{
		{FrameType: registry.FrameStreamData, FlowID: 0, Payload: []byte("data")},
		{FrameType: registry.FrameStreamData, FlowID: 1},
		{FrameType: registry.FrameDatagramData, FlowID: 0, Payload: []byte("data")},
		{FrameType: registry.FrameDatagramData, FlowID: 1},
		{FrameType: registry.FrameDNSMessage, FlowID: 0, Payload: []byte("data")},
		{FrameType: registry.FrameDNSMessage, FlowID: 1},
	}
	for _, frame := range cases {
		if err := ValidateFrameBlock(FrameBlock{Frames: []AuroraFrame{frame}}); err == nil {
			t.Fatalf("malformed data frame accepted: %+v", frame)
		}
	}
}
