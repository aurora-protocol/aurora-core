package protocol

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/wire"
)

func TestDecodeExtensionsRejectsCountExceedingRemainingWithoutSyntheticEntries(t *testing.T) {
	r := wire.NewReader([]byte{0x02})
	extensions := DecodeExtensions(r)
	if r.Err() == nil {
		t.Fatalf("extension vector count exceeding remaining bytes was accepted")
	}
	if len(extensions) != 0 {
		t.Fatalf("decoder synthesized %d extension entries after count failure: %+v", len(extensions), extensions)
	}
}

func TestDecodeFrameBlockRejectsCountExceedingRemainingAtVectorBoundary(t *testing.T) {
	_, err := DecodeFrameBlock([]byte{0x02})
	if err == nil {
		t.Fatalf("frame block count exceeding remaining bytes was accepted")
	}
	if !strings.Contains(err.Error(), "frame count") {
		t.Fatalf("frame block count failure was not reported at vector boundary: %v", err)
	}
}

func TestDecodeFrameBlockRejectsResourceExhaustingFrameCountBeforeAllocation(t *testing.T) {
	prefix, err := wire.EncodeVarint(4097)
	if err != nil {
		t.Fatal(err)
	}
	encoded := append(prefix, bytes.Repeat([]byte{0}, 4097)...)
	_, err = DecodeFrameBlock(encoded)
	if err == nil || !strings.Contains(err.Error(), "frame count exceeds limit") {
		t.Fatalf("resource-exhausting frame count error = %v, want limit rejection", err)
	}
}

func TestValidateFrameBlockRejectsResourceExhaustingFrameCount(t *testing.T) {
	block := FrameBlock{Frames: make([]AuroraFrame, MaxFrameBlockFrames+1)}
	if err := ValidateFrameBlock(block); err == nil || !strings.Contains(err.Error(), "frame count exceeds limit") {
		t.Fatalf("resource-exhausting outbound frame count error = %v, want limit rejection", err)
	}
}
