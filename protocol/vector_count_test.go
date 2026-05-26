package protocol

import (
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
