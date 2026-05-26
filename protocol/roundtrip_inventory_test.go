package protocol

import (
	"bytes"
	"testing"
)

func TestDecodeFuzzTargetsRoundTripCanonically(t *testing.T) {
	for _, target := range decodeFuzzTargets() {
		t.Run(target.name, func(t *testing.T) {
			decoded, err := decodeFuzzTargetValue(target.name, target.seed)
			if err != nil {
				t.Fatalf("decode %s seed: %v", target.name, err)
			}
			encoded, err := Encode(decoded)
			if err != nil {
				t.Fatalf("re-encode %s seed: %v", target.name, err)
			}
			if !bytes.Equal(encoded, target.seed) {
				t.Fatalf("%s decode/re-encode changed canonical bytes:\n got=%x\nwant=%x", target.name, encoded, target.seed)
			}
		})
	}
}
