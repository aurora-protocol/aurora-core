package wire

import (
	"fmt"
	"testing"
)

func BenchmarkVarintRoundTrip(b *testing.B) {
	for _, value := range []uint64{63, 16383, 1073741823, 4611686018427387903} {
		b.Run(fmt.Sprintf("value_%d", value), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				encoded, err := EncodeVarint(value)
				if err != nil {
					b.Fatal(err)
				}
				decoded, n, err := DecodeVarint(encoded)
				if err != nil || decoded != value || n != len(encoded) {
					b.Fatal("round trip failed")
				}
			}
		})
	}
}
