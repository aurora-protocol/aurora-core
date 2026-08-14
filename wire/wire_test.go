package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestVarintMinimalEncodings(t *testing.T) {
	tests := []struct {
		value uint64
		hex   string
	}{
		{0, "00"},
		{63, "3f"},
		{64, "4040"},
		{0x200, "4200"},
		{0x0103, "4103"},
		{16383, "7fff"},
		{16384, "80004000"},
		{1073741823, "bfffffff"},
		{1073741824, "c000000040000000"},
	}
	for _, tt := range tests {
		got, err := EncodeVarint(tt.value)
		if err != nil {
			t.Fatalf("EncodeVarint(%d): %v", tt.value, err)
		}
		want, _ := hex.DecodeString(tt.hex)
		if !bytes.Equal(got, want) {
			t.Fatalf("EncodeVarint(%d) = %x, want %s", tt.value, got, tt.hex)
		}
		decoded, n, err := DecodeVarint(got)
		if err != nil {
			t.Fatalf("DecodeVarint(%x): %v", got, err)
		}
		if decoded != tt.value || n != len(got) {
			t.Fatalf("DecodeVarint(%x) = %d/%d, want %d/%d", got, decoded, n, tt.value, len(got))
		}
	}
}

func TestVarintRejectsNonMinimal(t *testing.T) {
	for _, encoded := range []string{"4000", "8000003f", "c000000000003fff"} {
		b, _ := hex.DecodeString(encoded)
		_, _, err := DecodeVarint(b)
		if !errors.Is(err, ErrNonMinimalVarint) {
			t.Fatalf("DecodeVarint(%s) err = %v, want ErrNonMinimalVarint", encoded, err)
		}
	}
}

func TestAppendVarintRetainsDestinationOnError(t *testing.T) {
	destination := []byte{0xaa}
	got, err := AppendVarint(destination, MaxVarint+1)
	if err == nil {
		t.Fatal("out-of-range varint accepted")
	}
	if !bytes.Equal(got, destination) {
		t.Fatalf("destination after rejected append = %x, want %x", got, destination)
	}
}

func TestOpaqueAndScalars(t *testing.T) {
	e := NewEncoder()
	e.WriteUint16(0x1234)
	e.WriteUint24(0xabcdef)
	e.WriteUint32(0x10203040)
	e.WriteUint64(0x0102030405060708)
	e.WriteOpaque8([]byte{1, 2})
	e.WriteOpaque16([]byte{3, 4, 5})
	got, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("1234abcdef1020304001020304050607080201020003030405")
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded = %x, want %x", got, want)
	}

	r := NewReader(got)
	if r.ReadUint16() != 0x1234 || r.ReadUint24() != 0xabcdef || r.ReadUint32() != 0x10203040 || r.ReadUint64() != 0x0102030405060708 {
		t.Fatalf("scalar decode failed")
	}
	if !bytes.Equal(r.ReadOpaque8(), []byte{1, 2}) || !bytes.Equal(r.ReadOpaque16(), []byte{3, 4, 5}) {
		t.Fatalf("opaque decode failed")
	}
	if !r.EOF() {
		t.Fatalf("reader did not finish: remaining=%d err=%v", r.Remaining(), r.Err())
	}
}

func TestOpaqueBoundaryCases(t *testing.T) {
	cases := []struct {
		name      string
		maxLen    int
		prefix    []byte
		shortRead []byte
		write     func(*Encoder, []byte)
		read      func(*Reader) []byte
	}{
		{
			name:      "opaque8",
			maxLen:    0xff,
			prefix:    []byte{0xff},
			shortRead: []byte{0xff},
			write:     func(e *Encoder, b []byte) { e.WriteOpaque8(b) },
			read:      func(r *Reader) []byte { return r.ReadOpaque8() },
		},
		{
			name:      "opaque16",
			maxLen:    0xffff,
			prefix:    []byte{0xff, 0xff},
			shortRead: []byte{0xff, 0xff},
			write:     func(e *Encoder, b []byte) { e.WriteOpaque16(b) },
			read:      func(r *Reader) []byte { return r.ReadOpaque16() },
		},
		{
			name:      "opaque24",
			maxLen:    0xffffff,
			prefix:    []byte{0xff, 0xff, 0xff},
			shortRead: []byte{0xff, 0xff, 0xff},
			write:     func(e *Encoder, b []byte) { e.WriteOpaque24(b) },
			read:      func(r *Reader) []byte { return r.ReadOpaque24() },
		},
	}

	for _, tt := range cases {
		t.Run(tt.name+"/max-length", func(t *testing.T) {
			payload := opaqueBoundaryPayload(tt.maxLen)
			e := NewEncoder()
			tt.write(e, payload)
			encoded, err := e.Bytes()
			if err != nil {
				t.Fatalf("max-length encode failed: %v", err)
			}
			if got, want := len(encoded), len(tt.prefix)+tt.maxLen; got != want {
				t.Fatalf("encoded length = %d, want %d", got, want)
			}
			if !bytes.Equal(encoded[:len(tt.prefix)], tt.prefix) {
				t.Fatalf("length prefix = %x, want %x", encoded[:len(tt.prefix)], tt.prefix)
			}
			assertOpaquePayloadShape(t, "encoded body", encoded[len(tt.prefix):], payload)

			r := NewReader(encoded)
			decoded := tt.read(r)
			if err := r.Err(); err != nil {
				t.Fatalf("max-length decode failed: %v", err)
			}
			if !r.EOF() {
				t.Fatalf("reader did not finish: remaining=%d", r.Remaining())
			}
			assertOpaquePayloadShape(t, "decoded body", decoded, payload)
		})

		t.Run(tt.name+"/overflow", func(t *testing.T) {
			e := NewEncoder()
			tt.write(e, make([]byte, tt.maxLen+1))
			if _, err := e.Bytes(); err == nil {
				t.Fatalf("overflow encode unexpectedly succeeded")
			}
		})

		t.Run(tt.name+"/short-read", func(t *testing.T) {
			r := NewReader(tt.shortRead)
			_ = tt.read(r)
			if err := r.Err(); err == nil {
				t.Fatalf("short read unexpectedly succeeded")
			}
		})
	}
}

func TestVectorElementCountBoundaries(t *testing.T) {
	e := NewEncoder()
	e.WriteVarintVector([]uint64{0, 63, 64})
	encoded, err := e.Bytes()
	if err != nil {
		t.Fatalf("vector encode failed: %v", err)
	}
	want, _ := hex.DecodeString("03003f4040")
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded vector = %x, want %x", encoded, want)
	}
	r := NewReader(encoded)
	if got := r.ReadVarintVector(); !equalUint64s(got, []uint64{0, 63, 64}) {
		t.Fatalf("decoded vector = %v", got)
	}
	if !r.EOF() {
		t.Fatalf("reader did not finish: remaining=%d err=%v", r.Remaining(), r.Err())
	}

	r = NewReader([]byte{0x02, 0xaa, 0xbb})
	if count := r.ReadVectorCount("unit vector"); count != 2 {
		t.Fatalf("exact vector count = %d, want 2", count)
	}
	if r.Err() != nil || r.Remaining() != 2 {
		t.Fatalf("exact vector count changed reader state incorrectly: remaining=%d err=%v", r.Remaining(), r.Err())
	}

	r = NewReader([]byte{0x03, 0xaa, 0xbb})
	if count := r.ReadVectorCount("unit vector"); count != 0 {
		t.Fatalf("overflow vector count = %d, want 0", count)
	}
	if err := r.Err(); err == nil {
		t.Fatalf("overflow vector count unexpectedly succeeded")
	} else if !strings.Contains(err.Error(), "unit vector count 3 exceeds remaining bytes 2") {
		t.Fatalf("overflow vector count error = %v", err)
	}

	r = NewReader([]byte{0x40, 0x00})
	if count := r.ReadVectorCount("unit vector"); count != 0 {
		t.Fatalf("non-minimal vector count = %d, want 0", count)
	}
	if !errors.Is(r.Err(), ErrNonMinimalVarint) {
		t.Fatalf("non-minimal vector count err = %v, want ErrNonMinimalVarint", r.Err())
	}

	r = NewReader([]byte{0x01})
	if count := r.ReadVectorCount(""); count != 0 {
		t.Fatalf("default-label overflow count = %d, want 0", count)
	}
	if err := r.Err(); err == nil {
		t.Fatalf("default-label overflow unexpectedly succeeded")
	} else if !strings.Contains(err.Error(), "vector count 1 exceeds remaining bytes 0") {
		t.Fatalf("default-label overflow error = %v", err)
	}

	r = NewReader([]byte{0x02, 0x40, 0x40})
	if got := r.ReadVarintVector(); got != nil {
		t.Fatalf("vector with missing element decoded as %v", got)
	}
	if err := r.Err(); err == nil {
		t.Fatalf("vector with missing element unexpectedly succeeded")
	}
}

func equalUint64s(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func opaqueBoundaryPayload(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*31 + 17) & 0xff)
	}
	return out
}

func assertOpaquePayloadShape(t *testing.T, label string, got, want []byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s length = %d, want %d", label, len(got), len(want))
	}
	if len(want) <= 0xffff {
		if !bytes.Equal(got, want) {
			t.Fatalf("%s mismatch", label)
		}
		return
	}
	for _, idx := range []int{0, len(want) / 2, len(want) - 1} {
		if got[idx] != want[idx] {
			t.Fatalf("%s[%d] = %x, want %x", label, idx, got[idx], want[idx])
		}
	}
}
