package wire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestBoolRoundTrip covers WriteBool/ReadBool, including the malformed-bool
// rejection path and the after-error short-circuit that TestOpaqueAndScalars
// does not exercise.
func TestBoolRoundTrip(t *testing.T) {
	e := NewEncoder()
	e.WriteBool(true)
	e.WriteBool(false)
	got, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x01, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("bool encode = %x, want %x", got, want)
	}

	r := NewReader(got)
	if v := r.ReadBool(); !v || r.Err() != nil {
		t.Fatalf("ReadBool(true) = %v, err %v", v, r.Err())
	}
	if v := r.ReadBool(); v || r.Err() != nil {
		t.Fatalf("ReadBool(false) = %v, err %v", v, r.Err())
	}
	if !r.EOF() {
		t.Fatalf("reader did not finish: remaining=%d", r.Remaining())
	}

	// A bool byte outside {0,1} is rejected and poisons the reader so a
	// subsequent ReadBool returns false without consuming another byte.
	r = NewReader([]byte{0x02})
	if v := r.ReadBool(); v {
		t.Fatalf("malformed bool decoded as true")
	}
	if err := r.Err(); err == nil || !strings.Contains(err.Error(), "malformed bool 2") {
		t.Fatalf("malformed bool err = %v", err)
	}
	if v := r.ReadBool(); v {
		t.Fatalf("ReadBool after error returned true")
	}
}

// TestOpaqueFixedAndView covers WriteOpaqueFixed (happy + length-mismatch
// rejection) and ReadOpaqueFixedView (borrowed view + short read).
func TestOpaqueFixedAndView(t *testing.T) {
	payload := []byte{0x10, 0x20, 0x30, 0x40}

	e := NewEncoder()
	e.WriteOpaqueFixed(payload, 4)
	got, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("WriteOpaqueFixed = %x, want %x", got, payload)
	}

	r := NewReader(got)
	view := r.ReadOpaqueFixedView(4)
	if err := r.Err(); err != nil {
		t.Fatalf("ReadOpaqueFixedView: %v", err)
	}
	if !bytes.Equal(view, payload) {
		t.Fatalf("ReadOpaqueFixedView = %x, want %x", view, payload)
	}
	// A view aliases the input buffer (no copy): same backing array element.
	if len(view) == 0 || &view[0] != &got[0] {
		t.Fatalf("ReadOpaqueFixedView did not alias input")
	}
	if !r.EOF() {
		t.Fatalf("reader did not finish: remaining=%d", r.Remaining())
	}

	// Length mismatch is rejected before any bytes are written.
	e = NewEncoder()
	e.WriteOpaqueFixed([]byte{0x11, 0x22}, 4)
	if _, err := e.Bytes(); err == nil {
		t.Fatal("WriteOpaqueFixed length mismatch unexpectedly succeeded")
	}

	// Short read on a fixed view sets an error and returns nil.
	r = NewReader([]byte{0x01, 0x02})
	if v := r.ReadOpaqueFixedView(4); v != nil {
		t.Fatalf("short fixed view = %x, want nil", v)
	}
	if err := r.Err(); err == nil {
		t.Fatal("short fixed view unexpectedly succeeded")
	}
}

// TestOpaque32And24View covers WriteOpaque32 (no ReadOpaque32 exists, so the
// 4-byte length prefix is decoded explicitly) and ReadOpaque24View (borrowed).
func TestOpaque32And24View(t *testing.T) {
	payload := []byte{0xa1, 0xa2, 0xa3}

	// WriteOpaque32 emits a 4-byte big-endian length prefix then the bytes.
	e := NewEncoder()
	e.WriteOpaque32(payload)
	got, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x00, 0x00, 0x00, 0x03, 0xa1, 0xa2, 0xa3}
	if !bytes.Equal(got, want) {
		t.Fatalf("WriteOpaque32 = %x, want %x", got, want)
	}
	// Round-trip by reading the explicit length prefix then the fixed body.
	r := NewReader(got)
	if n := r.ReadUint32(); n != uint32(len(payload)) {
		t.Fatalf("opaque32 length = %d, want %d", n, len(payload))
	}
	if body := r.ReadOpaqueFixed(len(payload)); !bytes.Equal(body, payload) {
		t.Fatalf("opaque32 body = %x, want %x", body, payload)
	}
	if !r.EOF() {
		t.Fatalf("reader did not finish: remaining=%d", r.Remaining())
	}

	// ReadOpaque24View returns a borrowed view of the opaque24 body (the
	// 3-byte length prefix is consumed first).
	e = NewEncoder()
	e.WriteOpaque24(payload)
	got, err = e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	r = NewReader(got)
	view := r.ReadOpaque24View()
	if err := r.Err(); err != nil {
		t.Fatalf("ReadOpaque24View: %v", err)
	}
	if !bytes.Equal(view, payload) {
		t.Fatalf("ReadOpaque24View = %x, want %x", view, payload)
	}
	if len(view) == 0 || &view[0] != &got[3] {
		t.Fatalf("ReadOpaque24View did not alias body")
	}
	if !r.EOF() {
		t.Fatalf("reader did not finish: remaining=%d", r.Remaining())
	}
}

// TestPreHashRoundTrip covers the 48-byte prehash pair WritePreHash/ReadPreHash.
func TestPreHashRoundTrip(t *testing.T) {
	hash := make([]byte, 48)
	for i := range hash {
		hash[i] = byte(i)
	}
	e := NewEncoder()
	e.WritePreHash(hash)
	got, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 48 {
		t.Fatalf("prehash encoded length = %d, want 48", len(got))
	}
	r := NewReader(got)
	if decoded := r.ReadPreHash(); !bytes.Equal(decoded, hash) {
		t.Fatalf("ReadPreHash = %x, want %x", decoded, hash)
	}
	if !r.EOF() {
		t.Fatalf("reader did not finish: remaining=%d", r.Remaining())
	}

	// A prehash with the wrong length is rejected (delegates to WriteOpaqueFixed).
	e = NewEncoder()
	e.WritePreHash(make([]byte, 47))
	if _, err := e.Bytes(); err == nil {
		t.Fatal("WritePreHash with 47-byte input unexpectedly succeeded")
	}
}

// TestEncodeUint64MatchesWriteUint64 covers the standalone EncodeUint64 helper
// and confirms it agrees with the streaming WriteUint64 encoder.
func TestEncodeUint64MatchesWriteUint64(t *testing.T) {
	for _, v := range []uint64{0, 1, 0x80, 0x0102030405060708, 0xffffffffffffffff} {
		standalone := EncodeUint64(v)
		e := NewEncoder()
		e.WriteUint64(v)
		streamed, err := e.Bytes()
		if err != nil {
			t.Fatalf("WriteUint64(%x): %v", v, err)
		}
		if !bytes.Equal(standalone, streamed) {
			t.Fatalf("EncodeUint64(%x) = %x, want %x", v, standalone, streamed)
		}
		if got := NewReader(standalone).ReadUint64(); got != v {
			t.Fatalf("ReadUint64(%x) = %x, want %x", standalone, got, v)
		}
	}
}

// TestEncoderWithBufferPreservesAndAppends covers NewEncoderWithBuffer and the
// no-copy Buffer() accessor: the seed buffer's contents and storage are
// preserved, and Buffer() shares backing storage with the encoder.
func TestEncoderWithBufferPreservesAndAppends(t *testing.T) {
	pre := make([]byte, 2, 8)
	pre[0], pre[1] = 0xaa, 0xbb
	e := NewEncoderWithBuffer(pre)
	e.WriteUint8(0xcc)
	e.WriteBytes([]byte{0xdd, 0xee})
	got, err := e.Buffer()
	if err != nil {
		t.Fatalf("Buffer: %v", err)
	}
	if want := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}; !bytes.Equal(got, want) {
		t.Fatalf("Buffer() = %x, want %x", got, want)
	}
	// Buffer() shares storage with the seed buffer (no second allocation/copy).
	if len(got) == 0 || &got[0] != &pre[0] {
		t.Fatalf("Buffer() did not share storage with the seed buffer")
	}
}

// TestBufferReturnsErrorAfterEncoderFailure covers Buffer()'s error path and
// the Err() accessor.
func TestBufferReturnsErrorAfterEncoderFailure(t *testing.T) {
	e := NewEncoder()
	e.WriteUint24(0x1000000) // out of range -> SetErr, nothing appended
	if err := e.Err(); err == nil {
		t.Fatal("expected encoder error after out-of-range uint24")
	}
	got, err := e.Buffer()
	if err == nil {
		t.Fatal("Buffer() after error unexpectedly succeeded")
	}
	if got != nil {
		t.Fatalf("Buffer() after error = %x, want nil", got)
	}
}

// TestVarintLenMatchesEncodedLength covers VarintLen across every range
// boundary and its out-of-range error path.
func TestVarintLenMatchesEncodedLength(t *testing.T) {
	for _, v := range []uint64{0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, MaxVarint} {
		n, err := VarintLen(v)
		if err != nil {
			t.Fatalf("VarintLen(%d): %v", v, err)
		}
		enc, err := EncodeVarint(v)
		if err != nil {
			t.Fatalf("EncodeVarint(%d): %v", v, err)
		}
		if n != len(enc) {
			t.Fatalf("VarintLen(%d) = %d, want %d (encoded length)", v, n, len(enc))
		}
	}
	if _, err := VarintLen(MaxVarint + 1); err == nil {
		t.Fatal("VarintLen(MaxVarint+1) unexpectedly succeeded")
	}
}

// TestWriteVarintRejectsOutOfRange covers WriteVarint's AppendVarint error
// branch: an out-of-range value sets the encoder error and appends nothing.
func TestWriteVarintRejectsOutOfRange(t *testing.T) {
	e := NewEncoder()
	e.WriteVarint(MaxVarint + 1)
	if err := e.Err(); err == nil {
		t.Fatal("WriteVarint(MaxVarint+1) unexpectedly succeeded")
	}
	if got := len(e.buf); got != 0 {
		t.Fatalf("buf = %d bytes after rejected varint, want 0", got)
	}
}

// TestEncodeWithReservedCapacityFallsBackOnInvalidBounds covers the
// expectedLength<0 and capacity<expectedLength guards that fall back to Encode
// (no length enforcement).
func TestEncodeWithReservedCapacityFallsBackOnInvalidBounds(t *testing.T) {
	payload := sizedPayload{payload: make([]byte, 1200)}
	for _, tc := range []struct {
		expected, capacity int
	}{{4, 2}, {-1, 0}} {
		got, err := EncodeWithReservedCapacity(payload, tc.expected, tc.capacity)
		if err != nil {
			t.Fatalf("EncodeWithReservedCapacity(%d,%d): %v", tc.expected, tc.capacity, err)
		}
		if len(got) != len(payload.payload) {
			t.Fatalf("EncodeWithReservedCapacity(%d,%d) len = %d, want %d",
				tc.expected, tc.capacity, len(got), len(payload.payload))
		}
	}
}

// TestWritesAreNoOpsAfterEncoderError covers the `if e.err != nil { return }`
// guard on every write method, ensuring a prior error suppresses all further
// writes and preserves the first error.
func TestWritesAreNoOpsAfterEncoderError(t *testing.T) {
	e := NewEncoder()
	e.SetErr(errors.New("seed error"))
	before := len(e.buf)
	e.WriteUint8(0x01)
	e.WriteUint16(0x0203)
	e.WriteUint24(0x040506)
	e.WriteUint32(0x0708090a)
	e.WriteUint64(0x0b0c0d0e0f101112)
	e.WriteBytes([]byte{0x13, 0x14})
	e.WriteVarint(42)
	e.WriteBool(true)
	e.WriteOpaqueFixed([]byte{0x15}, 1)
	e.WriteOpaque8([]byte{0x16})
	if got := len(e.buf); got != before {
		t.Fatalf("buf grew by %d after error, want 0", got-before)
	}
	if err := e.Err(); err == nil || err.Error() != "seed error" {
		t.Fatalf("Err() = %v, want seed error", err)
	}
}

// TestScalarShortReadsSetError covers the short-read error branch of take()
// for every scalar reader and the empty-input branch of ReadVarint.
func TestScalarShortReadsSetError(t *testing.T) {
	cases := []struct {
		name string
		read func(*Reader)
		need int // minimum bytes the reader needs to avoid a short read
	}{
		{"uint8", func(r *Reader) { r.ReadUint8() }, 1},
		{"uint16", func(r *Reader) { r.ReadUint16() }, 2},
		{"uint24", func(r *Reader) { r.ReadUint24() }, 3},
		{"uint32", func(r *Reader) { r.ReadUint32() }, 4},
		{"uint64", func(r *Reader) { r.ReadUint64() }, 8},
		{"varint", func(r *Reader) { r.ReadVarint() }, 1},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReader(make([]byte, tt.need-1))
			tt.read(r)
			if err := r.Err(); err == nil {
				t.Fatalf("%s short read unexpectedly succeeded", tt.name)
			}
		})
	}
}
