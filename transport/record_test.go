package transport

import (
	"bytes"
	"errors"
	"io"
	"sort"
	"sync"
	"testing"
)

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}

type oneByteReader struct {
	r io.Reader
}

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}

type prefixOnlyReader struct {
	prefix []byte
	reads  int
}

type partialRecordReader struct {
	prefix   []byte
	body     []byte
	reads    int
	retained []byte
}

type typedNilReader struct{}

func (*typedNilReader) Read([]byte) (int, error) {
	return 0, io.EOF
}

type typedNilWriter struct{}

func (*typedNilWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (r *prefixOnlyReader) Read(p []byte) (int, error) {
	r.reads++
	if r.reads > 1 {
		return 0, errors.New("unexpected body read")
	}
	return copy(p, r.prefix), nil
}

func (r *partialRecordReader) Read(p []byte) (int, error) {
	r.reads++
	if r.reads == 1 {
		return copy(p, r.prefix), nil
	}
	r.retained = p
	return copy(p, r.body), io.ErrUnexpectedEOF
}

func TestRecordWriterUsesThreeByteBigEndianPrefix(t *testing.T) {
	var out bytes.Buffer
	w, err := NewRecordWriter(&out, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if got, want := out.Bytes(), []byte{0, 0, 3, 'a', 'b', 'c'}; !bytes.Equal(got, want) {
		t.Fatalf("encoded record = %x, want %x", got, want)
	}
}

func TestRecordReaderHandlesOneByteAtATimeFragmentedReads(t *testing.T) {
	encoded := append([]byte{0, 0, 3}, []byte("one")...)
	encoded = append(encoded, append([]byte{0, 0, 3}, []byte("two")...)...)
	r, err := NewRecordReader(oneByteReader{r: bytes.NewReader(encoded)}, 16)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"one", "two"} {
		got, err := r.Read()
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("record = %q, want %q", got, want)
		}
	}
}

func TestRecordWriterRetriesShortWrites(t *testing.T) {
	out := &shortWriter{}
	w, err := NewRecordWriter(out, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	if got, want := out.Bytes(), []byte{0, 0, 5, 's', 'h', 'o', 'r', 't'}; !bytes.Equal(got, want) {
		t.Fatalf("encoded record = %x, want %x", got, want)
	}
}

func TestRecordReaderRejectsInvalidLengthsBeforeBodyRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix []byte
		max    uint32
	}{
		{name: "empty", prefix: []byte{0, 0, 0}, max: 16},
		{name: "over limit", prefix: []byte{0, 0, 17}, max: 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := &prefixOnlyReader{prefix: tc.prefix}
			r, err := NewRecordReader(input, tc.max)
			if err != nil {
				t.Fatal(err)
			}
			_, err = r.Read()
			want := ErrEmptyRecord
			if tc.name == "over limit" {
				want = ErrRecordTooLarge
			}
			if err != want {
				t.Fatalf("Read error = %v, want %v", err, want)
			}
			if input.reads != 1 {
				t.Fatalf("reader was called %d times, want only the prefix read", input.reads)
			}
		})
	}
}

func TestRecordReaderZeroesPartiallyReadBodyOnFailure(t *testing.T) {
	input := &partialRecordReader{
		prefix: []byte{0, 0, 8},
		body:   []byte("secr"),
	}
	reader, err := NewRecordReader(input, 16)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Read error = %v, want io.ErrUnexpectedEOF", err)
	}
	if len(input.retained) != 8 {
		t.Fatalf("retained body length = %d, want 8", len(input.retained))
	}
	for _, value := range input.retained {
		if value != 0 {
			t.Fatal("RecordReader retained partially read body bytes")
		}
	}
}

func TestNewRecordRejectsInvalidReadersWritersAndMaximums(t *testing.T) {
	if _, err := NewRecordReader(nil, 16); err == nil {
		t.Fatal("NewRecordReader(nil, ...) returned nil error")
	}
	if _, err := NewRecordWriter(nil, 16); err == nil {
		t.Fatal("NewRecordWriter(nil, ...) returned nil error")
	}
	if _, err := NewRecordReader(bytes.NewReader(nil), 0xffffff+1); err == nil {
		t.Fatal("NewRecordReader accepted a maximum above unsigned-24")
	}
	if _, err := NewRecordWriter(&bytes.Buffer{}, 0xffffff+1); err == nil {
		t.Fatal("NewRecordWriter accepted a maximum above unsigned-24")
	}
}

func TestNewRecordRejectsTypedNilReader(t *testing.T) {
	var reader *typedNilReader
	if _, err := NewRecordReader(reader, 16); err == nil {
		t.Fatal("NewRecordReader accepted a typed-nil reader")
	}
}

func TestNewRecordRejectsTypedNilWriter(t *testing.T) {
	var writer *typedNilWriter
	if _, err := NewRecordWriter(writer, 16); err == nil {
		t.Fatal("NewRecordWriter accepted a typed-nil writer")
	}
}

func TestRecordReaderAndWriterNormalizeZeroMaximum(t *testing.T) {
	var out bytes.Buffer
	w, err := NewRecordWriter(&out, 0)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte{0x5a}, int(DefaultMaxRecordBodyBytes))
	if err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	r, err := NewRecordReader(bytes.NewReader(out.Bytes()), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("zero maximum did not normalize to the default maximum")
	}
}

func TestRecordReadReturnsOwnedSlicesAndWriteDoesNotRetainInput(t *testing.T) {
	first := []byte("first")
	second := []byte("second")
	var out bytes.Buffer
	w, err := NewRecordWriter(&out, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(first); err != nil {
		t.Fatal(err)
	}
	first[0] = 'X'
	if err := w.Write(second); err != nil {
		t.Fatal(err)
	}
	r, err := NewRecordReader(bytes.NewReader(out.Bytes()), 16)
	if err != nil {
		t.Fatal(err)
	}
	gotFirst, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	gotFirst[0] = 'X'
	gotSecond, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	if string(gotSecond) != "second" {
		t.Fatalf("second record changed after mutating first result: %q", gotSecond)
	}
	if string(out.Bytes()[3:8]) != "first" {
		t.Fatalf("writer retained mutable input: %q", out.Bytes()[3:8])
	}
}

func TestRecordWriterSerializesConcurrentWritesAsIntactRecords(t *testing.T) {
	var out bytes.Buffer
	w, err := NewRecordWriter(&out, 64)
	if err != nil {
		t.Fatal(err)
	}
	const count = 32
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		body := []byte{byte(i), byte(i ^ 0xff), byte(i + 1)}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- w.Write(body)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	r, err := NewRecordReader(bytes.NewReader(out.Bytes()), 64)
	if err != nil {
		t.Fatal(err)
	}
	got := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		body, err := r.Read()
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, body)
	}
	if _, err := r.Read(); err != io.EOF {
		t.Fatalf("reading after concurrent records returned %v, want io.EOF", err)
	}
	sort.Slice(got, func(i, j int) bool { return bytes.Compare(got[i], got[j]) < 0 })
	for i, body := range got {
		want := []byte{byte(i), byte(i ^ 0xff), byte(i + 1)}
		if !bytes.Equal(body, want) {
			t.Fatalf("sorted record %d = %x, want %x", i, body, want)
		}
	}
}

func TestRecordRejectsEmptyAndOverLimitBodies(t *testing.T) {
	var out bytes.Buffer
	w, err := NewRecordWriter(&out, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(nil); err != ErrEmptyRecord {
		t.Fatalf("empty write error = %v, want %v", err, ErrEmptyRecord)
	}
	if err := w.Write([]byte{1, 2, 3}); err != ErrRecordTooLarge {
		t.Fatalf("oversized write error = %v, want %v", err, ErrRecordTooLarge)
	}
	if out.Len() != 0 {
		t.Fatalf("invalid writes emitted %d bytes", out.Len())
	}
}
