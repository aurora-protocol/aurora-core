package transport

import (
	"errors"
	"io"
	"reflect"
	"sync"

	"github.com/aurora-protocol/aurora-core/wire"
)

const DefaultMaxRecordBodyBytes uint32 = wire.DefaultRecordBodyBytes

var (
	ErrEmptyRecord    = errors.New("transport: empty record")
	ErrRecordTooLarge = errors.New("transport: record too large")
)

const maxRecordBodyBytes uint32 = 0xffffff

var (
	errInvalidRecordMaximum = errors.New("transport: record maximum exceeds unsigned-24 limit")
	errNilRecordReader      = errors.New("transport: nil record reader")
	errNilRecordWriter      = errors.New("transport: nil record writer")
)

type RecordReader struct {
	r   io.Reader
	max uint32
}

type RecordWriter struct {
	mu  sync.Mutex
	w   io.Writer
	max uint32
}

func NewRecordReader(r io.Reader, max uint32) (*RecordReader, error) {
	max, err := normalizeRecordMaximum(max)
	if err != nil {
		return nil, err
	}
	if isNilLike(r) {
		return nil, errNilRecordReader
	}
	return &RecordReader{r: r, max: max}, nil
}

func (r *RecordReader) Read() ([]byte, error) {
	var prefix [3]byte
	if _, err := io.ReadFull(r.r, prefix[:]); err != nil {
		return nil, err
	}
	length := uint32(prefix[0])<<16 | uint32(prefix[1])<<8 | uint32(prefix[2])
	if length == 0 {
		return nil, ErrEmptyRecord
	}
	if length > r.max {
		return nil, ErrRecordTooLarge
	}
	body := make([]byte, int(length))
	if _, err := io.ReadFull(r.r, body); err != nil {
		return nil, err
	}
	return body, nil
}

func NewRecordWriter(w io.Writer, max uint32) (*RecordWriter, error) {
	max, err := normalizeRecordMaximum(max)
	if err != nil {
		return nil, err
	}
	if isNilLike(w) {
		return nil, errNilRecordWriter
	}
	return &RecordWriter{w: w, max: max}, nil
}

func (w *RecordWriter) Write(body []byte) error {
	if len(body) == 0 {
		return ErrEmptyRecord
	}
	if uint64(len(body)) > uint64(w.max) {
		return ErrRecordTooLarge
	}
	prefix := [3]byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}

	w.mu.Lock()
	defer w.mu.Unlock()
	if err := writeRecordBytes(w.w, prefix[:]); err != nil {
		return err
	}
	return writeRecordBytes(w.w, body)
}

func normalizeRecordMaximum(max uint32) (uint32, error) {
	if max == 0 {
		max = DefaultMaxRecordBodyBytes
	}
	if max > maxRecordBodyBytes {
		return 0, errInvalidRecordMaximum
	}
	return max, nil
}

func isNilLike(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func writeRecordBytes(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
