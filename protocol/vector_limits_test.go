package protocol

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/wire"
)

func encodeVarint(t *testing.T, v uint64) []byte {
	t.Helper()
	b, err := wire.AppendVarint(nil, v)
	if err != nil {
		t.Fatalf("AppendVarint(%d): %v", v, err)
	}
	return b
}

func TestReadVectorCountWithMinimumAccepts(t *testing.T) {
	payload := append(encodeVarint(t, 3), make([]byte, 30)...)
	r := wire.NewReader(payload)
	count := readVectorCountWithMinimum(r, "test-vector", 10)
	if r.Err() != nil {
		t.Fatalf("unexpected error: %v", r.Err())
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestReadVectorCountWithMinimumRejectsExceedingRemaining(t *testing.T) {
	payload := append(encodeVarint(t, 5), make([]byte, 10)...)
	r := wire.NewReader(payload)
	count := readVectorCountWithMinimum(r, "test-vector", 4)
	if r.Err() == nil {
		t.Fatalf("expected error for count exceeding remaining bytes, got count=%d", count)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0 on error", count)
	}
}

func TestReadVectorCountWithMinimumRejectsZeroItemBytes(t *testing.T) {
	payload := append(encodeVarint(t, 1), make([]byte, 10)...)
	r := wire.NewReader(payload)
	count := readVectorCountWithMinimum(r, "test-vector", 0)
	if r.Err() == nil {
		t.Fatalf("expected error for invalid minimum item bytes, got count=%d", count)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0 on error", count)
	}
}

func TestReadVectorCountWithMinimumAcceptsExactFit(t *testing.T) {
	payload := append(encodeVarint(t, 3), make([]byte, 9)...)
	r := wire.NewReader(payload)
	count := readVectorCountWithMinimum(r, "test-vector", 3)
	if r.Err() != nil {
		t.Fatalf("unexpected error: %v", r.Err())
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestReadVectorCountWithMinimumPropagatesWireError(t *testing.T) {
	r := wire.NewReader(nil)
	count := readVectorCountWithMinimum(r, "test-vector", 10)
	if r.Err() == nil {
		t.Fatalf("expected wire error for empty input, got count=%d", count)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0 on error", count)
	}
}
