package transport

import (
	"bytes"
	"testing"
)

func FuzzRecordReader(f *testing.F) {
	f.Add([]byte{0, 0, 1, 0x01})
	f.Add([]byte{0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		reader, err := NewRecordReader(bytes.NewReader(data), 4096)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = reader.Read()
	})
}

func FuzzRecordRoundTrip(f *testing.F) {
	f.Add([]byte{0x01, 0x02, 0x03})
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) == 0 || len(body) > 4096 {
			return
		}
		var encoded bytes.Buffer
		writer, err := NewRecordWriter(&encoded, 4096)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		reader, err := NewRecordReader(bytes.NewReader(encoded.Bytes()), 4096)
		if err != nil {
			t.Fatal(err)
		}
		got, err := reader.Read()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("round trip = %x, want %x", got, body)
		}
	})
}
