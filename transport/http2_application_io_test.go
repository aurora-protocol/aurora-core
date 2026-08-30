package transport

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

type trackingHTTP2ReadCloser struct {
	*bytes.Reader
	closeErr   error
	closeCalls int
}

func (r *trackingHTTP2ReadCloser) Close() error {
	r.closeCalls++
	return r.closeErr
}

func TestHTTP2ApplicationReaderForwardsReadAndClose(t *testing.T) {
	closeErr := errors.New("reader close failed")
	body := &trackingHTTP2ReadCloser{
		Reader:   bytes.NewReader([]byte("packet")),
		closeErr: closeErr,
	}
	reader := &http2ApplicationReader{body: body}

	buffer := make([]byte, len("packet"))
	n, err := io.ReadFull(reader, buffer)
	if err != nil {
		t.Fatalf("ReadFull error = %v", err)
	}
	if n != len(buffer) || !bytes.Equal(buffer, []byte("packet")) {
		t.Fatalf("ReadFull = %d, %q", n, buffer)
	}
	if err := reader.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close error = %v, want %v", err, closeErr)
	}
	if body.closeCalls != 1 {
		t.Fatalf("body close calls = %d, want 1", body.closeCalls)
	}
}

func TestHTTP2ApplicationWriterClosesPipeAfterForwardedWrite(t *testing.T) {
	pipeReader, pipeWriter := io.Pipe()
	t.Cleanup(func() { _ = pipeReader.Close() })
	writer := &http2ApplicationWriter{pipe: pipeWriter}
	result := make(chan struct {
		body []byte
		err  error
	}, 1)
	go func() {
		body, err := io.ReadAll(pipeReader)
		result <- struct {
			body []byte
			err  error
		}{body: body, err: err}
	}()

	if n, err := writer.Write([]byte("packet")); err != nil || n != len("packet") {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("pipe read error = %v", got.err)
		}
		if !bytes.Equal(got.body, []byte("packet")) {
			t.Fatalf("pipe body = %q, want packet", got.body)
		}
	case <-time.After(time.Second):
		t.Fatal("writer Close did not finish the pipe read")
	}
}
