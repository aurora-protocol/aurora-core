package session

import (
	"errors"
	"testing"
)

func TestApplicationDoneTracksIdempotentShutdown(t *testing.T) {
	application, err := NewApplication(testApplicationConfig())
	if err != nil {
		t.Fatal(err)
	}
	done := application.Done()
	if done == nil {
		t.Fatal("Done returned a nil channel")
	}
	select {
	case <-done:
		t.Fatal("Done closed while the application was active")
	default:
	}
	if err := application.Err(); err != nil {
		t.Fatalf("Err while active = %v, want nil", err)
	}

	if err := application.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
	select {
	case <-done:
	default:
		t.Fatal("Done remained open after Close")
	}
	if application.Done() != done {
		t.Fatal("Done returned a different channel after Close")
	}
	if err := application.Err(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Err after Close = %v, want %v", err, ErrClosed)
	}
	if err := application.Close(); err != nil {
		t.Fatalf("second Close error = %v", err)
	}
}
