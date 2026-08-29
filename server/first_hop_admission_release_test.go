package server

import (
	"context"
	"fmt"
	"testing"
)

// An admission callback that reports an error while still handing back a
// permit must not leak that permit: the slot would stay taken for the life of
// the process, so a handful of rejected requests would exhaust the session
// limit and lock every later client out.
func TestAcquireSessionAdmissionReleasesPermitsRejectedWithAnError(t *testing.T) {
	released := 0
	handler := &FirstHopHandler{
		sessionAdmission: func(context.Context) (func(), error) {
			return func() { released++ }, fmt.Errorf("server: admission rejected")
		},
	}
	release, admitted := handler.acquireSessionAdmission(context.Background())
	if admitted || release != nil {
		t.Fatalf("rejected admission was admitted (release != nil: %t)", release != nil)
	}
	if released != 1 {
		t.Fatalf("permit releases = %d, want the rejected permit released once", released)
	}
}

func TestAcquireSessionAdmissionPassesThroughWhenUnconfigured(t *testing.T) {
	release, admitted := (&FirstHopHandler{}).acquireSessionAdmission(context.Background())
	if !admitted || release != nil {
		t.Fatalf("unconfigured admission = (%t, release != nil: %t), want admitted with no permit", admitted, release != nil)
	}
}

func TestAcquireSessionAdmissionReturnsTheGrantedPermit(t *testing.T) {
	released := 0
	handler := &FirstHopHandler{
		sessionAdmission: func(context.Context) (func(), error) {
			return func() { released++ }, nil
		},
	}
	release, admitted := handler.acquireSessionAdmission(context.Background())
	if !admitted || release == nil {
		t.Fatal("granted admission did not return its permit")
	}
	release()
	if released != 1 {
		t.Fatalf("permit releases = %d, want one", released)
	}
}
