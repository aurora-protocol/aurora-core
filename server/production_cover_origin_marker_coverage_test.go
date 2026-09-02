package server

// Coverage for the productionFirstHopCoverOrigin marker method
// (cover_origin.go:37). It is the unexported interface seal that distinguishes
// ProductionCoverOrigin from a plain CoverOrigin; no existing test invokes it
// directly. The test constructs a production origin through the public
// constructor and asserts the marker seals the concrete type.

import (
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestProductionCoverOriginMarkerSealsProductionConstructor(t *testing.T) {
	target := httptest.NewServer(nil)
	defer target.Close()
	parsed, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := NewProductionReverseProxyCoverOrigin(parsed)
	if err != nil {
		t.Fatal(err)
	}
	sealed, ok := origin.(productionCoverOrigin)
	if !ok {
		t.Fatalf("NewProductionReverseProxyCoverOrigin returned %T, want productionCoverOrigin", origin)
	}
	sealed.productionFirstHopCoverOrigin()

	plain, err := NewReverseProxyCoverOrigin(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plain.(ProductionCoverOrigin); ok {
		t.Fatalf("NewReverseProxyCoverOrigin returned %T, which must not satisfy ProductionCoverOrigin", plain)
	}
}
