package protocol

import (
	"strings"
	"testing"
)

func TestBootstrapValidateStructuralAcceptsFuzzSamples(t *testing.T) {
	cases := []struct {
		name     string
		validate func() error
	}{
		{"CoverPrelude0", func() error { return fuzzSampleCoverPrelude0().ValidateStructural() }},
		{"CoverPrelude1", func() error { return fuzzSampleCoverPrelude1().ValidateStructural() }},
		{"CoverCapsule1Plain", func() error { return fuzzSampleCoverCapsule1Plain().ValidateStructural(15, false) }},
		{"CoverCapsule2Plain", func() error { return fuzzSampleCoverCapsule2Plain().ValidateStructural() }},
		{"RouteCapsule1Plain", func() error { return fuzzSampleRouteCapsule1Plain().ValidateStructural(15, false) }},
		{"RouteCapsule2Plain", func() error { return fuzzSampleRouteCapsule2Plain().ValidateStructural() }},
		{"RoutePrelude1", func() error { return fuzzSampleRoutePrelude1().ValidateStructural() }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.validate(); err != nil {
				t.Fatalf("valid %s rejected: %v", tt.name, err)
			}
		})
	}
}

func TestBootstrapValidateStructuralRejectsUnknownCriticalExtensions(t *testing.T) {
	critical := []Extension{{ExtensionType: 0x4001, Critical: true, Body: []byte{0x01}}}
	cases := []struct {
		name     string
		validate func() error
	}{
		{"CoverPrelude0", func() error {
			v := fuzzSampleCoverPrelude0()
			v.Extensions = critical
			return v.ValidateStructural()
		}},
		{"CoverPrelude1", func() error {
			v := fuzzSampleCoverPrelude1()
			v.Extensions = critical
			return v.ValidateStructural()
		}},
		{"CoverCapsule1Plain", func() error {
			v := fuzzSampleCoverCapsule1Plain()
			v.Extensions = critical
			return v.ValidateStructural(15, false)
		}},
		{"CoverCapsule2Plain", func() error {
			v := fuzzSampleCoverCapsule2Plain()
			v.Extensions = critical
			return v.ValidateStructural()
		}},
		{"RouteCapsule1Plain", func() error {
			v := fuzzSampleRouteCapsule1Plain()
			v.Extensions = critical
			return v.ValidateStructural(15, false)
		}},
		{"RouteCapsule2Plain", func() error {
			v := fuzzSampleRouteCapsule2Plain()
			v.Extensions = critical
			return v.ValidateStructural()
		}},
		{"RoutePrelude1", func() error {
			v := fuzzSampleRoutePrelude1()
			v.Extensions = critical
			return v.ValidateStructural()
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.validate()
			if err == nil {
				t.Fatalf("unknown critical extension accepted by %s", tt.name)
			}
			if !strings.Contains(err.Error(), "critical extension") {
				t.Fatalf("%s error = %v, want critical extension failure", tt.name, err)
			}
		})
	}
}

func TestClientTransportHintsValidatePrototypeRejectsUnknownCriticalExtension(t *testing.T) {
	hints := fuzzSampleClientTransportHints()
	hints.Extensions = []Extension{{ExtensionType: 0x4001, Critical: true, Body: []byte{0x01}}}
	err := hints.ValidatePrototype()
	if err == nil {
		t.Fatalf("unknown critical ClientTransportHints extension accepted")
	}
	if !strings.Contains(err.Error(), "critical extension") {
		t.Fatalf("ClientTransportHints error = %v, want critical extension failure", err)
	}
}
