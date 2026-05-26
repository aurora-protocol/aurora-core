package protocol

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestPolicyOfferValidateStructuralRejectsReservedRegistryIDs(t *testing.T) {
	valid := samplePolicyOffer()
	if err := valid.ValidateStructural(); err != nil {
		t.Fatalf("valid policy offer rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*PolicyOffer)
		want   string
	}{
		{
			name:   "offered version",
			mutate: func(p *PolicyOffer) { p.OfferedVersions = []uint64{0x000201} },
			want:   "version",
		},
		{
			name:   "offered suite",
			mutate: func(p *PolicyOffer) { p.OfferedSuites = []uint64{0x4000} },
			want:   "suite",
		},
		{
			name:   "offered method",
			mutate: func(p *PolicyOffer) { p.OfferedMethods = []uint64{0x2003} },
			want:   "method",
		},
		{
			name:   "minimum policy",
			mutate: func(p *PolicyOffer) { p.MinimumPolicyID = 0x06 },
			want:   "policy",
		},
		{
			name:   "requested policy",
			mutate: func(p *PolicyOffer) { p.RequestedPolicyID = 0x06 },
			want:   "policy",
		},
		{
			name:   "requested route",
			mutate: func(p *PolicyOffer) { p.RequestedRouteModeID = 0x06 },
			want:   "route",
		},
		{
			name:   "requested shape",
			mutate: func(p *PolicyOffer) { p.RequestedShapeID = 0x05 },
			want:   "shape",
		},
		{
			name:   "tunnel personality offer",
			mutate: func(p *PolicyOffer) { p.TunnelPersonalityOffers = []uint64{0x04} },
			want:   "tunnel personality",
		},
		{
			name:   "critical extension",
			mutate: func(p *PolicyOffer) { p.Extensions = []Extension{{ExtensionType: 0x7001, Critical: true}} },
			want:   "critical extension",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			offer := valid
			tt.mutate(&offer)
			err := offer.ValidateStructural()
			if err == nil {
				t.Fatalf("reserved %s accepted", tt.name)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("reserved %s error = %v, want to mention %q", tt.name, err, tt.want)
			}
		})
	}
}

func TestPolicyAcceptValidateStructuralRejectsReservedRegistryIDs(t *testing.T) {
	valid := samplePolicyAccept()
	if err := valid.ValidateStructural(); err != nil {
		t.Fatalf("valid policy accept rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*PolicyAccept)
		want   string
	}{
		{
			name:   "selected version",
			mutate: func(p *PolicyAccept) { p.SelectedVersion = 0x000201 },
			want:   "version",
		},
		{
			name:   "selected suite",
			mutate: func(p *PolicyAccept) { p.SelectedSuite = 0x4000 },
			want:   "suite",
		},
		{
			name:   "selected method",
			mutate: func(p *PolicyAccept) { p.SelectedMethod = 0x2003 },
			want:   "method",
		},
		{
			name:   "selected policy",
			mutate: func(p *PolicyAccept) { p.SelectedPolicy = 0x06 },
			want:   "policy",
		},
		{
			name:   "selected route",
			mutate: func(p *PolicyAccept) { p.SelectedRouteModeID = 0x06 },
			want:   "route",
		},
		{
			name:   "selected shape",
			mutate: func(p *PolicyAccept) { p.SelectedShape = 0x05 },
			want:   "shape",
		},
		{
			name:   "tunnel personality",
			mutate: func(p *PolicyAccept) { p.SelectedTunnelPersonality = 0x04 },
			want:   "tunnel personality",
		},
		{
			name:   "fallback method",
			mutate: func(p *PolicyAccept) { p.FallbackMethods = []uint64{registry.MethodWebH1WS, 0x2003} },
			want:   "method",
		},
		{
			name:   "critical extension",
			mutate: func(p *PolicyAccept) { p.Extensions = []Extension{{ExtensionType: 0x7001, Critical: true}} },
			want:   "critical extension",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			accept := valid
			tt.mutate(&accept)
			err := accept.ValidateStructural()
			if err == nil {
				t.Fatalf("reserved %s accepted", tt.name)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("reserved %s error = %v, want to mention %q", tt.name, err, tt.want)
			}
		})
	}
}
