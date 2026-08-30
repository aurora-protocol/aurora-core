package packet

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestAcknowledgesCompletedKeyUpdateDecidesPerCondition(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DirectionState, *protocol.KeyUpdateACK)
		want   bool
	}{
		{name: "matching completed update", want: true},
		{
			name: "maximum canonical nonce length",
			mutate: func(_ *DirectionState, ack *protocol.KeyUpdateACK) {
				ack.AckNonce = make([]byte, maxOpaque16Bytes)
			},
			want: true,
		},
		{
			name: "update still pending",
			mutate: func(state *DirectionState, _ *protocol.KeyUpdateACK) {
				state.pendingSentUpdateActive = true
			},
		},
		{
			name: "initial key phase",
			mutate: func(state *DirectionState, _ *protocol.KeyUpdateACK) {
				state.KeyPhase = 0
			},
		},
		{
			name: "route mismatch",
			mutate: func(_ *DirectionState, ack *protocol.KeyUpdateACK) {
				ack.RouteInstanceID++
			},
		},
		{
			name: "hop mismatch",
			mutate: func(_ *DirectionState, ack *protocol.KeyUpdateACK) {
				ack.HopLayer++
			},
		},
		{
			name: "direction mismatch",
			mutate: func(_ *DirectionState, ack *protocol.KeyUpdateACK) {
				ack.AckedDirection++
			},
		},
		{
			name: "phase mismatch",
			mutate: func(_ *DirectionState, ack *protocol.KeyUpdateACK) {
				ack.AckedKeyPhase++
			},
		},
		{
			name: "nonce exceeds opaque16 range",
			mutate: func(_ *DirectionState, ack *protocol.KeyUpdateACK) {
				ack.AckNonce = make([]byte, maxOpaque16Bytes+1)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := transactionalDirectionState()
			state.KeyPhase = 1
			ack := protocol.KeyUpdateACK{
				RouteInstanceID: state.RouteInstanceID,
				HopLayer:        state.HopLayer,
				AckedDirection:  state.Direction,
				AckedKeyPhase:   state.KeyPhase,
				AckNonce:        bytesOf(0xa2, 16),
			}
			if test.mutate != nil {
				test.mutate(&state, &ack)
			}

			if got := state.AcknowledgesCompletedKeyUpdate(ack); got != test.want {
				t.Fatalf("AcknowledgesCompletedKeyUpdate() = %t, want %t", got, test.want)
			}
		})
	}
}
