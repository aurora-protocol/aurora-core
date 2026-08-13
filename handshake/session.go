package handshake

import (
	"crypto/subtle"
	"fmt"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
)

type State uint8

const (
	StateLoadDescriptor State = iota
	StateOpenCover
	StateSendCoverPrelude0
	StateVerifyCoverPrelude1
	StateSendCoverCapsule1
	StateVerifyCoverCapsule2
	StateApplicationReady
	StateAborted
)

type ClientSession struct {
	state State
}

func NewClientSession() *ClientSession {
	return &ClientSession{state: StateLoadDescriptor}
}

func (s *ClientSession) State() State {
	return s.state
}

func (s *ClientSession) MarkDescriptorLoaded() error {
	if s.state != StateLoadDescriptor {
		return fmt.Errorf("handshake: cannot load descriptor from state %d", s.state)
	}
	s.state = StateOpenCover
	return nil
}

func (s *ClientSession) MarkCoverOpened() error {
	if s.state != StateOpenCover {
		return fmt.Errorf("handshake: cannot open cover from state %d", s.state)
	}
	s.state = StateSendCoverPrelude0
	return nil
}

func (s *ClientSession) MarkCoverPrelude0Sent() error {
	if s.state != StateSendCoverPrelude0 {
		return fmt.Errorf("handshake: cannot send CoverPrelude0 from state %d", s.state)
	}
	s.state = StateVerifyCoverPrelude1
	return nil
}

func (s *ClientSession) VerifyCoverPrelude1(in CoverPreludeVerificationInput) ([]byte, error) {
	if s.state != StateVerifyCoverPrelude1 {
		return nil, fmt.Errorf("handshake: cannot verify CoverPrelude1 from state %d", s.state)
	}
	transcript, err := VerifyCoverPrelude1Signatures(in)
	if err != nil {
		s.state = StateAborted
		return nil, err
	}
	s.state = StateSendCoverCapsule1
	return transcript, nil
}

func (s *ClientSession) BuildCoverCapsule1(c protocol.CoverCapsule1Plain) (protocol.CoverCapsule1Plain, error) {
	if s.state != StateSendCoverCapsule1 {
		return protocol.CoverCapsule1Plain{}, fmt.Errorf("handshake: CoverPrelude1 not verified")
	}
	s.state = StateVerifyCoverCapsule2
	return c, nil
}

func (s *ClientSession) VerifyCoverCapsule2(c protocol.CoverCapsule2Plain, expectedServerFinished []byte) error {
	if s.state != StateVerifyCoverCapsule2 {
		return fmt.Errorf("handshake: cannot verify CoverCapsule2 from state %d", s.state)
	}
	if err := c.ValidateStructural(); err != nil {
		s.state = StateAborted
		return err
	}
	if len(c.ServerFinished) == 0 || subtle.ConstantTimeCompare(c.ServerFinished, expectedServerFinished) != 1 {
		s.state = StateAborted
		return fmt.Errorf("handshake: server finished mismatch")
	}
	s.state = StateApplicationReady
	return nil
}

type RelaySession struct {
	hintCache *admission.MemoryReplayCache
}

func NewRelaySession(hintCache *admission.MemoryReplayCache) *RelaySession {
	if hintCache == nil {
		hintCache = admission.NewMemoryReplayCache()
	}
	return &RelaySession{hintCache: hintCache}
}

func (s *RelaySession) AcceptCoverPrelude0(p0 protocol.CoverPrelude0, cred admission.AccessHintCredential, bindingContext []byte, p1 protocol.CoverPrelude1) (protocol.CoverPrelude1, error) {
	return s.AcceptCoverPrelude0At(p0, cred, bindingContext, p1, 0, 0)
}

func (s *RelaySession) AcceptCoverPrelude0At(p0 protocol.CoverPrelude0, cred admission.AccessHintCredential, bindingContext []byte, p1 protocol.CoverPrelude1, nowUnix, relayEpochValidUntilUnix uint64) (protocol.CoverPrelude1, error) {
	if err := p0.ValidateStructural(); err != nil {
		return protocol.CoverPrelude1{}, err
	}
	if err := ValidatePrelude0ClientHybridShares(p0); err != nil {
		return protocol.CoverPrelude1{}, err
	}
	if err := admission.VerifyAndSpendAccessHintAt(s.hintCache, cred, bindingContext, p0.ClientNonce, p0.AccessHint, nowUnix, relayEpochValidUntilUnix); err != nil {
		return protocol.CoverPrelude1{}, err
	}
	return p1, nil
}
