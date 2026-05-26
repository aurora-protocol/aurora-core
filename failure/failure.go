package failure

import (
	"bytes"
	"fmt"
)

type Kind uint16

const (
	Unknown Kind = iota
	BadAccessHint
	ReplayedAccessHint
	MalformedPrelude
	WrongSignature
	WrongSuite
	BadAEADTag
	ReplayedAdmission
	MalformedFlowOpen
	MalformedKeyUpdate
	InvalidCoverSlot
	UnsupportedMethod
	PolicyGate
	VerifierUnavailable
	ReplayCacheFailure
	WrongH3Settings
	UnsupportedVersion
	MalformedHybridShare
)

type Action uint8

const (
	CoverOrigin Action = iota + 1
	EncryptedInTunnel
)

type Classification struct {
	Kind         Kind
	Action       Action
	PublicStatus int
	PublicBody   []byte
	CloseCode    uint16
	LogKey       string
}

type ProbeSurface struct {
	HTTPStatus         int
	Body               []byte
	CloseCode          uint16
	TLSAlertClass      uint16
	QUICCloseCode      uint64
	WebSocketCloseCode uint16
	TimingClass        string
	ReflectedLog       string
}

type ProbeCase struct {
	Name string
	Kind Kind
}

func (k Kind) Code() uint16 {
	if k < BadAccessHint || k > MalformedHybridShare {
		return uint16(Unknown)
	}
	return uint16(k)
}

func (k Kind) LogKey() string {
	return fmt.Sprintf("f%04x", k.Code())
}

func Classify(k Kind) Classification {
	if k.Code() == 0 {
		k = Unknown
	}
	return Classification{
		Kind:   k,
		Action: CoverOrigin,
		LogKey: k.LogKey(),
	}
}

func PublicProbeSurface(k Kind) (ProbeSurface, error) {
	classification := Classify(k)
	if classification.Action != CoverOrigin {
		return ProbeSurface{}, fmt.Errorf("failure: public probe surface action = %d, want cover-origin", classification.Action)
	}
	return ProbeSurface{
		HTTPStatus: classification.PublicStatus,
		Body:       append([]byte(nil), classification.PublicBody...),
		CloseCode:  classification.CloseCode,
	}, nil
}

func ActiveProbeCases() []ProbeCase {
	return []ProbeCase{
		{Name: "bad-access-hint", Kind: BadAccessHint},
		{Name: "replayed-access-hint", Kind: ReplayedAccessHint},
		{Name: "malformed-cover-prelude0", Kind: MalformedPrelude},
		{Name: "invalid-prelude-signature", Kind: WrongSignature},
		{Name: "wrong-suite", Kind: WrongSuite},
		{Name: "bad-aead-tag", Kind: BadAEADTag},
		{Name: "replayed-admission-proof", Kind: ReplayedAdmission},
		{Name: "unsupported-version", Kind: UnsupportedVersion},
		{Name: "malformed-hybrid-share", Kind: MalformedHybridShare},
		{Name: "unsupported-method", Kind: UnsupportedMethod},
		{Name: "wrong-h3-settings", Kind: WrongH3Settings},
		{Name: "malformed-flow-open", Kind: MalformedFlowOpen},
		{Name: "malformed-key-update", Kind: MalformedKeyUpdate},
	}
}

func VerifyProbeNeutrality(cases []ProbeCase) error {
	if len(cases) == 0 {
		return fmt.Errorf("failure: no active-probe cases")
	}
	first := Classify(cases[0].Kind)
	if first.Action != CoverOrigin {
		return fmt.Errorf("failure: probe case %q action = %d, want cover-origin", cases[0].Name, first.Action)
	}
	firstSurface, err := PublicProbeSurface(cases[0].Kind)
	if err != nil {
		return fmt.Errorf("failure: probe case %q surface: %w", cases[0].Name, err)
	}
	for _, tc := range cases[1:] {
		got := Classify(tc.Kind)
		if got.Action != CoverOrigin {
			return fmt.Errorf("failure: probe case %q action = %d, want cover-origin", tc.Name, got.Action)
		}
		surface, err := PublicProbeSurface(tc.Kind)
		if err != nil {
			return fmt.Errorf("failure: probe case %q surface: %w", tc.Name, err)
		}
		if surface.HTTPStatus != firstSurface.HTTPStatus ||
			surface.CloseCode != firstSurface.CloseCode ||
			surface.TLSAlertClass != firstSurface.TLSAlertClass ||
			surface.QUICCloseCode != firstSurface.QUICCloseCode ||
			surface.WebSocketCloseCode != firstSurface.WebSocketCloseCode ||
			surface.TimingClass != firstSurface.TimingClass ||
			surface.ReflectedLog != firstSurface.ReflectedLog ||
			!bytes.Equal(surface.Body, firstSurface.Body) {
			return fmt.Errorf("failure: probe case %q has distinguishable public surface", tc.Name)
		}
	}
	return nil
}
