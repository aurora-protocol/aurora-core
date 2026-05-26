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
	RateLimited
	WrongToken
	MalformedCapsule
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

type ProbeReport struct {
	Passed           bool
	CanonicalSurface ProbeSurface
	Cases            []ProbeFinding
}

type ProbeFinding struct {
	Name    string
	Kind    Kind
	Surface ProbeSurface
	Passed  bool
}

func (k Kind) Code() uint16 {
	if k < BadAccessHint || k > MalformedCapsule {
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

func RunActiveProbeHarness(cases []ProbeCase) (ProbeReport, error) {
	if len(cases) == 0 {
		return ProbeReport{}, fmt.Errorf("failure: no active-probe cases")
	}
	canonical, err := PublicProbeSurface(cases[0].Kind)
	if err != nil {
		return ProbeReport{}, fmt.Errorf("failure: probe case %q surface: %w", cases[0].Name, err)
	}
	report := ProbeReport{
		Passed:           true,
		CanonicalSurface: canonical,
		Cases:            make([]ProbeFinding, 0, len(cases)),
	}
	for _, tc := range cases {
		surface, err := PublicProbeSurface(tc.Kind)
		if err != nil {
			return ProbeReport{}, fmt.Errorf("failure: probe case %q surface: %w", tc.Name, err)
		}
		passed := sameProbeSurface(surface, canonical)
		report.Passed = report.Passed && passed
		report.Cases = append(report.Cases, ProbeFinding{
			Name:    tc.Name,
			Kind:    tc.Kind,
			Surface: surface,
			Passed:  passed,
		})
	}
	return report, nil
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
		{Name: "wrong-token", Kind: WrongToken},
		{Name: "malformed-capsule", Kind: MalformedCapsule},
		{Name: "verifier-unavailable", Kind: VerifierUnavailable},
		{Name: "unsupported-version", Kind: UnsupportedVersion},
		{Name: "malformed-hybrid-share", Kind: MalformedHybridShare},
		{Name: "unsupported-method", Kind: UnsupportedMethod},
		{Name: "wrong-h3-settings", Kind: WrongH3Settings},
		{Name: "malformed-flow-open", Kind: MalformedFlowOpen},
		{Name: "malformed-key-update", Kind: MalformedKeyUpdate},
		{Name: "rate-limited", Kind: RateLimited},
	}
}

func VerifyProbeNeutrality(cases []ProbeCase) error {
	report, err := RunActiveProbeHarness(cases)
	if err != nil {
		return err
	}
	for i, tc := range cases {
		got := Classify(tc.Kind)
		if got.Action != CoverOrigin {
			return fmt.Errorf("failure: probe case %q action = %d, want cover-origin", tc.Name, got.Action)
		}
		if !report.Cases[i].Passed {
			return fmt.Errorf("failure: probe case %q has distinguishable public surface", tc.Name)
		}
	}
	return nil
}

func sameProbeSurface(a, b ProbeSurface) bool {
	return a.HTTPStatus == b.HTTPStatus &&
		a.CloseCode == b.CloseCode &&
		a.TLSAlertClass == b.TLSAlertClass &&
		a.QUICCloseCode == b.QUICCloseCode &&
		a.WebSocketCloseCode == b.WebSocketCloseCode &&
		a.TimingClass == b.TimingClass &&
		a.ReflectedLog == b.ReflectedLog &&
		bytes.Equal(a.Body, b.Body)
}
