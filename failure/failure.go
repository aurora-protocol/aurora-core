package failure

import "fmt"

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

func (k Kind) Code() uint16 {
	if k < BadAccessHint || k > ReplayCacheFailure {
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
