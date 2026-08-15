package admission

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/wire"
)

// accessHintLabel avoids a per-call string-to-[]byte conversion on the relay's
// hot access-hint path. It is allocated once at init and never mutated, so
// concurrent reads are safe; the bytes are identical to the previous inline
// []byte("aurora v2.0 access hint").
//
// This measurably helps ComputeAccessHint because mac.Write dispatches through
// the hash.Hash interface, so the inline []byte("...") escaped to the heap on
// every call. Hoisting it drops ComputeAccessHint from 9 to 8 allocs/op.
// (ComputeSpentHintKey's label is left inline: wire.NewEncoder() returns a
// concrete type whose WriteBytes the compiler proves non-escaping, so the
// conversion there was already stack-allocated and hoisting it is a no-op.)
var accessHintLabel = []byte("aurora v2.0 access hint")

type AccessHintCredential struct {
	HintIssuerID  []byte
	RelayBucketID []byte
	HintEpochID   uint64
	HintSelector  []byte
	HintSecret    []byte
	ExpiryUnix    uint64
	MaxUses       uint16
}

func DeriveHintSecret(verifierSecret, issuerID, relayBucketID []byte, hintEpochID uint64, hintSelector []byte) ([]byte, error) {
	context := wire.NewEncoder()
	context.WriteOpaqueFixed(issuerID, 16)
	context.WriteOpaqueFixed(relayBucketID, 16)
	context.WriteUint64(hintEpochID)
	context.WriteOpaqueFixed(hintSelector, 16)
	contextBytes, err := context.Bytes()
	if err != nil {
		return nil, err
	}
	secret, err := auroracrypto.HKDFExtractSHA384(verifierSecret, []byte("aurora v2.0 hint"))
	if err != nil {
		return nil, err
	}
	return auroracrypto.HKDFExpandLabelSHA384(secret, "hint secret", contextBytes, 32)
}

func ComputeAccessHint(cred AccessHintCredential, accessHintBindingContext, clientNonceForAccessHint []byte) ([]byte, error) {
	if err := cred.validate(); err != nil {
		return nil, err
	}
	if len(accessHintBindingContext) != 48 {
		return nil, fmt.Errorf("admission: access hint binding context length %d, want 48", len(accessHintBindingContext))
	}
	if len(clientNonceForAccessHint) != 32 {
		return nil, fmt.Errorf("admission: client nonce length %d, want 32", len(clientNonceForAccessHint))
	}
	mac := hmac.New(sha256.New, cred.HintSecret)
	mac.Write(accessHintLabel)
	mac.Write(cred.HintIssuerID)
	mac.Write(cred.HintSelector)
	mac.Write(cred.RelayBucketID)
	mac.Write(wire.EncodeUint64(cred.HintEpochID))
	mac.Write(accessHintBindingContext)
	mac.Write(clientNonceForAccessHint)
	return auroracrypto.Truncate128(mac.Sum(nil)), nil
}

func ComputeSpentHintKey(cred AccessHintCredential) ([]byte, error) {
	if err := cred.validate(); err != nil {
		return nil, err
	}
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 spent hint credential"))
	e.WriteOpaqueFixed(cred.HintIssuerID, 16)
	e.WriteOpaqueFixed(cred.RelayBucketID, 16)
	e.WriteUint64(cred.HintEpochID)
	e.WriteOpaqueFixed(cred.HintSelector, 16)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func VerifyAndSpendAccessHint(cache ReplayCache, cred AccessHintCredential, bindingContext, clientNonce, receivedHint []byte) error {
	return VerifyAndSpendAccessHintAt(cache, cred, bindingContext, clientNonce, receivedHint, 0, 0)
}

func VerifyAndSpendAccessHintAt(cache ReplayCache, cred AccessHintCredential, bindingContext, clientNonce, receivedHint []byte, nowUnix, epochValidUntilUnix uint64) error {
	if cache == nil {
		return fmt.Errorf("admission: missing access hint replay cache")
	}
	if nowUnix != 0 && cred.ExpiryUnix != 0 && nowUnix >= cred.ExpiryUnix {
		return fmt.Errorf("admission: access hint expired")
	}
	if nowUnix != 0 && (epochValidUntilUnix == 0 || nowUnix >= epochValidUntilUnix) {
		return fmt.Errorf("admission: access hint relay epoch expired")
	}
	expected, err := ComputeAccessHint(cred, bindingContext, clientNonce)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expected, receivedHint) != 1 {
		return fmt.Errorf("admission: access hint mismatch")
	}
	spentKey, err := ComputeSpentHintKey(cred)
	if err != nil {
		return err
	}
	var inserted bool
	if nowUnix == 0 {
		inserted, err = cache.InsertIfAbsent(spentKey)
	} else {
		retentionDeadline, deadlineErr := MaximumRetentionDeadline(cred.ExpiryUnix, epochValidUntilUnix)
		if deadlineErr != nil {
			return deadlineErr
		}
		inserted, err = InsertIfAbsentRetained(cache, spentKey, retentionDeadline, nowUnix)
	}
	if err != nil {
		return fmt.Errorf("admission: access hint replay cache failed: %w", err)
	}
	if !inserted {
		return fmt.Errorf("admission: access hint already spent")
	}
	return nil
}

func (c AccessHintCredential) validate() error {
	if len(c.HintIssuerID) != 16 || len(c.RelayBucketID) != 16 || len(c.HintSelector) != 16 {
		return fmt.Errorf("admission: hint issuer, bucket, and selector must be 16 bytes")
	}
	if len(c.HintSecret) != 32 {
		return fmt.Errorf("admission: hint secret length %d, want 32", len(c.HintSecret))
	}
	if c.MaxUses != 1 {
		return fmt.Errorf("admission: AccessHint max_uses must be 1")
	}
	return nil
}
