package client

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestNativeProvisioningWalletCanonicalRoundTripAndReservation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	first := validNativeProvisioning(t, now)
	second := nativeProvisioningWithDistinctHint(t, first, 0x42)

	encoded, err := EncodeNativeProvisioningWallet([]NativeProvisioning{second, first})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := ParseNativeProvisioningWallet(encoded, now)
	if err != nil {
		t.Fatal(err)
	}
	zeroNativeProvisioningBytes(encoded)
	t.Cleanup(wallet.Zero)

	firstReservation, err := wallet.Reserve(nil, now)
	if err != nil {
		t.Fatal(err)
	}
	defer firstReservation.Zero()
	if len(firstReservation.SpentHintKey) != 48 || len(firstReservation.RelayBucketID) != 16 {
		t.Fatalf("reservation identifiers have unexpected lengths: key=%d bucket=%d", len(firstReservation.SpentHintKey), len(firstReservation.RelayBucketID))
	}
	credential, err := admission.DecodeAccessHintCredential(firstReservation.Provisioning.AccessHint)
	if err != nil {
		t.Fatal(err)
	}
	if firstReservation.AccessHintExpiryUnix != credential.ExpiryUnix {
		t.Fatalf("reservation expiry = %d, want %d", firstReservation.AccessHintExpiryUnix, credential.ExpiryUnix)
	}
	zeroNativeAccessHintCredential(&credential)
	if _, err := firstReservation.Provisioning.ClientDriverConfig(now, nativeProvisioningProofProvider{}); err != nil {
		t.Fatalf("reserved provisioning is invalid: %v", err)
	}

	secondReservation, err := wallet.Reserve(nil, now)
	if err != nil {
		t.Fatal(err)
	}
	defer secondReservation.Zero()
	if bytes.Equal(firstReservation.SpentHintKey, secondReservation.SpentHintKey) {
		t.Fatal("wallet returned the same access hint twice")
	}
	if _, err := wallet.Reserve(nil, now); !errors.Is(err, ErrNoUsableNativeProvisioning) {
		t.Fatalf("reservation after exhaustion = %v, want no usable provisioning", err)
	}

	firstReservation.Zero()
	if firstReservation.Provisioning.AccessHint != nil || firstReservation.SpentHintKey != nil || firstReservation.RelayBucketID != nil {
		t.Fatal("reservation zero did not erase private data")
	}
}

func TestNativeProvisioningWalletRejectsDuplicateAndNonCanonicalEntries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	first := validNativeProvisioning(t, now)
	if _, err := EncodeNativeProvisioningWallet([]NativeProvisioning{first, first}); err == nil {
		t.Fatal("wallet accepted duplicate access hint")
	}

	second := nativeProvisioningWithDistinctHint(t, first, 0x42)
	firstEncoded, err := EncodeNativeProvisioning(first)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(firstEncoded)
	secondEncoded, err := EncodeNativeProvisioning(second)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(secondEncoded)
	firstKey := nativeProvisioningSpentHintKey(t, first)
	secondKey := nativeProvisioningSpentHintKey(t, second)
	if bytes.Compare(firstKey, secondKey) < 0 {
		firstEncoded, secondEncoded = secondEncoded, firstEncoded
	}
	encoder := wire.NewEncoder()
	encoder.WriteVarint(nativeProvisioningWalletFormat)
	encoder.WriteVarint(2)
	encoder.WriteOpaque24(firstEncoded)
	encoder.WriteOpaque24(secondEncoded)
	nonCanonical, err := encoder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(nonCanonical)
	if _, err := ParseNativeProvisioningWallet(nonCanonical, now); err == nil {
		t.Fatal("wallet accepted non-canonical entry ordering")
	}
}

func TestNativeProvisioningWalletChecksOrderAcrossExpiredEntries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid := validNativeProvisioning(t, now)
	validKey := nativeProvisioningSpentHintKey(t, valid)
	var expired NativeProvisioning
	for selector := 1; selector <= 255; selector++ {
		candidate := nativeProvisioningWithDistinctHint(t, valid, byte(selector))
		credential, err := admission.DecodeAccessHintCredential(candidate.AccessHint)
		if err != nil {
			zeroNativeProvisioning(&candidate)
			t.Fatal(err)
		}
		credential.ExpiryUnix = uint64(now.Add(-time.Second).Unix())
		candidate.AccessHint, err = admission.EncodeAccessHintCredential(credential)
		if err != nil {
			zeroNativeProvisioning(&candidate)
			t.Fatal(err)
		}
		if bytes.Compare(nativeProvisioningSpentHintKey(t, candidate), validKey) > 0 {
			expired = candidate
			break
		}
		zeroNativeProvisioning(&candidate)
	}
	if expired.AccessHint == nil {
		t.Fatal("could not build non-canonical expired test entry")
	}
	defer zeroNativeProvisioning(&valid)
	defer zeroNativeProvisioning(&expired)
	validEncoded, err := EncodeNativeProvisioning(valid)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(validEncoded)
	expiredEncoded, err := EncodeNativeProvisioning(expired)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(expiredEncoded)
	encoder := wire.NewEncoder()
	encoder.WriteVarint(nativeProvisioningWalletFormat)
	encoder.WriteVarint(2)
	encoder.WriteOpaque24(expiredEncoded)
	encoder.WriteOpaque24(validEncoded)
	nonCanonical, err := encoder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(nonCanonical)
	if _, err := ParseNativeProvisioningWallet(nonCanonical, now); err == nil {
		t.Fatal("wallet accepted non-canonical ordering after expired entry")
	}
}

func TestNativeProvisioningWalletFiltersExpiredEntriesAndReportsRefillNeed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	entries := make([]NativeProvisioning, 0, NativeProvisioningWalletTargetUnused)
	for index := range NativeProvisioningWalletTargetUnused {
		entry := validNativeProvisioning(t, now)
		entries = append(entries, nativeProvisioningWithDistinctHint(t, entry, byte(index+1)))
		zeroNativeProvisioning(&entry)
	}
	expired := nativeProvisioningWithDistinctHint(t, entries[0], 0xf0)
	credential, err := admission.DecodeAccessHintCredential(expired.AccessHint)
	if err != nil {
		t.Fatal(err)
	}
	credential.ExpiryUnix = uint64(now.Add(-time.Second).Unix())
	expired.AccessHint, err = admission.EncodeAccessHintCredential(credential)
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, expired)

	encoded, err := EncodeNativeProvisioningWallet(entries)
	if err != nil {
		t.Fatal(err)
	}
	for index := range entries {
		zeroNativeProvisioning(&entries[index])
	}
	zeroNativeProvisioning(&expired)
	wallet, err := ParseNativeProvisioningWallet(encoded, now)
	zeroNativeProvisioningBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer wallet.Zero()

	status := wallet.BucketStatus(nil, now)
	if len(status) != 1 || status[0].Unused != NativeProvisioningWalletTargetUnused || !status[0].TargetMet || status[0].RefillRecommended {
		t.Fatalf("initial wallet status = %+v", status)
	}
	reserved := make(map[string]struct{})
	for index := 0; index < NativeProvisioningWalletTargetUnused-NativeProvisioningWalletRefillThreshold+1; index++ {
		reservation, err := wallet.Reserve(func(key []byte) bool {
			_, found := reserved[string(key)]
			return found
		}, now)
		if err != nil {
			t.Fatal(err)
		}
		reserved[string(reservation.SpentHintKey)] = struct{}{}
		reservation.Zero()
	}
	status = wallet.BucketStatus(nil, now)
	if len(status) != 1 || status[0].Unused != NativeProvisioningWalletRefillThreshold-1 || status[0].TargetMet || !status[0].RefillRecommended {
		t.Fatalf("depleted wallet status = %+v", status)
	}

	malformedExpired := validNativeProvisioning(t, now)
	credential, err = admission.DecodeAccessHintCredential(malformedExpired.AccessHint)
	if err != nil {
		t.Fatal(err)
	}
	credential.ExpiryUnix = uint64(now.Add(-time.Second).Unix())
	malformedExpired.AccessHint, err = admission.EncodeAccessHintCredential(credential)
	if err != nil {
		t.Fatal(err)
	}
	malformedExpired.PolicyOffer = []byte{0xff}
	malformedEncoded, err := EncodeNativeProvisioningWallet([]NativeProvisioning{malformedExpired})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(malformedEncoded)
	if _, err := ParseNativeProvisioningWallet(malformedEncoded, now); err == nil {
		t.Fatal("wallet accepted malformed expired provisioning")
	}
	zeroNativeProvisioning(&malformedExpired)
}

func nativeProvisioningWithDistinctHint(t testing.TB, input NativeProvisioning, selector byte) NativeProvisioning {
	t.Helper()
	output := cloneProvisioningForSession(input)
	credential, err := admission.DecodeAccessHintCredential(output.AccessHint)
	if err != nil {
		t.Fatal(err)
	}
	credential.HintSelector[0] = selector
	credential.HintSecret[0] ^= selector
	output.AccessHint, err = admission.EncodeAccessHintCredential(credential)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func nativeProvisioningSpentHintKey(t testing.TB, provisioning NativeProvisioning) []byte {
	t.Helper()
	credential, err := admission.DecodeAccessHintCredential(provisioning.AccessHint)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeAccessHintCredential(&credential)
	key, err := admission.ComputeSpentHintKey(credential)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
