package client

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
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
	wallet, err := ParseNativeProvisioningWalletWithTrust(encoded, nativeProvisioningTrustFor(t, first, second), now)
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

func TestNativeProvisioningReservationCallbackCannotMutateWalletKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	provisioning := validNativeProvisioning(t, now)
	defer zeroNativeProvisioning(&provisioning)
	wantKey := nativeProvisioningSpentHintKey(t, provisioning)
	defer zeroNativeProvisioningBytes(wantKey)
	encoded, err := EncodeNativeProvisioningWallet([]NativeProvisioning{provisioning})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := ParseNativeProvisioningWalletWithTrust(encoded, provisioning.signedSeedTrust, now)
	zeroNativeProvisioningBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer wallet.Zero()
	reservation, err := wallet.Reserve(func(key []byte) bool {
		for index := range key {
			key[index] = 0
		}
		return false
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Zero()
	if !bytes.Equal(reservation.SpentHintKey, wantKey) {
		t.Fatal("reservation callback mutated the wallet-owned spent-hint key")
	}
}

func TestSingleNativeProvisioningReservationCallbackCannotMutateKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	provisioning := validNativeProvisioning(t, now)
	defer zeroNativeProvisioning(&provisioning)
	wantKey := nativeProvisioningSpentHintKey(t, provisioning)
	defer zeroNativeProvisioningBytes(wantKey)
	encoded, err := EncodeNativeProvisioning(provisioning)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(encoded)
	reservation, err := ReserveNativeProvisioningWithTrust(encoded, provisioning.signedSeedTrust, func(key []byte) bool {
		for index := range key {
			key[index] = 0
		}
		return false
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Zero()
	if !bytes.Equal(reservation.SpentHintKey, wantKey) {
		t.Fatal("reservation callback mutated the derived spent-hint key")
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
	if _, err := ParseNativeProvisioningWalletWithTrust(nonCanonical, nativeProvisioningTrustFor(t, first, second), now); err == nil {
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
	if _, err := ParseNativeProvisioningWalletWithTrust(nonCanonical, nativeProvisioningTrustFor(t, valid, expired), now); err == nil {
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
	walletTrust := nativeProvisioningTrustFor(t, entries...)

	encoded, err := EncodeNativeProvisioningWallet(entries)
	if err != nil {
		t.Fatal(err)
	}
	for index := range entries {
		zeroNativeProvisioning(&entries[index])
	}
	zeroNativeProvisioning(&expired)
	wallet, err := ParseNativeProvisioningWalletWithTrust(encoded, walletTrust, now)
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
	if _, err := ParseNativeProvisioningWalletWithTrust(malformedEncoded, malformedExpired.signedSeedTrust, now); err == nil {
		t.Fatal("wallet accepted malformed expired provisioning")
	}
	zeroNativeProvisioning(&malformedExpired)
}

func TestNativeProvisioningWalletBucketStatusClearsDurablyReservedEntries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	provisioning := validNativeProvisioning(t, now)
	defer zeroNativeProvisioning(&provisioning)

	encoded, err := EncodeNativeProvisioningWallet([]NativeProvisioning{provisioning})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := ParseNativeProvisioningWalletWithTrust(encoded, provisioning.signedSeedTrust, now)
	zeroNativeProvisioningBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer wallet.Zero()
	if len(wallet.entries) != 1 || len(wallet.entries[0].encoded) == 0 {
		t.Fatal("loaded wallet entry is unavailable")
	}

	status := wallet.BucketStatus(func([]byte) bool { return true }, now)
	if len(status) != 0 {
		t.Fatalf("durably reserved wallet status = %+v, want none", status)
	}
	entry := wallet.entries[0]
	if entry.encoded != nil || entry.spentHintKey != nil || entry.relayBucketID != nil || entry.expiryUnix != 0 {
		t.Fatal("bucket status retained a durably reserved provisioning entry")
	}
}

func TestNativeProvisioningWalletBucketStatusClearsExpiredEntries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	provisioning := validNativeProvisioning(t, now)
	defer zeroNativeProvisioning(&provisioning)
	credential, err := admission.DecodeAccessHintCredential(provisioning.AccessHint)
	if err != nil {
		t.Fatal(err)
	}
	credential.ExpiryUnix = uint64(now.Add(time.Second).Unix())
	provisioning.AccessHint, err = admission.EncodeAccessHintCredential(credential)
	zeroNativeAccessHintCredential(&credential)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := EncodeNativeProvisioningWallet([]NativeProvisioning{provisioning})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := ParseNativeProvisioningWalletWithTrust(encoded, provisioning.signedSeedTrust, now)
	zeroNativeProvisioningBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer wallet.Zero()
	if len(wallet.entries) != 1 || len(wallet.entries[0].encoded) == 0 {
		t.Fatal("loaded wallet entry is unavailable")
	}

	status := wallet.BucketStatus(nil, now.Add(2*time.Second))
	if len(status) != 0 {
		t.Fatalf("expired wallet status = %+v, want none", status)
	}
	entry := wallet.entries[0]
	if entry.encoded != nil || entry.spentHintKey != nil || entry.relayBucketID != nil || entry.expiryUnix != 0 {
		t.Fatal("bucket status retained an expired provisioning entry")
	}
}

func TestReserveNativeProvisioningSupportsSingleAndWalletSources(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	first := validNativeProvisioning(t, now)
	second := nativeProvisioningWithDistinctHint(t, first, 0x42)
	firstEncoded, err := EncodeNativeProvisioning(first)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(firstEncoded)
	firstReservation, err := ReserveNativeProvisioningWithTrust(firstEncoded, first.signedSeedTrust, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	defer firstReservation.Zero()
	if _, err := ReserveNativeProvisioningWithTrust(firstEncoded, first.signedSeedTrust, func(key []byte) bool {
		return bytes.Equal(key, firstReservation.SpentHintKey)
	}, now); !errors.Is(err, ErrNoUsableNativeProvisioning) {
		t.Fatalf("single provisioning reuse error = %v, want no usable provisioning", err)
	}

	walletEncoded, err := EncodeNativeProvisioningWallet([]NativeProvisioning{first, second})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(walletEncoded)
	walletTrust := nativeProvisioningTrustFor(t, first, second)
	walletFirst, err := ReserveNativeProvisioningWithTrust(walletEncoded, walletTrust, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	defer walletFirst.Zero()
	walletSecond, err := ReserveNativeProvisioningWithTrust(walletEncoded, walletTrust, func(key []byte) bool {
		return bytes.Equal(key, walletFirst.SpentHintKey)
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer walletSecond.Zero()
	if bytes.Equal(walletFirst.SpentHintKey, walletSecond.SpentHintKey) {
		t.Fatal("wallet source reused the first access hint")
	}
}

func TestValidateNativeProvisioningSourceAcceptsSingleAndWalletWithoutReservation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	first := validNativeProvisioning(t, now)
	second := nativeProvisioningWithDistinctHint(t, first, 0x42)

	single, err := EncodeNativeProvisioning(first)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(single)
	if err := ValidateNativeProvisioningSourceWithTrust(single, first.signedSeedTrust, now); err != nil {
		t.Fatalf("validate single provisioning: %v", err)
	}
	singleReservation, err := ReserveNativeProvisioningWithTrust(single, first.signedSeedTrust, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	defer singleReservation.Zero()

	wallet, err := EncodeNativeProvisioningWallet([]NativeProvisioning{first, second})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(wallet)
	walletTrust := nativeProvisioningTrustFor(t, first, second)
	expectedReservation, err := ReserveNativeProvisioningWithTrust(wallet, walletTrust, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	defer expectedReservation.Zero()
	if err := ValidateNativeProvisioningSourceWithTrust(wallet, walletTrust, now); err != nil {
		t.Fatalf("validate wallet provisioning: %v", err)
	}
	actualReservation, err := ReserveNativeProvisioningWithTrust(wallet, walletTrust, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	defer actualReservation.Zero()
	if !bytes.Equal(expectedReservation.SpentHintKey, actualReservation.SpentHintKey) {
		t.Fatal("validation consumed a wallet provisioning entry")
	}
}

func TestValidateNativeProvisioningSourceRejectsMalformedAndExpiredInput(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	trust := validNativeProvisioning(t, now).signedSeedTrust
	if err := ValidateNativeProvisioningSourceWithTrust([]byte{byte(nativeProvisioningWalletFormat)}, trust, now); err == nil {
		t.Fatal("malformed native provisioning source was accepted")
	}

	expired := validNativeProvisioning(t, now)
	credential, err := admission.DecodeAccessHintCredential(expired.AccessHint)
	if err != nil {
		t.Fatal(err)
	}
	credential.ExpiryUnix = uint64(now.Add(-time.Second).Unix())
	expired.AccessHint, err = admission.EncodeAccessHintCredential(credential)
	zeroNativeAccessHintCredential(&credential)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioning(&expired)
	encoded, err := EncodeNativeProvisioningWallet([]NativeProvisioning{expired})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(encoded)
	if err := ValidateNativeProvisioningSourceWithTrust(encoded, expired.signedSeedTrust, now); err == nil {
		t.Fatal("expired native provisioning wallet was accepted")
	}
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

func nativeProvisioningTrustFor(t testing.TB, provisioning ...NativeProvisioning) NativeProvisioningTrust {
	t.Helper()
	roots := make([]protocol.AuthorityKeyRecord, 0, len(provisioning))
	deployments := make([]NativeProvisioningDeploymentTrust, 0, len(provisioning))
	seenRoots := make(map[string]struct{})
	seenDeployments := make(map[string]struct{})
	for _, value := range provisioning {
		for _, root := range value.signedSeedTrust.roots {
			encoded, err := protocol.Encode(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := seenRoots[string(encoded)]; !exists {
				seenRoots[string(encoded)] = struct{}{}
				roots = append(roots, cloneNativeProvisioningAuthorityKeys([]protocol.AuthorityKeyRecord{root})[0])
			}
			zeroNativeProvisioningBytes(encoded)
		}
		for _, deployment := range value.signedSeedTrust.deployments {
			encodedKey, err := protocol.Encode(deployment.TemplateAuthorityKey)
			if err != nil {
				t.Fatal(err)
			}
			identity := string(deployment.DescriptorHash) + string(deployment.CoverTemplateHash) + string(encodedKey)
			zeroNativeProvisioningBytes(encodedKey)
			if _, exists := seenDeployments[identity]; !exists {
				seenDeployments[identity] = struct{}{}
				deployments = append(deployments, cloneNativeProvisioningDeploymentTrusts([]NativeProvisioningDeploymentTrust{deployment})[0])
			}
		}
	}
	trusted, err := NewNativeProvisioningTrust(roots, deployments...)
	zeroNativeProvisioningAuthorityKeys(roots)
	zeroNativeProvisioningDeploymentTrusts(deployments)
	if err != nil {
		t.Fatal(err)
	}
	return trusted
}

func FuzzParseNativeProvisioningWallet(f *testing.F) {
	now := time.Unix(1_700_000_000, 0).UTC()
	provisioning := validNativeProvisioning(f, now)
	trusted := provisioning.signedSeedTrust
	encoded, err := EncodeNativeProvisioningWallet([]NativeProvisioning{provisioning})
	zeroNativeProvisioning(&provisioning)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Fuzz(func(t *testing.T, encoded []byte) {
		wallet, _ := ParseNativeProvisioningWalletWithTrust(encoded, trusted, now)
		if wallet != nil {
			wallet.Zero()
		}
	})
}
