//go:build cgo

package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/client"
)

func TestNativeProvisioningReservationRejectsSingleSourceReuse(t *testing.T) {
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)
	provisioning := fixture.Provisioning(t)
	encoded, err := client.EncodeNativeProvisioning(provisioning)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encoded)

	request, err := encodeNativeProvisioningReservationRequest(encoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(request)
	reservation := reserveNativeProvisioningForTest(t, request)
	if len(reservation.provisioning) == 0 || len(reservation.spentHintKey) != 48 {
		t.Fatalf("single reservation is incomplete: %+v", reservation)
	}
	defer reservation.zero()

	reused, err := encodeNativeProvisioningReservationRequest(encoded, [][]byte{reservation.spentHintKey})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(reused)
	if status, payload := dispatch(opReserveNativeProvisioning, reused, uint64(time.Now().Unix())); status != statusError || len(payload) != 0 {
		t.Fatalf("single source reuse status=%d payload=%x", status, payload)
	}
}

func TestNativeProvisioningReservationSelectsDistinctWalletEntries(t *testing.T) {
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)
	first := fixture.Provisioning(t)
	second := nativeReservationDistinctProvisioning(t, first)
	wallet, err := client.EncodeNativeProvisioningWallet([]client.NativeProvisioning{first, second})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(wallet)

	firstRequest, err := encodeNativeProvisioningReservationRequest(wallet, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(firstRequest)
	firstReservation := reserveNativeProvisioningForTest(t, firstRequest)
	defer firstReservation.zero()
	secondRequest, err := encodeNativeProvisioningReservationRequest(wallet, [][]byte{firstReservation.spentHintKey})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(secondRequest)
	secondReservation := reserveNativeProvisioningForTest(t, secondRequest)
	defer secondReservation.zero()
	if bytes.Equal(firstReservation.spentHintKey, secondReservation.spentHintKey) {
		t.Fatal("wallet reservation reused an access hint")
	}
	if bytes.Equal(firstReservation.provisioning, secondReservation.provisioning) {
		t.Fatal("wallet reservation reused a provisioning entry")
	}
}

func TestNativeProvisioningReservationRejectsMalformedEnvelope(t *testing.T) {
	for _, input := range [][]byte{
		nil,
		{0, 0, 1},
		bytes.Repeat([]byte{0}, 32),
	} {
		if status, payload := dispatch(opReserveNativeProvisioning, input, uint64(time.Now().Unix())); status != statusError || len(payload) != 0 {
			t.Fatalf("malformed reservation input status=%d payload=%x", status, payload)
		}
	}
}

func TestNativeProvisioningReservationTraversesCABI(t *testing.T) {
	caller := newNativeIntegrationCaller(t)
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)
	provisioning := fixture.Provisioning(t)
	encoded, err := client.EncodeNativeProvisioning(provisioning)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encoded)
	request, err := encodeNativeProvisioningReservationRequest(encoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(request)
	status, payload := nativeIntegrationCall(t, caller, opReserveNativeProvisioning, request, uint64(time.Now().Unix()))
	if status != statusOK {
		t.Fatalf("C ABI reservation status=%d", status)
	}
	defer zeroNativeBytes(payload)
	reservation, err := decodeNativeProvisioningReservation(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(reservation.Provisioning)
	defer zeroNativeBytes(reservation.SpentHintKey)
	defer zeroNativeBytes(reservation.RelayBucketID)
	if _, err := client.ParseNativeProvisioning(reservation.Provisioning, time.Now()); err != nil {
		t.Fatalf("C ABI reserved provisioning is invalid: %v", err)
	}
}

func TestValidateNativeProvisioningSourceTraversesCABI(t *testing.T) {
	caller := newNativeIntegrationCaller(t)
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)
	encoded, err := client.EncodeNativeProvisioning(fixture.Provisioning(t))
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encoded)

	status, payload := nativeIntegrationCall(t, caller, opValidateNativeProvisioningSource, encoded, uint64(time.Now().Unix()))
	if status != statusOK || len(payload) != 0 {
		t.Fatalf("C ABI validation = status %d payload %x", status, payload)
	}
	if status, payload := nativeIntegrationCall(t, caller, opValidateNativeProvisioningSource, []byte{0x01}, uint64(time.Now().Unix())); status != statusError || len(payload) != 0 {
		t.Fatalf("C ABI malformed validation = status %d payload %x", status, payload)
	}
}

func TestValidateNativeProvisioningSourceRejectsTamperedSignedSeed(t *testing.T) {
	caller := newNativeIntegrationCaller(t)
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)
	provisioning := fixture.Provisioning(t)
	provisioning.SignedSeed[0] ^= 0xff
	encoded, err := client.EncodeNativeProvisioning(provisioning)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encoded)

	status, payload := nativeIntegrationCall(t, caller, opValidateNativeProvisioningSource, encoded, uint64(time.Now().Unix()))
	if status != statusError || len(payload) != 0 {
		t.Fatalf("C ABI tampered seed validation = status %d payload %x", status, payload)
	}
}

type nativeProvisioningReservationTestResult struct {
	provisioning  []byte
	spentHintKey  []byte
	relayBucketID []byte
	expiresAtUnix uint64
}

func (result *nativeProvisioningReservationTestResult) zero() {
	if result == nil {
		return
	}
	zeroNativeBytes(result.provisioning)
	zeroNativeBytes(result.spentHintKey)
	zeroNativeBytes(result.relayBucketID)
	*result = nativeProvisioningReservationTestResult{}
}

func reserveNativeProvisioningForTest(t testing.TB, input []byte) nativeProvisioningReservationTestResult {
	t.Helper()
	status, payload := dispatch(opReserveNativeProvisioning, input, uint64(time.Now().Unix()))
	if status != statusOK {
		t.Fatalf("reserve provisioning status=%d", status)
	}
	defer zeroNativeBytes(payload)
	reservation, err := decodeNativeProvisioningReservation(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(reservation.Provisioning) == 0 || len(reservation.SpentHintKey) != 48 || len(reservation.RelayBucketID) != 16 || reservation.AccessHintExpiryUnix == 0 {
		t.Fatalf("reservation JSON is incomplete: %+v", reservation)
	}
	if _, err := client.ParseNativeProvisioning(reservation.Provisioning, time.Now()); err != nil {
		t.Fatalf("reserved provisioning is invalid: %v", err)
	}
	return nativeProvisioningReservationTestResult{
		provisioning:  reservation.Provisioning,
		spentHintKey:  reservation.SpentHintKey,
		relayBucketID: reservation.RelayBucketID,
		expiresAtUnix: reservation.AccessHintExpiryUnix,
	}
}

func nativeReservationDistinctProvisioning(t testing.TB, provisioning client.NativeProvisioning) client.NativeProvisioning {
	t.Helper()
	result := provisioning
	result.AccessHint = append([]byte(nil), provisioning.AccessHint...)
	credential, err := admission.DecodeAccessHintCredential(result.AccessHint)
	if err != nil {
		t.Fatal(err)
	}
	credential.HintSelector[0] ^= 0xff
	credential.HintSecret[0] ^= 0xff
	result.AccessHint, err = admission.EncodeAccessHintCredential(credential)
	zeroNativeBytes(credential.HintIssuerID)
	zeroNativeBytes(credential.RelayBucketID)
	zeroNativeBytes(credential.HintSelector)
	zeroNativeBytes(credential.HintSecret)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
