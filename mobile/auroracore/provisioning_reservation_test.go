//go:build cgo

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/client"
)

const nativeReservationJSONOperation = 22

func TestNativeProvisioningReservationJSONTraversesCABI(t *testing.T) {
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)
	caller := newNativeIntegrationCaller(t, fixture.ProvisioningTrust(t))
	encoded, err := client.EncodeNativeProvisioning(fixture.Provisioning(t))
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encoded)
	request, err := encodeNativeProvisioningReservationRequest(encoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(request)

	status, payload := nativeIntegrationCall(t, caller, nativeReservationJSONOperation, request, uint64(time.Now().Unix()))
	if status != statusOK {
		t.Fatalf("C ABI JSON reservation status=%d", status)
	}
	defer zeroNativeBytes(payload)
	result := decodeNativeProvisioningReservationJSONForTest(t, payload)
	defer result.zero()
	if _, err := client.ParseNativeProvisioningWithTrust(result.provisioning, fixture.ProvisioningTrust(t), time.Now()); err != nil {
		t.Fatalf("C ABI JSON reserved provisioning is invalid: %v", err)
	}
}

func TestNativeProvisioningReservationJSONRejectsSingleSourceReuse(t *testing.T) {
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)
	encoded, err := client.EncodeNativeProvisioning(fixture.Provisioning(t))
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encoded)
	request, err := encodeNativeProvisioningReservationRequest(encoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(request)
	status, payload := dispatch(nativeReservationJSONOperation, request, uint64(time.Now().Unix()))
	if status != statusOK {
		t.Fatalf("JSON reservation status=%d", status)
	}
	defer zeroNativeBytes(payload)
	reservation := decodeNativeProvisioningReservationJSONForTest(t, payload)
	defer reservation.zero()

	reused, err := encodeNativeProvisioningReservationRequest(encoded, [][]byte{reservation.spentHintKey})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(reused)
	if status, payload := dispatch(nativeReservationJSONOperation, reused, uint64(time.Now().Unix())); status != statusError || len(payload) != 0 {
		t.Fatalf("JSON single source reuse status=%d payload=%x", status, payload)
	}
}

func TestNativeProvisioningReservationJSONRejectsMalformedEnvelope(t *testing.T) {
	for _, input := range [][]byte{
		nil,
		{0, 0, 1},
		bytes.Repeat([]byte{0}, 32),
	} {
		if status, payload := dispatch(nativeReservationJSONOperation, input, uint64(time.Now().Unix())); status != statusError || len(payload) != 0 {
			t.Fatalf("malformed JSON reservation input status=%d payload=%x", status, payload)
		}
	}
}

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

func TestNativeProvisioningReservationRejectsUnrepresentableSourceLength(t *testing.T) {
	request := make([]byte, nativeProvisioningReservationSourceLengthBytes+nativeProvisioningReservationCountBytes)
	binary.BigEndian.PutUint32(request, ^uint32(0))
	if _, _, err := decodeNativeProvisioningReservationRequest(request); err == nil {
		t.Fatal("reservation request accepted an unrepresentable source length")
	}
}

func TestNativeProvisioningReservationTraversesCABI(t *testing.T) {
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)
	caller := newNativeIntegrationCaller(t, fixture.ProvisioningTrust(t))
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
	if _, err := client.ParseNativeProvisioningWithTrust(reservation.Provisioning, fixture.ProvisioningTrust(t), time.Now()); err != nil {
		t.Fatalf("C ABI reserved provisioning is invalid: %v", err)
	}
}

func TestValidateNativeProvisioningSourceTraversesCABI(t *testing.T) {
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)
	caller := newNativeIntegrationCaller(t, fixture.ProvisioningTrust(t))
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
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)
	caller := newNativeIntegrationCaller(t, fixture.ProvisioningTrust(t))
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

type nativeProvisioningReservationJSONTestResult struct {
	provisioning  []byte
	spentHintKey  []byte
	relayBucketID []byte
	expiresAtUnix uint64
}

func (result *nativeProvisioningReservationJSONTestResult) zero() {
	if result == nil {
		return
	}
	zeroNativeBytes(result.provisioning)
	zeroNativeBytes(result.spentHintKey)
	zeroNativeBytes(result.relayBucketID)
	*result = nativeProvisioningReservationJSONTestResult{}
}

func decodeNativeProvisioningReservationJSONForTest(t testing.TB, encoded []byte) nativeProvisioningReservationJSONTestResult {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4 {
		t.Fatalf("reservation JSON field count=%d", len(fields))
	}
	for _, name := range []string{"provisioning_base64", "spent_hint_key_base64", "relay_bucket_id_base64", "access_hint_expiry_unix"} {
		if _, ok := fields[name]; !ok {
			t.Fatalf("reservation JSON is missing %q", name)
		}
	}
	var result struct {
		ProvisioningBase64   string `json:"provisioning_base64"`
		SpentHintKeyBase64   string `json:"spent_hint_key_base64"`
		RelayBucketIDBase64  string `json:"relay_bucket_id_base64"`
		AccessHintExpiryUnix uint64 `json:"access_hint_expiry_unix"`
	}
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	provisioning, err := base64.StdEncoding.DecodeString(result.ProvisioningBase64)
	if err != nil {
		t.Fatal(err)
	}
	spentHintKey, err := base64.StdEncoding.DecodeString(result.SpentHintKeyBase64)
	if err != nil {
		zeroNativeBytes(provisioning)
		t.Fatal(err)
	}
	relayBucketID, err := base64.StdEncoding.DecodeString(result.RelayBucketIDBase64)
	if err != nil {
		zeroNativeBytes(provisioning)
		zeroNativeBytes(spentHintKey)
		t.Fatal(err)
	}
	if len(provisioning) == 0 || len(spentHintKey) != nativeProvisioningReservationSpentHintKeyBytes || len(relayBucketID) != nativeProvisioningReservationRelayBucketBytes || result.AccessHintExpiryUnix == 0 {
		zeroNativeBytes(provisioning)
		zeroNativeBytes(spentHintKey)
		zeroNativeBytes(relayBucketID)
		t.Fatalf("reservation JSON is incomplete: %+v", result)
	}
	return nativeProvisioningReservationJSONTestResult{
		provisioning:  provisioning,
		spentHintKey:  spentHintKey,
		relayBucketID: relayBucketID,
		expiresAtUnix: result.AccessHintExpiryUnix,
	}
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
	trusted, err := nativeProvisioningTrust.load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ParseNativeProvisioningWithTrust(reservation.Provisioning, trusted, time.Now()); err != nil {
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
