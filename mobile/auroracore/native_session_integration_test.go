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

func TestNativeSessionFFIExchangesTCPAndUDPThroughProductionFirstHop(t *testing.T) {
	caller := newNativeIntegrationCaller(t)
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)

	work := nativeIntegrationBegin(t, caller, fixture.Provisioning(t))
	defer nativeIntegrationClose(t, caller, work.handle)
	if status, payload := nativeIntegrationCall(t, caller, opCompleteNativeSessionRaw, fixture.Issue(t, work.requestBody), work.handle); status != statusOK || len(payload) != 0 {
		t.Fatalf("native completion = status %d payload %x", status, payload)
	}

	tcpRequest := nativeTCPv4([4]byte{10, 0, 0, 2}, fixture.TCPAddress(t), 50000, fixture.TCPPort(t), 100, 0, 0x02, nil)
	tcpImmediate := nativeIntegrationIngress(t, caller, work.handle, tcpRequest)
	if len(tcpImmediate) != 1 || len(tcpImmediate[0]) < 34 || tcpImmediate[0][33] != 0x12 {
		t.Fatalf("TCP SYN immediate packets = %x", tcpImmediate)
	}
	tcpPayload := []byte("native TCP echo")
	tcpData := nativeTCPv4([4]byte{10, 0, 0, 2}, fixture.TCPAddress(t), 50000, fixture.TCPPort(t), 101, binary.BigEndian.Uint32(tcpImmediate[0][24:28])+1, 0x18, tcpPayload)
	_ = nativeIntegrationIngress(t, caller, work.handle, tcpData)
	tcpResponse := nativeIntegrationNextLocalPacket(t, caller, work.handle)
	if len(tcpResponse) < 40 || !bytes.Equal(tcpResponse[40:], tcpPayload) {
		t.Fatalf("TCP echo response = %x", tcpResponse)
	}

	udpPayload := []byte("native UDP echo")
	udpRequest := nativeUDPv4([4]byte{10, 0, 0, 2}, fixture.UDPAddress(t), 40000, fixture.UDPPort(t), udpPayload)
	_ = nativeIntegrationIngress(t, caller, work.handle, udpRequest)
	udpResponse := nativeIntegrationNextLocalPacket(t, caller, work.handle)
	if len(udpResponse) < 28 || !bytes.Equal(udpResponse[28:], udpPayload) {
		t.Fatalf("UDP echo response = %x", udpResponse)
	}
}

func TestNativeSessionFFIRejectsDuplicateCompletionAndClosesHandle(t *testing.T) {
	caller := newNativeIntegrationCaller(t)
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)

	work := nativeIntegrationBegin(t, caller, fixture.Provisioning(t))
	issuerResponse := fixture.Issue(t, work.requestBody)
	if status, payload := nativeIntegrationCall(t, caller, opCompleteNativeSessionRaw, issuerResponse, work.handle); status != statusOK || len(payload) != 0 {
		t.Fatalf("initial native completion = status %d payload %x", status, payload)
	}
	if status, payload := nativeIntegrationCall(t, caller, opCompleteNativeSessionRaw, issuerResponse, work.handle); status != statusError || len(payload) != 0 {
		t.Fatalf("duplicate native completion = status %d payload %x", status, payload)
	}
	status, payload := nativeIntegrationCall(t, caller, opCloseNativeSession, nil, work.handle)
	if (status != statusOK && status != statusError) || len(payload) != 0 {
		t.Fatalf("native close after duplicate completion = status %d payload %x", status, payload)
	}
	if status, payload := nativeIntegrationCall(t, caller, opCloseNativeSession, nil, work.handle); status != statusError || len(payload) != 0 {
		t.Fatalf("closed native handle = status %d payload %x", status, payload)
	}
}

func TestNativeSessionFFIRejectsSpentAccessHintOnFreshConnection(t *testing.T) {
	caller := newNativeIntegrationCaller(t)
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)

	provisioning := fixture.Provisioning(t)
	work := nativeIntegrationBegin(t, caller, provisioning)
	defer nativeIntegrationClose(t, caller, work.handle)
	if status, payload := nativeIntegrationCall(t, caller, opCompleteNativeSessionRaw, fixture.Issue(t, work.requestBody), work.handle); status != statusOK || len(payload) != 0 {
		t.Fatalf("initial native completion = status %d payload %x", status, payload)
	}
	fixture.waitForConnections(t, 1)

	encoded, err := client.EncodeNativeProvisioning(provisioning)
	if err != nil {
		t.Fatal(err)
	}
	if status, payload := nativeIntegrationCall(t, caller, opBeginNativeSessionJSON, encoded, 0); status != statusError || len(payload) != 0 {
		t.Fatalf("spent access hint begin = status %d payload %x", status, payload)
	}
	fixture.waitForConnections(t, 2)
}

func TestNativeSessionFFIRejectsExpiredProvisioningBeforeNetworkOpen(t *testing.T) {
	caller := newNativeIntegrationCaller(t)
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)

	provisioning := fixture.Provisioning(t)
	accessHint, err := admission.DecodeAccessHintCredential(provisioning.AccessHint)
	if err != nil {
		t.Fatal(err)
	}
	accessHint.ExpiryUnix = uint64(time.Now().Add(-time.Second).Unix())
	provisioning.AccessHint, err = admission.EncodeAccessHintCredential(accessHint)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := client.EncodeNativeProvisioning(provisioning)
	if err != nil {
		t.Fatal(err)
	}
	connections := fixture.ConnectionCount()
	status, payload := nativeIntegrationCall(t, caller, opBeginNativeSessionJSON, encoded, 0)
	if status != statusError || len(payload) != 0 {
		t.Fatalf("expired native provisioning = status %d payload %x", status, payload)
	}
	fixture.assertNoAdditionalConnections(t, connections, 250*time.Millisecond)
}

func TestNativeSessionFFIStopsOnCarrierCancellation(t *testing.T) {
	caller := newNativeIntegrationCaller(t)
	fixture := newNativeSessionFixture(t, time.Now())
	defer fixture.Close(t)

	work := nativeIntegrationBegin(t, caller, fixture.Provisioning(t))
	if status, payload := nativeIntegrationCall(t, caller, opCompleteNativeSessionRaw, fixture.Issue(t, work.requestBody), work.handle); status != statusOK || len(payload) != 0 {
		t.Fatalf("native completion = status %d payload %x", status, payload)
	}
	result := make(chan nativeIntegrationCallResult, 1)
	go func() {
		status, payload, err := caller.call(opNextLocalPacket, nil, work.handle)
		result <- nativeIntegrationCallResult{status: status, payload: payload, err: err}
	}()
	fixture.Close(t)
	select {
	case value := <-result:
		if value.err != nil {
			t.Fatalf("carrier cancellation next packet: %v", value.err)
		}
		if value.status != statusError {
			t.Fatalf("carrier cancellation next packet status = %d", value.status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("carrier cancellation did not unblock native packet wait")
	}
	if status, payload := nativeIntegrationCall(t, caller, opCloseNativeSession, nil, work.handle); status != statusError || len(payload) != 0 {
		t.Fatalf("carrier cancellation retained native handle: status %d payload %x", status, payload)
	}
}

type nativeIntegrationIssuerWork struct {
	handle      uint64
	requestBody []byte
}

type nativeIntegrationCallResult struct {
	status  byte
	payload []byte
	err     error
}

func nativeIntegrationCall(t testing.TB, caller nativeIntegrationCaller, operation int, input []byte, argument uint64) (byte, []byte) {
	t.Helper()
	status, payload, err := caller.call(operation, input, argument)
	if err != nil {
		t.Fatalf("native C ABI operation %d: %v", operation, err)
	}
	return status, payload
}

func nativeIntegrationBegin(t testing.TB, caller nativeIntegrationCaller, provisioning client.NativeProvisioning) nativeIntegrationIssuerWork {
	t.Helper()
	encoded, err := client.EncodeNativeProvisioning(provisioning)
	if err != nil {
		t.Fatal(err)
	}
	status, payload := nativeIntegrationCall(t, caller, opBeginNativeSessionJSON, encoded, 0)
	if status != statusOK {
		t.Fatalf("native begin status = %d", status)
	}
	var work nativeIssuerWorkJSON
	if err := json.Unmarshal(payload, &work); err != nil || work.Handle == 0 {
		t.Fatalf("decode native issuer work: %v (%s)", err, payload)
	}
	requestBody, err := base64.StdEncoding.DecodeString(work.RequestBodyBase64)
	if err != nil || len(requestBody) == 0 {
		t.Fatalf("decode native issuer work body: %v", err)
	}
	return nativeIntegrationIssuerWork{handle: work.Handle, requestBody: requestBody}
}

func nativeIntegrationIngress(t testing.TB, caller nativeIntegrationCaller, handle uint64, packet []byte) [][]byte {
	t.Helper()
	status, payload := nativeIntegrationCall(t, caller, opIngressLocalPacketJSON, packet, handle)
	if status != statusOK {
		t.Fatalf("native ingress status = %d", status)
	}
	var local nativeLocalPacketsJSON
	if err := json.Unmarshal(payload, &local); err != nil {
		t.Fatalf("decode native local packets: %v", err)
	}
	packets := make([][]byte, len(local.PacketsBase64))
	for index, value := range local.PacketsBase64 {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) == 0 {
			t.Fatalf("decode native local packet %d: %v", index, err)
		}
		packets[index] = decoded
	}
	return packets
}

func nativeIntegrationNextLocalPacket(t testing.TB, caller nativeIntegrationCaller, handle uint64) []byte {
	t.Helper()
	status, payload := nativeIntegrationNextLocalPacketResult(t, caller, handle)
	if status != statusOK || len(payload) == 0 {
		t.Fatalf("native next local packet = status %d payload %x", status, payload)
	}
	return payload
}

func nativeIntegrationNextLocalPacketResult(t testing.TB, caller nativeIntegrationCaller, handle uint64) (byte, []byte) {
	t.Helper()
	result := make(chan nativeIntegrationCallResult, 1)
	go func() {
		status, payload, err := caller.call(opNextLocalPacket, nil, handle)
		result <- nativeIntegrationCallResult{status: status, payload: payload, err: err}
	}()
	select {
	case value := <-result:
		if value.err != nil {
			t.Fatalf("native next local packet: %v", value.err)
		}
		return value.status, value.payload
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for native local packet")
		return statusError, nil
	}
}

func nativeIntegrationClose(t testing.TB, caller nativeIntegrationCaller, handle uint64) {
	t.Helper()
	status, payload := nativeIntegrationCall(t, caller, opCloseNativeSession, nil, handle)
	if status != statusOK || len(payload) != 0 {
		t.Fatalf("native close = status %d payload %x", status, payload)
	}
}

func nativeUDPv4(source, target [4]byte, sourcePort, targetPort uint16, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], source[:])
	copy(packet[16:20], target[:])
	binary.BigEndian.PutUint16(packet[10:12], nativeChecksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], targetPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(len(packet)-20))
	copy(packet[28:], payload)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], source[:])
	copy(pseudo[4:8], target[:])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-20))
	checksum := nativeChecksum(pseudo, packet[20:])
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(packet[26:28], checksum)
	return packet
}
