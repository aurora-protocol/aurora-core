package relay

import (
	"errors"
	"testing"
)

// A SVCB target name that runs past its own rdata used to leave the parameter
// offset beyond len(rdata), so the SvcParam loop never ran and every ipv4hint
// and ipv6hint in that record skipped its destination-policy check. The record
// is malformed, so it must be rejected rather than silently trusted.
func TestValidateSocketDNSServiceBindingHintsRejectsTargetNameBeyondRdata(t *testing.T) {
	// rdata: priority(2) + an unterminated 5-byte label, so the name only ends
	// in the bytes that follow this record inside the full message.
	rdata := []byte{0x00, 0x01, 0x05, 'a', 'b', 'c', 'd', 'e'}
	// The message continues with the root label, then a loopback ipv4hint that
	// the exit policy must never accept.
	message := append(append([]byte{}, rdata...), 0x00,
		0x00, byte(socketDNSSvcIPv4), 0x00, 0x04, 127, 0, 0, 1)
	if err := validateSocketDNSServiceBindingHints(message, rdata, 0, ExitPolicy{}); !errors.Is(err, ErrExitEventInvalid) {
		t.Fatalf("target name past rdata err = %v, want ErrExitEventInvalid", err)
	}
}
