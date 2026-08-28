package relay

// Regression test: validateSocketDNSServiceBindingHints derives the rdata base
// offset as len(message)-len(rdata), which equals the true rdata start only
// when the SVCB/HTTPS record is the LAST record in the message. When a forged
// upstream response places the SVCB/HTTPS record before another record, the
// target-name skip and the parameter loop run at skewed offsets and the
// ipv4hint/ipv6hint exit-policy checks are bypassed (fail-open). The relay
// speaks cleartext UDP/53 to its upstream (UDPDNSMessageResolver), so response
// forgery is within the threat model this validator exists for.

import (
	"encoding/binary"
	"testing"
)

// craftShiftedSVCBResponse builds a DNS response for an HTTPS query whose
// answer section holds one HTTPS record carrying a loopback ipv4hint
// (policy-denied under the default ExitPolicy). When trailing is true, a dummy
// TXT record follows the HTTPS record so the HTTPS rdata is not the message
// tail; the HTTPS rdata tail is arranged so the skewed parameter loop parses a
// decoy alpn parameter and never sees the hint.
func craftShiftedSVCBResponse(query []byte, trailing bool) []byte {
	// 21-byte SVCB rdata:
	//   [0:2]  priority 1
	//   [2]    root target name (what a correct parser skips)
	//   [3:11] ipv4hint = 127.0.0.1 (loopback: policy-denied)
	//   [11:15] decoy param key=1 (alpn), length 6 (the 0x06 low byte doubles
	//           as the fake 6-byte label length for the skewed name skip)
	//   [15:21] decoy param value / fake label content
	rdata := []byte{
		0x00, 0x01,
		0x00,
		0x00, 0x04, 0x00, 0x04, 127, 0, 0, 1,
		0x00, 0x01, 0x00, 0x06,
		'a', 'a', 'a', 'a', 'a', 'a',
	}
	answerCount := uint16(1)
	if trailing {
		answerCount = 2
	}
	message := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01}
	message = binary.BigEndian.AppendUint16(message, answerCount)
	message = append(message, 0x00, 0x00, 0x00, 0x00)
	message = append(message, query[socketDNSHeaderBytes:]...)
	record := []byte{0xc0, 0x0c} // name: pointer to the question name
	record = binary.BigEndian.AppendUint16(record, socketDNSTypeHTTPS)
	record = binary.BigEndian.AppendUint16(record, socketDNSClassIN)
	record = binary.BigEndian.AppendUint32(record, 60)
	record = binary.BigEndian.AppendUint16(record, uint16(len(rdata)))
	record = append(record, rdata...)
	message = append(message, record...)
	if trailing {
		dummy := []byte{0xc0, 0x0c}                      // name: pointer to the question name
		dummy = binary.BigEndian.AppendUint16(dummy, 16) // TXT: no hint validation
		dummy = binary.BigEndian.AppendUint16(dummy, socketDNSClassIN)
		dummy = binary.BigEndian.AppendUint32(dummy, 60)
		dummy = binary.BigEndian.AppendUint16(dummy, 0)
		message = append(message, dummy...)
	}
	return message
}

func TestValidateSocketDNSResponseRejectsShiftedServiceBindingHint(t *testing.T) {
	query := socketEgressDNSQuery(t, "example.com", socketDNSTypeHTTPS)
	question, err := parseSocketDNSQuestion(query)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}

	t.Run("last record is rejected", func(t *testing.T) {
		message := craftShiftedSVCBResponse(query, false)
		if err := validateSocketDNSResponse(question, message, ExitPolicy{}); err == nil {
			t.Fatal("policy-denied ipv4hint accepted when the HTTPS record is last")
		}
	})

	t.Run("non-final record must be rejected", func(t *testing.T) {
		message := craftShiftedSVCBResponse(query, true)
		if err := validateSocketDNSResponse(question, message, ExitPolicy{}); err == nil {
			t.Fatal("policy-denied ipv4hint bypassed by placing a record after the HTTPS record")
		}
	})
}
