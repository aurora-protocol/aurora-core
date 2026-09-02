package route

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

// FuzzDecodePrivatePrelude drives the private prelude decoder that runs on
// AEAD-opened route prelude plaintext. The plaintext is authenticated, but a
// confused or malicious peer can still place arbitrary bytes inside a valid
// wrap, so the decoder must not panic and must stay fail-closed: it rejects
// trailing bytes, so an accepted encoding must re-encode to the exact input.
// A second wire form for one prelude would make the hop transcript malleable.
func FuzzDecodePrivatePrelude(f *testing.F) {
	valid, err := protocol.Encode(routeCovEncodablePrivatePrelude())
	if err != nil {
		f.Fatal(err)
	}
	withExtras := routeCovEncodablePrivatePrelude()
	withExtras.Padding = []byte{0x00, 0x00, 0x00}
	withExtras.Extensions = []protocol.Extension{{ExtensionType: 0x401, Critical: false, Body: []byte{0xde, 0xad}}}
	validWithExtras, err := protocol.Encode(withExtras)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(validWithExtras)
	f.Add([]byte{})
	f.Add([]byte{0x02})                                // single varint (a plausible MsgType), then underflow
	f.Add(valid[:len(valid)-1])                        // truncated mid-extensions
	f.Add(append(append([]byte(nil), valid...), 0xff)) // trailing byte
	f.Add(bytes.Repeat([]byte{0xff}, len(valid)))      // garbage at valid length

	f.Fuzz(func(t *testing.T, encoded []byte) {
		decoded, err := DecodePrivatePrelude(encoded)
		if err != nil {
			return
		}
		reencoded, err := protocol.Encode(decoded)
		if err != nil {
			t.Fatalf("decoded private prelude failed to re-encode: %v", err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Fatalf("private prelude re-encoded to %x, want %x", reencoded, encoded)
		}
	})
}
