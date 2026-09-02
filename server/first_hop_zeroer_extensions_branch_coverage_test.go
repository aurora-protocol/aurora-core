package server

// Coverage for the loop body of zeroFirstHopExtensions
// (server/first_hop.go:1143-1148), reached from zeroFirstHopPrelude0 (:1121)
// and zeroFirstHopPrelude1 (:1139). The existing zeroer tests only pass nil
// preludes (first_hop_zeroer_nil_safety_branch_coverage_test.go) and the live
// first-hop paths only ever build preludes with nil Extensions (see
// decode_first_hop_prelude0_trailing_branch_coverage_test.go), so the
// extension-body erase and per-entry reset never executed.
//
// The test drives populated preludes carrying extensions with non-zero Body
// bytes through the same destroy helpers the live teardown path uses, then
// proves both halves of the contract: the captured Body backing arrays are
// zeroed in place, and each prelude struct is reset to its zero value
// (Extensions nil, every byte-slice field nil).
//
// In-package (package server) matches the existing zeroer test family. No
// network, no goroutine, no crypto — the prelude fields need only be non-zero,
// not wire-valid.

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestZeroFirstHopPreludesEraseExtensions(t *testing.T) {
	prelude0Body := bytes.Repeat([]byte{0xA5}, 24)
	prelude0 := &protocol.CoverPrelude0{
		MsgType:     registry.MsgCoverPrelude0,
		Version:     registry.Version20,
		ClientNonce: bytes.Repeat([]byte{0x11}, 32),
		Extensions: []protocol.Extension{
			{ExtensionType: 1, Critical: true, Body: prelude0Body},
		},
	}
	zeroFirstHopPrelude0(prelude0)
	if !bytes.Equal(prelude0Body, make([]byte, len(prelude0Body))) {
		t.Fatal("zeroFirstHopPrelude0 retained extension body bytes")
	}
	if !reflect.DeepEqual(*prelude0, protocol.CoverPrelude0{}) {
		t.Fatalf("zeroFirstHopPrelude0 left non-zero struct state: %+v", *prelude0)
	}

	prelude1Body := bytes.Repeat([]byte{0x5A}, 24)
	prelude1 := &protocol.CoverPrelude1{
		MsgType:     registry.MsgCoverPrelude1,
		Version:     registry.Version20,
		ServerNonce: bytes.Repeat([]byte{0x21}, 32),
		Extensions: []protocol.Extension{
			{ExtensionType: 2, Body: prelude1Body},
		},
	}
	zeroFirstHopPrelude1(prelude1)
	if !bytes.Equal(prelude1Body, make([]byte, len(prelude1Body))) {
		t.Fatal("zeroFirstHopPrelude1 retained extension body bytes")
	}
	if !reflect.DeepEqual(*prelude1, protocol.CoverPrelude1{}) {
		t.Fatalf("zeroFirstHopPrelude1 left non-zero struct state: %+v", *prelude1)
	}
}
