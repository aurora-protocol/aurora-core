package auroracrypto

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

var appendTestSuites = []uint64{
	registry.SuiteHybrid768AESGCM,
	registry.SuiteHybrid768P256AESGCM,
	registry.SuiteHybrid768ChaCha20,
	registry.SuiteHybrid768P256ChaCha20,
	registry.SuiteHybrid1024AESGCM,
	registry.SuiteHybrid1024ChaCha20,
	registry.SuiteLabClassical,
}

// TestAppendSuiteHashMatchesSuiteHash pins the appending form to the allocating
// form for every suite, including when it writes into existing storage.
func TestAppendSuiteHashMatchesSuiteHash(t *testing.T) {
	parts := [][]byte{[]byte("first"), {}, bytes.Repeat([]byte{0x5a}, 300)}
	for _, suite := range appendTestSuites {
		want, err := SuiteHash(suite, parts...)
		if err != nil {
			t.Fatalf("suite 0x%x: %v", suite, err)
		}
		got, err := AppendSuiteHash(nil, suite, parts...)
		if err != nil {
			t.Fatalf("suite 0x%x: %v", suite, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("suite 0x%x: appended hash %x, want %x", suite, got, want)
		}

		// Appending into a populated buffer must leave the prefix intact and
		// place the same digest after it.
		prefix := []byte("prefix")
		var storage [96]byte
		combined, err := AppendSuiteHash(append(storage[:0], prefix...), suite, parts...)
		if err != nil {
			t.Fatalf("suite 0x%x: %v", suite, err)
		}
		if !bytes.Equal(combined[:len(prefix)], prefix) {
			t.Fatalf("suite 0x%x: destination prefix was overwritten", suite)
		}
		if !bytes.Equal(combined[len(prefix):], want) {
			t.Fatalf("suite 0x%x: appended digest %x, want %x", suite, combined[len(prefix):], want)
		}
	}
	if _, err := AppendSuiteHash(nil, 0xdead); err == nil {
		t.Fatal("unsupported suite was hashed")
	}
}

func TestAppendPacketADMatchesPacketAD(t *testing.T) {
	cases := []struct {
		routeInstanceID uint64
		hopLayer        uint8
		direction       uint8
		keyPhase        uint8
		packetNumber    uint64
	}{
		{0, 0, 0, 0, 0},
		{1, 1, 1, 1, 1},
		{16384, 2, 0, 3, 16384},
		{1 << 30, 7, 1, 255, 1 << 40},
	}
	for _, suite := range appendTestSuites {
		for _, c := range cases {
			want, err := PacketAD(suite, c.routeInstanceID, c.hopLayer, c.direction, c.keyPhase, c.packetNumber)
			if err != nil {
				t.Fatalf("suite 0x%x %+v: %v", suite, c, err)
			}
			var storage [64]byte
			got, err := AppendPacketAD(storage[:0], suite, c.routeInstanceID, c.hopLayer, c.direction, c.keyPhase, c.packetNumber)
			if err != nil {
				t.Fatalf("suite 0x%x %+v: %v", suite, c, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("suite 0x%x %+v: appended AD %x, want %x", suite, c, got, want)
			}
		}
	}
	if _, err := AppendPacketAD(nil, registry.SuiteHybrid768AESGCM, 1, 1, 2, 0, 1); err == nil {
		t.Fatal("reserved packet direction produced associated data")
	}
}

func TestAppendXORNonce96MatchesXORNonce96(t *testing.T) {
	staticIV := bytes.Repeat([]byte{0x44}, 12)
	for _, packetNumber := range []uint64{0, 1, 255, 256, 1 << 32, ^uint64(0)} {
		want, err := XORNonce96(staticIV, packetNumber)
		if err != nil {
			t.Fatalf("packet %d: %v", packetNumber, err)
		}
		var storage [12]byte
		got, err := AppendXORNonce96(storage[:0], staticIV, packetNumber)
		if err != nil {
			t.Fatalf("packet %d: %v", packetNumber, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("packet %d: appended nonce %x, want %x", packetNumber, got, want)
		}
		if len(got) != 12 {
			t.Fatalf("packet %d: nonce length %d, want 12", packetNumber, len(got))
		}
		// The static IV must not be modified by the XOR.
		if !bytes.Equal(staticIV, bytes.Repeat([]byte{0x44}, 12)) {
			t.Fatalf("packet %d: static IV was modified", packetNumber)
		}
	}
	if _, err := AppendXORNonce96(nil, bytes.Repeat([]byte{0x44}, 11), 1); err == nil {
		t.Fatal("short static IV produced a nonce")
	}
}
