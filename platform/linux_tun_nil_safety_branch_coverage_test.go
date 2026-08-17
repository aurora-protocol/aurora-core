package platform

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across platform/linux_tun.go. Each guard exists so a caller that holds
// a nil *LinuxTUNAdapter / *LinuxTUNDevice does not panic or proceed into the
// device-I/O path: the method returns at its very first statement, before any
// field is dereferenced (a.config, d.file, d.interfaceName, d.mtu, d.mu,
// d.closeOnce). The existing platform tests only ever drive a fully-built
// adapter / device (and the linux-only open path is build-tag-gated), so the
// nil-receiver guards stayed count-0 even though each is plainly reachable.
//
// These are nil-RECEIVER guards. None of the guarded methods take a context, so
// there is no SA1012 surface. No network, no goroutine, no crypto — each call
// returns at the first statement (Read/Write are NOT exercised here; only the
// nil-receiver guards of Config / InterfaceName / MTU / Close / openFile). The
// test is in-package because openFile is unexported.
//
//   - :95  (*LinuxTUNAdapter).Config()        a == nil -> LinuxTUNConfig{}
//     (the zero value, distinct from DefaultLinuxTUNConfig which sets
//     DevicePath="/dev/net/tun" and MTU=1280)
//   - :121 (*LinuxTUNDevice).InterfaceName()  d == nil -> ""
//   - :128 (*LinuxTUNDevice).MTU()            d == nil -> 0
//   - :151 (*LinuxTUNDevice).Close()          d == nil -> nil
//   - :171 (*LinuxTUNDevice).openFile()       d == nil -> nil (UNEXPORTED)
//
// This test file adds only TestXxx entry points and uses existing exported
// (plus unexported, in-package) symbols, so it adds no U1000 surface.

import (
	"testing"
)

func TestLinuxTUNAdapterNilReceiverGuard(t *testing.T) {
	// 95: a nil *LinuxTUNAdapter returns the zero LinuxTUNConfig (not the default
	// config): an empty DevicePath and zero MTU distinguish it from
	// DefaultLinuxTUNConfig, proving the nil guard returned the zero value.
	var a *LinuxTUNAdapter
	cfg := a.Config()
	if cfg.DevicePath != "" || cfg.MTU != 0 || cfg.InterfaceName != "" {
		t.Fatalf("nil.Config = %+v, want zero LinuxTUNConfig{} (:95 should return the zero value)", cfg)
	}
}

func TestLinuxTUNDeviceNilReceiverGuards(t *testing.T) {
	// 121/128/151/171: a nil *LinuxTUNDevice returns at the first statement of
	// InterfaceName / MTU / Close / openFile rather than dereferencing d.file /
	// d.interfaceName / d.mtu / d.mu / d.closeOnce.
	var d *LinuxTUNDevice

	// 121: InterfaceName returns "".
	if name := d.InterfaceName(); name != "" {
		t.Fatalf("nil.InterfaceName = %q, want \"\" (:121)", name)
	}

	// 128: MTU returns 0.
	if mtu := d.MTU(); mtu != 0 {
		t.Fatalf("nil.MTU = %d, want 0 (:128)", mtu)
	}

	// 151: Close returns nil.
	if err := d.Close(); err != nil {
		t.Fatalf("nil.Close err = %v, want nil (:151 should return nil)", err)
	}

	// 171: openFile (unexported) returns nil.
	if file := d.openFile(); file != nil {
		t.Fatalf("nil.openFile = %v, want nil (:171 should return nil)", file)
	}
}