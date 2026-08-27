//go:build linux

package platform

import (
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

const privilegedLinuxTUNTestEnvironment = "AURORA_PRIVILEGED_TUN_TEST"

func TestLinuxTUNRequestRequiresExclusiveCreation(t *testing.T) {
	ifreq, err := newExclusiveLinuxTUNIfreq(defaultLinuxTUNInterfaceName)
	if err != nil {
		t.Fatal(err)
	}
	want := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	if got := ifreq.Uint16(); got != want {
		t.Fatalf("Linux TUN flags = %#x, want exclusive create flags %#x", got, want)
	}
}

func TestOpenLinuxTUNDeviceRejectsPreexistingPersistentInterface(t *testing.T) {
	if os.Getenv(privilegedLinuxTUNTestEnvironment) != "1" {
		t.Skipf("set %s=1 and run with CAP_NET_ADMIN", privilegedLinuxTUNTestEnvironment)
	}

	interfaceName := createPersistentLinuxTUN(t)
	before := snapshotLinuxTUNInterface(t, interfaceName)
	config := DefaultLinuxTUNConfig()
	config.InterfaceName = interfaceName

	device, err := OpenLinuxTUNDevice(config)
	if device != nil {
		_ = device.Close()
	}
	if err == nil {
		t.Fatal("exclusive Linux TUN open attached to an existing persistent interface")
	}
	if !errors.Is(err, unix.EBUSY) {
		t.Fatalf("exclusive Linux TUN open error = %v, want EBUSY", err)
	}
	if after := snapshotLinuxTUNInterface(t, interfaceName); after != before {
		t.Fatalf("existing Linux TUN state changed: before=%+v after=%+v", before, after)
	}
}

func createPersistentLinuxTUN(t *testing.T) string {
	t.Helper()
	file, err := os.OpenFile(defaultLinuxTUNDevicePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open Linux TUN control device: %v", err)
	}
	defer func() { _ = file.Close() }()

	ifreq, err := unix.NewIfreq("aurora%d")
	if err != nil {
		t.Fatalf("prepare persistent Linux TUN: %v", err)
	}
	ifreq.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, ifreq); err != nil {
		t.Fatalf("create persistent Linux TUN: %v", err)
	}
	if err := unix.IoctlSetInt(int(file.Fd()), unix.TUNSETPERSIST, 1); err != nil {
		t.Fatalf("persist Linux TUN: %v", err)
	}
	interfaceName := ifreq.Name()
	t.Cleanup(func() { removePersistentLinuxTUN(t, interfaceName) })
	return interfaceName
}

func removePersistentLinuxTUN(t *testing.T, interfaceName string) {
	t.Helper()
	file, err := os.OpenFile(defaultLinuxTUNDevicePath, os.O_RDWR, 0)
	if err != nil {
		t.Errorf("open Linux TUN control device for cleanup: %v", err)
		return
	}
	defer func() { _ = file.Close() }()

	ifreq, err := unix.NewIfreq(interfaceName)
	if err != nil {
		t.Errorf("prepare Linux TUN cleanup: %v", err)
		return
	}
	ifreq.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, ifreq); err != nil {
		t.Errorf("attach persistent Linux TUN for cleanup: %v", err)
		return
	}
	if err := unix.IoctlSetInt(int(file.Fd()), unix.TUNSETPERSIST, 0); err != nil {
		t.Errorf("remove persistent Linux TUN: %v", err)
	}
}

type linuxTUNInterfaceSnapshot struct {
	Index        int
	MTU          int
	Name         string
	HardwareAddr string
	Flags        net.Flags
}

func snapshotLinuxTUNInterface(t *testing.T, interfaceName string) linuxTUNInterfaceSnapshot {
	t.Helper()
	device, err := net.InterfaceByName(interfaceName)
	if err != nil {
		t.Fatalf("inspect Linux TUN interface %s: %v", interfaceName, err)
	}
	return linuxTUNInterfaceSnapshot{
		Index:        device.Index,
		MTU:          device.MTU,
		Name:         device.Name,
		HardwareAddr: device.HardwareAddr.String(),
		Flags:        device.Flags,
	}
}
