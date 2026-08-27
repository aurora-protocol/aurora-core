//go:build linux

package platform

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openLinuxTUNDevice(config LinuxTUNConfig) (*LinuxTUNDevice, error) {
	file, err := os.OpenFile(config.DevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("platform: open Linux TUN device %s: %w", config.DevicePath, err)
	}
	ifreq, err := newExclusiveLinuxTUNIfreq(config.InterfaceName)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("platform: prepare Linux TUN interface %s: %w", config.InterfaceName, err)
	}
	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, ifreq); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("platform: create exclusive Linux TUN interface %s: %w", config.InterfaceName, err)
	}
	return newLinuxTUNDevice(file, ifreq.Name(), config.MTU), nil
}

func newExclusiveLinuxTUNIfreq(interfaceName string) (*unix.Ifreq, error) {
	ifreq, err := unix.NewIfreq(interfaceName)
	if err != nil {
		return nil, err
	}
	ifreq.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	return ifreq, nil
}
