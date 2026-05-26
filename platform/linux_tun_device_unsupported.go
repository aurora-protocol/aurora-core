//go:build !linux

package platform

import "fmt"

func openLinuxTUNDevice(config LinuxTUNConfig) (*LinuxTUNDevice, error) {
	return nil, fmt.Errorf("platform: Linux TUN device open is unsupported for %s", config.InterfaceName)
}
