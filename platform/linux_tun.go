package platform

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
)

const (
	defaultLinuxTUNDevicePath    = "/dev/net/tun"
	defaultLinuxTUNInterfaceName = "aurora0"
	defaultLinuxTUNMTU           = 1280
	linuxInterfaceNameLimit      = 16
)

type LinuxTUNConfig struct {
	DevicePath          string
	InterfaceName       string
	MTU                 int
	PacketMode          string
	LocalModes          []string
	ContainsCryptoState bool
}

func DefaultLinuxTUNConfig() LinuxTUNConfig {
	return LinuxTUNConfig{
		DevicePath:    defaultLinuxTUNDevicePath,
		InterfaceName: defaultLinuxTUNInterfaceName,
		MTU:           defaultLinuxTUNMTU,
		PacketMode:    PacketTUN,
		LocalModes: []string{
			LocalSOCKS5,
			LocalHTTPConnect,
			LocalDNSForwarder,
		},
	}
}

func (c LinuxTUNConfig) SupportsLocalMode(mode string) bool {
	for _, candidate := range c.LocalModes {
		if candidate == mode {
			return true
		}
	}
	return false
}

func (c LinuxTUNConfig) Validate() error {
	if strings.TrimSpace(c.DevicePath) == "" {
		return fmt.Errorf("platform: Linux TUN device path is required")
	}
	if strings.TrimSpace(c.InterfaceName) == "" {
		return fmt.Errorf("platform: Linux TUN interface name is required")
	}
	if len(c.InterfaceName) >= linuxInterfaceNameLimit {
		return fmt.Errorf("platform: Linux TUN interface name %q exceeds kernel limit", c.InterfaceName)
	}
	if strings.ContainsAny(c.InterfaceName, "/\x00") {
		return fmt.Errorf("platform: Linux TUN interface name %q contains invalid characters", c.InterfaceName)
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return fmt.Errorf("platform: Linux TUN MTU %d outside supported range", c.MTU)
	}
	if c.PacketMode != PacketTUN {
		return fmt.Errorf("platform: Linux TUN packet mode = %s, want %s", c.PacketMode, PacketTUN)
	}
	if c.ContainsCryptoState {
		return fmt.Errorf("platform: Linux TUN config must not contain crypto state")
	}
	if !c.SupportsLocalMode(LocalSOCKS5) || !c.SupportsLocalMode(LocalHTTPConnect) {
		return fmt.Errorf("platform: Linux TUN config requires SOCKS5 and HTTP CONNECT fallback")
	}
	return nil
}

type LinuxTUNAdapter struct {
	*ThinAdapter
	config LinuxTUNConfig
}

func NewLinuxTUNAdapter(config LinuxTUNConfig, core CoreSink) (*LinuxTUNAdapter, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &LinuxTUNAdapter{
		ThinAdapter: NewThinAdapter(ProfileFor(KindLinux), core),
		config:      cloneLinuxTUNConfig(config),
	}, nil
}

func (a *LinuxTUNAdapter) Config() LinuxTUNConfig {
	if a == nil {
		return LinuxTUNConfig{}
	}
	return cloneLinuxTUNConfig(a.config)
}

type LinuxTUNDevice struct {
	mu            sync.Mutex
	closeOnce     sync.Once
	closeErr      error
	file          *os.File
	interfaceName string
	mtu           int
}

func OpenLinuxTUNDevice(config LinuxTUNConfig) (*LinuxTUNDevice, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("platform: Linux TUN device open is unsupported on %s", runtime.GOOS)
	}
	return openLinuxTUNDevice(config)
}

func (d *LinuxTUNDevice) InterfaceName() string {
	if d == nil {
		return ""
	}
	return d.interfaceName
}

func (d *LinuxTUNDevice) MTU() int {
	if d == nil {
		return 0
	}
	return d.mtu
}

func (d *LinuxTUNDevice) Read(packet []byte) (int, error) {
	file := d.openFile()
	if file == nil {
		return 0, fmt.Errorf("platform: Linux TUN device is closed")
	}
	return file.Read(packet)
}

func (d *LinuxTUNDevice) Write(packet []byte) (int, error) {
	file := d.openFile()
	if file == nil {
		return 0, fmt.Errorf("platform: Linux TUN device is closed")
	}
	return file.Write(packet)
}

func (d *LinuxTUNDevice) Close() error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		d.mu.Lock()
		file := d.file
		d.file = nil
		d.mu.Unlock()
		if file != nil {
			d.closeErr = file.Close()
		}
	})
	return d.closeErr
}

func newLinuxTUNDevice(file *os.File, interfaceName string, mtu int) *LinuxTUNDevice {
	return &LinuxTUNDevice{file: file, interfaceName: interfaceName, mtu: mtu}
}

func (d *LinuxTUNDevice) openFile() *os.File {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.file
}

func cloneLinuxTUNConfig(config LinuxTUNConfig) LinuxTUNConfig {
	config.LocalModes = append([]string(nil), config.LocalModes...)
	return config
}

var (
	_ io.ReadWriteCloser = (*LinuxTUNDevice)(nil)
)
