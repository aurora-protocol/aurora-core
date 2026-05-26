package platform

import "testing"

func TestDefaultLinuxTUNConfigRequiresProxyFallback(t *testing.T) {
	config := DefaultLinuxTUNConfig()
	if config.DevicePath != "/dev/net/tun" {
		t.Fatalf("Linux TUN device path = %q", config.DevicePath)
	}
	if config.InterfaceName == "" {
		t.Fatalf("Linux TUN interface name is empty")
	}
	if config.PacketMode != PacketTUN {
		t.Fatalf("Linux packet mode = %s, want %s", config.PacketMode, PacketTUN)
	}
	if config.ContainsCryptoState {
		t.Fatalf("Linux TUN config reported crypto state")
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("default Linux TUN config did not validate: %v", err)
	}
	for _, mode := range []string{LocalSOCKS5, LocalHTTPConnect} {
		if !config.SupportsLocalMode(mode) {
			t.Fatalf("Linux TUN config missing fallback mode %s: %+v", mode, config.LocalModes)
		}
	}
}

func TestLinuxTUNConfigRejectsMissingProxyFallback(t *testing.T) {
	config := DefaultLinuxTUNConfig()
	config.LocalModes = []string{LocalDNSForwarder}
	if err := config.Validate(); err == nil {
		t.Fatalf("Linux TUN config accepted missing SOCKS/HTTP fallback")
	}
}

func TestLinuxTUNConfigRejectsInvalidDeviceSettings(t *testing.T) {
	for name, mutate := range map[string]func(*LinuxTUNConfig){
		"empty device": func(config *LinuxTUNConfig) {
			config.DevicePath = ""
		},
		"empty interface": func(config *LinuxTUNConfig) {
			config.InterfaceName = ""
		},
		"path interface": func(config *LinuxTUNConfig) {
			config.InterfaceName = "tun/0"
		},
		"wrong packet mode": func(config *LinuxTUNConfig) {
			config.PacketMode = PacketNone
		},
		"crypto state": func(config *LinuxTUNConfig) {
			config.ContainsCryptoState = true
		},
		"tiny mtu": func(config *LinuxTUNConfig) {
			config.MTU = 500
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := DefaultLinuxTUNConfig()
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatalf("Linux TUN config accepted invalid settings: %+v", config)
			}
		})
	}
}

func TestLinuxTUNAdapterIsThin(t *testing.T) {
	adapter, err := NewLinuxTUNAdapter(DefaultLinuxTUNConfig(), &recordingCoreSink{})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.HasCryptoState() {
		t.Fatalf("Linux TUN adapter reported crypto state")
	}
	if adapter.Profile().Kind != KindLinux {
		t.Fatalf("Linux TUN adapter profile = %+v", adapter.Profile())
	}
}

func TestLinuxTUNAdapterCopiesConfig(t *testing.T) {
	config := DefaultLinuxTUNConfig()
	adapter, err := NewLinuxTUNAdapter(config, &recordingCoreSink{})
	if err != nil {
		t.Fatal(err)
	}
	config.LocalModes[0] = "mutated"
	got := adapter.Config()
	if got.SupportsLocalMode("mutated") {
		t.Fatalf("Linux TUN adapter retained mutable config slice: %+v", got.LocalModes)
	}
	got.LocalModes[0] = "mutated-again"
	if adapter.Config().SupportsLocalMode("mutated-again") {
		t.Fatalf("Linux TUN adapter exposed mutable config slice")
	}
}

func TestOpenLinuxTUNDeviceRejectsInvalidConfigBeforeOSOpen(t *testing.T) {
	config := DefaultLinuxTUNConfig()
	config.InterfaceName = ""
	if _, err := OpenLinuxTUNDevice(config); err == nil {
		t.Fatalf("OpenLinuxTUNDevice accepted invalid config")
	}
}
