package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/platform"
)

func TestReadinessCheckReportsRunnableServer(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--readiness-check"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned %d stderr=%s", code, stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{
		"server_check passed=true",
		"health=true",
		"cover=true",
		"issuer_metadata=true",
		"blind_rsa_issue=true",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("readiness output missing %q:\n%s", want, text)
		}
	}
}

func TestRunRejectsEmptyListenAddress(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--listen", ""}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run accepted empty listen address stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "listen address") {
		t.Fatalf("stderr missing listen address error: %s", stderr.String())
	}
}

func TestRunTunPacketModeOpensLinuxTUNDevice(t *testing.T) {
	var opened platform.LinuxTUNConfig
	device := &recordingPacketDevice{}
	restoreOpen := setOpenLinuxPacketDeviceForTest(func(config platform.LinuxTUNConfig) (io.ReadWriteCloser, int, error) {
		opened = config
		return device, 1400, nil
	})
	defer restoreOpen()
	restoreListen := setListenAndServeForTest(func(addr string, handler http.Handler) error {
		return http.ErrServerClosed
	})
	defer restoreListen()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--packet-mode", "tun",
		"--tun-device", "/tmp/aurora-tun",
		"--tun-iface", "aurtest0",
		"--tun-mtu", "1400",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if opened.DevicePath != "/tmp/aurora-tun" || opened.InterfaceName != "aurtest0" || opened.MTU != 1400 {
		t.Fatalf("opened TUN config = %+v", opened)
	}
	if !device.closed {
		t.Fatal("packet device was not closed when aurorad exited")
	}
	if !strings.Contains(stdout.String(), "packet_mode=tun") {
		t.Fatalf("stdout missing packet mode: %s", stdout.String())
	}
}

func TestRunRejectsUnknownPacketMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--packet-mode", "bogus"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run accepted unknown packet mode stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "packet mode") {
		t.Fatalf("stderr missing packet mode error: %s", stderr.String())
	}
}

type recordingPacketDevice struct {
	writes [][]byte
	closed bool
}

func (d *recordingPacketDevice) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (d *recordingPacketDevice) Write(packet []byte) (int, error) {
	d.writes = append(d.writes, append([]byte(nil), packet...))
	return len(packet), nil
}

func (d *recordingPacketDevice) Close() error {
	d.closed = true
	return nil
}

func setOpenLinuxPacketDeviceForTest(fn func(platform.LinuxTUNConfig) (io.ReadWriteCloser, int, error)) func() {
	previous := openLinuxPacketDevice
	openLinuxPacketDevice = fn
	return func() {
		openLinuxPacketDevice = previous
	}
}

func setListenAndServeForTest(fn func(string, http.Handler) error) func() {
	previous := listenAndServe
	listenAndServe = fn
	return func() {
		listenAndServe = previous
	}
}
