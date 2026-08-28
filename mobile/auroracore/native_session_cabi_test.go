//go:build cgo

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
)

const (
	nativeIntegrationMaximumABIFrame = 16 << 20
	// The call and close timeouts are watchdogs against a wedged harness, not
	// latency assertions. Each call spawns a freshly compiled c-archive binary
	// whose first response bears exec, dynamic linking, and Go runtime startup;
	// under `go test -race ./...` load that cold start can legitimately take
	// several seconds, so the bounds carry generous headroom.
	nativeIntegrationCallTimeout  = 30 * time.Second
	nativeIntegrationCloseTimeout = 10 * time.Second
	nativeIntegrationOversizedCall   = 1<<31 - 1
	nativeIntegrationOversizedFree   = nativeIntegrationOversizedCall - 1
	nativeIntegrationDuplicateFree   = nativeIntegrationOversizedFree - 1
)

type nativeIntegrationCaller interface {
	call(int, []byte, uint64) (byte, []byte, error)
}

type nativeIntegrationDispatchCaller struct{}

func (nativeIntegrationDispatchCaller) call(operation int, input []byte, argument uint64) (byte, []byte, error) {
	status, payload := dispatch(operation, input, argument)
	return status, payload, nil
}

type nativeIntegrationCABICaller struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  io.ReadCloser
	stderr  nativeIntegrationLogBuffer
	timeout time.Duration
	mu      sync.Mutex
}

type nativeIntegrationLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *nativeIntegrationLogBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(value)
}

func (b *nativeIntegrationLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

var nativeIntegrationArchive struct {
	once    sync.Once
	dir     string
	harness string
	err     error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if nativeIntegrationArchive.dir != "" {
		_ = os.RemoveAll(nativeIntegrationArchive.dir)
	}
	os.Exit(code)
}

func TestNativeIntegrationCABICallerDeadlineReleasesHarness(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("shell-backed deadline test is unsupported on %s", runtime.GOOS)
	}
	command := exec.Command("sh", "-c", "cat >/dev/null")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	caller := &nativeIntegrationCABICaller{command: command, input: input, output: output, timeout: 50 * time.Millisecond}
	if err := command.Start(); err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	start := time.Now()
	if _, _, err := caller.call(opEncodeMetadataRequest, nil, 0); err == nil {
		t.Fatal("blocked C ABI caller succeeded")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("blocked C ABI caller exceeded deadline: %s", elapsed)
	}
	lockReleased := make(chan struct{})
	go func() {
		caller.mu.Lock()
		defer caller.mu.Unlock()
		close(lockReleased)
	}()
	select {
	case <-lockReleased:
	case <-time.After(time.Second):
		t.Fatal("blocked C ABI caller retained its cleanup lock")
	}
	_ = command.Wait()
}

func TestNativeCallInputLengthIsBoundedBeforeCopy(t *testing.T) {
	for _, input := range []struct {
		name   string
		length int
		valid  bool
	}{
		{name: "empty", length: 0, valid: true},
		{name: "largest valid", length: maximumNativeCallInputBytes, valid: true},
		{name: "too large", length: maximumNativeCallInputBytes + 1},
		{name: "negative", length: -1},
	} {
		t.Run(input.name, func(t *testing.T) {
			if got := nativeCallInputLengthValid(input.length); got != input.valid {
				t.Fatalf("native input length %d valid=%t, want %t", input.length, got, input.valid)
			}
		})
	}
}

func TestNativeIntegrationCABIRejectsOversizedLengthBeforeRead(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("native archive process test is unsupported on %s", runtime.GOOS)
	}
	caller := newNativeIntegrationCABICaller(t)
	status, payload, err := caller.call(nativeIntegrationOversizedCall, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if status != statusError || len(payload) != 0 {
		t.Fatalf("oversized native input = status %d payload %x", status, payload)
	}
}

func TestNativeIntegrationCABIUsesRecordedOutputLengthForRelease(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("native archive process test is unsupported on %s", runtime.GOOS)
	}
	caller := newNativeIntegrationCABICaller(t)
	status, payload, err := caller.call(nativeIntegrationOversizedFree, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if status != statusError || len(payload) != 0 {
		t.Fatalf("oversized native release = status %d payload %x", status, payload)
	}
}

func TestNativeIntegrationCABIRejectsDuplicateOutputRelease(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("native archive process test is unsupported on %s", runtime.GOOS)
	}
	caller := newNativeIntegrationCABICaller(t)
	status, payload, err := caller.call(nativeIntegrationDuplicateFree, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if status != statusError || len(payload) != 0 {
		t.Fatalf("duplicate native release = status %d payload %x", status, payload)
	}
}

func newNativeIntegrationCaller(t testing.TB, trusted client.NativeProvisioningTrust) nativeIntegrationCaller {
	t.Helper()
	caller := newNativeIntegrationCallerWithoutTrust(t)
	configureNativeIntegrationProvisioningTrust(t, caller, trusted)
	return caller
}

func newNativeIntegrationCallerWithoutTrust(t testing.TB) nativeIntegrationCaller {
	t.Helper()
	var caller nativeIntegrationCaller
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Logf("native archive process test is unsupported on %s; using the dispatcher fallback", runtime.GOOS)
		caller = nativeIntegrationDispatchCaller{}
	} else {
		caller = newNativeIntegrationCABICaller(t)
	}
	return caller
}

func configureNativeIntegrationProvisioningTrust(t testing.TB, caller nativeIntegrationCaller, trusted client.NativeProvisioningTrust) {
	t.Helper()
	encoded, err := client.EncodeNativeProvisioningTrust(trusted)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encoded)
	status, payload, err := caller.call(opConfigureNativeProvisioningTrust, encoded, 0)
	zeroNativeBytes(payload)
	if err != nil || status != statusOK {
		t.Fatalf("configure native provisioning trust: status=%d err=%v", status, err)
	}
}

func newNativeIntegrationCABICaller(t testing.TB) *nativeIntegrationCABICaller {
	t.Helper()
	harness := nativeIntegrationArchiveHarness(t)
	command := exec.Command(harness)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	caller := &nativeIntegrationCABICaller{command: command, input: input, output: output}
	command.Stderr = &caller.stderr
	if err := command.Start(); err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { caller.close(t) })
	return caller
}

func nativeIntegrationArchiveHarness(t testing.TB) string {
	t.Helper()
	nativeIntegrationArchive.once.Do(func() {
		nativeIntegrationArchive.dir, nativeIntegrationArchive.err = os.MkdirTemp("", "aurora-native-cabi-")
		if nativeIntegrationArchive.err != nil {
			return
		}
		_, callerFile, _, ok := runtime.Caller(0)
		if !ok {
			nativeIntegrationArchive.err = os.ErrNotExist
			return
		}
		packageDir := filepath.Dir(callerFile)
		moduleRoot := filepath.Clean(filepath.Join(packageDir, "..", ".."))
		archive := filepath.Join(nativeIntegrationArchive.dir, "auroracore.a")
		build := exec.Command("go", "build", "-buildmode=c-archive", "-o", archive, "./mobile/auroracore")
		build.Dir = moduleRoot
		if output, err := build.CombinedOutput(); err != nil {
			nativeIntegrationArchive.err = &nativeIntegrationCommandError{command: "build native archive", err: err, output: output}
			return
		}
		nativeIntegrationArchive.harness = filepath.Join(nativeIntegrationArchive.dir, "auroracore-call-harness")
		compiler := exec.Command("cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-I", nativeIntegrationArchive.dir, filepath.Join(packageDir, "testdata", "auroracore_call_harness.c"), archive, "-o", nativeIntegrationArchive.harness)
		if runtime.GOOS == "darwin" {
			compiler.Args = append(compiler.Args, "-framework", "CoreFoundation", "-framework", "Security")
		}
		if runtime.GOOS == "linux" {
			compiler.Args = append(compiler.Args, "-pthread")
		}
		if output, err := compiler.CombinedOutput(); err != nil {
			nativeIntegrationArchive.err = &nativeIntegrationCommandError{command: "build C ABI harness", err: err, output: output}
		}
	})
	if nativeIntegrationArchive.err != nil {
		t.Fatal(nativeIntegrationArchive.err)
	}
	return nativeIntegrationArchive.harness
}

func (c *nativeIntegrationCABICaller) call(operation int, input []byte, argument uint64) (byte, []byte, error) {
	if c == nil {
		return 0, nil, fmt.Errorf("native C ABI caller is unavailable")
	}
	if len(input) > nativeIntegrationMaximumABIFrame {
		return 0, nil, fmt.Errorf("native C ABI input exceeds limit: %d", len(input))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.command == nil || c.command.Process == nil || c.input == nil || c.output == nil {
		return 0, nil, fmt.Errorf("native C ABI caller is unavailable")
	}
	process := c.command.Process
	inputPipe := c.input
	outputPipe := c.output
	timedOut := make(chan struct{})
	timeout := c.timeout
	if timeout <= 0 {
		timeout = nativeIntegrationCallTimeout
	}
	timer := time.AfterFunc(timeout, func() {
		_ = inputPipe.Close()
		_ = outputPipe.Close()
		_ = process.Kill()
		close(timedOut)
	})
	defer func() {
		if !timer.Stop() {
			<-timedOut
		}
	}()
	var header [16]byte
	binary.BigEndian.PutUint32(header[0:4], uint32(operation))
	binary.BigEndian.PutUint64(header[4:12], argument)
	binary.BigEndian.PutUint32(header[12:16], uint32(len(input)))
	if _, err := inputPipe.Write(header[:]); err != nil {
		return 0, nil, c.callError("write header", err)
	}
	if len(input) != 0 {
		if _, err := inputPipe.Write(input); err != nil {
			return 0, nil, c.callError("write input", err)
		}
	}
	var length [4]byte
	if _, err := io.ReadFull(outputPipe, length[:]); err != nil {
		return 0, nil, c.callError("read result length", err)
	}
	resultLength := binary.BigEndian.Uint32(length[:])
	if resultLength == 0 || resultLength > nativeIntegrationMaximumABIFrame {
		return 0, nil, fmt.Errorf("native C ABI result length = %d", resultLength)
	}
	result := make([]byte, resultLength)
	if _, err := io.ReadFull(outputPipe, result); err != nil {
		return 0, nil, c.callError("read result", err)
	}
	return result[0], append([]byte(nil), result[1:]...), nil
}

func (c *nativeIntegrationCABICaller) callError(operation string, err error) error {
	if c == nil {
		return fmt.Errorf("native C ABI %s: %w", operation, err)
	}
	return fmt.Errorf("native C ABI %s: %w; stderr=%s", operation, err, c.stderr.String())
}

func (c *nativeIntegrationCABICaller) close(t testing.TB) {
	t.Helper()
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.command == nil {
		return
	}
	if c.input != nil {
		_ = c.input.Close()
		c.input = nil
	}
	process := c.command.Process
	wait := make(chan error, 1)
	go func() { wait <- c.command.Wait() }()
	select {
	case err := <-wait:
		if err != nil {
			t.Errorf("native C ABI harness: %v; stderr=%s", err, c.stderr.String())
		}
	case <-time.After(nativeIntegrationCloseTimeout):
		_ = process.Kill()
		if err := <-wait; err != nil {
			t.Errorf("native C ABI harness did not exit cleanly: %v; stderr=%s", err, c.stderr.String())
		}
	}
	c.command = nil
}

type nativeIntegrationCommandError struct {
	command string
	err     error
	output  []byte
}

func (e *nativeIntegrationCommandError) Error() string {
	return e.command + ": " + e.err.Error() + ": " + strconv.Quote(string(e.output))
}
