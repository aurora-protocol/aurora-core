//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"golang.org/x/sys/unix"
)

type provisioningWalletStateStore struct {
	path     string
	lockPath string
}

func newProvisioningWalletStateStore(path string) (*provisioningWalletStateStore, error) {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(path) != path {
		return nil, fmt.Errorf("client: wallet state path is invalid")
	}
	return &provisioningWalletStateStore{path: path, lockPath: path + ".lock"}, nil
}

func transactProvisioningWalletState(store *provisioningWalletStateStore, now time.Time, update func(*provisioningWalletState) error) error {
	if store == nil || store.path == "" || store.lockPath == "" {
		return fmt.Errorf("client: wallet state store is unavailable")
	}
	if now.IsZero() || now.Unix() < 0 {
		return fmt.Errorf("client: wallet state requires a valid time")
	}
	if update == nil {
		return fmt.Errorf("client: wallet state update is required")
	}
	directory := filepath.Dir(store.path)
	if err := validateProvisioningWalletStateDirectory(directory); err != nil {
		return err
	}
	lock, err := openProvisioningWalletStateFile(store.lockPath, unix.O_CREAT|unix.O_RDWR)
	if err != nil {
		return fmt.Errorf("client: open wallet state lock: %w", err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("client: lock wallet state: %w", err)
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()

	state, err := readProvisioningWalletState(store.path, now)
	if err != nil {
		return err
	}
	if err := update(state); err != nil {
		return err
	}
	state.prune(now)
	encoded, err := state.Encode()
	if err != nil {
		return err
	}
	defer zeroProxyBytes(encoded)
	if err := writeProvisioningWalletState(directory, store.path, encoded); err != nil {
		return err
	}
	return nil
}

func (store *provisioningWalletStateStore) Reserve(wallet provisioningWalletSource, sourceDigest [provisioningWalletSourceDigestBytes]byte, now time.Time) (client.NativeProvisioningReservation, error) {
	if wallet == nil {
		return client.NativeProvisioningReservation{}, client.ErrNoUsableNativeProvisioning
	}
	var reservation client.NativeProvisioningReservation
	err := store.Transact(now, func(state *provisioningWalletState) error {
		state.bindSourceDigest(sourceDigest)
		var err error
		reservation, err = wallet.Reserve(state.Contains, now)
		if err != nil {
			return err
		}
		if reservation.AccessHintExpiryUnix <= uint64(now.Unix()) {
			reservation.Zero()
			return fmt.Errorf("client: wallet reservation is expired")
		}
		if err := state.Add(reservation.SpentHintKey, reservation.AccessHintExpiryUnix); err != nil {
			reservation.Zero()
			return err
		}
		return nil
	})
	if err != nil {
		reservation.Zero()
		return client.NativeProvisioningReservation{}, err
	}
	return reservation, nil
}

func validateProvisioningWalletStateDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("client: inspect wallet state directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("client: wallet state directory is not owner-only")
	}
	if err := validateProvisioningWalletStateOwner(info); err != nil {
		return fmt.Errorf("client: wallet state directory: %w", err)
	}
	return nil
}

func openProvisioningWalletStateFile(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create wallet state file handle")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("wallet state file is not owner-only regular")
	}
	if err := validateProvisioningWalletStateOwner(info); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateProvisioningWalletStateOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("wallet state owner does not match the current user")
	}
	return nil
}

func readProvisioningWalletState(path string, now time.Time) (*provisioningWalletState, error) {
	file, err := openProvisioningWalletStateFile(path, unix.O_RDONLY)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return newProvisioningWalletState(), nil
		}
		return nil, fmt.Errorf("client: open wallet state: %w", err)
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, maximumProvisioningWalletStateBytes+1))
	if err != nil {
		zeroProxyBytes(encoded)
		return nil, fmt.Errorf("client: read wallet state: %w", err)
	}
	defer zeroProxyBytes(encoded)
	return parseProvisioningWalletState(encoded, now)
}

func writeProvisioningWalletState(directory, path string, encoded []byte) error {
	temporary, err := os.CreateTemp(directory, ".wallet-state-*")
	if err != nil {
		return fmt.Errorf("client: create wallet state temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("client: restrict wallet state temporary file: %w", err)
	}
	if err := writeAllProvisioningWalletState(temporary, encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("client: sync wallet state temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("client: close wallet state temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("client: replace wallet state: %w", err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("client: open wallet state directory: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("client: sync wallet state directory: %w", err)
	}
	return nil
}

func writeAllProvisioningWalletState(file *os.File, encoded []byte) error {
	for len(encoded) > 0 {
		written, err := file.Write(encoded)
		if err != nil {
			return fmt.Errorf("client: write wallet state: %w", err)
		}
		if written == 0 {
			return fmt.Errorf("client: write wallet state: %w", io.ErrShortWrite)
		}
		encoded = encoded[written:]
	}
	return nil
}
