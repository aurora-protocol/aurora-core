package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestProvisioningWalletStateCanonicalRoundTripAndExpiryPruning(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state := newProvisioningWalletState()
	past := bytes.Repeat([]byte{0x11}, provisioningWalletSpentHintKeyBytes)
	future := bytes.Repeat([]byte{0x22}, provisioningWalletSpentHintKeyBytes)
	if err := state.Add(future, uint64(now.Add(time.Hour).Unix())); err != nil {
		t.Fatal(err)
	}
	if err := state.Add(past, uint64(now.Add(-time.Second).Unix())); err != nil {
		t.Fatal(err)
	}
	encoded, err := state.Encode()
	if err != nil {
		t.Fatal(err)
	}
	defer zeroProxyBytes(encoded)
	parsed, err := parseProvisioningWalletState(encoded, now)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Contains(past) || !parsed.Contains(future) || parsed.Len() != 1 {
		t.Fatalf("parsed wallet state did not prune expired entry: %+v", parsed)
	}
	if err := parsed.Add(future, uint64(now.Add(2*time.Hour).Unix())); err == nil {
		t.Fatal("wallet state accepted duplicate spent hint key")
	}
}

func TestProvisioningWalletStateRejectsNonCanonicalEntries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	encoder := wire.NewEncoder()
	encoder.WriteVarint(provisioningWalletStateFormat)
	encoder.WriteVarint(2)
	encoder.WriteOpaqueFixed(bytes.Repeat([]byte{0x22}, provisioningWalletSpentHintKeyBytes), provisioningWalletSpentHintKeyBytes)
	encoder.WriteUint64(uint64(now.Add(time.Hour).Unix()))
	encoder.WriteOpaqueFixed(bytes.Repeat([]byte{0x11}, provisioningWalletSpentHintKeyBytes), provisioningWalletSpentHintKeyBytes)
	encoder.WriteUint64(uint64(now.Add(time.Hour).Unix()))
	encoded, err := encoder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	defer zeroProxyBytes(encoded)
	if _, err := parseProvisioningWalletState(encoded, now); err == nil {
		t.Fatal("wallet state accepted non-canonical entries")
	}
}

func TestProvisioningWalletStateStorePersistsAtomicTransactions(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "wallet-state.bin")
	store, err := newProvisioningWalletStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x33}, provisioningWalletSpentHintKeyBytes)
	if err := store.Transact(now, func(state *provisioningWalletState) error {
		return state.Add(key, uint64(now.Add(time.Hour).Unix()))
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("wallet state mode = %v, want owner-only regular file", info.Mode())
	}
	if err := store.Transact(now, func(state *provisioningWalletState) error {
		if !state.Contains(key) || state.Len() != 1 {
			t.Fatalf("wallet state was not persisted: %+v", state)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProvisioningWalletStateStoreSerializesConcurrentTransactions(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := newProvisioningWalletStateStore(filepath.Join(directory, "wallet-state.bin"))
	if err != nil {
		t.Fatal(err)
	}
	const reservations = 24
	errors := make(chan error, reservations)
	var group sync.WaitGroup
	for index := range reservations {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			key := bytes.Repeat([]byte{byte(index + 1)}, provisioningWalletSpentHintKeyBytes)
			errors <- store.Transact(now, func(state *provisioningWalletState) error {
				return state.Add(key, uint64(now.Add(time.Hour).Unix()))
			})
		}(index)
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Transact(now, func(state *provisioningWalletState) error {
		if state.Len() != reservations {
			t.Fatalf("wallet state reservations = %d, want %d", state.Len(), reservations)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProvisioningWalletStateStorePersistsReservationBeforeNextUse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := newProvisioningWalletStateStore(filepath.Join(directory, "wallet-state.bin"))
	if err != nil {
		t.Fatal(err)
	}
	source := &recordingProvisioningWalletSource{now: now}
	first, err := store.Reserve(source, now)
	if err != nil {
		t.Fatal(err)
	}
	first.Zero()
	second, err := store.Reserve(source, now)
	if err != nil {
		t.Fatal(err)
	}
	second.Zero()
	if source.calls != 2 || !source.sawPreviousReservation {
		t.Fatalf("wallet source calls=%d sawPrevious=%t, want two calls with durable first reservation", source.calls, source.sawPreviousReservation)
	}
}

func TestProvisioningWalletStateStoreRejectsUnsafeDirectoryAndSymlink(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	unsafePath := filepath.Join(directory, "wallet-state.bin")
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	unsafeStore, err := newProvisioningWalletStateStore(unsafePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := unsafeStore.Transact(now, func(*provisioningWalletState) error { return nil }); err == nil {
		t.Fatal("wallet state accepted a group-readable directory")
	}

	safeDirectory := t.TempDir()
	if err := os.Chmod(safeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(safeDirectory, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(safeDirectory, "wallet-state.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	store, err := newProvisioningWalletStateStore(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Transact(now, func(*provisioningWalletState) error { return nil }); err == nil {
		t.Fatal("wallet state followed a symlink")
	}
}

type recordingProvisioningWalletSource struct {
	now                    time.Time
	calls                  int
	previous               []byte
	sawPreviousReservation bool
}

func FuzzParseProvisioningWalletState(f *testing.F) {
	now := time.Unix(1_700_000_000, 0).UTC()
	state := newProvisioningWalletState()
	if err := state.Add(bytes.Repeat([]byte{0x55}, provisioningWalletSpentHintKeyBytes), uint64(now.Add(time.Hour).Unix())); err != nil {
		f.Fatal(err)
	}
	encoded, err := state.Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = parseProvisioningWalletState(encoded, now)
	})
}

func (source *recordingProvisioningWalletSource) Reserve(alreadyReserved func([]byte) bool, _ time.Time) (client.NativeProvisioningReservation, error) {
	if source.calls > 0 {
		source.sawPreviousReservation = alreadyReserved(source.previous)
	}
	source.calls++
	key := bytes.Repeat([]byte{byte(source.calls)}, provisioningWalletSpentHintKeyBytes)
	source.previous = append(source.previous[:0], key...)
	return client.NativeProvisioningReservation{
		SpentHintKey:         key,
		RelayBucketID:        bytes.Repeat([]byte{0x44}, 16),
		AccessHintExpiryUnix: uint64(source.now.Add(time.Hour).Unix()),
	}, nil
}
