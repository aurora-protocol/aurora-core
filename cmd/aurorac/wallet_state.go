package main

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	provisioningWalletStateFormat         uint64 = 1
	provisioningWalletSpentHintKeyBytes          = 48
	maximumProvisioningWalletStateEntries        = 65536
	maximumProvisioningWalletStateBytes          = 4 << 20
)

type provisioningWalletState struct {
	reservations map[string]uint64
}

type provisioningWalletSource interface {
	Reserve(func([]byte) bool, time.Time) (client.NativeProvisioningReservation, error)
}

func newProvisioningWalletState() *provisioningWalletState {
	return &provisioningWalletState{reservations: make(map[string]uint64)}
}

func parseProvisioningWalletState(encoded []byte, now time.Time) (*provisioningWalletState, error) {
	if now.IsZero() || now.Unix() < 0 {
		return nil, fmt.Errorf("client: wallet state requires a valid time")
	}
	if len(encoded) == 0 || len(encoded) > maximumProvisioningWalletStateBytes {
		return nil, fmt.Errorf("client: wallet state size is invalid")
	}
	reader := wire.NewReader(encoded)
	if format := reader.ReadVarint(); format != provisioningWalletStateFormat {
		return nil, fmt.Errorf("client: unsupported wallet state format")
	}
	count := reader.ReadVectorCount("wallet state entry")
	if reader.Err() != nil || count > maximumProvisioningWalletStateEntries {
		return nil, fmt.Errorf("client: wallet state entry count is invalid")
	}
	state := newProvisioningWalletState()
	var previous []byte
	defer func() { zeroProxyBytes(previous) }()
	for range count {
		key := reader.ReadOpaqueFixed(provisioningWalletSpentHintKeyBytes)
		expiryUnix := reader.ReadUint64()
		if reader.Err() != nil || expiryUnix == 0 {
			zeroProxyBytes(key)
			return nil, fmt.Errorf("client: malformed wallet state entry")
		}
		if previous != nil && bytes.Compare(previous, key) >= 0 {
			zeroProxyBytes(key)
			return nil, fmt.Errorf("client: wallet state entries are not canonical")
		}
		previous = append(previous[:0], key...)
		state.reservations[string(key)] = expiryUnix
		zeroProxyBytes(key)
	}
	if reader.Err() != nil || !reader.EOF() {
		return nil, fmt.Errorf("client: malformed wallet state")
	}
	state.prune(now)
	return state, nil
}

func (state *provisioningWalletState) Encode() ([]byte, error) {
	if state == nil {
		return nil, fmt.Errorf("client: wallet state is unavailable")
	}
	if len(state.reservations) > maximumProvisioningWalletStateEntries {
		return nil, fmt.Errorf("client: wallet state entry count is invalid")
	}
	keys := make([]string, 0, len(state.reservations))
	for key, expiryUnix := range state.reservations {
		if len(key) != provisioningWalletSpentHintKeyBytes || expiryUnix == 0 {
			return nil, fmt.Errorf("client: wallet state entry is invalid")
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	encoder := wire.NewEncoder()
	encoder.WriteVarint(provisioningWalletStateFormat)
	encoder.WriteVarint(uint64(len(keys)))
	for _, key := range keys {
		encoder.WriteOpaqueFixed([]byte(key), provisioningWalletSpentHintKeyBytes)
		encoder.WriteUint64(state.reservations[key])
	}
	encoded, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("client: encode wallet state: %w", err)
	}
	if len(encoded) > maximumProvisioningWalletStateBytes {
		zeroProxyBytes(encoded)
		return nil, fmt.Errorf("client: wallet state exceeds size limit")
	}
	return encoded, nil
}

func (state *provisioningWalletState) Add(spentHintKey []byte, expiryUnix uint64) error {
	if state == nil {
		return fmt.Errorf("client: wallet state is unavailable")
	}
	if len(spentHintKey) != provisioningWalletSpentHintKeyBytes || expiryUnix == 0 {
		return fmt.Errorf("client: wallet reservation is invalid")
	}
	if state.reservations == nil {
		state.reservations = make(map[string]uint64)
	}
	key := string(spentHintKey)
	if _, exists := state.reservations[key]; exists {
		return fmt.Errorf("client: wallet reservation already exists")
	}
	if len(state.reservations) >= maximumProvisioningWalletStateEntries {
		return fmt.Errorf("client: wallet state entry count is invalid")
	}
	state.reservations[key] = expiryUnix
	return nil
}

func (state *provisioningWalletState) Contains(spentHintKey []byte) bool {
	if state == nil || len(spentHintKey) != provisioningWalletSpentHintKeyBytes {
		return false
	}
	_, exists := state.reservations[string(spentHintKey)]
	return exists
}

func (state *provisioningWalletState) Len() int {
	if state == nil {
		return 0
	}
	return len(state.reservations)
}

func (state *provisioningWalletState) prune(now time.Time) {
	if state == nil || now.IsZero() || now.Unix() < 0 {
		return
	}
	for key, expiryUnix := range state.reservations {
		if expiryUnix <= uint64(now.Unix()) {
			delete(state.reservations, key)
		}
	}
}

// Transact locks, reloads, updates, and durably writes the local wallet state.
func (store *provisioningWalletStateStore) Transact(now time.Time, update func(*provisioningWalletState) error) error {
	return transactProvisioningWalletState(store, now, update)
}
