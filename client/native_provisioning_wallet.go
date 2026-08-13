package client

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	nativeProvisioningWalletFormat uint64 = 1
	// MaximumNativeProvisioningWalletBytes bounds a complete wallet loaded into memory.
	MaximumNativeProvisioningWalletBytes   = 16 << 20
	maximumNativeProvisioningWalletEntries = 64

	// NativeProvisioningWalletTargetUnused is the recommended unused credential reserve per relay bucket.
	NativeProvisioningWalletTargetUnused = 8
	// NativeProvisioningWalletRefillThreshold is the point below which replenishment is recommended.
	NativeProvisioningWalletRefillThreshold = 3
)

// ErrNoUsableNativeProvisioning indicates that a wallet cannot start another session.
var ErrNoUsableNativeProvisioning = errors.New("client: native provisioning wallet has no usable entries")

// NativeProvisioningWallet holds complete, one-time session provisioning entries.
// It is in-memory only. Callers that may restart must durably record a reservation
// before beginning a session with the returned provisioning.
type NativeProvisioningWallet struct {
	mu      sync.Mutex
	entries []nativeProvisioningWalletEntry
}

type nativeProvisioningWalletEntry struct {
	encoded       []byte
	spentHintKey  []byte
	relayBucketID []byte
	expiryUnix    uint64
}

// NativeProvisioningReservation is a provisioning entry removed from its wallet.
// The entry is consumed even if subsequent session setup fails.
type NativeProvisioningReservation struct {
	SpentHintKey         []byte
	RelayBucketID        []byte
	AccessHintExpiryUnix uint64
	Provisioning         NativeProvisioning
}

// NativeProvisioningWalletBucketStatus reports non-secret wallet availability for one relay bucket.
type NativeProvisioningWalletBucketStatus struct {
	RelayBucketID     []byte
	Unused            int
	TargetMet         bool
	RefillRecommended bool
}

// EncodeNativeProvisioningWallet encodes a bounded canonical collection of complete provisioning entries.
func EncodeNativeProvisioningWallet(provisioning []NativeProvisioning) ([]byte, error) {
	if len(provisioning) == 0 || len(provisioning) > maximumNativeProvisioningWalletEntries {
		return nil, fmt.Errorf("client: native provisioning wallet entry count is invalid")
	}
	entries := make([]nativeProvisioningWalletEntry, 0, len(provisioning))
	defer zeroNativeProvisioningWalletEntries(entries)
	seen := make(map[string]struct{}, len(provisioning))
	for _, value := range provisioning {
		encoded, err := EncodeNativeProvisioning(value)
		if err != nil {
			return nil, fmt.Errorf("client: encode native provisioning wallet entry: %w", err)
		}
		entry, err := nativeProvisioningWalletEntryFor(value, encoded)
		if err != nil {
			zeroNativeProvisioningBytes(encoded)
			return nil, err
		}
		if _, exists := seen[string(entry.spentHintKey)]; exists {
			entry.zero()
			return nil, fmt.Errorf("client: native provisioning wallet has duplicate access hint")
		}
		seen[string(entry.spentHintKey)] = struct{}{}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(left, right int) bool {
		return bytes.Compare(entries[left].spentHintKey, entries[right].spentHintKey) < 0
	})
	encoder := wire.NewEncoder()
	encoder.WriteVarint(nativeProvisioningWalletFormat)
	encoder.WriteVarint(uint64(len(entries)))
	for _, entry := range entries {
		encoder.WriteOpaque24(entry.encoded)
	}
	encoded, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("client: encode native provisioning wallet: %w", err)
	}
	if len(encoded) > MaximumNativeProvisioningWalletBytes {
		zeroNativeProvisioningBytes(encoded)
		return nil, fmt.Errorf("client: native provisioning wallet exceeds size limit")
	}
	return encoded, nil
}

// ParseNativeProvisioningWallet validates and loads a canonical wallet. Expired
// entries are discarded; malformed or unauthenticated entries reject the wallet.
func ParseNativeProvisioningWallet(encoded []byte, now time.Time) (*NativeProvisioningWallet, error) {
	if len(encoded) == 0 || len(encoded) > MaximumNativeProvisioningWalletBytes {
		return nil, fmt.Errorf("client: native provisioning wallet size is invalid")
	}
	if now.IsZero() || now.Unix() < 0 {
		return nil, fmt.Errorf("client: native provisioning wallet requires a valid time")
	}
	reader := wire.NewReader(encoded)
	if format := reader.ReadVarint(); format != nativeProvisioningWalletFormat {
		return nil, fmt.Errorf("client: unsupported native provisioning wallet format")
	}
	count := reader.ReadVectorCount("native provisioning wallet entry")
	if reader.Err() != nil || count == 0 || count > maximumNativeProvisioningWalletEntries {
		return nil, fmt.Errorf("client: native provisioning wallet entry count is invalid")
	}
	wallet := &NativeProvisioningWallet{entries: make([]nativeProvisioningWalletEntry, 0, count)}
	defer func() {
		if wallet != nil {
			wallet.Zero()
		}
	}()
	var previousSpentHintKey []byte
	defer func() { zeroNativeProvisioningBytes(previousSpentHintKey) }()
	for range count {
		entryEncoded := reader.ReadOpaque24()
		if reader.Err() != nil || len(entryEncoded) == 0 || len(entryEncoded) > maximumNativeProvisioningBytes {
			zeroNativeProvisioningBytes(entryEncoded)
			return nil, fmt.Errorf("client: malformed native provisioning wallet entry")
		}
		provisioning, err := parseNativeProvisioningContainer(entryEncoded)
		if err != nil {
			zeroNativeProvisioningBytes(entryEncoded)
			return nil, fmt.Errorf("client: parse native provisioning wallet entry: %w", err)
		}
		entry, err := nativeProvisioningWalletEntryFor(provisioning, entryEncoded)
		if err != nil {
			zeroNativeProvisioning(&provisioning)
			zeroNativeProvisioningBytes(entryEncoded)
			return nil, err
		}
		if previousSpentHintKey != nil && bytes.Compare(previousSpentHintKey, entry.spentHintKey) >= 0 {
			entry.zero()
			zeroNativeProvisioning(&provisioning)
			return nil, fmt.Errorf("client: native provisioning wallet entries are not canonical")
		}
		previousSpentHintKey = append(previousSpentHintKey[:0], entry.spentHintKey...)
		if err := validateNativeProvisioningWalletEntryAt(provisioning, now); err != nil {
			entry.zero()
			zeroNativeProvisioning(&provisioning)
			return nil, fmt.Errorf("client: validate native provisioning wallet entry: %w", err)
		}
		if entry.expiryUnix <= uint64(now.Unix()) {
			entry.zero()
			zeroNativeProvisioning(&provisioning)
			continue
		}
		zeroNativeProvisioning(&provisioning)
		wallet.entries = append(wallet.entries, entry)
	}
	if reader.Err() != nil || !reader.EOF() {
		return nil, fmt.Errorf("client: malformed native provisioning wallet")
	}
	if len(wallet.entries) == 0 {
		return nil, ErrNoUsableNativeProvisioning
	}
	result := wallet
	wallet = nil
	return result, nil
}

// Reserve removes and returns one entry that has not already been reserved by
// persistent caller state. No network activity occurs before this method returns.
func (w *NativeProvisioningWallet) Reserve(alreadyReserved func([]byte) bool, now time.Time) (NativeProvisioningReservation, error) {
	if w == nil {
		return NativeProvisioningReservation{}, ErrNoUsableNativeProvisioning
	}
	if now.IsZero() || now.Unix() < 0 {
		return NativeProvisioningReservation{}, fmt.Errorf("client: native provisioning wallet requires a valid time")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for index := range w.entries {
		entry := &w.entries[index]
		if len(entry.encoded) == 0 {
			continue
		}
		if alreadyReserved != nil && alreadyReserved(entry.spentHintKey) {
			entry.zero()
			continue
		}
		if entry.expiryUnix <= uint64(now.Unix()) {
			entry.zero()
			continue
		}
		provisioning, err := ParseNativeProvisioning(entry.encoded, now)
		if err != nil {
			entry.zero()
			continue
		}
		reservation := NativeProvisioningReservation{
			SpentHintKey:         append([]byte(nil), entry.spentHintKey...),
			RelayBucketID:        append([]byte(nil), entry.relayBucketID...),
			AccessHintExpiryUnix: entry.expiryUnix,
			Provisioning:         provisioning,
		}
		entry.zero()
		return reservation, nil
	}
	return NativeProvisioningReservation{}, ErrNoUsableNativeProvisioning
}

// BucketStatus returns the remaining unreserved entries grouped by relay bucket.
func (w *NativeProvisioningWallet) BucketStatus(alreadyReserved func([]byte) bool, now time.Time) []NativeProvisioningWalletBucketStatus {
	if w == nil || now.IsZero() || now.Unix() < 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	type bucket struct {
		id     []byte
		unused int
	}
	buckets := make(map[string]bucket)
	for index := range w.entries {
		entry := &w.entries[index]
		if len(entry.encoded) == 0 || entry.expiryUnix <= uint64(now.Unix()) || (alreadyReserved != nil && alreadyReserved(entry.spentHintKey)) {
			continue
		}
		key := string(entry.relayBucketID)
		value := buckets[key]
		if value.id == nil {
			value.id = append([]byte(nil), entry.relayBucketID...)
		}
		value.unused++
		buckets[key] = value
	}
	status := make([]NativeProvisioningWalletBucketStatus, 0, len(buckets))
	for _, value := range buckets {
		status = append(status, NativeProvisioningWalletBucketStatus{
			RelayBucketID:     value.id,
			Unused:            value.unused,
			TargetMet:         value.unused >= NativeProvisioningWalletTargetUnused,
			RefillRecommended: value.unused < NativeProvisioningWalletRefillThreshold,
		})
	}
	sort.Slice(status, func(left, right int) bool {
		return bytes.Compare(status[left].RelayBucketID, status[right].RelayBucketID) < 0
	})
	return status
}

// Zero erases all entries retained by the wallet.
func (w *NativeProvisioningWallet) Zero() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	zeroNativeProvisioningWalletEntries(w.entries)
	w.entries = nil
}

// Zero erases the reserved provisioning and its non-secret identifiers.
func (r *NativeProvisioningReservation) Zero() {
	if r == nil {
		return
	}
	zeroNativeProvisioningBytes(r.SpentHintKey)
	zeroNativeProvisioningBytes(r.RelayBucketID)
	zeroNativeProvisioning(&r.Provisioning)
	*r = NativeProvisioningReservation{}
}

func nativeProvisioningWalletEntryFor(provisioning NativeProvisioning, encoded []byte) (nativeProvisioningWalletEntry, error) {
	credential, err := admission.DecodeAccessHintCredential(provisioning.AccessHint)
	if err != nil {
		return nativeProvisioningWalletEntry{}, fmt.Errorf("client: native provisioning wallet access hint: %w", err)
	}
	defer zeroNativeAccessHintCredential(&credential)
	spentHintKey, err := admission.ComputeSpentHintKey(credential)
	if err != nil {
		return nativeProvisioningWalletEntry{}, fmt.Errorf("client: native provisioning wallet spent hint key: %w", err)
	}
	return nativeProvisioningWalletEntry{
		encoded:       encoded,
		spentHintKey:  spentHintKey,
		relayBucketID: append([]byte(nil), credential.RelayBucketID...),
		expiryUnix:    credential.ExpiryUnix,
	}, nil
}

func validateNativeProvisioningWalletEntryAt(provisioning NativeProvisioning, now time.Time) error {
	if err := provisioning.validateContainer(); err != nil {
		return err
	}
	if now.IsZero() || now.Unix() < 0 {
		return fmt.Errorf("client: native provisioning wallet requires a valid time")
	}
	objects, err := provisioning.decodeObjects()
	if err != nil {
		return err
	}
	defer zeroNativeAccessHintCredential(&objects.accessHint)
	if err := validateNativePolicy(objects.policyOffer, objects.transportHints, provisioning.Suite); err != nil {
		return err
	}
	if _, err := provisioning.verifyDeployment(now, objects); err != nil {
		return fmt.Errorf("client: native provisioning relay deployment: %w", err)
	}
	return nil
}

func (entry *nativeProvisioningWalletEntry) zero() {
	if entry == nil {
		return
	}
	zeroNativeProvisioningBytes(entry.encoded)
	zeroNativeProvisioningBytes(entry.spentHintKey)
	zeroNativeProvisioningBytes(entry.relayBucketID)
	*entry = nativeProvisioningWalletEntry{}
}

func zeroNativeProvisioningWalletEntries(entries []nativeProvisioningWalletEntry) {
	for index := range entries {
		entries[index].zero()
	}
}

func zeroNativeAccessHintCredential(credential *admission.AccessHintCredential) {
	if credential == nil {
		return
	}
	zeroNativeProvisioningBytes(credential.HintIssuerID)
	zeroNativeProvisioningBytes(credential.RelayBucketID)
	zeroNativeProvisioningBytes(credential.HintSelector)
	zeroNativeProvisioningBytes(credential.HintSecret)
	*credential = admission.AccessHintCredential{}
}

func zeroNativeProvisioning(provisioning *NativeProvisioning) {
	if provisioning == nil {
		return
	}
	for _, field := range [][]byte{
		provisioning.Descriptor,
		provisioning.TrustedDescriptorHash,
		provisioning.Template,
		provisioning.TemplateAuthorityKey,
		provisioning.AccessHint,
		provisioning.PolicyOffer,
		provisioning.TransportHints,
		provisioning.RelayRequestHeaders,
		provisioning.RelayResponseHeaders,
		provisioning.RelayTrustRoots,
	} {
		zeroNativeProvisioningBytes(field)
	}
	*provisioning = NativeProvisioning{}
}

func zeroNativeProvisioningBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
