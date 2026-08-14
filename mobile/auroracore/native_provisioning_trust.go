package main

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/aurora-protocol/aurora-core/client"
)

type nativeProvisioningTrustConfig struct {
	mu      sync.RWMutex
	encoded []byte
	value   client.NativeProvisioningTrust
}

func (c *nativeProvisioningTrustConfig) configure(encoded []byte) error {
	if c == nil {
		return fmt.Errorf("auroracore: native provisioning trust configuration is unavailable")
	}
	value, err := client.ParseNativeProvisioningTrust(encoded)
	if err != nil {
		return fmt.Errorf("auroracore: parse native provisioning trust: %w", err)
	}
	canonical, err := client.EncodeNativeProvisioningTrust(value)
	if err != nil {
		return fmt.Errorf("auroracore: encode native provisioning trust: %w", err)
	}
	defer zeroNativeBytes(canonical)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.encoded) != 0 {
		if bytes.Equal(c.encoded, canonical) {
			return nil
		}
		return fmt.Errorf("auroracore: native provisioning trust is already configured")
	}
	c.encoded = append([]byte(nil), canonical...)
	c.value = value
	return nil
}

func (c *nativeProvisioningTrustConfig) load() (client.NativeProvisioningTrust, error) {
	if c == nil {
		return client.NativeProvisioningTrust{}, fmt.Errorf("auroracore: native provisioning trust configuration is unavailable")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.encoded) == 0 {
		return client.NativeProvisioningTrust{}, client.ErrNativeProvisioningTrustRequired
	}
	return c.value, nil
}

var nativeProvisioningTrust = nativeProvisioningTrustConfig{}
