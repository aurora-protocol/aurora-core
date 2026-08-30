package client

import "testing"

func TestValidateTCPProxyRuntimeOptionsDecidesEveryResourceBoundary(t *testing.T) {
	tests := []struct {
		name    string
		options TCPProxyRuntimeOptions
		wantErr bool
	}{
		{name: "defaults"},
		{
			name: "minimums",
			options: TCPProxyRuntimeOptions{
				MaxFlows:                  1,
				ReadBufferBytes:           minimumTCPProxyReadBufferBytes,
				MaxPendingWriteBytes:      minimumTCPProxyReadBufferBytes,
				MaxTotalPendingWriteBytes: minimumTCPProxyReadBufferBytes,
			},
		},
		{
			name: "maximums",
			options: TCPProxyRuntimeOptions{
				MaxFlows:                  maximumTCPProxyMaxFlows,
				ReadBufferBytes:           maximumTCPProxyReadBufferBytes,
				MaxPendingWriteBytes:      maximumTCPProxyPendingWriteBytes,
				MaxTotalPendingWriteBytes: maximumTCPProxyTotalPendingWriteBytes,
			},
		},
		{
			name:    "flow limit below minimum",
			options: TCPProxyRuntimeOptions{MaxFlows: -1},
			wantErr: true,
		},
		{
			name:    "flow limit above maximum",
			options: TCPProxyRuntimeOptions{MaxFlows: maximumTCPProxyMaxFlows + 1},
			wantErr: true,
		},
		{
			name:    "read buffer below minimum",
			options: TCPProxyRuntimeOptions{ReadBufferBytes: minimumTCPProxyReadBufferBytes - 1},
			wantErr: true,
		},
		{
			name:    "read buffer above maximum",
			options: TCPProxyRuntimeOptions{ReadBufferBytes: maximumTCPProxyReadBufferBytes + 1},
			wantErr: true,
		},
		{
			name:    "per-flow pending writes below minimum",
			options: TCPProxyRuntimeOptions{MaxPendingWriteBytes: minimumTCPProxyReadBufferBytes - 1},
			wantErr: true,
		},
		{
			name:    "per-flow pending writes above maximum",
			options: TCPProxyRuntimeOptions{MaxPendingWriteBytes: maximumTCPProxyPendingWriteBytes + 1},
			wantErr: true,
		},
		{
			name:    "aggregate pending writes below minimum",
			options: TCPProxyRuntimeOptions{MaxTotalPendingWriteBytes: minimumTCPProxyReadBufferBytes - 1},
			wantErr: true,
		},
		{
			name:    "aggregate pending writes above maximum",
			options: TCPProxyRuntimeOptions{MaxTotalPendingWriteBytes: maximumTCPProxyTotalPendingWriteBytes + 1},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateTCPProxyRuntimeOptions(test.options)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateTCPProxyRuntimeOptions(%+v) error = %v, wantErr %t", test.options, err, test.wantErr)
			}
		})
	}
}
