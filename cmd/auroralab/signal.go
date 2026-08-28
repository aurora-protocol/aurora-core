package main

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func defaultLabSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// tlsListener wraps a listener with the lab issuer TLS configuration.
func tlsListener(listener net.Listener, config *tls.Config) net.Listener {
	return tls.NewListener(listener, config)
}
