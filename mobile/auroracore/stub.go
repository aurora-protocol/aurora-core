//go:build !cgo

// This stub keeps the package buildable under CGO_ENABLED=0 (e.g. the portable
// host-build matrix). The real C-archive binding in auroracore.go requires cgo
// and is compiled only when CGO is enabled, via the xcframework build script.
package main

func main() {}
