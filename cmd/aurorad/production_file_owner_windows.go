//go:build windows

package main

import "os"

func validateProductionFileOwner(os.FileInfo) error {
	return nil
}
