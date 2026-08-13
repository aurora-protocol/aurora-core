//go:build windows

package main

import "os"

func validateRestrictedOwnerFileOwner(os.FileInfo) error {
	return nil
}
