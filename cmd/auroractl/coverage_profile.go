package main

import (
	"fmt"
	"os"
)

func validateCoverageProfile(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, fmt.Errorf("coverage profile is unavailable")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, closeRejectedCoverageProfile(file, fmt.Errorf("coverage profile stat failed"))
	}
	if !info.Mode().IsRegular() {
		return nil, closeRejectedCoverageProfile(file, fmt.Errorf("coverage profile is not regular"))
	}
	return file, nil
}

func closeRejectedCoverageProfile(file *os.File, rejected error) error {
	if err := file.Close(); err != nil {
		return fmt.Errorf("coverage profile close failed")
	}
	return rejected
}
