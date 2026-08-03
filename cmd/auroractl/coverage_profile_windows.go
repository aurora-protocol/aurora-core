//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func openCoverageProfile(path string) (*os.File, error) {
	if unsafeWindowsCoverageProfilePath(path) {
		return nil, fmt.Errorf("coverage profile open failed")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("coverage profile open failed")
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("coverage profile open failed")
	}
	fileType, err := windows.GetFileType(handle)
	if err != nil || fileType != windows.FILE_TYPE_DISK {
		return nil, closeRejectedWindowsCoverageProfile(handle, fmt.Errorf("coverage profile is not a disk file"))
	}
	file := os.NewFile(uintptr(handle), "")
	if file == nil {
		return nil, closeRejectedWindowsCoverageProfile(handle, fmt.Errorf("coverage profile open failed"))
	}
	return validateCoverageProfile(file)
}

func unsafeWindowsCoverageProfilePath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(path, "/", "\\"))
	return strings.HasPrefix(normalized, `\\.\`) ||
		strings.HasPrefix(normalized, `\\?\pipe\`) ||
		strings.HasPrefix(normalized, `\\?\globalroot`) ||
		strings.HasPrefix(normalized, `\device\namedpipe\`) ||
		strings.HasPrefix(normalized, `\??\pipe\`)
}

func closeRejectedWindowsCoverageProfile(handle windows.Handle, rejected error) error {
	if err := windows.CloseHandle(handle); err != nil {
		return fmt.Errorf("coverage profile close failed")
	}
	return rejected
}
