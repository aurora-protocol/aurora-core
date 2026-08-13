//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package admission

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func createRetentionReplayCacheTemporary(directory *os.File, name string) (*os.File, string, error) {
	temporaryName := "." + name + ".compact"
	directoryFD := int(directory.Fd())
	fd, err := unix.Openat(directoryFD, temporaryName, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err == unix.EEXIST {
		if err := unix.Unlinkat(directoryFD, temporaryName, 0); err != nil {
			return nil, "", err
		}
		fd, err = unix.Openat(directoryFD, temporaryName, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	}
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(fd), temporaryName)
	if file == nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("admission: create retention replay cache temporary handle")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, "", err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, "", fmt.Errorf("admission: retention replay cache temporary must be regular")
	}
	return file, temporaryName, nil
}

func replaceRetentionReplayCacheFile(directory *os.File, temporaryName, name string) error {
	return unix.Renameat(int(directory.Fd()), temporaryName, int(directory.Fd()), name)
}

func removeRetentionReplayCacheTemporary(directory *os.File, temporaryName string) error {
	err := unix.Unlinkat(int(directory.Fd()), temporaryName, 0)
	if err == unix.ENOENT {
		return nil
	}
	return err
}
