//go:build windows

package admission

import (
	"os"
	"path/filepath"
)

func createRetentionReplayCacheTemporary(directory *os.File, name string) (*os.File, string, error) {
	file, err := os.CreateTemp(directory.Name(), "."+name+".compact-")
	if err != nil {
		return nil, "", err
	}
	return file, filepath.Base(file.Name()), nil
}

func replaceRetentionReplayCacheFile(directory *os.File, temporaryName, name string) error {
	return os.Rename(filepath.Join(directory.Name(), temporaryName), filepath.Join(directory.Name(), name))
}

func removeRetentionReplayCacheTemporary(directory *os.File, temporaryName string) error {
	err := os.Remove(filepath.Join(directory.Name(), temporaryName))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func syncRetentionReplayCacheDirectory(*os.File) error {
	return nil
}
