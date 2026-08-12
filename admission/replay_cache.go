package admission

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type ReplayCache interface {
	InsertIfAbsent(key []byte) (bool, error)
	Has(key []byte) bool
}

type MemoryReplayCache struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{seen: make(map[string]struct{})}
}

func (*MemoryReplayCache) Durable() bool { return false }

func (c *MemoryReplayCache) InsertIfAbsent(key []byte) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("admission: missing replay cache")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := string(key)
	if _, ok := c.seen[k]; ok {
		return false, nil
	}
	c.seen[k] = struct{}{}
	return true, nil
}

func (c *MemoryReplayCache) Has(key []byte) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.seen[string(key)]
	return ok
}

type FileReplayCache struct {
	mu   sync.Mutex
	path string
	file *os.File
	seen map[string]struct{}
}

func NewFileReplayCache(path string) (*FileReplayCache, error) {
	if path == "" {
		return nil, fmt.Errorf("admission: replay cache path is empty")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	cache := &FileReplayCache{
		path: path,
		file: file,
		seen: make(map[string]struct{}),
	}
	if err := lockReplayCacheFile(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := cache.load(); err != nil {
		_ = unlockReplayCacheFile(file)
		_ = file.Close()
		return nil, err
	}
	if err := unlockReplayCacheFile(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return cache, nil
}

func (*FileReplayCache) Durable() bool { return true }

func (c *FileReplayCache) InsertIfAbsent(key []byte) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("admission: replay cache is closed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return false, fmt.Errorf("admission: replay cache is closed")
	}
	if err := lockReplayCacheFile(c.file); err != nil {
		return false, err
	}
	defer unlockReplayCacheFile(c.file)
	if err := c.load(); err != nil {
		return false, err
	}
	k := string(key)
	if _, ok := c.seen[k]; ok {
		return false, nil
	}
	line := hex.EncodeToString(key) + "\n"
	n, err := c.file.WriteString(line)
	if err != nil {
		return false, err
	}
	if n != len(line) {
		return false, io.ErrShortWrite
	}
	if err := c.file.Sync(); err != nil {
		return false, err
	}
	c.seen[k] = struct{}{}
	return true, nil
}

func (c *FileReplayCache) Has(key []byte) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.seen[string(key)]
	return ok
}

func (c *FileReplayCache) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return nil
	}
	err := c.file.Close()
	c.file = nil
	return err
}

func (c *FileReplayCache) load() error {
	if _, err := c.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(c.file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, err := hex.DecodeString(line)
		if err != nil {
			return fmt.Errorf("admission: replay cache %s has malformed key: %w", c.path, err)
		}
		seen[string(key)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	c.seen = seen
	_, err := c.file.Seek(0, io.SeekEnd)
	return err
}
