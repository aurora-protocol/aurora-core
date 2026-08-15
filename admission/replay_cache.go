package admission

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const replayCacheRetentionGraceSeconds uint64 = 10 * 60

type ReplayCache interface {
	InsertIfAbsent(key []byte) (bool, error)
	Has(key []byte) bool
}

type RetentionReplayCache interface {
	InsertIfAbsentUntil(key []byte, retainUntilUnix, nowUnix uint64) (bool, error)
}

func InsertIfAbsentRetained(cache ReplayCache, key []byte, retainUntilUnix, nowUnix uint64) (bool, error) {
	retained, ok := cache.(RetentionReplayCache)
	if !ok {
		return false, fmt.Errorf("admission: replay cache does not support retention")
	}
	return retained.InsertIfAbsentUntil(key, retainUntilUnix, nowUnix)
}

func RetentionDeadline(baseUnix uint64) (uint64, error) {
	if baseUnix == 0 || baseUnix > math.MaxUint64-replayCacheRetentionGraceSeconds {
		return 0, fmt.Errorf("admission: replay-cache retention deadline is invalid")
	}
	return baseUnix + replayCacheRetentionGraceSeconds, nil
}

func MaximumRetentionDeadline(values ...uint64) (uint64, error) {
	var latest uint64
	for _, value := range values {
		if value == 0 {
			return 0, fmt.Errorf("admission: replay-cache retention time is invalid")
		}
		if value > latest {
			latest = value
		}
	}
	return RetentionDeadline(latest)
}

type MemoryReplayCache struct {
	mu   sync.Mutex
	seen map[string]uint64
	// minDeadline is the earliest retention deadline held, so expired records
	// can be dropped without scanning until one of them has actually expired.
	// Records inserted without retention are permanent and never contribute.
	minDeadline uint64
}

func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{seen: make(map[string]uint64), minDeadline: math.MaxUint64}
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
	c.seen[k] = 0
	return true, nil
}

func (c *MemoryReplayCache) InsertIfAbsentUntil(key []byte, retainUntilUnix, nowUnix uint64) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("admission: missing replay cache")
	}
	if retainUntilUnix == 0 || nowUnix == 0 || retainUntilUnix <= nowUnix {
		return false, fmt.Errorf("admission: replay cache retention window is invalid")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// One-time credentials are rarely presented twice, so a record that is only
	// dropped when its own key returns would be retained for the process
	// lifetime. Reclaim every expired record once the earliest one has passed.
	if c.minDeadline <= nowUnix {
		c.expireLocked(nowUnix)
	}
	k := string(key)
	if previous, ok := c.seen[k]; ok {
		if previous == 0 || previous > nowUnix {
			return false, nil
		}
		delete(c.seen, k)
	}
	c.seen[k] = retainUntilUnix
	if retainUntilUnix < c.minDeadline {
		c.minDeadline = retainUntilUnix
	}
	return true, nil
}

func (c *MemoryReplayCache) expireLocked(nowUnix uint64) {
	earliest := uint64(math.MaxUint64)
	for key, deadline := range c.seen {
		if deadline == 0 {
			continue
		}
		if deadline <= nowUnix {
			delete(c.seen, key)
			continue
		}
		if deadline < earliest {
			earliest = deadline
		}
	}
	c.minDeadline = earliest
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
	file, err := openReplayCacheFile(path)
	if err != nil {
		return nil, err
	}
	return newFileReplayCache(path, file)
}

func NewFileReplayCacheAt(directory *os.File, name string) (*FileReplayCache, error) {
	if directory == nil || name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, fmt.Errorf("admission: replay cache directory entry is invalid")
	}
	file, err := openReplayCacheFileAt(directory, name)
	if err != nil {
		return nil, err
	}
	return newFileReplayCache(filepath.Join(directory.Name(), name), file)
}

func newFileReplayCache(path string, file *os.File) (*FileReplayCache, error) {
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

func (*FileReplayCache) Durable() bool { return replayCacheFileDurable() }

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
	if c.file == nil {
		return false
	}
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
		c.seen = nil
		return nil
	}
	err := c.file.Close()
	c.file = nil
	c.seen = nil
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
