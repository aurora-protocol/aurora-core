package admission

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RetentionFileReplayCache struct {
	mu        sync.Mutex
	directory *os.File
	name      string
	path      string
	lock      *os.File
	seen      map[string]uint64
}

func NewRetentionFileReplayCacheAt(directory *os.File, name string, nowUnix uint64) (*RetentionFileReplayCache, error) {
	if directory == nil || name == "" || name == "." || name == ".." || filepath.Base(name) != name || nowUnix == 0 {
		return nil, fmt.Errorf("admission: retention replay cache directory entry is invalid")
	}
	lock, err := openReplayCacheFileAt(directory, name+".lock")
	if err != nil {
		return nil, err
	}
	if err := lock.Chmod(0o600); err != nil {
		_ = lock.Close()
		return nil, err
	}
	cache := &RetentionFileReplayCache{directory: directory, name: name, path: filepath.Join(directory.Name(), name), lock: lock, seen: make(map[string]uint64)}
	if err := cache.withLock(func() error {
		expired, err := cache.load(nowUnix)
		if err != nil {
			return err
		}
		if expired {
			return cache.rewrite()
		}
		return syncRetentionReplayCacheDirectory(directory)
	}); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return cache, nil
}

func (*RetentionFileReplayCache) Durable() bool { return replayCacheFileDurable() }

func (c *RetentionFileReplayCache) InsertIfAbsent(key []byte) (bool, error) {
	return c.InsertIfAbsentUntil(key, math.MaxUint64, uint64(time.Now().Unix()))
}

func (c *RetentionFileReplayCache) InsertIfAbsentUntil(key []byte, retainUntilUnix, nowUnix uint64) (inserted bool, err error) {
	if c == nil || nowUnix == 0 || retainUntilUnix == 0 || retainUntilUnix <= nowUnix {
		return false, fmt.Errorf("admission: replay cache retention window is invalid")
	}
	if len(key) == 0 {
		return false, fmt.Errorf("admission: replay cache key is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.directory == nil || c.lock == nil {
		return false, fmt.Errorf("admission: replay cache is closed")
	}
	err = c.withLock(func() error {
		expired, err := c.load(nowUnix)
		if err != nil {
			return err
		}
		entry := string(key)
		if _, ok := c.seen[entry]; ok {
			return nil
		}
		c.seen[entry] = retainUntilUnix
		inserted = true
		if expired {
			return c.rewrite()
		}
		return c.append(entry, retainUntilUnix)
	})
	return inserted, err
}

func (c *RetentionFileReplayCache) Has(key []byte) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.seen[string(key)]
	return ok
}

func (c *RetentionFileReplayCache) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	if c.lock != nil {
		err = c.lock.Close()
		c.lock = nil
	}
	if c.directory != nil {
		closeErr := c.directory.Close()
		c.directory = nil
		if err == nil {
			err = closeErr
		}
	}
	return err
}

func (c *RetentionFileReplayCache) withLock(fn func() error) error {
	if err := lockReplayCacheFile(c.lock); err != nil {
		return err
	}
	defer unlockReplayCacheFile(c.lock)
	return fn()
}

func (c *RetentionFileReplayCache) load(nowUnix uint64) (bool, error) {
	file, err := openReplayCacheFileAt(c.directory, c.name)
	if err != nil {
		return false, err
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return false, err
	}
	seen := make(map[string]uint64)
	expired := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) > 2 || len(fields) == 2 && fields[1] == "" {
			return false, fmt.Errorf("admission: retention replay cache %s has malformed entry", c.path)
		}
		key, err := hex.DecodeString(fields[0])
		if err != nil || len(key) == 0 || hex.EncodeToString(key) != fields[0] {
			return false, fmt.Errorf("admission: retention replay cache %s has malformed key", c.path)
		}
		deadline := uint64(math.MaxUint64)
		if len(fields) == 2 {
			deadline, err = strconv.ParseUint(fields[1], 10, 64)
			if err != nil || deadline == 0 || strconv.FormatUint(deadline, 10) != fields[1] {
				return false, fmt.Errorf("admission: retention replay cache %s has malformed retention deadline", c.path)
			}
		}
		if deadline > nowUnix {
			seen[string(key)] = deadline
		} else {
			expired = true
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	c.seen = seen
	return expired, nil
}

func (c *RetentionFileReplayCache) rewrite() error {
	temporary, temporaryName, err := createRetentionReplayCacheTemporary(c.directory, c.name)
	if err != nil {
		return err
	}
	defer func() { _ = removeRetentionReplayCacheTemporary(c.directory, temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	keys := make([]string, 0, len(c.seen))
	for key := range c.seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		line := hex.EncodeToString([]byte(key)) + "\t" + strconv.FormatUint(c.seen[key], 10) + "\n"
		written, err := io.WriteString(temporary, line)
		if err != nil {
			_ = temporary.Close()
			return err
		}
		if written != len(line) {
			_ = temporary.Close()
			return io.ErrShortWrite
		}
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := replaceRetentionReplayCacheFile(c.directory, temporaryName, c.name); err != nil {
		return err
	}
	return syncRetentionReplayCacheDirectory(c.directory)
}

func (c *RetentionFileReplayCache) append(key string, deadline uint64) error {
	file, err := openReplayCacheFileAt(c.directory, c.name)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	line := hex.EncodeToString([]byte(key)) + "\t" + strconv.FormatUint(deadline, 10) + "\n"
	written, err := io.WriteString(file, line)
	if err != nil {
		return err
	}
	if written != len(line) {
		return io.ErrShortWrite
	}
	return file.Sync()
}
