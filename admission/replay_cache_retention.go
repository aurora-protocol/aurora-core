package admission

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
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
	// loaded identifies the data file region already parsed into seen. Records
	// are only ever appended between compactions, so a reload parses just the
	// appended tail; a compaction replaces the file and forces a full reload.
	loadedInfo os.FileInfo
	loadedSize int64
	// loadedGeneration is advanced before every in-process compaction. It
	// closes an inode-reuse ABA hole on filesystems that can assign a replaced
	// cache file the same identity as an older file after its last handle closes.
	loadedGeneration uint64
	minDeadline      uint64
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
	cache := &RetentionFileReplayCache{directory: directory, name: name, path: filepath.Join(directory.Name(), name), lock: lock, seen: make(map[string]uint64), minDeadline: math.MaxUint64}
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
		if retainUntilUnix < c.minDeadline {
			c.minDeadline = retainUntilUnix
		}
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
	if c.directory == nil || c.lock == nil {
		return false
	}
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
	c.seen = nil
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
	generation, err := c.readGeneration()
	if err != nil {
		return false, err
	}
	file, err := openReplayCacheFileAt(c.directory, c.name)
	if err != nil {
		return false, err
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return false, err
	}
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	offset := c.loadedSize
	if c.loadedInfo == nil || generation != c.loadedGeneration || !os.SameFile(c.loadedInfo, info) || info.Size() < offset {
		// The file was replaced or truncated behind this handle; reparse it all.
		c.seen = make(map[string]uint64)
		c.minDeadline = math.MaxUint64
		offset = 0
	}
	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return false, err
		}
	}
	consumed, err := c.consume(file, offset)
	if err != nil {
		return false, err
	}
	c.loadedInfo = info
	c.loadedSize = consumed
	c.loadedGeneration = generation
	if c.minDeadline > nowUnix {
		return false, nil
	}
	c.expireLoaded(nowUnix)
	return true, nil
}

func (c *RetentionFileReplayCache) readGeneration() (uint64, error) {
	file, err := openReplayCacheFileAt(c.directory, c.name+".generation")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return 0, err
	}
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if info.Size() == 0 {
		// Empty is the legacy state before the first compaction.
		return 0, nil
	}
	if info.Size() != 8 {
		return 0, fmt.Errorf("admission: retention replay cache %s has malformed generation", c.path)
	}
	var encoded [8]byte
	if _, err := file.ReadAt(encoded[:], 0); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(encoded[:]), nil
}

// consume parses records from the current file position and reports the offset
// past the last newline-terminated record. A partial trailing record is parsed
// but not consumed, so a completed record is never skipped.
func (c *RetentionFileReplayCache) consume(file *os.File, offset int64) (int64, error) {
	reader := bufio.NewReader(file)
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			terminated := readErr == nil
			if record := strings.TrimSuffix(line, "\n"); record != "" {
				key, deadline, err := c.parseRecord(record)
				if err != nil {
					return 0, err
				}
				c.seen[key] = deadline
				if deadline < c.minDeadline {
					c.minDeadline = deadline
				}
			}
			if terminated {
				offset += int64(len(line))
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return offset, nil
			}
			return 0, readErr
		}
	}
}

func (c *RetentionFileReplayCache) parseRecord(record string) (string, uint64, error) {
	fields := strings.Split(record, "\t")
	if len(fields) > 2 || len(fields) == 2 && fields[1] == "" {
		return "", 0, fmt.Errorf("admission: retention replay cache %s has malformed entry", c.path)
	}
	key, err := hex.DecodeString(fields[0])
	if err != nil || len(key) == 0 || hex.EncodeToString(key) != fields[0] {
		return "", 0, fmt.Errorf("admission: retention replay cache %s has malformed key", c.path)
	}
	deadline := uint64(math.MaxUint64)
	if len(fields) == 2 {
		deadline, err = strconv.ParseUint(fields[1], 10, 64)
		if err != nil || deadline == 0 || strconv.FormatUint(deadline, 10) != fields[1] {
			return "", 0, fmt.Errorf("admission: retention replay cache %s has malformed retention deadline", c.path)
		}
	}
	return string(key), deadline, nil
}

// expireLoaded drops records whose retention deadline has passed and refreshes
// the earliest remaining deadline.
func (c *RetentionFileReplayCache) expireLoaded(nowUnix uint64) {
	earliest := uint64(math.MaxUint64)
	for key, deadline := range c.seen {
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
	nextGeneration, err := c.advanceGeneration()
	if err != nil {
		return err
	}
	if err := replaceRetentionReplayCacheFile(c.directory, temporaryName, c.name); err != nil {
		return err
	}
	// The compacted file is a new directory entry, so the next load reparses it.
	c.loadedInfo = nil
	c.loadedSize = 0
	c.loadedGeneration = nextGeneration
	return syncRetentionReplayCacheDirectory(c.directory)
}

func (c *RetentionFileReplayCache) advanceGeneration() (uint64, error) {
	if c.loadedGeneration == math.MaxUint64 {
		return 0, fmt.Errorf("admission: retention replay cache %s exhausted its generation", c.path)
	}
	next := c.loadedGeneration + 1
	temporary, temporaryName, err := createRetentionReplayCacheTemporary(c.directory, c.name+".generation")
	if err != nil {
		return 0, err
	}
	defer func() { _ = removeRetentionReplayCacheTemporary(c.directory, temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return 0, err
	}
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], next)
	written, err := temporary.Write(encoded[:])
	if err != nil {
		_ = temporary.Close()
		return 0, err
	}
	if written != len(encoded) {
		_ = temporary.Close()
		return 0, io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return 0, err
	}
	if err := temporary.Close(); err != nil {
		return 0, err
	}
	if err := replaceRetentionReplayCacheFile(c.directory, temporaryName, c.name+".generation"); err != nil {
		return 0, err
	}
	// Persist the new generation before replacing the data file. A crash in
	// between can cause an unnecessary full reload, but can never skip records.
	if err := syncRetentionReplayCacheDirectory(c.directory); err != nil {
		return 0, err
	}
	return next, nil
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
	if err := file.Sync(); err != nil {
		return err
	}
	// The record is already resident, so the next load starts past it.
	c.loadedSize += int64(len(line))
	return nil
}
