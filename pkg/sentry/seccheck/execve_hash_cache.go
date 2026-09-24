// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package seccheck

import (
	"container/list"
	"sync"

	"gvisor.dev/gvisor/pkg/log"
)

// DefaultExecveHashCacheCapacity is the default maximum capacity of a per-session
// execve hash cache.
const DefaultExecveHashCacheCapacity = 512

// ExecveKey represents the unique filesystem attributes identifying a cached binary hash.
type ExecveKey struct {
	MountID   uint64
	Ino       uint64
	Size      uint64
	MtimeSec  int64
	MtimeNsec uint32
}

// ExecveHashes holds cached digests (SHA-256 and/or SHA-1) for an executable binary.
type ExecveHashes struct {
	SHA256 []byte
	SHA1   []byte
}

type execveEntry struct {
	key    ExecveKey
	hashes ExecveHashes
}

// ExecveHashOptions defines which binary check algorithms are enabled or requested
// on the session state.
type ExecveHashOptions struct {
	SHA256 bool
	SHA1   bool
}

// ExecveHashCache provides a thread-safe, bounded LRU cache mapping binary filesystem
// keys to digests.
type ExecveHashCache struct {
	mu       sync.Mutex
	capacity int
	opts     ExecveHashOptions
	entries  map[ExecveKey]*list.Element
	lru      *list.List
}

// NewExecveHashCache constructs a new ExecveHashCache with the specified capacity and options.
func NewExecveHashCache(capacity int, opts ExecveHashOptions) *ExecveHashCache {
	if capacity < 0 {
		log.Warningf("ExecveHashCache capacity %d is negative; clamping to 0", capacity)
		capacity = 0
	}
	return &ExecveHashCache{
		capacity: capacity,
		opts:     opts,
		entries:  make(map[ExecveKey]*list.Element, capacity),
		lru:      list.New(),
	}
}

// Opts returns the hash check algorithms enabled for this cache.
func (c *ExecveHashCache) Opts() ExecveHashOptions {
	return c.opts
}

// Capacity returns the maximum capacity of the cache.
func (c *ExecveHashCache) Capacity() int {
	return c.capacity
}

// Lookup attempts to retrieve cached digests for key.
func (c *ExecveHashCache) Lookup(key ExecveKey) (ExecveHashes, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.capacity <= 0 {
		return ExecveHashes{}, false
	}

	if elem, ok := c.entries[key]; ok {
		c.lru.MoveToFront(elem)
		e := elem.Value.(*execveEntry)
		h := ExecveHashes{
			SHA256: append([]byte(nil), e.hashes.SHA256...),
			SHA1:   append([]byte(nil), e.hashes.SHA1...),
		}
		return h, true
	}
	return ExecveHashes{}, false
}

// Add updates or inserts digests into the cache for key, evicting the least recently used
// entry if capacity is reached.
func (c *ExecveHashCache) Add(key ExecveKey, hashes ExecveHashes) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.capacity <= 0 {
		return
	}

	if elem, ok := c.entries[key]; ok {
		e := elem.Value.(*execveEntry)
		if len(hashes.SHA256) > 0 {
			e.hashes.SHA256 = append([]byte(nil), hashes.SHA256...)
		}
		if len(hashes.SHA1) > 0 {
			e.hashes.SHA1 = append([]byte(nil), hashes.SHA1...)
		}
		c.lru.MoveToFront(elem)
		return
	}

	if c.lru.Len() >= c.capacity {
		back := c.lru.Back()
		if back != nil {
			c.lru.Remove(back)
			e := back.Value.(*execveEntry)
			delete(c.entries, e.key)
		}
	}

	e := &execveEntry{
		key: key,
		hashes: ExecveHashes{
			SHA256: append([]byte(nil), hashes.SHA256...),
			SHA1:   append([]byte(nil), hashes.SHA1...),
		},
	}
	elem := c.lru.PushFront(e)
	c.entries[key] = elem
}
