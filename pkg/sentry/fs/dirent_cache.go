// Copyright 2018 The gVisor Authors.
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

package fs

import (
	"fmt"
	"sync"
)

// DirentCache is an LRU cache of Dirents. The Dirent's refCount is
// incremented when it is added to the cache, and decremented when it is
// removed.
//
// A nil DirentCache corresponds to a cache with size 0. All methods can be
// called, but nothing is actually cached.
//
// +stateify savable
type DirentCache struct {
	// Maximum size of the cache. This must be saved manually, to handle the case
	// when cache is nil.
	maxSize uint64

	// limit restricts the number of entries in the cache amoung multiple caches.
	// It may be nil if there are no global limit for this cache.
	limit *DirentCacheLimiter

	// mu protects currentSize and direntList.
	mu sync.Mutex `state:"nosave"`

	// currentSize is the number of elements in the cache. It must be zero (i.e.
	// the cache must be empty) on Save.
	currentSize uint64 `state:"zerovalue"`

	// list is a direntList, an ilist of Dirents. New Dirents are added
	// to the front of the list. Old Dirents are removed from the back of
	// the list. It must be zerovalue (i.e. the cache must be empty) on Save.
	list direntList `state:"zerovalue"`
}

// NewDirentCache returns a new DirentCache with the given maxSize.
func NewDirentCache(maxSize uint64) *DirentCache {
	return &DirentCache{
		maxSize: maxSize,
	}
}

// Add adds the element to the cache and increments the refCount. If the
// argument is already in the cache, it is moved to the front. An element is
// removed from the back if the cache is over capacity.
func (c *DirentCache) Add(d *Dirent) {
	if c == nil || c.maxSize == 0 {
		return
	}

	c.mu.Lock()
	if c.contains(d) {
		// d is already in cache. Bump it to the front.
		// currentSize and refCount are unaffected.
		c.list.Remove(d)
		c.list.PushFront(d)
		c.mu.Unlock()
		return
	}

	// First check against the global limit.
	for c.limit != nil && !c.limit.tryInc() {
		if c.currentSize == 0 {
			// If the global limit is reached, but there is nothing more to drop from
			// this cache, there is not much else to do.
			c.mu.Unlock()
			return
		}
		c.remove(c.list.Back())
	}

	// d is not in cache. Add it and take a reference.
	c.list.PushFront(d)
	d.IncRef()
	c.currentSize++

	c.maybeShrink()

	c.mu.Unlock()
}

func (c *DirentCache) remove(d *Dirent) {
	if !c.contains(d) {
		panic(fmt.Sprintf("trying to remove %v, which is not in the dirent cache", d))
	}
	c.list.Remove(d)
	d.SetPrev(nil)
	d.SetNext(nil)
	d.DecRef()
	c.currentSize--
	if c.limit != nil {
		c.limit.dec()
	}
}

// Remove removes the element from the cache and decrements its refCount. It
// also sets the previous and next elements to nil, which allows us to
// determine if a given element is in the cache.
func (c *DirentCache) Remove(d *Dirent) {
	if c == nil || c.maxSize == 0 {
		return
	}
	c.mu.Lock()
	if !c.contains(d) {
		c.mu.Unlock()
		return
	}
	c.remove(d)
	c.mu.Unlock()
}

// Size returns the number of elements in the cache.
func (c *DirentCache) Size() uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	size := c.currentSize
	c.mu.Unlock()
	return size
}

func (c *DirentCache) contains(d *Dirent) bool {
	// If d has a Prev or Next element, then it is in the cache.
	if d.Prev() != nil || d.Next() != nil {
		return true
	}
	// Otherwise, d is in the cache if it is the only element (and thus the
	// first element).
	return c.list.Front() == d
}

// Invalidate removes all Dirents from the cache, caling DecRef on each.
func (c *DirentCache) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	for c.list.Front() != nil {
		c.remove(c.list.Front())
	}
	c.mu.Unlock()
}

// setMaxSize sets cache max size. If current size is larger than max size, the
// cache shrinks to acommodate the new max.
func (c *DirentCache) setMaxSize(max uint64) {
	c.mu.Lock()
	c.maxSize = max
	c.maybeShrink()
	c.mu.Unlock()
}

// shrink removes the oldest element until the list is under the size limit.
func (c *DirentCache) maybeShrink() {
	for c.maxSize > 0 && c.currentSize > c.maxSize {
		c.remove(c.list.Back())
	}
}
