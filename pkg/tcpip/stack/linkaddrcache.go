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

package stack

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

const linkAddrCacheSize = 512 // max cache entries

// linkAddrCache is a fixed-sized cache mapping IP addresses to link addresses.
//
// The entries are stored in a ring buffer, oldest entry replaced first.
//
// This struct is safe for concurrent use.
type linkAddrCache struct {
	// ageLimit is how long a cache entry is valid for.
	ageLimit time.Duration

	// resolutionTimeout is the amount of time to wait for a link request to
	// resolve an address.
	resolutionTimeout time.Duration

	// resolutionAttempts is the number of times an address is attempted to be
	// resolved before failing.
	resolutionAttempts int

	cache struct {
		sync.Mutex
		table map[tcpip.FullAddress]*linkAddrEntry
		lru   linkAddrEntryList
	}
}

// entryState controls the state of a single entry in the cache.
type entryState int

const (
	// incomplete means that there is an outstanding request to resolve the
	// address. This is the initial state.
	incomplete entryState = iota
	// ready means that the address has been resolved and can be used.
	ready
)

// String implements Stringer.
func (s entryState) String() string {
	switch s {
	case incomplete:
		return "incomplete"
	case ready:
		return "ready"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// A linkAddrEntry is an entry in the linkAddrCache.
// This struct is thread-compatible.
type linkAddrEntry struct {
	// linkAddrEntryEntry access is synchronized by the linkAddrCache lock.
	linkAddrEntryEntry

	// TODO(gvisor.dev/issue/5150): move these fields under mu.
	// mu protects the fields below.
	mu sync.RWMutex

	addr       tcpip.FullAddress
	linkAddr   tcpip.LinkAddress
	expiration time.Time
	s          entryState

	// done is closed when address resolution is complete. It is nil iff s is
	// incomplete and resolution is not yet in progress.
	done chan struct{}

	// onResolve is called with the result of address resolution.
	onResolve []func(tcpip.LinkAddress, bool)
}

func (e *linkAddrEntry) notifyCompletionLocked(linkAddr tcpip.LinkAddress) {
	for _, callback := range e.onResolve {
		callback(linkAddr, len(linkAddr) != 0)
	}
	e.onResolve = nil
	if ch := e.done; ch != nil {
		close(ch)
		e.done = nil
	}
}

// changeStateLocked sets the entry's state to ns.
//
// The entry's expiration is bumped up to the greater of itself and the passed
// expiration; the zero value indicates immediate expiration, and is set
// unconditionally - this is an implementation detail that allows for entries
// to be reused.
//
// Precondition: e.mu must be locked
func (e *linkAddrEntry) changeStateLocked(ns entryState, expiration time.Time) {
	if e.s == incomplete && ns == ready {
		e.notifyCompletionLocked(e.linkAddr)
	}

	if expiration.IsZero() || expiration.After(e.expiration) {
		e.expiration = expiration
	}
	e.s = ns
}

// add adds a k -> v mapping to the cache.
func (c *linkAddrCache) add(k tcpip.FullAddress, v tcpip.LinkAddress) {
	// Calculate expiration time before acquiring the lock, since expiration is
	// relative to the time when information was learned, rather than when it
	// happened to be inserted into the cache.
	expiration := time.Now().Add(c.ageLimit)

	c.cache.Lock()
	entry := c.getOrCreateEntryLocked(k)
	c.cache.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	entry.linkAddr = v
	entry.changeStateLocked(ready, expiration)
}

// getOrCreateEntryLocked retrieves a cache entry associated with k. The
// returned entry is always refreshed in the cache (it is reachable via the
// map, and its place is bumped in LRU).
//
// If a matching entry exists in the cache, it is returned. If no matching
// entry exists and the cache is full, an existing entry is evicted via LRU,
// reset to state incomplete, and returned. If no matching entry exists and the
// cache is not full, a new entry with state incomplete is allocated and
// returned.
func (c *linkAddrCache) getOrCreateEntryLocked(k tcpip.FullAddress) *linkAddrEntry {
	if entry, ok := c.cache.table[k]; ok {
		c.cache.lru.Remove(entry)
		c.cache.lru.PushFront(entry)
		return entry
	}
	var entry *linkAddrEntry
	if len(c.cache.table) == linkAddrCacheSize {
		entry = c.cache.lru.Back()
		entry.mu.Lock()

		delete(c.cache.table, entry.addr)
		c.cache.lru.Remove(entry)

		// Wake waiters and mark the soon-to-be-reused entry as expired.
		entry.notifyCompletionLocked("" /* linkAddr */)
		entry.mu.Unlock()
	} else {
		entry = new(linkAddrEntry)
	}

	*entry = linkAddrEntry{
		addr: k,
		s:    incomplete,
	}
	c.cache.table[k] = entry
	c.cache.lru.PushFront(entry)
	return entry
}

// get reports any known link address for k.
func (c *linkAddrCache) get(k tcpip.FullAddress, linkRes LinkAddressResolver, localAddr tcpip.Address, nic NetworkInterface, onResolve func(tcpip.LinkAddress, bool)) (tcpip.LinkAddress, <-chan struct{}, *tcpip.Error) {
	if linkRes != nil {
		if addr, ok := linkRes.ResolveStaticAddress(k.Addr); ok {
			if onResolve != nil {
				onResolve(addr, true)
			}
			return addr, nil, nil
		}
	}

	c.cache.Lock()
	defer c.cache.Unlock()
	entry := c.getOrCreateEntryLocked(k)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	switch s := entry.s; s {
	case ready:
		if !time.Now().After(entry.expiration) {
			// Not expired.
			if onResolve != nil {
				onResolve(entry.linkAddr, true)
			}
			return entry.linkAddr, nil, nil
		}

		entry.changeStateLocked(incomplete, time.Time{})
		fallthrough
	case incomplete:
		if onResolve != nil {
			entry.onResolve = append(entry.onResolve, onResolve)
		}
		if entry.done == nil {
			entry.done = make(chan struct{})
			go c.startAddressResolution(k, linkRes, localAddr, nic, entry.done) // S/R-SAFE: link non-savable; wakers dropped synchronously.
		}
		return entry.linkAddr, entry.done, tcpip.ErrWouldBlock
	default:
		panic(fmt.Sprintf("invalid cache entry state: %s", s))
	}
}

func (c *linkAddrCache) startAddressResolution(k tcpip.FullAddress, linkRes LinkAddressResolver, localAddr tcpip.Address, nic NetworkInterface, done <-chan struct{}) {
	for i := 0; ; i++ {
		// Send link request, then wait for the timeout limit and check
		// whether the request succeeded.
		linkRes.LinkAddressRequest(k.Addr, localAddr, "" /* linkAddr */, nic)

		select {
		case now := <-time.After(c.resolutionTimeout):
			if stop := c.checkLinkRequest(now, k, i); stop {
				return
			}
		case <-done:
			return
		}
	}
}

// checkLinkRequest checks whether previous attempt to resolve address has
// succeeded and mark the entry accordingly. Returns true if request can stop,
// false if another request should be sent.
func (c *linkAddrCache) checkLinkRequest(now time.Time, k tcpip.FullAddress, attempt int) bool {
	c.cache.Lock()
	defer c.cache.Unlock()
	entry, ok := c.cache.table[k]
	if !ok {
		// Entry was evicted from the cache.
		return true
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()

	switch s := entry.s; s {
	case ready:
		// Entry was made ready by resolver.
	case incomplete:
		if attempt+1 < c.resolutionAttempts {
			// No response yet, need to send another ARP request.
			return false
		}
		// Max number of retries reached, delete entry.
		entry.notifyCompletionLocked("" /* linkAddr */)
		delete(c.cache.table, k)
	default:
		panic(fmt.Sprintf("invalid cache entry state: %s", s))
	}
	return true
}

func newLinkAddrCache(ageLimit, resolutionTimeout time.Duration, resolutionAttempts int) *linkAddrCache {
	c := &linkAddrCache{
		ageLimit:           ageLimit,
		resolutionTimeout:  resolutionTimeout,
		resolutionAttempts: resolutionAttempts,
	}
	c.cache.table = make(map[tcpip.FullAddress]*linkAddrEntry, linkAddrCacheSize)
	return c
}
