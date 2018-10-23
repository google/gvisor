// Copyright 2018 Google LLC
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
	"sync"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/sleep"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
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

	mu      sync.Mutex
	cache   map[tcpip.FullAddress]*linkAddrEntry
	next    int // array index of next available entry
	entries [linkAddrCacheSize]linkAddrEntry
}

// entryState controls the state of a single entry in the cache.
type entryState int

const (
	// incomplete means that there is an outstanding request to resolve the
	// address. This is the initial state.
	incomplete entryState = iota
	// ready means that the address has been resolved and can be used.
	ready
	// failed means that address resolution timed out and the address
	// could not be resolved.
	failed
	// expired means that the cache entry has expired and the address must be
	// resolved again.
	expired
)

// String implements Stringer.
func (s entryState) String() string {
	switch s {
	case incomplete:
		return "incomplete"
	case ready:
		return "ready"
	case failed:
		return "failed"
	case expired:
		return "expired"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// A linkAddrEntry is an entry in the linkAddrCache.
// This struct is thread-compatible.
type linkAddrEntry struct {
	addr       tcpip.FullAddress
	linkAddr   tcpip.LinkAddress
	expiration time.Time
	s          entryState

	// wakers is a set of waiters for address resolution result. Anytime
	// state transitions out of 'incomplete' these waiters are notified.
	wakers map[*sleep.Waker]struct{}

	done chan struct{}
}

func (e *linkAddrEntry) state() entryState {
	if e.s != expired && time.Now().After(e.expiration) {
		// Force the transition to ensure waiters are notified.
		e.changeState(expired)
	}
	return e.s
}

func (e *linkAddrEntry) changeState(ns entryState) {
	if e.s == ns {
		return
	}

	// Validate state transition.
	switch e.s {
	case incomplete:
		// All transitions are valid.
	case ready, failed:
		if ns != expired {
			panic(fmt.Sprintf("invalid state transition from %s to %s", e.s, ns))
		}
	case expired:
		// Terminal state.
		panic(fmt.Sprintf("invalid state transition from %s to %s", e.s, ns))
	default:
		panic(fmt.Sprintf("invalid state: %s", e.s))
	}

	// Notify whoever is waiting on address resolution when transitioning
	// out of 'incomplete'.
	if e.s == incomplete {
		for w := range e.wakers {
			w.Assert()
		}
		e.wakers = nil
		if e.done != nil {
			close(e.done)
		}
	}
	e.s = ns
}

func (e *linkAddrEntry) addWaker(w *sleep.Waker) {
	e.wakers[w] = struct{}{}
}

func (e *linkAddrEntry) removeWaker(w *sleep.Waker) {
	delete(e.wakers, w)
}

// add adds a k -> v mapping to the cache.
func (c *linkAddrCache) add(k tcpip.FullAddress, v tcpip.LinkAddress) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.cache[k]
	if ok {
		s := entry.state()
		if s != expired && entry.linkAddr == v {
			// Disregard repeated calls.
			return
		}
		// Check if entry is waiting for address resolution.
		if s == incomplete {
			entry.linkAddr = v
		} else {
			// Otherwise create a new entry to replace it.
			entry = c.makeAndAddEntry(k, v)
		}
	} else {
		entry = c.makeAndAddEntry(k, v)
	}

	entry.changeState(ready)
}

// makeAndAddEntry is a helper function to create and add a new
// entry to the cache map and evict older entry as needed.
func (c *linkAddrCache) makeAndAddEntry(k tcpip.FullAddress, v tcpip.LinkAddress) *linkAddrEntry {
	// Take over the next entry.
	entry := &c.entries[c.next]
	if c.cache[entry.addr] == entry {
		delete(c.cache, entry.addr)
	}

	// Mark the soon-to-be-replaced entry as expired, just in case there is
	// someone waiting for address resolution on it.
	entry.changeState(expired)

	*entry = linkAddrEntry{
		addr:       k,
		linkAddr:   v,
		expiration: time.Now().Add(c.ageLimit),
		wakers:     make(map[*sleep.Waker]struct{}),
		done:       make(chan struct{}),
	}

	c.cache[k] = entry
	c.next = (c.next + 1) % len(c.entries)
	return entry
}

// get reports any known link address for k.
func (c *linkAddrCache) get(k tcpip.FullAddress, linkRes LinkAddressResolver, localAddr tcpip.Address, linkEP LinkEndpoint, waker *sleep.Waker) (tcpip.LinkAddress, <-chan struct{}, *tcpip.Error) {
	if linkRes != nil {
		if addr, ok := linkRes.ResolveStaticAddress(k.Addr); ok {
			return addr, nil, nil
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.cache[k]; ok {
		switch s := entry.state(); s {
		case expired:
		case ready:
			return entry.linkAddr, nil, nil
		case failed:
			return "", nil, tcpip.ErrNoLinkAddress
		case incomplete:
			// Address resolution is still in progress.
			entry.addWaker(waker)
			return "", entry.done, tcpip.ErrWouldBlock
		default:
			panic(fmt.Sprintf("invalid cache entry state: %s", s))
		}
	}

	if linkRes == nil {
		return "", nil, tcpip.ErrNoLinkAddress
	}

	// Add 'incomplete' entry in the cache to mark that resolution is in progress.
	e := c.makeAndAddEntry(k, "")
	e.addWaker(waker)

	go c.startAddressResolution(k, linkRes, localAddr, linkEP, e.done) // S/R-SAFE: link non-savable; wakers dropped synchronously.

	return "", e.done, tcpip.ErrWouldBlock
}

// removeWaker removes a waker previously added through get().
func (c *linkAddrCache) removeWaker(k tcpip.FullAddress, waker *sleep.Waker) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.cache[k]; ok {
		entry.removeWaker(waker)
	}
}

func (c *linkAddrCache) startAddressResolution(k tcpip.FullAddress, linkRes LinkAddressResolver, localAddr tcpip.Address, linkEP LinkEndpoint, done <-chan struct{}) {
	for i := 0; ; i++ {
		// Send link request, then wait for the timeout limit and check
		// whether the request succeeded.
		linkRes.LinkAddressRequest(k.Addr, localAddr, linkEP)

		select {
		case <-time.After(c.resolutionTimeout):
			if stop := c.checkLinkRequest(k, i); stop {
				return
			}
		case <-done:
			return
		}
	}
}

// checkLinkRequest checks whether previous attempt to resolve address has succeeded
// and mark the entry accordingly, e.g. ready, failed, etc. Return true if request
// can stop, false if another request should be sent.
func (c *linkAddrCache) checkLinkRequest(k tcpip.FullAddress, attempt int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.cache[k]
	if !ok {
		// Entry was evicted from the cache.
		return true
	}

	switch s := entry.state(); s {
	case ready, failed, expired:
		// Entry was made ready by resolver or failed. Either way we're done.
		return true
	case incomplete:
		if attempt+1 >= c.resolutionAttempts {
			// Max number of retries reached, mark entry as failed.
			entry.changeState(failed)
			return true
		}
		// No response yet, need to send another ARP request.
		return false
	default:
		panic(fmt.Sprintf("invalid cache entry state: %s", s))
	}
}

func newLinkAddrCache(ageLimit, resolutionTimeout time.Duration, resolutionAttempts int) *linkAddrCache {
	return &linkAddrCache{
		ageLimit:           ageLimit,
		resolutionTimeout:  resolutionTimeout,
		resolutionAttempts: resolutionAttempts,
		cache:              make(map[tcpip.FullAddress]*linkAddrEntry, linkAddrCacheSize),
	}
}
