// Copyright 2020 The gVisor Authors.
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

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

const neighborCacheSize = 512 // max entries per interface

// NeighborStats holds metrics for the neighbor table.
type NeighborStats struct {
	// FailedEntryLookups counts the number of lookups performed on an entry in
	// Failed state.
	FailedEntryLookups *tcpip.StatCounter
}

// neighborCache maps IP addresses to link addresses. It uses the Least
// Recently Used (LRU) eviction strategy to implement a bounded cache for
// dynamically acquired entries. It contains the state machine and configuration
// for running Neighbor Unreachability Detection (NUD).
//
// There are two types of entries in the neighbor cache:
//  1. Dynamic entries are discovered automatically by neighbor discovery
//     protocols (e.g. ARP, NDP). These protocols will attempt to reconfirm
//     reachability with the device once the entry's state becomes Stale.
//  2. Static entries are explicitly added by a user and have no expiration.
//     Their state is always Static. The amount of static entries stored in the
//     cache is unbounded.
type neighborCache struct {
	nic   *NIC
	state *NUDState

	// mu protects the fields below.
	mu sync.RWMutex

	cache   map[tcpip.Address]*neighborEntry
	dynamic struct {
		lru neighborEntryList

		// count tracks the amount of dynamic entries in the cache. This is
		// needed since static entries do not count towards the LRU cache
		// eviction strategy.
		count uint16
	}
}

// getOrCreateEntry retrieves a cache entry associated with addr. The
// returned entry is always refreshed in the cache (it is reachable via the
// map, and its place is bumped in LRU).
//
// If a matching entry exists in the cache, it is returned. If no matching
// entry exists and the cache is full, an existing entry is evicted via LRU,
// reset to state incomplete, and returned. If no matching entry exists and the
// cache is not full, a new entry with state incomplete is allocated and
// returned.
func (n *neighborCache) getOrCreateEntry(remoteAddr tcpip.Address, linkRes LinkAddressResolver) *neighborEntry {
	n.mu.Lock()
	defer n.mu.Unlock()

	if entry, ok := n.cache[remoteAddr]; ok {
		entry.mu.RLock()
		if entry.neigh.State != Static {
			n.dynamic.lru.Remove(entry)
			n.dynamic.lru.PushFront(entry)
		}
		entry.mu.RUnlock()
		return entry
	}

	// The entry that needs to be created must be dynamic since all static
	// entries are directly added to the cache via addStaticEntry.
	entry := newNeighborEntry(n.nic, remoteAddr, n.state, linkRes)
	if n.dynamic.count == neighborCacheSize {
		e := n.dynamic.lru.Back()
		e.mu.Lock()

		delete(n.cache, e.neigh.Addr)
		n.dynamic.lru.Remove(e)
		n.dynamic.count--

		e.removeLocked()
		e.mu.Unlock()
	}
	n.cache[remoteAddr] = entry
	n.dynamic.lru.PushFront(entry)
	n.dynamic.count++
	return entry
}

// entry looks up neighbor information matching the remote address, and returns
// it if readily available.
//
// Returns ErrWouldBlock if the link address is not readily available, along
// with a notification channel for the caller to block on. Triggers address
// resolution asynchronously.
//
// If onResolve is provided, it will be called either immediately, if resolution
// is not required, or when address resolution is complete, with the resolved
// link address and whether resolution succeeded. After any callbacks have been
// called, the returned notification channel is closed.
//
// NB: if a callback is provided, it should not call into the neighbor cache.
//
// If specified, the local address must be an address local to the interface the
// neighbor cache belongs to. The local address is the source address of a
// packet prompting NUD/link address resolution.
//
// TODO(gvisor.dev/issue/5151): Don't return the neighbor entry.
func (n *neighborCache) entry(remoteAddr, localAddr tcpip.Address, linkRes LinkAddressResolver, onResolve func(LinkResolutionResult)) (NeighborEntry, <-chan struct{}, tcpip.Error) {
	entry := n.getOrCreateEntry(remoteAddr, linkRes)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	switch s := entry.neigh.State; s {
	case Stale:
		entry.handlePacketQueuedLocked(localAddr)
		fallthrough
	case Reachable, Static, Delay, Probe:
		// As per RFC 4861 section 7.3.3:
		//  "Neighbor Unreachability Detection operates in parallel with the sending
		//   of packets to a neighbor. While reasserting a neighbor's reachability,
		//   a node continues sending packets to that neighbor using the cached
		//   link-layer address."
		if onResolve != nil {
			onResolve(LinkResolutionResult{LinkAddress: entry.neigh.LinkAddr, Success: true})
		}
		return entry.neigh, nil, nil
	case Unknown, Incomplete, Failed:
		if onResolve != nil {
			entry.onResolve = append(entry.onResolve, onResolve)
		}
		if entry.done == nil {
			// Address resolution needs to be initiated.
			entry.done = make(chan struct{})
		}
		entry.handlePacketQueuedLocked(localAddr)
		return entry.neigh, entry.done, &tcpip.ErrWouldBlock{}
	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", s))
	}
}

// entries returns all entries in the neighbor cache.
func (n *neighborCache) entries() []NeighborEntry {
	n.mu.RLock()
	defer n.mu.RUnlock()

	entries := make([]NeighborEntry, 0, len(n.cache))
	for _, entry := range n.cache {
		entry.mu.RLock()
		entries = append(entries, entry.neigh)
		entry.mu.RUnlock()
	}
	return entries
}

// addStaticEntry adds a static entry to the neighbor cache, mapping an IP
// address to a link address. If a dynamic entry exists in the neighbor cache
// with the same address, it will be replaced with this static entry. If a
// static entry exists with the same address but different link address, it
// will be updated with the new link address. If a static entry exists with the
// same address and link address, nothing will happen.
func (n *neighborCache) addStaticEntry(addr tcpip.Address, linkAddr tcpip.LinkAddress) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if entry, ok := n.cache[addr]; ok {
		entry.mu.Lock()
		if entry.neigh.State != Static {
			// Dynamic entry found with the same address.
			n.dynamic.lru.Remove(entry)
			n.dynamic.count--
		} else if entry.neigh.LinkAddr == linkAddr {
			// Static entry found with the same address and link address.
			entry.mu.Unlock()
			return
		} else {
			// Static entry found with the same address but different link address.
			entry.neigh.LinkAddr = linkAddr
			entry.dispatchChangeEventLocked()
			entry.mu.Unlock()
			return
		}

		entry.removeLocked()
		entry.mu.Unlock()
	}

	n.cache[addr] = newStaticNeighborEntry(n.nic, addr, linkAddr, n.state)
}

// removeEntry removes a dynamic or static entry by address from the neighbor
// cache. Returns true if the entry was found and deleted.
func (n *neighborCache) removeEntry(addr tcpip.Address) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	entry, ok := n.cache[addr]
	if !ok {
		return false
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.neigh.State != Static {
		n.dynamic.lru.Remove(entry)
		n.dynamic.count--
	}

	entry.removeLocked()
	delete(n.cache, entry.neigh.Addr)
	return true
}

// clear removes all dynamic and static entries from the neighbor cache.
func (n *neighborCache) clear() {
	n.mu.Lock()
	defer n.mu.Unlock()

	for _, entry := range n.cache {
		entry.mu.Lock()
		entry.removeLocked()
		entry.mu.Unlock()
	}

	n.dynamic.lru = neighborEntryList{}
	n.cache = make(map[tcpip.Address]*neighborEntry)
	n.dynamic.count = 0
}

// config returns the NUD configuration.
func (n *neighborCache) config() NUDConfigurations {
	return n.state.Config()
}

// setConfig changes the NUD configuration.
//
// If config contains invalid NUD configuration values, it will be fixed to
// use default values for the erroneous values.
func (n *neighborCache) setConfig(config NUDConfigurations) {
	config.resetInvalidFields()
	n.state.SetConfig(config)
}

var _ neighborTable = (*neighborCache)(nil)

func (n *neighborCache) neighbors() ([]NeighborEntry, tcpip.Error) {
	return n.entries(), nil
}

func (n *neighborCache) get(addr tcpip.Address, linkRes LinkAddressResolver, localAddr tcpip.Address, onResolve func(LinkResolutionResult)) (tcpip.LinkAddress, <-chan struct{}, tcpip.Error) {
	entry, ch, err := n.entry(addr, localAddr, linkRes, onResolve)
	return entry.LinkAddr, ch, err
}

func (n *neighborCache) remove(addr tcpip.Address) tcpip.Error {
	if !n.removeEntry(addr) {
		return &tcpip.ErrBadAddress{}
	}

	return nil
}

func (n *neighborCache) removeAll() tcpip.Error {
	n.clear()
	return nil
}

// handleProbe handles a neighbor probe as defined by RFC 4861 section 7.2.3.
//
// Validation of the probe is expected to be handled by the caller.
func (n *neighborCache) handleProbe(remoteAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress, linkRes LinkAddressResolver) {
	entry := n.getOrCreateEntry(remoteAddr, linkRes)
	entry.mu.Lock()
	entry.handleProbeLocked(remoteLinkAddr)
	entry.mu.Unlock()
}

// handleConfirmation handles a neighbor confirmation as defined by
// RFC 4861 section 7.2.5.
//
// Validation of the confirmation is expected to be handled by the caller.
func (n *neighborCache) handleConfirmation(addr tcpip.Address, linkAddr tcpip.LinkAddress, flags ReachabilityConfirmationFlags) {
	n.mu.RLock()
	entry, ok := n.cache[addr]
	n.mu.RUnlock()
	if ok {
		entry.mu.Lock()
		entry.handleConfirmationLocked(linkAddr, flags)
		entry.mu.Unlock()
	}
	// The confirmation SHOULD be silently discarded if the recipient did not
	// initiate any communication with the target. This is indicated if there is
	// no matching entry for the remote address.
}

// handleUpperLevelConfirmation processes a confirmation of reachablity from
// some protocol that operates at a layer above the IP/link layer.
func (n *neighborCache) handleUpperLevelConfirmation(addr tcpip.Address) {
	n.mu.RLock()
	entry, ok := n.cache[addr]
	n.mu.RUnlock()
	if ok {
		entry.mu.Lock()
		entry.handleUpperLevelConfirmationLocked()
		entry.mu.Unlock()
	}
}

func (n *neighborCache) nudConfig() (NUDConfigurations, tcpip.Error) {
	return n.config(), nil
}

func (n *neighborCache) setNUDConfig(c NUDConfigurations) tcpip.Error {
	n.setConfig(c)
	return nil
}
