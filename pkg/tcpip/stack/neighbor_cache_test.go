// Copyright 2019 The gVisor Authors.
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
	"math"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
)

const (
	// entryStoreSize is the default number of entries that will be generated and
	// added to the entry store. This number needs to be larger than the size of
	// the neighbor cache to give ample opportunity for verifying behavior during
	// cache overflows. Four times the size of the neighbor cache allows for
	// three complete cache overflows.
	entryStoreSize = 4 * neighborCacheSize

	// typicalLatency is the typical latency for an ARP or NDP packet to travel
	// to a router and back.
	typicalLatency = time.Millisecond

	// testEntryBroadcastAddr is a special address that indicates a packet should
	// be sent to all nodes.
	testEntryBroadcastAddr = tcpip.Address("broadcast")

	// testEntryBroadcastLinkAddr is a special link address sent back to
	// multicast neighbor probes.
	testEntryBroadcastLinkAddr = tcpip.LinkAddress("mac_broadcast")

	// infiniteDuration indicates that a task will not occur in our lifetime.
	infiniteDuration = time.Duration(math.MaxInt64)
)

// unorderedEventsDiffOpts returns options passed to cmp.Diff to sort slices of
// events for cases where ordering must be ignored.
func unorderedEventsDiffOpts() []cmp.Option {
	return []cmp.Option{
		cmpopts.SortSlices(func(a, b testEntryEventInfo) bool {
			return strings.Compare(string(a.Entry.Addr), string(b.Entry.Addr)) < 0
		}),
	}
}

// unorderedEntriesDiffOpts returns options passed to cmp.Diff to sort slices of
// entries for cases where ordering must be ignored.
func unorderedEntriesDiffOpts() []cmp.Option {
	return []cmp.Option{
		cmpopts.SortSlices(func(a, b NeighborEntry) bool {
			return strings.Compare(string(a.Addr), string(b.Addr)) < 0
		}),
	}
}

func newTestNeighborResolver(nudDisp NUDDispatcher, config NUDConfigurations, clock tcpip.Clock) *testNeighborResolver {
	config.resetInvalidFields()
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	linkRes := &testNeighborResolver{
		clock:   clock,
		entries: newTestEntryStore(),
		delay:   typicalLatency,
	}
	linkRes.neigh.init(&nic{
		stack: &Stack{
			clock:           clock,
			nudDisp:         nudDisp,
			nudConfigs:      config,
			randomGenerator: rng,
		},
		id:    1,
		stats: makeNICStats(tcpip.NICStats{}.FillIn()),
	}, linkRes)
	return linkRes
}

// testEntryStore contains a set of IP to NeighborEntry mappings.
type testEntryStore struct {
	mu         sync.RWMutex
	entriesMap map[tcpip.Address]NeighborEntry
}

func toAddress(i uint16) tcpip.Address {
	return tcpip.Address([]byte{
		1,
		0,
		byte(i >> 8),
		byte(i),
	})
}

func toLinkAddress(i uint16) tcpip.LinkAddress {
	return tcpip.LinkAddress([]byte{
		1,
		0,
		0,
		0,
		byte(i >> 8),
		byte(i),
	})
}

// newTestEntryStore returns a testEntryStore pre-populated with entries.
func newTestEntryStore() *testEntryStore {
	store := &testEntryStore{
		entriesMap: make(map[tcpip.Address]NeighborEntry),
	}
	for i := uint16(0); i < entryStoreSize; i++ {
		addr := toAddress(i)
		linkAddr := toLinkAddress(i)

		store.entriesMap[addr] = NeighborEntry{
			Addr:     addr,
			LinkAddr: linkAddr,
		}
	}
	return store
}

// size returns the number of entries in the store.
func (s *testEntryStore) size() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint16(len(s.entriesMap))
}

// entry returns the entry at index i. Returns an empty entry and false if i is
// out of bounds.
func (s *testEntryStore) entry(i uint16) (NeighborEntry, bool) {
	return s.entryByAddr(toAddress(i))
}

// entryByAddr returns the entry matching addr for situations when the index is
// not available. Returns an empty entry and false if no entries match addr.
func (s *testEntryStore) entryByAddr(addr tcpip.Address) (NeighborEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entriesMap[addr]
	return entry, ok
}

// entries returns all entries in the store.
func (s *testEntryStore) entries() []NeighborEntry {
	entries := make([]NeighborEntry, 0, len(s.entriesMap))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := uint16(0); i < entryStoreSize; i++ {
		addr := toAddress(i)
		if entry, ok := s.entriesMap[addr]; ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

// set modifies the link addresses of an entry.
func (s *testEntryStore) set(i uint16, linkAddr tcpip.LinkAddress) {
	addr := toAddress(i)
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.entriesMap[addr]; ok {
		entry.LinkAddr = linkAddr
		s.entriesMap[addr] = entry
	}
}

// testNeighborResolver implements LinkAddressResolver to emulate sending a
// neighbor probe.
type testNeighborResolver struct {
	clock                tcpip.Clock
	neigh                neighborCache
	entries              *testEntryStore
	delay                time.Duration
	onLinkAddressRequest func()
	dropReplies          bool
}

var _ LinkAddressResolver = (*testNeighborResolver)(nil)

func (r *testNeighborResolver) LinkAddressRequest(targetAddr, _ tcpip.Address, _ tcpip.LinkAddress) tcpip.Error {
	if !r.dropReplies {
		// Delay handling the request to emulate network latency.
		r.clock.AfterFunc(r.delay, func() {
			r.fakeRequest(targetAddr)
		})
	}

	// Execute post address resolution action, if available.
	if f := r.onLinkAddressRequest; f != nil {
		f()
	}
	return nil
}

// fakeRequest emulates handling a response for a link address request.
func (r *testNeighborResolver) fakeRequest(addr tcpip.Address) {
	if entry, ok := r.entries.entryByAddr(addr); ok {
		r.neigh.handleConfirmation(addr, entry.LinkAddr, ReachabilityConfirmationFlags{
			Solicited: true,
			Override:  false,
			IsRouter:  false,
		})
	}
}

func (*testNeighborResolver) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if addr == testEntryBroadcastAddr {
		return testEntryBroadcastLinkAddr, true
	}
	return "", false
}

func (*testNeighborResolver) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return 0
}

func TestNeighborCacheGetConfig(t *testing.T) {
	nudDisp := testNUDDispatcher{}
	c := DefaultNUDConfigurations()
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(&nudDisp, c, clock)

	if got, want := linkRes.neigh.config(), c; got != want {
		t.Errorf("got linkRes.neigh.config() = %+v, want = %+v", got, want)
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	defer nudDisp.mu.Unlock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
}

func TestNeighborCacheSetConfig(t *testing.T) {
	nudDisp := testNUDDispatcher{}
	c := DefaultNUDConfigurations()
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(&nudDisp, c, clock)

	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1
	linkRes.neigh.setConfig(c)

	if got, want := linkRes.neigh.config(), c; got != want {
		t.Errorf("got linkRes.neigh.config() = %+v, want = %+v", got, want)
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	defer nudDisp.mu.Unlock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
}

func addReachableEntryWithRemoved(nudDisp *testNUDDispatcher, clock *faketime.ManualClock, linkRes *testNeighborResolver, entry NeighborEntry, removed []NeighborEntry) error {
	var gotLinkResolutionResult LinkResolutionResult

	_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
		gotLinkResolutionResult = r
	})
	if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		return fmt.Errorf("got linkRes.neigh.entry(%s, '', _) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
	}

	{
		var wantEvents []testEntryEventInfo

		for _, removedEntry := range removed {
			wantEvents = append(wantEvents, testEntryEventInfo{
				EventType: entryTestRemoved,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      removedEntry.Addr,
					LinkAddr:  removedEntry.LinkAddr,
					State:     Reachable,
					UpdatedAt: clock.Now(),
				},
			})
		}

		wantEvents = append(wantEvents, testEntryEventInfo{
			EventType: entryTestAdded,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:      entry.Addr,
				LinkAddr:  "",
				State:     Incomplete,
				UpdatedAt: clock.Now(),
			},
		})

		nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, nudDisp.mu.events)
		nudDisp.mu.events = nil
		nudDisp.mu.Unlock()
		if diff != "" {
			return fmt.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	clock.Advance(typicalLatency)

	select {
	case <-ch:
	default:
		return fmt.Errorf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _)", entry.Addr)
	}
	wantLinkResolutionResult := LinkResolutionResult{LinkAddress: entry.LinkAddr, Err: nil}
	if diff := cmp.Diff(wantLinkResolutionResult, gotLinkResolutionResult); diff != "" {
		return fmt.Errorf("got link resolution result mismatch (-want +got):\n%s", diff)
	}

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestChanged,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entry.Addr,
					LinkAddr:  entry.LinkAddr,
					State:     Reachable,
					UpdatedAt: clock.Now(),
				},
			},
		}
		nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, nudDisp.mu.events)
		nudDisp.mu.events = nil
		nudDisp.mu.Unlock()
		if diff != "" {
			return fmt.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	return nil
}

func addReachableEntry(nudDisp *testNUDDispatcher, clock *faketime.ManualClock, linkRes *testNeighborResolver, entry NeighborEntry) error {
	return addReachableEntryWithRemoved(nudDisp, clock, linkRes, entry, nil /* removed */)
}

func TestNeighborCacheEntry(t *testing.T) {
	c := DefaultNUDConfigurations()
	nudDisp := testNUDDispatcher{}
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(&nudDisp, c, clock)

	entry, ok := linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got linkRes.entries.entry(0) = _, false, want = true ")
	}
	if err := addReachableEntry(&nudDisp, clock, linkRes, entry); err != nil {
		t.Fatalf("addReachableEntry(...) = %s", err)
	}

	if _, _, err := linkRes.neigh.entry(entry.Addr, "", nil); err != nil {
		t.Fatalf("unexpected error from linkRes.neigh.entry(%s, '', nil): %s", entry.Addr, err)
	}

	// No more events should have been dispatched.
	nudDisp.mu.Lock()
	defer nudDisp.mu.Unlock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
}

func TestNeighborCacheRemoveEntry(t *testing.T) {
	config := DefaultNUDConfigurations()

	nudDisp := testNUDDispatcher{}
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(&nudDisp, config, clock)

	entry, ok := linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got linkRes.entries.entry(0) = _, false, want = true ")
	}
	if err := addReachableEntry(&nudDisp, clock, linkRes, entry); err != nil {
		t.Fatalf("addReachableEntry(...) = %s", err)
	}

	linkRes.neigh.removeEntry(entry.Addr)

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entry.Addr,
					LinkAddr:  entry.LinkAddr,
					State:     Reachable,
					UpdatedAt: clock.Now(),
				},
			},
		}
		nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, nudDisp.mu.events)
		nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	{
		_, _, err := linkRes.neigh.entry(entry.Addr, "", nil)
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Errorf("got linkRes.neigh.entry(%s, '', nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
		}
	}
}

type testContext struct {
	clock   *faketime.ManualClock
	linkRes *testNeighborResolver
	nudDisp *testNUDDispatcher
}

func newTestContext(c NUDConfigurations) testContext {
	nudDisp := &testNUDDispatcher{}
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(nudDisp, c, clock)

	return testContext{
		clock:   clock,
		linkRes: linkRes,
		nudDisp: nudDisp,
	}
}

type overflowOptions struct {
	startAtEntryIndex uint16
	wantStaticEntries []NeighborEntry
}

func (c *testContext) overflowCache(opts overflowOptions) error {
	// Fill the neighbor cache to capacity to verify the LRU eviction strategy is
	// working properly after the entry removal.
	for i := opts.startAtEntryIndex; i < c.linkRes.entries.size(); i++ {
		var removedEntries []NeighborEntry

		// When beyond the full capacity, the cache will evict an entry as per the
		// LRU eviction strategy. Note that the number of static entries should not
		// affect the total number of dynamic entries that can be added.
		if i >= neighborCacheSize+opts.startAtEntryIndex {
			removedEntry, ok := c.linkRes.entries.entry(i - neighborCacheSize)
			if !ok {
				return fmt.Errorf("got linkRes.entries.entry(%d) = _, false, want = true", i-neighborCacheSize)
			}
			removedEntries = append(removedEntries, removedEntry)
		}

		entry, ok := c.linkRes.entries.entry(i)
		if !ok {
			return fmt.Errorf("got c.linkRes.entries.entry(%d) = _, false, want = true", i)
		}
		if err := addReachableEntryWithRemoved(c.nudDisp, c.clock, c.linkRes, entry, removedEntries); err != nil {
			return fmt.Errorf("addReachableEntryWithRemoved(...) = %s", err)
		}
	}

	// Expect to find only the most recent entries. The order of entries reported
	// by entries() is nondeterministic, so entries have to be sorted before
	// comparison.
	wantUnorderedEntries := opts.wantStaticEntries
	for i := c.linkRes.entries.size() - neighborCacheSize; i < c.linkRes.entries.size(); i++ {
		entry, ok := c.linkRes.entries.entry(i)
		if !ok {
			return fmt.Errorf("got c.linkRes.entries.entry(%d) = _, false, want = true", i)
		}
		durationReachableNanos := time.Duration(c.linkRes.entries.size()-i-1) * typicalLatency
		wantEntry := NeighborEntry{
			Addr:      entry.Addr,
			LinkAddr:  entry.LinkAddr,
			State:     Reachable,
			UpdatedAt: c.clock.Now().Add(-durationReachableNanos),
		}
		wantUnorderedEntries = append(wantUnorderedEntries, wantEntry)
	}

	if diff := cmp.Diff(wantUnorderedEntries, c.linkRes.neigh.entries(), unorderedEntriesDiffOpts()...); diff != "" {
		return fmt.Errorf("neighbor entries mismatch (-want, +got):\n%s", diff)
	}

	// No more events should have been dispatched.
	c.nudDisp.mu.Lock()
	defer c.nudDisp.mu.Unlock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), c.nudDisp.mu.events); diff != "" {
		return fmt.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}

	return nil
}

// TestNeighborCacheOverflow verifies that the LRU cache eviction strategy
// respects the dynamic entry count.
func TestNeighborCacheOverflow(t *testing.T) {
	config := DefaultNUDConfigurations()
	// Stay in Reachable so the cache can overflow
	config.BaseReachableTime = infiniteDuration
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	c := newTestContext(config)
	opts := overflowOptions{
		startAtEntryIndex: 0,
	}
	if err := c.overflowCache(opts); err != nil {
		t.Errorf("c.overflowCache(%+v): %s", opts, err)
	}
}

// TestNeighborCacheRemoveEntryThenOverflow verifies that the LRU cache
// eviction strategy respects the dynamic entry count when an entry is removed.
func TestNeighborCacheRemoveEntryThenOverflow(t *testing.T) {
	config := DefaultNUDConfigurations()
	// Stay in Reachable so the cache can overflow
	config.BaseReachableTime = infiniteDuration
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	c := newTestContext(config)

	// Add a dynamic entry
	entry, ok := c.linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got c.linkRes.entries.entry(0) = _, false, want = true ")
	}
	if err := addReachableEntry(c.nudDisp, c.clock, c.linkRes, entry); err != nil {
		t.Fatalf("addReachableEntry(...) = %s", err)
	}

	// Remove the entry
	c.linkRes.neigh.removeEntry(entry.Addr)

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entry.Addr,
					LinkAddr:  entry.LinkAddr,
					State:     Reachable,
					UpdatedAt: c.clock.Now(),
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.mu.events)
		c.nudDisp.mu.events = nil
		c.nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	opts := overflowOptions{
		startAtEntryIndex: 0,
	}
	if err := c.overflowCache(opts); err != nil {
		t.Errorf("c.overflowCache(%+v): %s", opts, err)
	}
}

// TestNeighborCacheDuplicateStaticEntryWithSameLinkAddress verifies that
// adding a duplicate static entry with the same link address does not dispatch
// any events.
func TestNeighborCacheDuplicateStaticEntryWithSameLinkAddress(t *testing.T) {
	config := DefaultNUDConfigurations()
	c := newTestContext(config)

	// Add a static entry
	entry, ok := c.linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got c.linkRes.entries.entry(0) = _, false, want = true ")
	}
	staticLinkAddr := entry.LinkAddr + "static"
	c.linkRes.neigh.addStaticEntry(entry.Addr, staticLinkAddr)

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entry.Addr,
					LinkAddr:  staticLinkAddr,
					State:     Static,
					UpdatedAt: c.clock.Now(),
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.mu.events)
		c.nudDisp.mu.events = nil
		c.nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	// Add a duplicate static entry with the same link address.
	c.linkRes.neigh.addStaticEntry(entry.Addr, staticLinkAddr)

	c.nudDisp.mu.Lock()
	defer c.nudDisp.mu.Unlock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), c.nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
}

// TestNeighborCacheDuplicateStaticEntryWithDifferentLinkAddress verifies that
// adding a duplicate static entry with a different link address dispatches a
// change event.
func TestNeighborCacheDuplicateStaticEntryWithDifferentLinkAddress(t *testing.T) {
	config := DefaultNUDConfigurations()
	c := newTestContext(config)

	// Add a static entry
	entry, ok := c.linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got c.linkRes.entries.entry(0) = _, false, want = true ")
	}
	staticLinkAddr := entry.LinkAddr + "static"
	c.linkRes.neigh.addStaticEntry(entry.Addr, staticLinkAddr)

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entry.Addr,
					LinkAddr:  staticLinkAddr,
					State:     Static,
					UpdatedAt: c.clock.Now(),
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.mu.events)
		c.nudDisp.mu.events = nil
		c.nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	// Add a duplicate entry with a different link address
	staticLinkAddr += "duplicate"
	c.linkRes.neigh.addStaticEntry(entry.Addr, staticLinkAddr)

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestChanged,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entry.Addr,
					LinkAddr:  staticLinkAddr,
					State:     Static,
					UpdatedAt: c.clock.Now(),
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.mu.events)
		c.nudDisp.mu.events = nil
		c.nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}
}

// TestNeighborCacheRemoveStaticEntryThenOverflow verifies that the LRU cache
// eviction strategy respects the dynamic entry count when a static entry is
// added then removed. In this case, the dynamic entry count shouldn't have
// been touched.
func TestNeighborCacheRemoveStaticEntryThenOverflow(t *testing.T) {
	config := DefaultNUDConfigurations()
	// Stay in Reachable so the cache can overflow
	config.BaseReachableTime = infiniteDuration
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	c := newTestContext(config)

	// Add a static entry
	entry, ok := c.linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got c.linkRes.entries.entry(0) = _, false, want = true ")
	}
	staticLinkAddr := entry.LinkAddr + "static"
	c.linkRes.neigh.addStaticEntry(entry.Addr, staticLinkAddr)

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entry.Addr,
					LinkAddr:  staticLinkAddr,
					State:     Static,
					UpdatedAt: c.clock.Now(),
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.mu.events)
		c.nudDisp.mu.events = nil
		c.nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	// Remove the static entry that was just added
	c.linkRes.neigh.removeEntry(entry.Addr)

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entry.Addr,
					LinkAddr:  staticLinkAddr,
					State:     Static,
					UpdatedAt: c.clock.Now(),
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.mu.events)
		c.nudDisp.mu.events = nil
		c.nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	opts := overflowOptions{
		startAtEntryIndex: 0,
	}
	if err := c.overflowCache(opts); err != nil {
		t.Errorf("c.overflowCache(%+v): %s", opts, err)
	}
}

// TestNeighborCacheOverwriteWithStaticEntryThenOverflow verifies that the LRU
// cache eviction strategy keeps count of the dynamic entry count when an entry
// is overwritten by a static entry. Static entries should not count towards
// the size of the LRU cache.
func TestNeighborCacheOverwriteWithStaticEntryThenOverflow(t *testing.T) {
	config := DefaultNUDConfigurations()
	// Stay in Reachable so the cache can overflow
	config.BaseReachableTime = infiniteDuration
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	c := newTestContext(config)

	// Add a dynamic entry
	entry, ok := c.linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got c.linkRes.entries.entry(0) = _, false, want = true ")
	}
	if err := addReachableEntry(c.nudDisp, c.clock, c.linkRes, entry); err != nil {
		t.Fatalf("addReachableEntry(...) = %s", err)
	}

	// Override the entry with a static one using the same address
	staticLinkAddr := entry.LinkAddr + "static"
	c.linkRes.neigh.addStaticEntry(entry.Addr, staticLinkAddr)

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entry.Addr,
					LinkAddr:  entry.LinkAddr,
					State:     Reachable,
					UpdatedAt: c.clock.Now(),
				},
			},
			{
				EventType: entryTestAdded,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entry.Addr,
					LinkAddr:  staticLinkAddr,
					State:     Static,
					UpdatedAt: c.clock.Now(),
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.mu.events)
		c.nudDisp.mu.events = nil
		c.nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	opts := overflowOptions{
		startAtEntryIndex: 1,
		wantStaticEntries: []NeighborEntry{
			{
				Addr:      entry.Addr,
				LinkAddr:  staticLinkAddr,
				State:     Static,
				UpdatedAt: c.clock.Now(),
			},
		},
	}
	if err := c.overflowCache(opts); err != nil {
		t.Errorf("c.overflowCache(%+v): %s", opts, err)
	}
}

func TestNeighborCacheAddStaticEntryThenOverflow(t *testing.T) {
	config := DefaultNUDConfigurations()
	// Stay in Reachable so the cache can overflow
	config.BaseReachableTime = infiniteDuration
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	c := newTestContext(config)

	entry, ok := c.linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got c.linkRes.entries.entry(0) = _, false, want = true ")
	}
	c.linkRes.neigh.addStaticEntry(entry.Addr, entry.LinkAddr)
	e, _, err := c.linkRes.neigh.entry(entry.Addr, "", nil)
	if err != nil {
		t.Errorf("unexpected error from c.linkRes.neigh.entry(%s, \"\", nil): %s", entry.Addr, err)
	}
	want := NeighborEntry{
		Addr:      entry.Addr,
		LinkAddr:  entry.LinkAddr,
		State:     Static,
		UpdatedAt: c.clock.Now(),
	}
	if diff := cmp.Diff(want, e); diff != "" {
		t.Errorf("c.linkRes.neigh.entry(%s, \"\", nil) mismatch (-want, +got):\n%s", entry.Addr, diff)
	}

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entry.Addr,
					LinkAddr:  entry.LinkAddr,
					State:     Static,
					UpdatedAt: c.clock.Now(),
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.mu.events)
		c.nudDisp.mu.events = nil
		c.nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	opts := overflowOptions{
		startAtEntryIndex: 1,
		wantStaticEntries: []NeighborEntry{
			{
				Addr:      entry.Addr,
				LinkAddr:  entry.LinkAddr,
				State:     Static,
				UpdatedAt: c.clock.Now(),
			},
		},
	}
	if err := c.overflowCache(opts); err != nil {
		t.Errorf("c.overflowCache(%+v): %s", opts, err)
	}
}

func TestNeighborCacheClear(t *testing.T) {
	config := DefaultNUDConfigurations()

	nudDisp := testNUDDispatcher{}
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(&nudDisp, config, clock)

	// Add a dynamic entry.
	entry, ok := linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got linkRes.entries.entry(0) = _, false, want = true ")
	}
	if err := addReachableEntry(&nudDisp, clock, linkRes, entry); err != nil {
		t.Fatalf("addReachableEntry(...) = %s", err)
	}

	// Add a static entry.
	linkRes.neigh.addStaticEntry(entryTestAddr1, entryTestLinkAddr1)

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entryTestAddr1,
					LinkAddr:  entryTestLinkAddr1,
					State:     Static,
					UpdatedAt: clock.Now(),
				},
			},
		}
		nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, nudDisp.mu.events)
		nudDisp.mu.events = nil
		nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	// Clear should remove both dynamic and static entries.
	linkRes.neigh.clear()

	// Remove events dispatched from clear() have no deterministic order so they
	// need to be sorted before comparison.
	wantUnorderedEvents := []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:      entry.Addr,
				LinkAddr:  entry.LinkAddr,
				State:     Reachable,
				UpdatedAt: clock.Now(),
			},
		},
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:      entryTestAddr1,
				LinkAddr:  entryTestLinkAddr1,
				State:     Static,
				UpdatedAt: clock.Now(),
			},
		},
	}
	nudDisp.mu.Lock()
	defer nudDisp.mu.Unlock()
	if diff := cmp.Diff(wantUnorderedEvents, nudDisp.mu.events, unorderedEventsDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
}

// TestNeighborCacheClearThenOverflow verifies that the LRU cache eviction
// strategy keeps count of the dynamic entry count when all entries are
// cleared.
func TestNeighborCacheClearThenOverflow(t *testing.T) {
	config := DefaultNUDConfigurations()
	// Stay in Reachable so the cache can overflow
	config.BaseReachableTime = infiniteDuration
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	c := newTestContext(config)

	// Add a dynamic entry
	entry, ok := c.linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got c.linkRes.entries.entry(0) = _, false, want = true ")
	}
	if err := addReachableEntry(c.nudDisp, c.clock, c.linkRes, entry); err != nil {
		t.Fatalf("addReachableEntry(...) = %s", err)
	}

	// Clear the cache.
	c.linkRes.neigh.clear()

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:      entry.Addr,
					LinkAddr:  entry.LinkAddr,
					State:     Reachable,
					UpdatedAt: c.clock.Now(),
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.mu.events)
		c.nudDisp.mu.events = nil
		c.nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	opts := overflowOptions{
		startAtEntryIndex: 0,
	}
	if err := c.overflowCache(opts); err != nil {
		t.Errorf("c.overflowCache(%+v): %s", opts, err)
	}
}

func TestNeighborCacheKeepFrequentlyUsed(t *testing.T) {
	config := DefaultNUDConfigurations()
	// Stay in Reachable so the cache can overflow
	config.BaseReachableTime = infiniteDuration
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	nudDisp := testNUDDispatcher{}
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(&nudDisp, config, clock)

	startedAt := clock.Now()

	// The following logic is very similar to overflowCache, but
	// periodically refreshes the frequently used entry.

	// Fill the neighbor cache to capacity
	for i := uint16(0); i < neighborCacheSize; i++ {
		entry, ok := linkRes.entries.entry(i)
		if !ok {
			t.Fatalf("got linkRes.entries.entry(%d) = _, false, want = true", i)
		}
		if err := addReachableEntry(&nudDisp, clock, linkRes, entry); err != nil {
			t.Fatalf("addReachableEntry(...) = %s", err)
		}
	}

	frequentlyUsedEntry, ok := linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got linkRes.entries.entry(0) = _, false, want = true ")
	}

	// Keep adding more entries
	for i := uint16(neighborCacheSize); i < linkRes.entries.size(); i++ {
		// Periodically refresh the frequently used entry
		if i%(neighborCacheSize/2) == 0 {
			if _, _, err := linkRes.neigh.entry(frequentlyUsedEntry.Addr, "", nil); err != nil {
				t.Errorf("unexpected error from linkRes.neigh.entry(%s, '', nil): %s", frequentlyUsedEntry.Addr, err)
			}
		}

		entry, ok := linkRes.entries.entry(i)
		if !ok {
			t.Fatalf("got linkRes.entries.entry(%d) = _, false, want = true", i)
		}

		// An entry should have been removed, as per the LRU eviction strategy
		removedEntry, ok := linkRes.entries.entry(i - neighborCacheSize + 1)
		if !ok {
			t.Fatalf("got linkRes.entries.entry(%d) = _, false, want = true", i-neighborCacheSize+1)
		}

		if err := addReachableEntryWithRemoved(&nudDisp, clock, linkRes, entry, []NeighborEntry{removedEntry}); err != nil {
			t.Fatalf("addReachableEntryWithRemoved(...) = %s", err)
		}
	}

	// Expect to find only the frequently used entry and the most recent entries.
	// The order of entries reported by entries() is nondeterministic, so entries
	// have to be sorted before comparison.
	wantUnsortedEntries := []NeighborEntry{
		{
			Addr:     frequentlyUsedEntry.Addr,
			LinkAddr: frequentlyUsedEntry.LinkAddr,
			State:    Reachable,
			// Can be inferred since the frequently used entry is the first to
			// be created and transitioned to Reachable.
			UpdatedAt: startedAt.Add(typicalLatency),
		},
	}

	for i := linkRes.entries.size() - neighborCacheSize + 1; i < linkRes.entries.size(); i++ {
		entry, ok := linkRes.entries.entry(i)
		if !ok {
			t.Fatalf("got linkRes.entries.entry(%d) = _, false, want = true", i)
		}
		durationReachableNanos := time.Duration(linkRes.entries.size()-i-1) * typicalLatency
		wantUnsortedEntries = append(wantUnsortedEntries, NeighborEntry{
			Addr:      entry.Addr,
			LinkAddr:  entry.LinkAddr,
			State:     Reachable,
			UpdatedAt: clock.Now().Add(-durationReachableNanos),
		})
	}

	if diff := cmp.Diff(wantUnsortedEntries, linkRes.neigh.entries(), unorderedEntriesDiffOpts()...); diff != "" {
		t.Errorf("neighbor entries mismatch (-want, +got):\n%s", diff)
	}

	// No more events should have been dispatched.
	nudDisp.mu.Lock()
	defer nudDisp.mu.Unlock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
}

func TestNeighborCacheConcurrent(t *testing.T) {
	const concurrentProcesses = 16

	config := DefaultNUDConfigurations()

	nudDisp := testNUDDispatcher{}
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(&nudDisp, config, clock)

	storeEntries := linkRes.entries.entries()
	for _, entry := range storeEntries {
		var wg sync.WaitGroup
		for r := 0; r < concurrentProcesses; r++ {
			wg.Add(1)
			go func(entry NeighborEntry) {
				defer wg.Done()
				switch e, _, err := linkRes.neigh.entry(entry.Addr, "", nil); err.(type) {
				case nil, *tcpip.ErrWouldBlock:
				default:
					t.Errorf("got linkRes.neigh.entry(%s, '', nil) = (%+v, _, %s), want (_, _, nil) or (_, _, %s)", entry.Addr, e, err, &tcpip.ErrWouldBlock{})
				}
			}(entry)
		}

		// Wait for all goroutines to send a request
		wg.Wait()

		// Process all the requests for a single entry concurrently
		clock.Advance(typicalLatency)
	}

	// All goroutines add in the same order and add more values than can fit in
	// the cache. Our eviction strategy requires that the last entries are
	// present, up to the size of the neighbor cache, and the rest are missing.
	// The order of entries reported by entries() is nondeterministic, so entries
	// have to be sorted before comparison.
	var wantUnsortedEntries []NeighborEntry
	for i := linkRes.entries.size() - neighborCacheSize; i < linkRes.entries.size(); i++ {
		entry, ok := linkRes.entries.entry(i)
		if !ok {
			t.Errorf("got linkRes.entries.entry(%d) = _, false, want = true", i)
		}
		durationReachableNanos := time.Duration(linkRes.entries.size()-i-1) * typicalLatency
		wantUnsortedEntries = append(wantUnsortedEntries, NeighborEntry{
			Addr:      entry.Addr,
			LinkAddr:  entry.LinkAddr,
			State:     Reachable,
			UpdatedAt: clock.Now().Add(-durationReachableNanos),
		})
	}

	if diff := cmp.Diff(wantUnsortedEntries, linkRes.neigh.entries(), unorderedEntriesDiffOpts()...); diff != "" {
		t.Errorf("neighbor entries mismatch (-want, +got):\n%s", diff)
	}
}

func TestNeighborCacheReplace(t *testing.T) {
	config := DefaultNUDConfigurations()

	nudDisp := testNUDDispatcher{}
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(&nudDisp, config, clock)

	entry, ok := linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got linkRes.entries.entry(0) = _, false, want = true ")
	}
	if err := addReachableEntry(&nudDisp, clock, linkRes, entry); err != nil {
		t.Fatalf("addReachableEntry(...) = %s", err)
	}

	// Notify of a link address change
	var updatedLinkAddr tcpip.LinkAddress
	{
		entry, ok := linkRes.entries.entry(1)
		if !ok {
			t.Fatal("got linkRes.entries.entry(1) = _, false, want = true")
		}
		updatedLinkAddr = entry.LinkAddr
	}
	linkRes.entries.set(0, updatedLinkAddr)
	linkRes.neigh.handleConfirmation(entry.Addr, updatedLinkAddr, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})

	// Requesting the entry again should start neighbor reachability confirmation.
	//
	// Verify the entry's new link address and the new state.
	{
		e, _, err := linkRes.neigh.entry(entry.Addr, "", nil)
		if err != nil {
			t.Fatalf("linkRes.neigh.entry(%s, '', nil): %s", entry.Addr, err)
		}
		want := NeighborEntry{
			Addr:      entry.Addr,
			LinkAddr:  updatedLinkAddr,
			State:     Delay,
			UpdatedAt: clock.Now(),
		}
		if diff := cmp.Diff(want, e); diff != "" {
			t.Errorf("linkRes.neigh.entry(%s, '', nil) mismatch (-want, +got):\n%s", entry.Addr, diff)
		}
	}

	clock.Advance(config.DelayFirstProbeTime + typicalLatency)

	// Verify that the neighbor is now reachable.
	{
		e, _, err := linkRes.neigh.entry(entry.Addr, "", nil)
		if err != nil {
			t.Errorf("unexpected error from linkRes.neigh.entry(%s, '', nil): %s", entry.Addr, err)
		}
		want := NeighborEntry{
			Addr:      entry.Addr,
			LinkAddr:  updatedLinkAddr,
			State:     Reachable,
			UpdatedAt: clock.Now(),
		}
		if diff := cmp.Diff(want, e); diff != "" {
			t.Errorf("linkRes.neigh.entry(%s, '', nil) mismatch (-want, +got):\n%s", entry.Addr, diff)
		}
	}
}

func TestNeighborCacheResolutionFailed(t *testing.T) {
	config := DefaultNUDConfigurations()

	nudDisp := testNUDDispatcher{}
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(&nudDisp, config, clock)

	var requestCount uint32
	linkRes.onLinkAddressRequest = func() {
		atomic.AddUint32(&requestCount, 1)
	}

	entry, ok := linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got linkRes.entries.entry(0) = _, false, want = true ")
	}

	// First, sanity check that resolution is working
	if err := addReachableEntry(&nudDisp, clock, linkRes, entry); err != nil {
		t.Fatalf("addReachableEntry(...) = %s", err)
	}

	got, _, err := linkRes.neigh.entry(entry.Addr, "", nil)
	if err != nil {
		t.Fatalf("unexpected error from linkRes.neigh.entry(%s, '', nil): %s", entry.Addr, err)
	}
	want := NeighborEntry{
		Addr:      entry.Addr,
		LinkAddr:  entry.LinkAddr,
		State:     Reachable,
		UpdatedAt: clock.Now(),
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("linkRes.neigh.entry(%s, '', nil) mismatch (-want, +got):\n%s", entry.Addr, diff)
	}

	// Verify address resolution fails for an unknown address.
	before := atomic.LoadUint32(&requestCount)

	entry.Addr += "2"
	{
		_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
			if diff := cmp.Diff(LinkResolutionResult{Err: &tcpip.ErrTimeout{}}, r); diff != "" {
				t.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
			}
		})
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("got linkRes.neigh.entry(%s, '', _) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
		}
		waitFor := config.DelayFirstProbeTime + typicalLatency*time.Duration(config.MaxMulticastProbes)
		clock.Advance(waitFor)
		select {
		case <-ch:
		default:
			t.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _)", entry.Addr)
		}
	}

	maxAttempts := linkRes.neigh.config().MaxUnicastProbes
	if got, want := atomic.LoadUint32(&requestCount)-before, maxAttempts; got != want {
		t.Errorf("got link address request count = %d, want = %d", got, want)
	}
}

// TestNeighborCacheResolutionTimeout simulates sending MaxMulticastProbes
// probes and not retrieving a confirmation before the duration defined by
// MaxMulticastProbes * RetransmitTimer.
func TestNeighborCacheResolutionTimeout(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.RetransmitTimer = time.Millisecond // small enough to cause timeout

	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(nil, config, clock)
	// large enough to cause timeout
	linkRes.delay = time.Minute

	entry, ok := linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got linkRes.entries.entry(0) = _, false, want = true ")
	}

	_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
		if diff := cmp.Diff(LinkResolutionResult{Err: &tcpip.ErrTimeout{}}, r); diff != "" {
			t.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
		}
	})
	if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		t.Fatalf("got linkRes.neigh.entry(%s, '', _) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
	}
	waitFor := config.RetransmitTimer * time.Duration(config.MaxMulticastProbes)
	clock.Advance(waitFor)

	select {
	case <-ch:
	default:
		t.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _)", entry.Addr)
	}
}

// TestNeighborCacheRetryResolution simulates retrying communication after
// failing to perform address resolution.
func TestNeighborCacheRetryResolution(t *testing.T) {
	config := DefaultNUDConfigurations()
	nudDisp := testNUDDispatcher{}
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(&nudDisp, config, clock)
	// Simulate a faulty link.
	linkRes.dropReplies = true

	entry, ok := linkRes.entries.entry(0)
	if !ok {
		t.Fatal("got linkRes.entries.entry(0) = _, false, want = true ")
	}

	// Perform address resolution with a faulty link, which will fail.
	{
		_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
			if diff := cmp.Diff(LinkResolutionResult{Err: &tcpip.ErrTimeout{}}, r); diff != "" {
				t.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
			}
		})
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("got linkRes.neigh.entry(%s, '', _) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
		}

		{
			wantEvents := []testEntryEventInfo{
				{
					EventType: entryTestAdded,
					NICID:     1,
					Entry: NeighborEntry{
						Addr:      entry.Addr,
						LinkAddr:  "",
						State:     Incomplete,
						UpdatedAt: clock.Now(),
					},
				},
			}
			nudDisp.mu.Lock()
			diff := cmp.Diff(wantEvents, nudDisp.mu.events)
			nudDisp.mu.events = nil
			nudDisp.mu.Unlock()
			if diff != "" {
				t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
			}
		}

		waitFor := config.RetransmitTimer * time.Duration(config.MaxMulticastProbes)
		clock.Advance(waitFor)

		select {
		case <-ch:
		default:
			t.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _)", entry.Addr)
		}

		{
			wantEvents := []testEntryEventInfo{
				{
					EventType: entryTestChanged,
					NICID:     1,
					Entry: NeighborEntry{
						Addr:      entry.Addr,
						LinkAddr:  "",
						State:     Unreachable,
						UpdatedAt: clock.Now(),
					},
				},
			}
			nudDisp.mu.Lock()
			diff := cmp.Diff(wantEvents, nudDisp.mu.events)
			nudDisp.mu.events = nil
			nudDisp.mu.Unlock()
			if diff != "" {
				t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
			}
		}

		{
			wantEntries := []NeighborEntry{
				{
					Addr:      entry.Addr,
					LinkAddr:  "",
					State:     Unreachable,
					UpdatedAt: clock.Now(),
				},
			}
			if diff := cmp.Diff(linkRes.neigh.entries(), wantEntries, unorderedEntriesDiffOpts()...); diff != "" {
				t.Fatalf("neighbor entries mismatch (-got, +want):\n%s", diff)
			}
		}
	}

	// Retry address resolution with a working link.
	linkRes.dropReplies = false
	{
		incompleteEntry, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
			if diff := cmp.Diff(LinkResolutionResult{LinkAddress: entry.LinkAddr, Err: nil}, r); diff != "" {
				t.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
			}
		})
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("got linkRes.neigh.entry(%s, '', _) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
		}
		if incompleteEntry.State != Incomplete {
			t.Fatalf("got entry.State = %s, want = %s", incompleteEntry.State, Incomplete)
		}

		{
			wantEvents := []testEntryEventInfo{
				{
					EventType: entryTestChanged,
					NICID:     1,
					Entry: NeighborEntry{
						Addr:      entry.Addr,
						LinkAddr:  "",
						State:     Incomplete,
						UpdatedAt: clock.Now(),
					},
				},
			}
			nudDisp.mu.Lock()
			diff := cmp.Diff(wantEvents, nudDisp.mu.events)
			nudDisp.mu.events = nil
			nudDisp.mu.Unlock()
			if diff != "" {
				t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
			}
		}

		clock.Advance(typicalLatency)

		select {
		case <-ch:
		default:
			t.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _)", entry.Addr)
		}

		{
			wantEvents := []testEntryEventInfo{
				{
					EventType: entryTestChanged,
					NICID:     1,
					Entry: NeighborEntry{
						Addr:      entry.Addr,
						LinkAddr:  entry.LinkAddr,
						State:     Reachable,
						UpdatedAt: clock.Now(),
					},
				},
			}
			nudDisp.mu.Lock()
			diff := cmp.Diff(wantEvents, nudDisp.mu.events)
			nudDisp.mu.events = nil
			nudDisp.mu.Unlock()
			if diff != "" {
				t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
			}
		}

		{
			gotEntry, _, err := linkRes.neigh.entry(entry.Addr, "", nil)
			if err != nil {
				t.Fatalf("linkRes.neigh.entry(%s, '', _): %s", entry.Addr, err)
			}

			wantEntry := NeighborEntry{
				Addr:      entry.Addr,
				LinkAddr:  entry.LinkAddr,
				State:     Reachable,
				UpdatedAt: clock.Now(),
			}
			if diff := cmp.Diff(gotEntry, wantEntry); diff != "" {
				t.Fatalf("neighbor entry mismatch (-got, +want):\n%s", diff)
			}
		}
	}
}

func BenchmarkCacheClear(b *testing.B) {
	b.StopTimer()
	config := DefaultNUDConfigurations()
	clock := tcpip.NewStdClock()
	linkRes := newTestNeighborResolver(nil, config, clock)
	linkRes.delay = 0

	// Clear for every possible size of the cache
	for cacheSize := uint16(0); cacheSize < neighborCacheSize; cacheSize++ {
		// Fill the neighbor cache to capacity.
		for i := uint16(0); i < cacheSize; i++ {
			entry, ok := linkRes.entries.entry(i)
			if !ok {
				b.Fatalf("got linkRes.entries.entry(%d) = _, false, want = true", i)
			}

			_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
				if diff := cmp.Diff(LinkResolutionResult{LinkAddress: entry.LinkAddr, Err: nil}, r); diff != "" {
					b.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
				}
			})
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				b.Fatalf("got linkRes.neigh.entry(%s, '', _) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
			}

			select {
			case <-ch:
			default:
				b.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _)", entry.Addr)
			}
		}

		b.StartTimer()
		linkRes.neigh.clear()
		b.StopTimer()
	}
}
