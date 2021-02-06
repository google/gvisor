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
	"bytes"
	"encoding/binary"
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

	// testEntryLocalAddr is the source address of neighbor probes.
	testEntryLocalAddr = tcpip.Address("local_addr")

	// testEntryBroadcastLinkAddr is a special link address sent back to
	// multicast neighbor probes.
	testEntryBroadcastLinkAddr = tcpip.LinkAddress("mac_broadcast")

	// infiniteDuration indicates that a task will not occur in our lifetime.
	infiniteDuration = time.Duration(math.MaxInt64)
)

// entryDiffOpts returns the options passed to cmp.Diff to compare neighbor
// entries. The UpdatedAtNanos field is ignored due to a lack of a
// deterministic method to predict the time that an event will be dispatched.
func entryDiffOpts() []cmp.Option {
	return []cmp.Option{
		cmpopts.IgnoreFields(NeighborEntry{}, "UpdatedAtNanos"),
	}
}

// entryDiffOptsWithSort is like entryDiffOpts but also includes an option to
// sort slices of entries for cases where ordering must be ignored.
func entryDiffOptsWithSort() []cmp.Option {
	return append(entryDiffOpts(), cmpopts.SortSlices(func(a, b NeighborEntry) bool {
		return strings.Compare(string(a.Addr), string(b.Addr)) < 0
	}))
}

func newTestNeighborResolver(nudDisp NUDDispatcher, config NUDConfigurations, clock tcpip.Clock) *testNeighborResolver {
	config.resetInvalidFields()
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	linkRes := &testNeighborResolver{
		clock:   clock,
		entries: newTestEntryStore(),
		delay:   typicalLatency,
	}
	linkRes.neigh = newNeighborCache(&nic{
		stack: &Stack{
			clock:           clock,
			nudDisp:         nudDisp,
			nudConfigs:      config,
			randomGenerator: rng,
		},
		id:    1,
		stats: makeNICStats(),
	}, linkRes)
	return linkRes
}

// testEntryStore contains a set of IP to NeighborEntry mappings.
type testEntryStore struct {
	mu         sync.RWMutex
	entriesMap map[tcpip.Address]NeighborEntry
}

func toAddress(i int) tcpip.Address {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint8(1))
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, uint16(i))
	return tcpip.Address(buf.String())
}

func toLinkAddress(i int) tcpip.LinkAddress {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint8(1))
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, uint32(i))
	return tcpip.LinkAddress(buf.String())
}

// newTestEntryStore returns a testEntryStore pre-populated with entries.
func newTestEntryStore() *testEntryStore {
	store := &testEntryStore{
		entriesMap: make(map[tcpip.Address]NeighborEntry),
	}
	for i := 0; i < entryStoreSize; i++ {
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
func (s *testEntryStore) size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entriesMap)
}

// entry returns the entry at index i. Returns an empty entry and false if i is
// out of bounds.
func (s *testEntryStore) entry(i int) (NeighborEntry, bool) {
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
	for i := 0; i < entryStoreSize; i++ {
		addr := toAddress(i)
		if entry, ok := s.entriesMap[addr]; ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

// set modifies the link addresses of an entry.
func (s *testEntryStore) set(i int, linkAddr tcpip.LinkAddress) {
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
	neigh                *neighborCache
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

type entryEvent struct {
	nicID    tcpip.NICID
	address  tcpip.Address
	linkAddr tcpip.LinkAddress
	state    NeighborState
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
	if diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.events); diff != "" {
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
	if diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
}

func TestNeighborCacheEntry(t *testing.T) {
	c := DefaultNUDConfigurations()
	nudDisp := testNUDDispatcher{}
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(&nudDisp, c, clock)

	entry, ok := linkRes.entries.entry(0)
	if !ok {
		t.Fatal("linkRes.entries.entry(0) not found")
	}
	_, _, err := linkRes.neigh.entry(entry.Addr, "", nil)
	if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		t.Errorf("got linkRes.neigh.entry(%s, '', nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
	}

	clock.Advance(typicalLatency)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:  entry.Addr,
				State: Incomplete,
			},
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entry.Addr,
				LinkAddr: entry.LinkAddr,
				State:    Reachable,
			},
		},
	}
	nudDisp.mu.Lock()
	diff := cmp.Diff(wantEvents, nudDisp.events, eventDiffOpts()...)
	nudDisp.events = nil
	nudDisp.mu.Unlock()
	if diff != "" {
		t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}

	if _, _, err := linkRes.neigh.entry(entry.Addr, "", nil); err != nil {
		t.Fatalf("unexpected error from linkRes.neigh.entry(%s, '', nil): %s", entry.Addr, err)
	}

	// No more events should have been dispatched.
	nudDisp.mu.Lock()
	defer nudDisp.mu.Unlock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.events); diff != "" {
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
		t.Fatal("linkRes.entries.entry(0) not found")
	}

	_, _, err := linkRes.neigh.entry(entry.Addr, "", nil)
	if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		t.Errorf("got linkRes.neigh.entry(%s, '', nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
	}

	clock.Advance(typicalLatency)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:  entry.Addr,
				State: Incomplete,
			},
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entry.Addr,
				LinkAddr: entry.LinkAddr,
				State:    Reachable,
			},
		},
	}
	nudDisp.mu.Lock()
	diff := cmp.Diff(wantEvents, nudDisp.events, eventDiffOpts()...)
	nudDisp.events = nil
	nudDisp.mu.Unlock()
	if diff != "" {
		t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}

	linkRes.neigh.removeEntry(entry.Addr)

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:     entry.Addr,
					LinkAddr: entry.LinkAddr,
					State:    Reachable,
				},
			},
		}
		nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, nudDisp.events, eventDiffOpts()...)
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
	startAtEntryIndex int
	wantStaticEntries []NeighborEntry
}

func (c *testContext) overflowCache(opts overflowOptions) error {
	// Fill the neighbor cache to capacity to verify the LRU eviction strategy is
	// working properly after the entry removal.
	for i := opts.startAtEntryIndex; i < c.linkRes.entries.size(); i++ {
		// Add a new entry
		entry, ok := c.linkRes.entries.entry(i)
		if !ok {
			return fmt.Errorf("c.linkRes.entries.entry(%d) not found", i)
		}
		_, _, err := c.linkRes.neigh.entry(entry.Addr, "", nil)
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			return fmt.Errorf("got c.linkRes.neigh.entry(%s, '', nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
		}
		c.clock.Advance(c.linkRes.neigh.config().RetransmitTimer)

		var wantEvents []testEntryEventInfo

		// When beyond the full capacity, the cache will evict an entry as per the
		// LRU eviction strategy. Note that the number of static entries should not
		// affect the total number of dynamic entries that can be added.
		if i >= neighborCacheSize+opts.startAtEntryIndex {
			removedEntry, ok := c.linkRes.entries.entry(i - neighborCacheSize)
			if !ok {
				return fmt.Errorf("linkRes.entries.entry(%d) not found", i-neighborCacheSize)
			}
			wantEvents = append(wantEvents, testEntryEventInfo{
				EventType: entryTestRemoved,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:     removedEntry.Addr,
					LinkAddr: removedEntry.LinkAddr,
					State:    Reachable,
				},
			})
		}

		wantEvents = append(wantEvents, testEntryEventInfo{
			EventType: entryTestAdded,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:  entry.Addr,
				State: Incomplete,
			},
		}, testEntryEventInfo{
			EventType: entryTestChanged,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entry.Addr,
				LinkAddr: entry.LinkAddr,
				State:    Reachable,
			},
		})

		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...)
		c.nudDisp.events = nil
		c.nudDisp.mu.Unlock()
		if diff != "" {
			return fmt.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	// Expect to find only the most recent entries. The order of entries reported
	// by entries() is nondeterministic, so entries have to be sorted before
	// comparison.
	wantUnsortedEntries := opts.wantStaticEntries
	for i := c.linkRes.entries.size() - neighborCacheSize; i < c.linkRes.entries.size(); i++ {
		entry, ok := c.linkRes.entries.entry(i)
		if !ok {
			return fmt.Errorf("c.linkRes.entries.entry(%d) not found", i)
		}
		wantEntry := NeighborEntry{
			Addr:     entry.Addr,
			LinkAddr: entry.LinkAddr,
			State:    Reachable,
		}
		wantUnsortedEntries = append(wantUnsortedEntries, wantEntry)
	}

	if diff := cmp.Diff(wantUnsortedEntries, c.linkRes.neigh.entries(), entryDiffOptsWithSort()...); diff != "" {
		return fmt.Errorf("neighbor entries mismatch (-want, +got):\n%s", diff)
	}

	// No more events should have been dispatched.
	c.nudDisp.mu.Lock()
	defer c.nudDisp.mu.Unlock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), c.nudDisp.events); diff != "" {
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
		t.Fatal("c.linkRes.entries.entry(0) not found")
	}
	_, _, err := c.linkRes.neigh.entry(entry.Addr, "", nil)
	if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		t.Errorf("got c.linkRes.neigh.entry(%s, '', nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
	}
	c.clock.Advance(c.linkRes.neigh.config().RetransmitTimer)
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:  entry.Addr,
				State: Incomplete,
			},
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entry.Addr,
				LinkAddr: entry.LinkAddr,
				State:    Reachable,
			},
		},
	}
	c.nudDisp.mu.Lock()
	diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...)
	c.nudDisp.events = nil
	c.nudDisp.mu.Unlock()
	if diff != "" {
		t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}

	// Remove the entry
	c.linkRes.neigh.removeEntry(entry.Addr)

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:     entry.Addr,
					LinkAddr: entry.LinkAddr,
					State:    Reachable,
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...)
		c.nudDisp.events = nil
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
		t.Fatal("c.linkRes.entries.entry(0) not found")
	}
	staticLinkAddr := entry.LinkAddr + "static"
	c.linkRes.neigh.addStaticEntry(entry.Addr, staticLinkAddr)
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entry.Addr,
				LinkAddr: staticLinkAddr,
				State:    Static,
			},
		},
	}
	c.nudDisp.mu.Lock()
	diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...)
	c.nudDisp.events = nil
	c.nudDisp.mu.Unlock()
	if diff != "" {
		t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}

	// Remove the static entry that was just added
	c.linkRes.neigh.addStaticEntry(entry.Addr, staticLinkAddr)

	// No more events should have been dispatched.
	c.nudDisp.mu.Lock()
	defer c.nudDisp.mu.Unlock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), c.nudDisp.events); diff != "" {
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
		t.Fatal("c.linkRes.entries.entry(0) not found")
	}
	staticLinkAddr := entry.LinkAddr + "static"
	c.linkRes.neigh.addStaticEntry(entry.Addr, staticLinkAddr)
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entry.Addr,
				LinkAddr: staticLinkAddr,
				State:    Static,
			},
		},
	}
	c.nudDisp.mu.Lock()
	diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...)
	c.nudDisp.events = nil
	c.nudDisp.mu.Unlock()
	if diff != "" {
		t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
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
					Addr:     entry.Addr,
					LinkAddr: staticLinkAddr,
					State:    Static,
				},
			},
		}
		c.nudDisp.mu.Lock()
		defer c.nudDisp.mu.Unlock()
		if diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...); diff != "" {
			t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
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
		t.Fatal("c.linkRes.entries.entry(0) not found")
	}
	staticLinkAddr := entry.LinkAddr + "static"
	c.linkRes.neigh.addStaticEntry(entry.Addr, staticLinkAddr)
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entry.Addr,
				LinkAddr: staticLinkAddr,
				State:    Static,
			},
		},
	}
	c.nudDisp.mu.Lock()
	diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...)
	c.nudDisp.events = nil
	c.nudDisp.mu.Unlock()
	if diff != "" {
		t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}

	// Remove the static entry that was just added
	c.linkRes.neigh.removeEntry(entry.Addr)
	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:     entry.Addr,
					LinkAddr: staticLinkAddr,
					State:    Static,
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...)
		c.nudDisp.events = nil
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
		t.Fatal("c.linkRes.entries.entry(0) not found")
	}
	_, _, err := c.linkRes.neigh.entry(entry.Addr, "", nil)
	if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		t.Errorf("got c.linkRes.neigh.entry(%s, '', nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
	}
	c.clock.Advance(typicalLatency)
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:  entry.Addr,
				State: Incomplete,
			},
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entry.Addr,
				LinkAddr: entry.LinkAddr,
				State:    Reachable,
			},
		},
	}
	c.nudDisp.mu.Lock()
	diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...)
	c.nudDisp.events = nil
	c.nudDisp.mu.Unlock()
	if diff != "" {
		t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
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
					Addr:     entry.Addr,
					LinkAddr: entry.LinkAddr,
					State:    Reachable,
				},
			},
			{
				EventType: entryTestAdded,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:     entry.Addr,
					LinkAddr: staticLinkAddr,
					State:    Static,
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...)
		c.nudDisp.events = nil
		c.nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	opts := overflowOptions{
		startAtEntryIndex: 1,
		wantStaticEntries: []NeighborEntry{
			{
				Addr:     entry.Addr,
				LinkAddr: staticLinkAddr,
				State:    Static,
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
		t.Fatal("c.linkRes.entries.entry(0) not found")
	}
	c.linkRes.neigh.addStaticEntry(entry.Addr, entry.LinkAddr)
	e, _, err := c.linkRes.neigh.entry(entry.Addr, "", nil)
	if err != nil {
		t.Errorf("unexpected error from c.linkRes.neigh.entry(%s, \"\", nil): %s", entry.Addr, err)
	}
	want := NeighborEntry{
		Addr:     entry.Addr,
		LinkAddr: entry.LinkAddr,
		State:    Static,
	}
	if diff := cmp.Diff(want, e, entryDiffOpts()...); diff != "" {
		t.Errorf("c.linkRes.neigh.entry(%s, \"\", nil) mismatch (-want, +got):\n%s", entry.Addr, diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entry.Addr,
				LinkAddr: entry.LinkAddr,
				State:    Static,
			},
		},
	}
	c.nudDisp.mu.Lock()
	diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...)
	c.nudDisp.events = nil
	c.nudDisp.mu.Unlock()
	if diff != "" {
		t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}

	opts := overflowOptions{
		startAtEntryIndex: 1,
		wantStaticEntries: []NeighborEntry{
			{
				Addr:     entry.Addr,
				LinkAddr: entry.LinkAddr,
				State:    Static,
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
		t.Fatal("linkRes.entries.entry(0) not found")
	}
	_, _, err := linkRes.neigh.entry(entry.Addr, "", nil)
	if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		t.Errorf("got linkRes.neigh.entry(%s, '', nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
	}
	clock.Advance(typicalLatency)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:  entry.Addr,
				State: Incomplete,
			},
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entry.Addr,
				LinkAddr: entry.LinkAddr,
				State:    Reachable,
			},
		},
	}
	nudDisp.mu.Lock()
	diff := cmp.Diff(wantEvents, nudDisp.events, eventDiffOpts()...)
	nudDisp.events = nil
	nudDisp.mu.Unlock()
	if diff != "" {
		t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}

	// Add a static entry.
	linkRes.neigh.addStaticEntry(entryTestAddr1, entryTestLinkAddr1)

	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:     entryTestAddr1,
					LinkAddr: entryTestLinkAddr1,
					State:    Static,
				},
			},
		}
		nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, nudDisp.events, eventDiffOpts()...)
		nudDisp.events = nil
		nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	// Clear should remove both dynamic and static entries.
	linkRes.neigh.clear()

	// Remove events dispatched from clear() have no deterministic order so they
	// need to be sorted beforehand.
	wantUnsortedEvents := []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entry.Addr,
				LinkAddr: entry.LinkAddr,
				State:    Reachable,
			},
		},
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entryTestAddr1,
				LinkAddr: entryTestLinkAddr1,
				State:    Static,
			},
		},
	}
	nudDisp.mu.Lock()
	defer nudDisp.mu.Unlock()
	if diff := cmp.Diff(wantUnsortedEvents, nudDisp.events, eventDiffOptsWithSort()...); diff != "" {
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
		t.Fatal("c.linkRes.entries.entry(0) not found")
	}
	_, _, err := c.linkRes.neigh.entry(entry.Addr, "", nil)
	if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		t.Errorf("got c.linkRes.neigh.entry(%s, '', nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
	}
	c.clock.Advance(typicalLatency)
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:  entry.Addr,
				State: Incomplete,
			},
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Entry: NeighborEntry{
				Addr:     entry.Addr,
				LinkAddr: entry.LinkAddr,
				State:    Reachable,
			},
		},
	}
	c.nudDisp.mu.Lock()
	diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...)
	c.nudDisp.events = nil
	c.nudDisp.mu.Unlock()
	if diff != "" {
		t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}

	// Clear the cache.
	c.linkRes.neigh.clear()
	{
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:     entry.Addr,
					LinkAddr: entry.LinkAddr,
					State:    Reachable,
				},
			},
		}
		c.nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, c.nudDisp.events, eventDiffOpts()...)
		c.nudDisp.events = nil
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

	frequentlyUsedEntry, ok := linkRes.entries.entry(0)
	if !ok {
		t.Fatal("linkRes.entries.entry(0) not found")
	}

	// The following logic is very similar to overflowCache, but
	// periodically refreshes the frequently used entry.

	// Fill the neighbor cache to capacity
	for i := 0; i < neighborCacheSize; i++ {
		entry, ok := linkRes.entries.entry(i)
		if !ok {
			t.Fatalf("linkRes.entries.entry(%d) not found", i)
		}
		_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
			if diff := cmp.Diff(LinkResolutionResult{LinkAddress: entry.LinkAddr, Success: true}, r); diff != "" {
				t.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
			}
		})
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Errorf("got linkRes.neigh.entry(%s, '', _, _, nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
		}
		clock.Advance(typicalLatency)
		select {
		case <-ch:
		default:
			t.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _, _, nil)", entry.Addr)
		}
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:  entry.Addr,
					State: Incomplete,
				},
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:     entry.Addr,
					LinkAddr: entry.LinkAddr,
					State:    Reachable,
				},
			},
		}
		nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, nudDisp.events, eventDiffOpts()...)
		nudDisp.events = nil
		nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
		}
	}

	// Keep adding more entries
	for i := neighborCacheSize; i < linkRes.entries.size(); i++ {
		// Periodically refresh the frequently used entry
		if i%(neighborCacheSize/2) == 0 {
			if _, _, err := linkRes.neigh.entry(frequentlyUsedEntry.Addr, "", nil); err != nil {
				t.Errorf("unexpected error from linkRes.neigh.entry(%s, '', nil): %s", frequentlyUsedEntry.Addr, err)
			}
		}

		entry, ok := linkRes.entries.entry(i)
		if !ok {
			t.Fatalf("linkRes.entries.entry(%d) not found", i)
		}

		_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
			if diff := cmp.Diff(LinkResolutionResult{LinkAddress: entry.LinkAddr, Success: true}, r); diff != "" {
				t.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
			}
		})
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Errorf("got linkRes.neigh.entry(%s, '', _, _, nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
		}
		clock.Advance(typicalLatency)
		select {
		case <-ch:
		default:
			t.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _, _, nil)", entry.Addr)
		}

		// An entry should have been removed, as per the LRU eviction strategy
		removedEntry, ok := linkRes.entries.entry(i - neighborCacheSize + 1)
		if !ok {
			t.Fatalf("linkRes.entries.entry(%d) not found", i-neighborCacheSize+1)
		}
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:     removedEntry.Addr,
					LinkAddr: removedEntry.LinkAddr,
					State:    Reachable,
				},
			},
			{
				EventType: entryTestAdded,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:  entry.Addr,
					State: Incomplete,
				},
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Entry: NeighborEntry{
					Addr:     entry.Addr,
					LinkAddr: entry.LinkAddr,
					State:    Reachable,
				},
			},
		}
		nudDisp.mu.Lock()
		diff := cmp.Diff(wantEvents, nudDisp.events, eventDiffOpts()...)
		nudDisp.events = nil
		nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
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
		},
	}

	for i := linkRes.entries.size() - neighborCacheSize + 1; i < linkRes.entries.size(); i++ {
		entry, ok := linkRes.entries.entry(i)
		if !ok {
			t.Fatalf("linkRes.entries.entry(%d) not found", i)
		}
		wantEntry := NeighborEntry{
			Addr:     entry.Addr,
			LinkAddr: entry.LinkAddr,
			State:    Reachable,
		}
		wantUnsortedEntries = append(wantUnsortedEntries, wantEntry)
	}

	if diff := cmp.Diff(wantUnsortedEntries, linkRes.neigh.entries(), entryDiffOptsWithSort()...); diff != "" {
		t.Errorf("neighbor entries mismatch (-want, +got):\n%s", diff)
	}

	// No more events should have been dispatched.
	nudDisp.mu.Lock()
	defer nudDisp.mu.Unlock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.events); diff != "" {
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
			t.Errorf("linkRes.entries.entry(%d) not found", i)
		}
		wantEntry := NeighborEntry{
			Addr:     entry.Addr,
			LinkAddr: entry.LinkAddr,
			State:    Reachable,
		}
		wantUnsortedEntries = append(wantUnsortedEntries, wantEntry)
	}

	if diff := cmp.Diff(wantUnsortedEntries, linkRes.neigh.entries(), entryDiffOptsWithSort()...); diff != "" {
		t.Errorf("neighbor entries mismatch (-want, +got):\n%s", diff)
	}
}

func TestNeighborCacheReplace(t *testing.T) {
	config := DefaultNUDConfigurations()

	nudDisp := testNUDDispatcher{}
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(&nudDisp, config, clock)

	// Add an entry
	entry, ok := linkRes.entries.entry(0)
	if !ok {
		t.Fatal("linkRes.entries.entry(0) not found")
	}

	_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
		if diff := cmp.Diff(LinkResolutionResult{LinkAddress: entry.LinkAddr, Success: true}, r); diff != "" {
			t.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
		}
	})
	if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		t.Fatalf("got linkRes.neigh.entry(%s, '', _, _, nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
	}
	clock.Advance(typicalLatency)
	select {
	case <-ch:
	default:
		t.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _, _, nil)", entry.Addr)
	}

	// Verify the entry exists
	{
		e, _, err := linkRes.neigh.entry(entry.Addr, "", nil)
		if err != nil {
			t.Errorf("unexpected error from linkRes.neigh.entry(%s, '', _, _, nil): %s", entry.Addr, err)
		}
		if t.Failed() {
			t.FailNow()
		}
		want := NeighborEntry{
			Addr:     entry.Addr,
			LinkAddr: entry.LinkAddr,
			State:    Reachable,
		}
		if diff := cmp.Diff(want, e, entryDiffOpts()...); diff != "" {
			t.Errorf("linkRes.neigh.entry(%s, '', _, _, nil) mismatch (-want, +got):\n%s", entry.Addr, diff)
		}
	}

	// Notify of a link address change
	var updatedLinkAddr tcpip.LinkAddress
	{
		entry, ok := linkRes.entries.entry(1)
		if !ok {
			t.Fatal("linkRes.entries.entry(1) not found")
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
			Addr:     entry.Addr,
			LinkAddr: updatedLinkAddr,
			State:    Delay,
		}
		if diff := cmp.Diff(want, e, entryDiffOpts()...); diff != "" {
			t.Errorf("linkRes.neigh.entry(%s, '', nil) mismatch (-want, +got):\n%s", entry.Addr, diff)
		}
		clock.Advance(config.DelayFirstProbeTime + typicalLatency)
	}

	// Verify that the neighbor is now reachable.
	{
		e, _, err := linkRes.neigh.entry(entry.Addr, "", nil)
		clock.Advance(typicalLatency)
		if err != nil {
			t.Errorf("unexpected error from linkRes.neigh.entry(%s, '', nil): %s", entry.Addr, err)
		}
		want := NeighborEntry{
			Addr:     entry.Addr,
			LinkAddr: updatedLinkAddr,
			State:    Reachable,
		}
		if diff := cmp.Diff(want, e, entryDiffOpts()...); diff != "" {
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
		t.Fatal("linkRes.entries.entry(0) not found")
	}

	// First, sanity check that resolution is working
	{
		_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
			if diff := cmp.Diff(LinkResolutionResult{LinkAddress: entry.LinkAddr, Success: true}, r); diff != "" {
				t.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
			}
		})
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("got linkRes.neigh.entry(%s, '', _, _, nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
		}
		clock.Advance(typicalLatency)
		select {
		case <-ch:
		default:
			t.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _, _, nil)", entry.Addr)
		}
	}

	got, _, err := linkRes.neigh.entry(entry.Addr, "", nil)
	if err != nil {
		t.Fatalf("unexpected error from linkRes.neigh.entry(%s, '', nil): %s", entry.Addr, err)
	}
	want := NeighborEntry{
		Addr:     entry.Addr,
		LinkAddr: entry.LinkAddr,
		State:    Reachable,
	}
	if diff := cmp.Diff(want, got, entryDiffOpts()...); diff != "" {
		t.Errorf("linkRes.neigh.entry(%s, '', nil) mismatch (-want, +got):\n%s", entry.Addr, diff)
	}

	// Verify address resolution fails for an unknown address.
	before := atomic.LoadUint32(&requestCount)

	entry.Addr += "2"
	{
		_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
			if diff := cmp.Diff(LinkResolutionResult{Success: false}, r); diff != "" {
				t.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
			}
		})
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("got linkRes.neigh.entry(%s, '', _, _, nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
		}
		waitFor := config.DelayFirstProbeTime + typicalLatency*time.Duration(config.MaxMulticastProbes)
		clock.Advance(waitFor)
		select {
		case <-ch:
		default:
			t.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _, _, nil)", entry.Addr)
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
		t.Fatal("linkRes.entries.entry(0) not found")
	}

	_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
		if diff := cmp.Diff(LinkResolutionResult{Success: false}, r); diff != "" {
			t.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
		}
	})
	if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		t.Fatalf("got linkRes.neigh.entry(%s, '', _, _, nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
	}
	waitFor := config.RetransmitTimer * time.Duration(config.MaxMulticastProbes)
	clock.Advance(waitFor)

	select {
	case <-ch:
	default:
		t.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _, _, nil)", entry.Addr)
	}
}

// TestNeighborCacheRetryResolution simulates retrying communication after
// failing to perform address resolution.
func TestNeighborCacheRetryResolution(t *testing.T) {
	config := DefaultNUDConfigurations()
	clock := faketime.NewManualClock()
	linkRes := newTestNeighborResolver(nil, config, clock)
	// Simulate a faulty link.
	linkRes.dropReplies = true

	entry, ok := linkRes.entries.entry(0)
	if !ok {
		t.Fatal("linkRes.entries.entry(0) not found")
	}

	// Perform address resolution with a faulty link, which will fail.
	{
		_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
			if diff := cmp.Diff(LinkResolutionResult{Success: false}, r); diff != "" {
				t.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
			}
		})
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("got linkRes.neigh.entry(%s, '', _, _, nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
		}
		waitFor := config.RetransmitTimer * time.Duration(config.MaxMulticastProbes)
		clock.Advance(waitFor)

		select {
		case <-ch:
		default:
			t.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _, _, nil)", entry.Addr)
		}
	}

	// Verify the entry is in Failed state.
	wantEntries := []NeighborEntry{
		{
			Addr:     entry.Addr,
			LinkAddr: "",
			State:    Failed,
		},
	}
	if diff := cmp.Diff(linkRes.neigh.entries(), wantEntries, entryDiffOptsWithSort()...); diff != "" {
		t.Fatalf("neighbor entries mismatch (-got, +want):\n%s", diff)
	}

	// Retry address resolution with a working link.
	linkRes.dropReplies = false
	{
		incompleteEntry, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
			if diff := cmp.Diff(LinkResolutionResult{LinkAddress: entry.LinkAddr, Success: true}, r); diff != "" {
				t.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
			}
		})
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("got linkRes.neigh.entry(%s, '', _) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
		}
		if incompleteEntry.State != Incomplete {
			t.Fatalf("got entry.State = %s, want = %s", incompleteEntry.State, Incomplete)
		}
		clock.Advance(typicalLatency)

		select {
		case <-ch:
			if !ok {
				t.Fatal("expected successful address resolution")
			}
			reachableEntry, _, err := linkRes.neigh.entry(entry.Addr, "", nil)
			if err != nil {
				t.Fatalf("linkRes.neigh.entry(%s, '', _, _, nil): %v", entry.Addr, err)
			}
			if reachableEntry.Addr != entry.Addr {
				t.Fatalf("got entry.Addr = %s, want = %s", reachableEntry.Addr, entry.Addr)
			}
			if reachableEntry.LinkAddr != entry.LinkAddr {
				t.Fatalf("got entry.LinkAddr = %s, want = %s", reachableEntry.LinkAddr, entry.LinkAddr)
			}
			if reachableEntry.State != Reachable {
				t.Fatalf("got entry.State = %s, want = %s", reachableEntry.State.String(), Reachable.String())
			}
		default:
			t.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _, _, nil)", entry.Addr)
		}
	}
}

func BenchmarkCacheClear(b *testing.B) {
	b.StopTimer()
	config := DefaultNUDConfigurations()
	clock := &tcpip.StdClock{}
	linkRes := newTestNeighborResolver(nil, config, clock)
	linkRes.delay = 0

	// Clear for every possible size of the cache
	for cacheSize := 0; cacheSize < neighborCacheSize; cacheSize++ {
		// Fill the neighbor cache to capacity.
		for i := 0; i < cacheSize; i++ {
			entry, ok := linkRes.entries.entry(i)
			if !ok {
				b.Fatalf("linkRes.entries.entry(%d) not found", i)
			}

			_, ch, err := linkRes.neigh.entry(entry.Addr, "", func(r LinkResolutionResult) {
				if diff := cmp.Diff(LinkResolutionResult{LinkAddress: entry.LinkAddr, Success: true}, r); diff != "" {
					b.Fatalf("got link resolution result mismatch (-want +got):\n%s", diff)
				}
			})
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				b.Fatalf("got linkRes.neigh.entry(%s, '', _, _, nil) = %v, want = %s", entry.Addr, err, &tcpip.ErrWouldBlock{})
			}

			select {
			case <-ch:
			default:
				b.Fatalf("expected notification from done channel returned by linkRes.neigh.entry(%s, '', _, _, nil)", entry.Addr)
			}
		}

		b.StartTimer()
		linkRes.neigh.clear()
		b.StopTimer()
	}
}
