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
	"math"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

const (
	entryTestNetNumber tcpip.NetworkProtocolNumber = math.MaxUint32

	entryTestNICID tcpip.NICID = 1

	entryTestLinkAddr1 = tcpip.LinkAddress("\x0a\x00\x00\x00\x00\x01")
	entryTestLinkAddr2 = tcpip.LinkAddress("\x0a\x00\x00\x00\x00\x02")

	// entryTestNetDefaultMTU is the MTU, in bytes, used throughout the tests,
	// except where another value is explicitly used. It is chosen to match the
	// MTU of loopback interfaces on Linux systems.
	entryTestNetDefaultMTU = 65536
)

var (
	entryTestAddr1 = testutil.MustParse6("a::1")
	entryTestAddr2 = testutil.MustParse6("a::2")
)

// runImmediatelyScheduledJobs runs all jobs scheduled to run at the current
// time.
func runImmediatelyScheduledJobs(clock *faketime.ManualClock) {
	clock.Advance(immediateDuration)
}

// The following unit tests exercise every state transition and verify its
// behavior with RFC 4681 and RFC 7048.
//
// | From        | To          | Cause                                      | Update   | Action     | Event   |
// | =========== | =========== | ========================================== | ======== | ===========| ======= |
// | Unknown     | Unknown     | Confirmation w/ unknown address            |          |            | Added   |
// | Unknown     | Incomplete  | Packet queued to unknown address           |          | Send probe | Added   |
// | Unknown     | Stale       | Probe                                      |          |            | Added   |
// | Incomplete  | Incomplete  | Retransmit timer expired                   |          | Send probe | Changed |
// | Incomplete  | Reachable   | Solicited confirmation                     | LinkAddr | Notify     | Changed |
// | Incomplete  | Stale       | Unsolicited confirmation                   | LinkAddr | Notify     | Changed |
// | Incomplete  | Stale       | Probe                                      | LinkAddr | Notify     | Changed |
// | Incomplete  | Unreachable | Max probes sent without reply              |          | Notify     | Changed |
// | Reachable   | Reachable   | Confirmation w/ different isRouter flag    | IsRouter |            |         |
// | Reachable   | Stale       | Reachable timer expired                    |          |            | Changed |
// | Reachable   | Stale       | Probe or confirmation w/ different address |          |            | Changed |
// | Stale       | Reachable   | Solicited override confirmation            | LinkAddr |            | Changed |
// | Stale       | Reachable   | Solicited confirmation w/o address         |          | Notify     | Changed |
// | Stale       | Stale       | Override confirmation                      | LinkAddr |            | Changed |
// | Stale       | Stale       | Probe w/ different address                 | LinkAddr |            | Changed |
// | Stale       | Delay       | Packet sent                                |          |            | Changed |
// | Delay       | Reachable   | Upper-layer confirmation                   |          |            | Changed |
// | Delay       | Reachable   | Solicited override confirmation            | LinkAddr |            | Changed |
// | Delay       | Reachable   | Solicited confirmation w/o address         |          | Notify     | Changed |
// | Delay       | Stale       | Probe or confirmation w/ different address |          |            | Changed |
// | Delay       | Probe       | Delay timer expired                        |          | Send probe | Changed |
// | Probe       | Reachable   | Solicited override confirmation            | LinkAddr |            | Changed |
// | Probe       | Reachable   | Solicited confirmation w/ same address     |          | Notify     | Changed |
// | Probe       | Reachable   | Solicited confirmation w/o address         |          | Notify     | Changed |
// | Probe       | Stale       | Probe or confirmation w/ different address |          |            | Changed |
// | Probe       | Probe       | Retransmit timer expired                   |          |            | Changed |
// | Probe       | Unreachable | Max probes sent without reply              |          | Notify     | Changed |
// | Unreachable | Incomplete  | Packet queued                              |          | Send probe | Changed |
// | Unreachable | Stale       | Probe w/ different address                 | LinkAddr |            | Changed |

type testEntryEventType uint8

const (
	entryTestAdded testEntryEventType = iota
	entryTestChanged
	entryTestRemoved
)

func (t testEntryEventType) String() string {
	switch t {
	case entryTestAdded:
		return "add"
	case entryTestChanged:
		return "change"
	case entryTestRemoved:
		return "remove"
	default:
		return fmt.Sprintf("unknown (%d)", t)
	}
}

// Fields are exported for use with cmp.Diff.
type testEntryEventInfo struct {
	EventType testEntryEventType
	NICID     tcpip.NICID
	Entry     NeighborEntry
}

func (e testEntryEventInfo) String() string {
	return fmt.Sprintf("%s event for NIC #%d, %#v", e.EventType, e.NICID, e.Entry)
}

// testNUDDispatcher implements NUDDispatcher to validate the dispatching of
// events upon certain NUD state machine events.
type testNUDDispatcher struct {
	mu struct {
		sync.Mutex
		events []testEntryEventInfo
	}
}

var _ NUDDispatcher = (*testNUDDispatcher)(nil)

func (d *testNUDDispatcher) queueEvent(e testEntryEventInfo) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.mu.events = append(d.mu.events, e)
}

func (d *testNUDDispatcher) OnNeighborAdded(nicID tcpip.NICID, entry NeighborEntry) {
	d.queueEvent(testEntryEventInfo{
		EventType: entryTestAdded,
		NICID:     nicID,
		Entry:     entry,
	})
}

func (d *testNUDDispatcher) OnNeighborChanged(nicID tcpip.NICID, entry NeighborEntry) {
	d.queueEvent(testEntryEventInfo{
		EventType: entryTestChanged,
		NICID:     nicID,
		Entry:     entry,
	})
}

func (d *testNUDDispatcher) OnNeighborRemoved(nicID tcpip.NICID, entry NeighborEntry) {
	d.queueEvent(testEntryEventInfo{
		EventType: entryTestRemoved,
		NICID:     nicID,
		Entry:     entry,
	})
}

type entryTestLinkResolver struct {
	mu struct {
		sync.Mutex
		probes []entryTestProbeInfo
	}
}

var _ LinkAddressResolver = (*entryTestLinkResolver)(nil)

type entryTestProbeInfo struct {
	RemoteAddress     tcpip.Address
	RemoteLinkAddress tcpip.LinkAddress
	LocalAddress      tcpip.Address
}

func (p entryTestProbeInfo) String() string {
	return fmt.Sprintf("probe with RemoteAddress=%q, RemoteLinkAddress=%q, LocalAddress=%q", p.RemoteAddress, p.RemoteLinkAddress, p.LocalAddress)
}

// LinkAddressRequest sends a request for the LinkAddress of addr. Broadcasts
// to the local network if linkAddr is the zero value.
func (r *entryTestLinkResolver) LinkAddressRequest(targetAddr, localAddr tcpip.Address, linkAddr tcpip.LinkAddress) tcpip.Error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mu.probes = append(r.mu.probes, entryTestProbeInfo{
		RemoteAddress:     targetAddr,
		RemoteLinkAddress: linkAddr,
		LocalAddress:      localAddr,
	})
	return nil
}

// ResolveStaticAddress attempts to resolve address without sending requests.
// It either resolves the name immediately or returns the empty LinkAddress.
func (r *entryTestLinkResolver) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	return "", false
}

// LinkAddressProtocol returns the network protocol of the addresses this
// resolver can resolve.
func (r *entryTestLinkResolver) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return entryTestNetNumber
}

func entryTestSetup(c NUDConfigurations) (*neighborEntry, *testNUDDispatcher, *entryTestLinkResolver, *faketime.ManualClock) {
	clock := faketime.NewManualClock()
	disp := testNUDDispatcher{}
	nic := nic{
		LinkEndpoint: nil, // entryTestLinkResolver doesn't use a LinkEndpoint

		id: entryTestNICID,
		stack: &Stack{
			clock:           clock,
			nudDisp:         &disp,
			nudConfigs:      c,
			randomGenerator: rand.New(rand.NewSource(time.Now().UnixNano())),
		},
		stats: makeNICStats(tcpip.NICStats{}.FillIn()),
	}
	netEP := (&testIPv6Protocol{}).NewEndpoint(&nic, nil)
	nic.networkEndpoints = map[tcpip.NetworkProtocolNumber]NetworkEndpoint{
		header.IPv6ProtocolNumber: netEP,
	}

	var linkRes entryTestLinkResolver
	// Stub out the neighbor cache to verify deletion from the cache.
	l := &linkResolver{
		resolver: &linkRes,
	}
	l.neigh.init(&nic, &linkRes)

	entry := newNeighborEntry(&l.neigh, entryTestAddr1 /* remoteAddr */, l.neigh.state)
	l.neigh.mu.Lock()
	l.neigh.mu.cache[entryTestAddr1] = entry
	l.neigh.mu.Unlock()
	nic.linkAddrResolvers = map[tcpip.NetworkProtocolNumber]*linkResolver{
		header.IPv6ProtocolNumber: l,
	}

	return entry, &disp, &linkRes, clock
}

// TestEntryInitiallyUnknown verifies that the state of a newly created
// neighborEntry is Unknown.
func TestEntryInitiallyUnknown(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	if e.mu.neigh.State != Unknown {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Unknown)
	}
	e.mu.Unlock()

	clock.Advance(c.RetransmitTimer)

	// No probes should have been sent.
	linkRes.mu.Lock()
	diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-want, +got):\n%s", diff)
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryUnknownToUnknownWhenConfirmationWithUnknownAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Unknown {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Unknown)
	}
	e.mu.Unlock()

	clock.Advance(time.Hour)

	// No probes should have been sent.
	linkRes.mu.Lock()
	diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-want, +got):\n%s", diff)
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryUnknownToIncomplete(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}
}

func unknownToIncomplete(e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock) error {
	if err := func() error {
		e.mu.Lock()
		defer e.mu.Unlock()

		if e.mu.neigh.State != Unknown {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Unknown)
		}
		e.handlePacketQueuedLocked(entryTestAddr2)
		if e.mu.neigh.State != Incomplete {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Incomplete)
		}
		return nil
	}(); err != nil {
		return err
	}

	runImmediatelyScheduledJobs(clock)
	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(wantProbes, linkRes.mu.probes)
	linkRes.mu.probes = nil
	linkRes.mu.Unlock()
	if diff != "" {
		return fmt.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       tcpip.LinkAddress(""),
				State:          Incomplete,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	{
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

func TestEntryUnknownToStale(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
}

func unknownToStale(e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock) error {
	if err := func() error {
		e.mu.Lock()
		defer e.mu.Unlock()

		if e.mu.neigh.State != Unknown {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Unknown)
		}
		e.handleProbeLocked(entryTestLinkAddr1)
		if e.mu.neigh.State != Stale {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
		}
		return nil
	}(); err != nil {
		return err
	}

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			return fmt.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr1,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	{
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

func TestEntryIncompleteToIncompleteDoesNotChangeUpdatedAt(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}

	// UpdatedAt should remain the same during address resolution.
	e.mu.Lock()
	startedAt := e.mu.neigh.UpdatedAtNanos
	e.mu.Unlock()

	// Wait for the rest of the reachability probe transmissions, signifying
	// Incomplete to Incomplete transitions.
	for i := uint32(1); i < c.MaxMulticastProbes; i++ {
		clock.Advance(c.RetransmitTimer)

		wantProbes := []entryTestProbeInfo{
			{
				RemoteAddress:     entryTestAddr1,
				RemoteLinkAddress: tcpip.LinkAddress(""),
				LocalAddress:      entryTestAddr2,
			},
		}
		linkRes.mu.Lock()
		diff := cmp.Diff(wantProbes, linkRes.mu.probes)
		linkRes.mu.probes = nil
		linkRes.mu.Unlock()
		if diff != "" {
			t.Fatalf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}

		e.mu.Lock()
		if got, want := e.mu.neigh.UpdatedAtNanos, startedAt; got != want {
			t.Errorf("got e.mu.neigh.UpdatedAt = %q, want = %q", got, want)
		}
		e.mu.Unlock()
	}

	// UpdatedAt should change after failing address resolution. Timing out after
	// sending the last probe transitions the entry to Unreachable.
	clock.Advance(c.RetransmitTimer)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       tcpip.LinkAddress(""),
				State:          Unreachable,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryIncompleteToReachable(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}
	if err := incompleteToReachable(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("incompleteToReachable(...) = %s", err)
	}
}

func incompleteToReachableWithFlags(e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock, flags ReachabilityConfirmationFlags) error {
	if err := func() error {
		e.mu.Lock()
		defer e.mu.Unlock()

		if e.mu.neigh.State != Incomplete {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Incomplete)
		}
		e.handleConfirmationLocked(entryTestLinkAddr1, flags)
		if e.mu.neigh.State != Reachable {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Reachable)
		}
		if e.mu.neigh.LinkAddr != entryTestLinkAddr1 {
			return fmt.Errorf("got e.mu.neigh.LinkAddr = %q, want = %q", e.mu.neigh.LinkAddr, entryTestLinkAddr1)
		}
		return nil
	}(); err != nil {
		return err
	}

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			return fmt.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr1,
				State:          Reachable,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	{
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

func incompleteToReachable(e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock) error {
	if err := incompleteToReachableWithFlags(e, nudDisp, linkRes, clock, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	}); err != nil {
		return err
	}

	e.mu.Lock()
	isRouter := e.mu.isRouter
	e.mu.Unlock()
	if isRouter {
		return fmt.Errorf("got e.mu.isRouter = %t, want = false", isRouter)
	}

	return nil
}

func TestEntryIncompleteToReachableWithRouterFlag(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}
	if err := incompleteToReachableWithRouterFlag(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("incompleteToReachableWithRouterFlag(...) = %s", err)
	}
}

func incompleteToReachableWithRouterFlag(e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock) error {
	if err := incompleteToReachableWithFlags(e, nudDisp, linkRes, clock, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  true,
	}); err != nil {
		return err
	}

	e.mu.Lock()
	isRouter := e.mu.isRouter
	e.mu.Unlock()
	if !isRouter {
		return fmt.Errorf("got e.mu.isRouter = %t, want = true", isRouter)
	}

	return nil
}

func TestEntryIncompleteToStaleWhenUnsolicitedConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Stale {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
	}
	if e.mu.isRouter {
		t.Errorf("got e.mu.isRouter = %t, want = false", e.mu.isRouter)
	}
	e.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr1,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryIncompleteToStaleWhenProbe(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}

	e.mu.Lock()
	e.handleProbeLocked(entryTestLinkAddr1)
	if e.mu.neigh.State != Stale {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
	}
	e.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr1,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryIncompleteToUnreachable(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}
	if err := incompleteToUnreachable(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("incompleteToUnreachable(...) = %s", err)
	}
}

func incompleteToUnreachable(c NUDConfigurations, e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock) error {
	{
		e.mu.Lock()
		state := e.mu.neigh.State
		e.mu.Unlock()
		if state != Incomplete {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", state, Incomplete)
		}
	}

	// The first probe was sent in the transition from Unknown to Incomplete.
	clock.Advance(c.RetransmitTimer)

	// Observe each subsequent multicast probe transmitted.
	for i := uint32(1); i < c.MaxMulticastProbes; i++ {
		wantProbes := []entryTestProbeInfo{{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: "",
			LocalAddress:      entryTestAddr2,
		}}
		linkRes.mu.Lock()
		diff := cmp.Diff(wantProbes, linkRes.mu.probes)
		linkRes.mu.probes = nil
		linkRes.mu.Unlock()
		if diff != "" {
			return fmt.Errorf("link address resolver probe #%d mismatch (-want, +got):\n%s", i+1, diff)
		}

		e.mu.Lock()
		state := e.mu.neigh.State
		e.mu.Unlock()
		if state != Incomplete {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", state, Incomplete)
		}

		clock.Advance(c.RetransmitTimer)
	}

	{
		e.mu.Lock()
		state := e.mu.neigh.State
		e.mu.Unlock()
		if state != Unreachable {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", state, Unreachable)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       tcpip.LinkAddress(""),
				State:          Unreachable,
				UpdatedAtNanos: clock.NowNanoseconds(),
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

	return nil
}

type testLocker struct{}

var _ sync.Locker = (*testLocker)(nil)

func (*testLocker) Lock()   {}
func (*testLocker) Unlock() {}

func TestEntryReachableToReachableClearsRouterWhenConfirmationWithoutRouter(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}
	if err := incompleteToReachableWithRouterFlag(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("incompleteToReachableWithRouterFlag(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Reachable {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Reachable)
	}
	if got, want := e.mu.isRouter, false; got != want {
		t.Errorf("got e.mu.isRouter = %t, want = %t", got, want)
	}
	ipv6EP := e.cache.nic.networkEndpoints[header.IPv6ProtocolNumber].(*testIPv6Endpoint)
	if ipv6EP.invalidatedRtr != e.mu.neigh.Addr {
		t.Errorf("got ipv6EP.invalidatedRtr = %s, want = %s", ipv6EP.invalidatedRtr, e.mu.neigh.Addr)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.mu.events)
	nudDisp.mu.Unlock()
	if diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
}

func TestEntryReachableToReachableWhenProbeWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}
	if err := incompleteToReachable(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("incompleteToReachable(...) = %s", err)
	}

	e.mu.Lock()
	e.handleProbeLocked(entryTestLinkAddr1)
	if e.mu.neigh.State != Reachable {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Reachable)
	}
	if e.mu.neigh.LinkAddr != entryTestLinkAddr1 {
		t.Errorf("got e.mu.neigh.LinkAddr = %q, want = %q", e.mu.neigh.LinkAddr, entryTestLinkAddr1)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.mu.events)
	nudDisp.mu.Unlock()
	if diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
}

func TestEntryReachableToStaleWhenTimeout(t *testing.T) {
	c := DefaultNUDConfigurations()
	// Eliminate random factors from ReachableTime computation so the transition
	// from Stale to Reachable will only take BaseReachableTime duration.
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1

	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}
	if err := incompleteToReachable(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("incompleteToReachable(...) = %s", err)
	}
	if err := reachableToStale(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("reachableToStale(...) = %s", err)
	}
}

// reachableToStale transitions a neighborEntry in Reachable state to Stale
// state. Depends on the elimination of random factors in the ReachableTime
// computation.
//
//	c.MinRandomFactor = 1
//	c.MaxRandomFactor = 1
func reachableToStale(c NUDConfigurations, e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock) error {
	// Ensure there are no random factors in the ReachableTime computation.
	if c.MinRandomFactor != 1 {
		return fmt.Errorf("got c.MinRandomFactor = %f, want = 1", c.MinRandomFactor)
	}
	if c.MaxRandomFactor != 1 {
		return fmt.Errorf("got c.MaxRandomFactor = %f, want = 1", c.MaxRandomFactor)
	}

	{
		e.mu.Lock()
		state := e.mu.neigh.State
		e.mu.Unlock()
		if state != Reachable {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", state, Reachable)
		}
	}

	clock.Advance(c.BaseReachableTime)

	{
		e.mu.Lock()
		state := e.mu.neigh.State
		e.mu.Unlock()
		if state != Stale {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", state, Stale)
		}
	}

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			return fmt.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr1,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	{

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

func TestEntryReachableToStaleWhenProbeWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}
	if err := incompleteToReachable(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("incompleteToReachable(...) = %s", err)
	}

	e.mu.Lock()
	e.handleProbeLocked(entryTestLinkAddr2)
	if e.mu.neigh.State != Stale {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr2,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryReachableToStaleWhenConfirmationWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}
	if err := incompleteToReachable(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("incompleteToReachable(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Stale {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr1,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryReachableToStaleWhenConfirmationWithDifferentAddressAndOverride(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}
	if err := incompleteToReachable(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("incompleteToReachable(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Stale {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr2,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToStaleWhenProbeWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}

	e.mu.Lock()
	e.handleProbeLocked(entryTestLinkAddr1)
	if e.mu.neigh.State != Stale {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
	}
	if e.mu.neigh.LinkAddr != entryTestLinkAddr1 {
		t.Errorf("got e.mu.neigh.LinkAddr = %q, want = %q", e.mu.neigh.LinkAddr, entryTestLinkAddr1)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToReachableWhenSolicitedOverrideConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Reachable {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Reachable)
	}
	if e.mu.neigh.LinkAddr != entryTestLinkAddr2 {
		t.Errorf("got e.mu.neigh.LinkAddr = %q, want = %q", e.mu.neigh.LinkAddr, entryTestLinkAddr2)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr2,
				State:          Reachable,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToReachableWhenSolicitedConfirmationWithoutAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked("" /* linkAddr */, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Reachable {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Reachable)
	}
	if e.mu.neigh.LinkAddr != entryTestLinkAddr1 {
		t.Errorf("got e.mu.neigh.LinkAddr = %q, want = %q", e.mu.neigh.LinkAddr, entryTestLinkAddr1)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr1,
				State:          Reachable,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToStaleWhenOverrideConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Stale {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
	}
	if e.mu.neigh.LinkAddr != entryTestLinkAddr2 {
		t.Errorf("got e.mu.neigh.LinkAddr = %q, want = %q", e.mu.neigh.LinkAddr, entryTestLinkAddr2)
	}
	e.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr2,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToStaleWhenProbeUpdateAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}

	e.mu.Lock()
	e.handleProbeLocked(entryTestLinkAddr2)
	if e.mu.neigh.State != Stale {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
	}
	if e.mu.neigh.LinkAddr != entryTestLinkAddr2 {
		t.Errorf("got e.mu.neigh.LinkAddr = %q, want = %q", e.mu.neigh.LinkAddr, entryTestLinkAddr2)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr2,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToDelay(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}
}

func staleToDelay(e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock) error {
	if err := func() error {
		e.mu.Lock()
		defer e.mu.Unlock()

		if e.mu.neigh.State != Stale {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
		}
		e.handlePacketQueuedLocked(entryTestAddr2)
		if e.mu.neigh.State != Delay {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Delay)
		}
		return nil
	}(); err != nil {
		return err
	}

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			return fmt.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr1,
				State:          Delay,
				UpdatedAtNanos: clock.NowNanoseconds(),
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

	return nil
}

func TestEntryDelayToReachableWhenUpperLevelConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}

	e.mu.Lock()
	e.handleUpperLevelConfirmationLocked()
	if e.mu.neigh.State != Reachable {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Reachable)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr1,
				State:          Reachable,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToReachableWhenSolicitedOverrideConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Reachable {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Reachable)
	}
	if e.mu.neigh.LinkAddr != entryTestLinkAddr2 {
		t.Errorf("got e.mu.neigh.LinkAddr = %q, want = %q", e.mu.neigh.LinkAddr, entryTestLinkAddr2)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr2,
				State:          Reachable,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToReachableWhenSolicitedConfirmationWithoutAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked("" /* linkAddr */, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Reachable {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Reachable)
	}
	if e.mu.neigh.LinkAddr != entryTestLinkAddr1 {
		t.Errorf("got e.mu.neigh.LinkAddr = %q, want = %q", e.mu.neigh.LinkAddr, entryTestLinkAddr1)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr1,
				State:          Reachable,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToDelayWhenOverrideConfirmationWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Delay {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Delay)
	}
	if e.mu.neigh.LinkAddr != entryTestLinkAddr1 {
		t.Errorf("got e.mu.neigh.LinkAddr = %q, want = %q", e.mu.neigh.LinkAddr, entryTestLinkAddr1)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToStaleWhenProbeWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}

	e.mu.Lock()
	e.handleProbeLocked(entryTestLinkAddr2)
	if e.mu.neigh.State != Stale {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr2,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToStaleWhenConfirmationWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Stale {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr2,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToProbe(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}
	if err := delayToProbe(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("delayToProbe(...) = %s", err)
	}
}

func delayToProbe(c NUDConfigurations, e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock) error {
	{
		e.mu.Lock()
		state := e.mu.neigh.State
		e.mu.Unlock()
		if state != Delay {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", state, Delay)
		}
	}

	// Wait for the first unicast probe to be transmitted, marking the
	// transition from Delay to Probe.
	clock.Advance(c.DelayFirstProbeTime)

	{
		e.mu.Lock()
		state := e.mu.neigh.State
		e.mu.Unlock()
		if state != Probe {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", state, Probe)
		}
	}

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
	}
	{
		linkRes.mu.Lock()
		diff := cmp.Diff(wantProbes, linkRes.mu.probes)
		linkRes.mu.probes = nil
		linkRes.mu.Unlock()
		if diff != "" {
			return fmt.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr1,
				State:          Probe,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	{
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

func TestEntryProbeToStaleWhenProbeWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}
	if err := delayToProbe(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("delayToProbe(...) = %s", err)
	}

	e.mu.Lock()
	e.handleProbeLocked(entryTestLinkAddr2)
	if e.mu.neigh.State != Stale {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr2,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryProbeToStaleWhenConfirmationWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}
	if err := delayToProbe(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("delayToProbe(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Stale {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Stale)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr2,
				State:          Stale,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(wantEvents, nudDisp.mu.events); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryProbeToProbeWhenOverrideConfirmationWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}
	if err := delayToProbe(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("delayToProbe(...) = %s", err)
	}

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if e.mu.neigh.State != Probe {
		t.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Probe)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("got e.mu.neigh.LinkAddr = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	diff := cmp.Diff([]testEntryEventInfo(nil), nudDisp.mu.events)
	nudDisp.mu.Unlock()
	if diff != "" {
		t.Errorf("nud dispatcher events mismatch (-want, +got):\n%s", diff)
	}
}

func TestEntryProbeToReachableWhenSolicitedOverrideConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}
	if err := delayToProbe(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("delayToProbe(...) = %s", err)
	}
	if err := probeToReachableWithOverride(e, nudDisp, linkRes, clock, entryTestLinkAddr2); err != nil {
		t.Fatalf("probeToReachableWithOverride(...) = %s", err)
	}
}

func probeToReachableWithFlags(e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock, linkAddr tcpip.LinkAddress, flags ReachabilityConfirmationFlags) error {
	if err := func() error {
		e.mu.Lock()
		defer e.mu.Unlock()

		prevLinkAddr := e.mu.neigh.LinkAddr
		if e.mu.neigh.State != Probe {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Probe)
		}
		e.handleConfirmationLocked(linkAddr, flags)

		if e.mu.neigh.State != Reachable {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Reachable)
		}
		if linkAddr == "" {
			linkAddr = prevLinkAddr
		}
		if e.mu.neigh.LinkAddr != linkAddr {
			return fmt.Errorf("got e.mu.neigh.LinkAddr = %q, want = %q", e.mu.neigh.LinkAddr, linkAddr)
		}
		return nil
	}(); err != nil {
		return err
	}

	// No probes should have been sent.
	runImmediatelyScheduledJobs(clock)
	{
		linkRes.mu.Lock()
		diff := cmp.Diff([]entryTestProbeInfo(nil), linkRes.mu.probes)
		linkRes.mu.Unlock()
		if diff != "" {
			return fmt.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       linkAddr,
				State:          Reachable,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	{
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

func probeToReachableWithOverride(e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock, linkAddr tcpip.LinkAddress) error {
	return probeToReachableWithFlags(e, nudDisp, linkRes, clock, linkAddr, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
}

func TestEntryProbeToReachableWhenSolicitedConfirmationWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}
	if err := delayToProbe(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("delayToProbe(...) = %s", err)
	}
	if err := probeToReachable(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("probeToReachable(...) = %s", err)
	}
}

func probeToReachable(e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock) error {
	return probeToReachableWithFlags(e, nudDisp, linkRes, clock, entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
}

func TestEntryProbeToReachableWhenSolicitedConfirmationWithoutAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}
	if err := delayToProbe(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("delayToProbe(...) = %s", err)
	}
	if err := probeToReachableWithoutAddress(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("probeToReachableWithoutAddress(...) = %s", err)
	}
}

func probeToReachableWithoutAddress(e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock) error {
	return probeToReachableWithFlags(e, nudDisp, linkRes, clock, "" /* linkAddr */, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
}

func TestEntryProbeToUnreachable(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	c.MaxUnicastProbes = 3
	c.DelayFirstProbeTime = c.RetransmitTimer
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToStale(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToStale(...) = %s", err)
	}
	if err := staleToDelay(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("staleToDelay(...) = %s", err)
	}
	if err := delayToProbe(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("delayToProbe(...) = %s", err)
	}
	if err := probeToUnreachable(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("probeToUnreachable(...) = %s", err)
	}
}

func probeToUnreachable(c NUDConfigurations, e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock) error {
	{
		e.mu.Lock()
		state := e.mu.neigh.State
		e.mu.Unlock()
		if state != Probe {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", state, Probe)
		}
	}

	// The first probe was sent in the transition from Delay to Probe.
	clock.Advance(c.RetransmitTimer)

	// Observe each subsequent unicast probe transmitted.
	for i := uint32(1); i < c.MaxUnicastProbes; i++ {
		wantProbes := []entryTestProbeInfo{{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		}}
		linkRes.mu.Lock()
		diff := cmp.Diff(wantProbes, linkRes.mu.probes)
		linkRes.mu.probes = nil
		linkRes.mu.Unlock()
		if diff != "" {
			return fmt.Errorf("link address resolver probe #%d mismatch (-want, +got):\n%s", i+1, diff)
		}

		e.mu.Lock()
		state := e.mu.neigh.State
		e.mu.Unlock()
		if state != Probe {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", state, Probe)
		}

		clock.Advance(c.RetransmitTimer)
	}

	{
		e.mu.Lock()
		state := e.mu.neigh.State
		e.mu.Unlock()
		if state != Unreachable {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", state, Unreachable)
		}
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       entryTestLinkAddr1,
				State:          Unreachable,
				UpdatedAtNanos: clock.NowNanoseconds(),
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

	return nil
}

func TestEntryUnreachableToIncomplete(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}
	if err := incompleteToUnreachable(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("incompleteToUnreachable(...) = %s", err)
	}
	if err := unreachableToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unreachableToIncomplete(...) = %s", err)
	}
}

func unreachableToIncomplete(e *neighborEntry, nudDisp *testNUDDispatcher, linkRes *entryTestLinkResolver, clock *faketime.ManualClock) error {
	if err := func() error {
		e.mu.Lock()
		defer e.mu.Unlock()

		if e.mu.neigh.State != Unreachable {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Unreachable)
		}
		e.handlePacketQueuedLocked(entryTestAddr2)
		if e.mu.neigh.State != Incomplete {
			return fmt.Errorf("got e.mu.neigh.State = %q, want = %q", e.mu.neigh.State, Incomplete)
		}
		return nil
	}(); err != nil {
		return err
	}

	runImmediatelyScheduledJobs(clock)
	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(wantProbes, linkRes.mu.probes)
	linkRes.mu.probes = nil
	linkRes.mu.Unlock()
	if diff != "" {
		return fmt.Errorf("link address resolver probes mismatch (-want, +got):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Entry: NeighborEntry{
				Addr:           entryTestAddr1,
				LinkAddr:       tcpip.LinkAddress(""),
				State:          Incomplete,
				UpdatedAtNanos: clock.NowNanoseconds(),
			},
		},
	}
	{
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

func TestEntryUnreachableToStale(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	// Eliminate random factors from ReachableTime computation so the transition
	// from Stale to Reachable will only take BaseReachableTime duration.
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1

	e, nudDisp, linkRes, clock := entryTestSetup(c)

	if err := unknownToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unknownToIncomplete(...) = %s", err)
	}
	if err := incompleteToUnreachable(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("incompleteToUnreachable(...) = %s", err)
	}
	if err := unreachableToIncomplete(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("unreachableToIncomplete(...) = %s", err)
	}
	if err := incompleteToReachable(e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("incompleteToReachable(...) = %s", err)
	}
	if err := reachableToStale(c, e, nudDisp, linkRes, clock); err != nil {
		t.Fatalf("reachableToStale(...) = %s", err)
	}
}
