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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	entryTestNetNumber tcpip.NetworkProtocolNumber = math.MaxUint32

	entryTestNICID tcpip.NICID = 1
	entryTestAddr1             = tcpip.Address("\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
	entryTestAddr2             = tcpip.Address("\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")

	entryTestLinkAddr1 = tcpip.LinkAddress("\x0a\x00\x00\x00\x00\x01")
	entryTestLinkAddr2 = tcpip.LinkAddress("\x0a\x00\x00\x00\x00\x02")

	// entryTestNetDefaultMTU is the MTU, in bytes, used throughout the tests,
	// except where another value is explicitly used. It is chosen to match the
	// MTU of loopback interfaces on Linux systems.
	entryTestNetDefaultMTU = 65536
)

// eventDiffOpts are the options passed to cmp.Diff to compare entry events.
// The UpdatedAt field is ignored due to a lack of a deterministic method to
// predict the time that an event will be dispatched.
func eventDiffOpts() []cmp.Option {
	return []cmp.Option{
		cmpopts.IgnoreFields(testEntryEventInfo{}, "UpdatedAt"),
	}
}

// eventDiffOptsWithSort is like eventDiffOpts but also includes an option to
// sort slices of events for cases where ordering must be ignored.
func eventDiffOptsWithSort() []cmp.Option {
	return []cmp.Option{
		cmpopts.IgnoreFields(testEntryEventInfo{}, "UpdatedAt"),
		cmpopts.SortSlices(func(a, b testEntryEventInfo) bool {
			return strings.Compare(string(a.Addr), string(b.Addr)) < 0
		}),
	}
}

// The following unit tests exercise every state transition and verify its
// behavior with RFC 4681.
//
// | From       | To         | Cause                                      | Action          | Event   |
// | ========== | ========== | ========================================== | =============== | ======= |
// | Unknown    | Unknown    | Confirmation w/ unknown address            |                 | Added   |
// | Unknown    | Incomplete | Packet queued to unknown address           | Send probe      | Added   |
// | Unknown    | Stale      | Probe w/ unknown address                   |                 | Added   |
// | Incomplete | Incomplete | Retransmit timer expired                   | Send probe      | Changed |
// | Incomplete | Reachable  | Solicited confirmation                     | Notify wakers   | Changed |
// | Incomplete | Stale      | Unsolicited confirmation                   | Notify wakers   | Changed |
// | Incomplete | Failed     | Max probes sent without reply              | Notify wakers   | Removed |
// | Reachable  | Reachable  | Confirmation w/ different isRouter flag    | Update IsRouter |         |
// | Reachable  | Stale      | Reachable timer expired                    |                 | Changed |
// | Reachable  | Stale      | Probe or confirmation w/ different address |                 | Changed |
// | Stale      | Reachable  | Solicited override confirmation            | Update LinkAddr | Changed |
// | Stale      | Reachable  | Solicited confirmation w/o address         | Notify wakers   | Changed |
// | Stale      | Stale      | Override confirmation                      | Update LinkAddr | Changed |
// | Stale      | Stale      | Probe w/ different address                 | Update LinkAddr | Changed |
// | Stale      | Delay      | Packet sent                                |                 | Changed |
// | Delay      | Reachable  | Upper-layer confirmation                   |                 | Changed |
// | Delay      | Reachable  | Solicited override confirmation            | Update LinkAddr | Changed |
// | Delay      | Reachable  | Solicited confirmation w/o address         | Notify wakers   | Changed |
// | Delay      | Stale      | Probe or confirmation w/ different address |                 | Changed |
// | Delay      | Probe      | Delay timer expired                        | Send probe      | Changed |
// | Probe      | Reachable  | Solicited override confirmation            | Update LinkAddr | Changed |
// | Probe      | Reachable  | Solicited confirmation w/ same address     | Notify wakers   | Changed |
// | Probe      | Reachable  | Solicited confirmation w/o address         | Notify wakers   | Changed |
// | Probe      | Stale      | Probe or confirmation w/ different address |                 | Changed |
// | Probe      | Probe      | Retransmit timer expired                   | Send probe      | Changed |
// | Probe      | Failed     | Max probes sent without reply              | Notify wakers   | Removed |
// | Failed     |            | Unreachability timer expired               | Delete entry    |         |

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
	Addr      tcpip.Address
	LinkAddr  tcpip.LinkAddress
	State     NeighborState
	UpdatedAt time.Time
}

func (e testEntryEventInfo) String() string {
	return fmt.Sprintf("%s event for NIC #%d, addr=%q, linkAddr=%q, state=%q", e.EventType, e.NICID, e.Addr, e.LinkAddr, e.State)
}

// testNUDDispatcher implements NUDDispatcher to validate the dispatching of
// events upon certain NUD state machine events.
type testNUDDispatcher struct {
	mu     sync.Mutex
	events []testEntryEventInfo
}

var _ NUDDispatcher = (*testNUDDispatcher)(nil)

func (d *testNUDDispatcher) queueEvent(e testEntryEventInfo) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, e)
}

func (d *testNUDDispatcher) OnNeighborAdded(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state NeighborState, updatedAt time.Time) {
	d.queueEvent(testEntryEventInfo{
		EventType: entryTestAdded,
		NICID:     nicID,
		Addr:      addr,
		LinkAddr:  linkAddr,
		State:     state,
		UpdatedAt: updatedAt,
	})
}

func (d *testNUDDispatcher) OnNeighborChanged(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state NeighborState, updatedAt time.Time) {
	d.queueEvent(testEntryEventInfo{
		EventType: entryTestChanged,
		NICID:     nicID,
		Addr:      addr,
		LinkAddr:  linkAddr,
		State:     state,
		UpdatedAt: updatedAt,
	})
}

func (d *testNUDDispatcher) OnNeighborRemoved(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state NeighborState, updatedAt time.Time) {
	d.queueEvent(testEntryEventInfo{
		EventType: entryTestRemoved,
		NICID:     nicID,
		Addr:      addr,
		LinkAddr:  linkAddr,
		State:     state,
		UpdatedAt: updatedAt,
	})
}

type entryTestLinkResolver struct {
	mu     sync.Mutex
	probes []entryTestProbeInfo
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
func (r *entryTestLinkResolver) LinkAddressRequest(targetAddr, localAddr tcpip.Address, linkAddr tcpip.LinkAddress, _ NetworkInterface) *tcpip.Error {
	p := entryTestProbeInfo{
		RemoteAddress:     targetAddr,
		RemoteLinkAddress: linkAddr,
		LocalAddress:      localAddr,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.probes = append(r.probes, p)
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
	nic := NIC{
		LinkEndpoint: nil, // entryTestLinkResolver doesn't use a LinkEndpoint

		id: entryTestNICID,
		stack: &Stack{
			clock:   clock,
			nudDisp: &disp,
		},
	}
	nic.networkEndpoints = map[tcpip.NetworkProtocolNumber]NetworkEndpoint{
		header.IPv6ProtocolNumber: (&testIPv6Protocol{}).NewEndpoint(&nic, nil, nil, nil),
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	nudState := NewNUDState(c, rng)
	linkRes := entryTestLinkResolver{}
	entry := newNeighborEntry(&nic, entryTestAddr1 /* remoteAddr */, entryTestAddr2 /* localAddr */, nudState, &linkRes)

	// Stub out the neighbor cache to verify deletion from the cache.
	nic.neigh = &neighborCache{
		nic:   &nic,
		state: nudState,
		cache: make(map[tcpip.Address]*neighborEntry, neighborCacheSize),
	}
	nic.neigh.cache[entryTestAddr1] = entry

	return entry, &disp, &linkRes, clock
}

// TestEntryInitiallyUnknown verifies that the state of a newly created
// neighborEntry is Unknown.
func TestEntryInitiallyUnknown(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	if got, want := e.neigh.State, Unknown; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	clock.Advance(c.RetransmitTimer)

	// No probes should have been sent.
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, []entryTestProbeInfo(nil))
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, []testEntryEventInfo(nil)); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
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
	if got, want := e.neigh.State, Unknown; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	clock.Advance(time.Hour)

	// No probes should have been sent.
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, []entryTestProbeInfo(nil))
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, []testEntryEventInfo(nil)); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryUnknownToIncomplete(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Incomplete; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
	}
	{
		nudDisp.mu.Lock()
		diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...)
		nudDisp.mu.Unlock()
		if diff != "" {
			t.Fatalf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
		}
	}
}

func TestEntryUnknownToStale(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handleProbeLocked(entryTestLinkAddr1)
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	// No probes should have been sent.
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, []entryTestProbeInfo(nil))
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryIncompleteToIncompleteDoesNotChangeUpdatedAt(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Incomplete; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	updatedAt := e.neigh.UpdatedAt
	e.mu.Unlock()

	clock.Advance(c.RetransmitTimer)

	// UpdatedAt should remain the same during address resolution.
	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.probes = nil
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	e.mu.Lock()
	if got, want := e.neigh.UpdatedAt, updatedAt; got != want {
		t.Errorf("got e.neigh.UpdatedAt = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	clock.Advance(c.RetransmitTimer)

	// UpdatedAt should change after failing address resolution. Timing out after
	// sending the last probe transitions the entry to Failed.
	{
		wantProbes := []entryTestProbeInfo{
			{
				RemoteAddress:     entryTestAddr1,
				RemoteLinkAddress: tcpip.LinkAddress(""),
				LocalAddress:      entryTestAddr2,
			},
		}
		linkRes.mu.Lock()
		diff := cmp.Diff(linkRes.probes, wantProbes)
		linkRes.mu.Unlock()
		if diff != "" {
			t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
		}
	}

	clock.Advance(c.RetransmitTimer)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestRemoved,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, notWant := e.neigh.UpdatedAt, updatedAt; got == notWant {
		t.Errorf("expected e.neigh.UpdatedAt to change, got = %q", got)
	}
	e.mu.Unlock()
}

func TestEntryIncompleteToReachable(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Incomplete; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

// TestEntryAddsAndClearsWakers verifies that wakers are added when
// addWakerLocked is called and cleared when address resolution finishes. In
// this case, address resolution will finish when transitioning from Incomplete
// to Reachable.
func TestEntryAddsAndClearsWakers(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	w := sleep.Waker{}
	s := sleep.Sleeper{}
	s.AddWaker(&w, 123)
	defer s.Done()

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got := e.wakers; got != nil {
		t.Errorf("got e.wakers = %v, want = nil", got)
	}
	e.addWakerLocked(&w)
	if got, want := w.IsAsserted(), false; got != want {
		t.Errorf("waker.IsAsserted() = %t, want = %t", got, want)
	}
	if e.wakers == nil {
		t.Error("expected e.wakers to be non-nil")
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if e.wakers != nil {
		t.Errorf("got e.wakers = %v, want = nil", e.wakers)
	}
	if got, want := w.IsAsserted(), true; got != want {
		t.Errorf("waker.IsAsserted() = %t, want = %t", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryIncompleteToReachableWithRouterFlag(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Incomplete; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  true,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	if got, want := e.isRouter, true; got != want {
		t.Errorf("got e.isRouter = %t, want = %t", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.probes, wantProbes); diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryIncompleteToStale(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Incomplete; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryIncompleteToFailed(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Incomplete; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	waitFor := c.RetransmitTimer * time.Duration(c.MaxMulticastProbes)
	clock.Advance(waitFor)

	wantProbes := []entryTestProbeInfo{
		// The Incomplete-to-Incomplete state transition is tested here by
		// verifying that 3 reachability probes were sent.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestRemoved,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.neigh.State, Failed; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()
}

type testLocker struct{}

var _ sync.Locker = (*testLocker)(nil)

func (*testLocker) Lock()   {}
func (*testLocker) Unlock() {}

func TestEntryStaysReachableWhenConfirmationWithRouterFlag(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	ipv6EP := e.nic.networkEndpoints[header.IPv6ProtocolNumber].(*testIPv6Endpoint)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  true,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	if got, want := e.isRouter, true; got != want {
		t.Errorf("got e.isRouter = %t, want = %t", got, want)
	}

	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.isRouter, false; got != want {
		t.Errorf("got e.isRouter = %t, want = %t", got, want)
	}
	if ipv6EP.invalidatedRtr != e.neigh.Addr {
		t.Errorf("got ipv6EP.invalidatedRtr = %s, want = %s", ipv6EP.invalidatedRtr, e.neigh.Addr)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryStaysReachableWhenProbeWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr1)
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	if got, want := e.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("got e.neigh.LinkAddr = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryReachableToStaleWhenTimeout(t *testing.T) {
	c := DefaultNUDConfigurations()
	// Eliminate random factors from ReachableTime computation so the transition
	// from Stale to Reachable will only take BaseReachableTime duration.
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1

	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	clock.Advance(c.BaseReachableTime)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryReachableToStaleWhenProbeWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr2)
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryReachableToStaleWhenConfirmationWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryReachableToStaleWhenConfirmationWithDifferentAddressAndOverride(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryStaysStaleWhenProbeWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr1)
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	if got, want := e.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("got e.neigh.LinkAddr = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToReachableWhenSolicitedOverrideConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	if got, want := e.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("got e.neigh.LinkAddr = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToReachableWhenSolicitedConfirmationWithoutAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if e.neigh.State != Stale {
		t.Errorf("got e.neigh.State = %q, want = %q", e.neigh.State, Stale)
	}
	e.handleConfirmationLocked("" /* linkAddr */, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if e.neigh.State != Reachable {
		t.Errorf("got e.neigh.State = %q, want = %q", e.neigh.State, Reachable)
	}
	if e.neigh.LinkAddr != entryTestLinkAddr1 {
		t.Errorf("got e.neigh.LinkAddr = %q, want = %q", e.neigh.LinkAddr, entryTestLinkAddr1)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToStaleWhenOverrideConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	if got, want := e.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("got e.neigh.LinkAddr = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToStaleWhenProbeUpdateAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr2)
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	if got, want := e.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("got e.neigh.LinkAddr = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToDelay(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Delay; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToReachableWhenUpperLevelConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	// Eliminate random factors from ReachableTime computation so the transition
	// from Stale to Reachable will only take BaseReachableTime duration.
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1

	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Delay; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleUpperLevelConfirmationLocked()
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	clock.Advance(c.BaseReachableTime)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToReachableWhenSolicitedOverrideConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 1
	// Eliminate random factors from ReachableTime computation so the transition
	// from Stale to Reachable will only take BaseReachableTime duration.
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1

	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Delay; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	if got, want := e.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("got e.neigh.LinkAddr = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	clock.Advance(c.BaseReachableTime)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToReachableWhenSolicitedConfirmationWithoutAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 1
	// Eliminate random factors from ReachableTime computation so the transition
	// from Stale to Reachable will only take BaseReachableTime duration.
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1

	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if e.neigh.State != Delay {
		t.Errorf("got e.neigh.State = %q, want = %q", e.neigh.State, Delay)
	}
	e.handleConfirmationLocked("" /* linkAddr */, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if e.neigh.State != Reachable {
		t.Errorf("got e.neigh.State = %q, want = %q", e.neigh.State, Reachable)
	}
	if e.neigh.LinkAddr != entryTestLinkAddr1 {
		t.Errorf("got e.neigh.LinkAddr = %q, want = %q", e.neigh.LinkAddr, entryTestLinkAddr1)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	clock.Advance(c.BaseReachableTime)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaysDelayWhenOverrideConfirmationWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Delay; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Delay; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	if got, want := e.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("got e.neigh.LinkAddr = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToStaleWhenProbeWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Delay; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr2)
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToStaleWhenConfirmationWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, _ := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Delay; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToProbe(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if got, want := e.neigh.State, Delay; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	clock.Advance(c.DelayFirstProbeTime)

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.neigh.State, Probe; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryProbeToStaleWhenProbeWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.Advance(c.DelayFirstProbeTime)

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	e.mu.Lock()
	if got, want := e.neigh.State, Probe; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr2)
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryProbeToStaleWhenConfirmationWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.Advance(c.DelayFirstProbeTime)

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	e.mu.Lock()
	if got, want := e.neigh.State, Probe; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.neigh.State, Stale; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryStaysProbeWhenOverrideConfirmationWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.Advance(c.DelayFirstProbeTime)

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	e.mu.Lock()
	if got, want := e.neigh.State, Probe; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Probe; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	if got, want := e.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("got e.neigh.LinkAddr = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

// TestEntryUnknownToStaleToProbeToReachable exercises the following scenario:
//   1. Probe is received
//   2. Entry is created in Stale
//   3. Packet is queued on the entry
//   4. Entry transitions to Delay then Probe
//   5. Probe is sent
func TestEntryUnknownToStaleToProbeToReachable(t *testing.T) {
	c := DefaultNUDConfigurations()
	// Eliminate random factors from ReachableTime computation so the transition
	// from Probe to Reachable will only take BaseReachableTime duration.
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1

	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handleProbeLocked(entryTestLinkAddr1)
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.Advance(c.DelayFirstProbeTime)

	wantProbes := []entryTestProbeInfo{
		// Probe caused by the Delay-to-Probe transition
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	e.mu.Lock()
	if got, want := e.neigh.State, Probe; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	if got, want := e.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("got e.neigh.LinkAddr = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	clock.Advance(c.BaseReachableTime)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryProbeToReachableWhenSolicitedOverrideConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	// Eliminate random factors from ReachableTime computation so the transition
	// from Stale to Reachable will only take BaseReachableTime duration.
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1

	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.Advance(c.DelayFirstProbeTime)

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	e.mu.Lock()
	if got, want := e.neigh.State, Probe; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	if got, want := e.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("got e.neigh.LinkAddr = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	clock.Advance(c.BaseReachableTime)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryProbeToReachableWhenSolicitedConfirmationWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	// Eliminate random factors from ReachableTime computation so the transition
	// from Stale to Reachable will only take BaseReachableTime duration.
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1

	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.Advance(c.DelayFirstProbeTime)

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	e.mu.Lock()
	if got, want := e.neigh.State, Probe; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.neigh.State, Reachable; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()

	clock.Advance(c.BaseReachableTime)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryProbeToReachableWhenSolicitedConfirmationWithoutAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	// Eliminate random factors from ReachableTime computation so the transition
	// from Stale to Reachable will only take BaseReachableTime duration.
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1

	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.Advance(c.DelayFirstProbeTime)

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	e.mu.Lock()
	if e.neigh.State != Probe {
		t.Errorf("got e.neigh.State = %q, want = %q", e.neigh.State, Probe)
	}
	e.handleConfirmationLocked("" /* linkAddr */, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if e.neigh.State != Reachable {
		t.Errorf("got e.neigh.State = %q, want = %q", e.neigh.State, Reachable)
	}
	e.mu.Unlock()

	clock.Advance(c.BaseReachableTime)

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryProbeToFailed(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	c.MaxUnicastProbes = 3
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	waitFor := c.DelayFirstProbeTime + c.RetransmitTimer*time.Duration(c.MaxUnicastProbes)
	clock.Advance(waitFor)

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The next three probe are caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestRemoved,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.neigh.State, Failed; got != want {
		t.Errorf("got e.neigh.State = %q, want = %q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryFailedGetsDeleted(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	c.MaxUnicastProbes = 3
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	// Verify the cache contains the entry.
	if _, ok := e.nic.neigh.cache[entryTestAddr1]; !ok {
		t.Errorf("expected entry %q to exist in the neighbor cache", entryTestAddr1)
	}

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	waitFor := c.DelayFirstProbeTime + c.RetransmitTimer*time.Duration(c.MaxUnicastProbes) + c.UnreachableTime
	clock.Advance(waitFor)

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The next three probe are caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	diff := cmp.Diff(linkRes.probes, wantProbes)
	linkRes.mu.Unlock()
	if diff != "" {
		t.Fatalf("link address resolver probes mismatch (-got, +want):\n%s", diff)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestRemoved,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.events, wantEvents, eventDiffOpts()...); diff != "" {
		t.Errorf("nud dispatcher events mismatch (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	// Verify the cache no longer contains the entry.
	if _, ok := e.nic.neigh.cache[entryTestAddr1]; ok {
		t.Errorf("entry %q should have been deleted from the neighbor cache", entryTestAddr1)
	}
}
