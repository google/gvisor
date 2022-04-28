// Copyright 2022 The gVisor Authors.
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

// Package multicast contains utilities for supporting multicast routing.
package multicast

import (
	"errors"
	"fmt"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// RouteTable represents a multicast routing table.
type RouteTable struct {
	// Internally, installed and pending routes are stored and locked separately
	// A couple of reasons for structuring the table this way:
	//
	// 1. We can avoid write locking installed routes when pending packets are
	//		being queued. In other words, the happy path of reading installed
	//		routes doesn't require an exclusive lock.
	// 2. The cleanup process for expired routes only needs to operate on pending
	//		routes. Like above, a write lock on the installed routes can be
	//		avoided.
	// 3. This structure is similar to the Linux implementation:
	//		https://github.com/torvalds/linux/blob/cffb2b72d3e/include/linux/mroute_base.h#L250

	// TODO(https://gvisor.dev/issue/7338): Implement time based expiration of
	// pending packets.

	// The installedMu lock should typically be acquired before the pendingMu
	// lock. This ensures that installed routes can continue to be read even when
	// the pending routes are write locked.

	installedMu sync.RWMutex
	// Maintaining pointers ensures that the installed routes are exclusively
	// locked only when a route is being installed.
	// +checklocks:installedMu
	installedRoutes map[RouteKey]*InstalledRoute

	pendingMu sync.RWMutex
	// +checklocks:pendingMu
	pendingRoutes map[RouteKey]PendingRoute

	config Config
}

var (
	// ErrNoBufferSpace indicates that no buffer space is available in the
	// pending route packet queue.
	ErrNoBufferSpace = errors.New("unable to queue packet, no buffer space available")

	// ErrMissingClock indicates that a clock was not provided as part of the
	// Config, but is required.
	ErrMissingClock = errors.New("clock must not be nil")

	// ErrAlreadyInitialized indicates that RouteTable.Init was already invoked.
	ErrAlreadyInitialized = errors.New("table is already initialized")
)

// RouteKey represents an entry key in the RouteTable.
type RouteKey struct {
	UnicastSource        tcpip.Address
	MulticastDestination tcpip.Address
}

// InstalledRoute represents a route that is in the installed state.
//
// If a route is in the installed state, then it may be used to forward
// multicast packets.
type InstalledRoute struct {
	expectedInputInterface tcpip.NICID
	outgoingInterfaces     []OutgoingInterface

	lastUsedTimestampMu sync.RWMutex
	// +checklocks:lastUsedTimestampMu
	lastUsedTimestamp tcpip.MonotonicTime
}

// ExpectedInputInterface returns the expected input interface for the route.
func (r *InstalledRoute) ExpectedInputInterface() tcpip.NICID {
	return r.expectedInputInterface
}

// OutgoingInterfaces returns the outgoing interfaces for the route.
func (r *InstalledRoute) OutgoingInterfaces() []OutgoingInterface {
	return r.outgoingInterfaces
}

// LastUsedTimestamp returns a monotonic timestamp that corresponds to the last
// time the route was used or updated.
func (r *InstalledRoute) LastUsedTimestamp() tcpip.MonotonicTime {
	r.lastUsedTimestampMu.RLock()
	defer r.lastUsedTimestampMu.RUnlock()

	return r.lastUsedTimestamp
}

// SetLastUsedTimestamp sets the time that the route was last used.
//
// The timestamp is only updated if it occurs after the currently set
// timestamp. Callers should invoke this anytime the route is used to forward a
// packet.
func (r *InstalledRoute) SetLastUsedTimestamp(monotonicTime tcpip.MonotonicTime) {
	r.lastUsedTimestampMu.Lock()
	defer r.lastUsedTimestampMu.Unlock()

	if monotonicTime.After(r.lastUsedTimestamp) {
		r.lastUsedTimestamp = monotonicTime
	}
}

// OutgoingInterface represents an interface that packets should be forwarded
// out of.
type OutgoingInterface struct {
	// ID corresponds to the outgoing NIC.
	ID tcpip.NICID

	// MinTTL represents the minumum TTL/HopLimit a multicast packet must have to
	// be sent through the outgoing interface.
	MinTTL uint8
}

// PendingRoute represents a route that is in the "pending" state.
//
// A route is in the pending state if an installed route does not yet exist
// for the entry. For such routes, packets are added to an expiring queue until
// a route is installed.
type PendingRoute struct {
	packets []*stack.PacketBuffer
}

func newPendingRoute(maxSize uint8) PendingRoute {
	return PendingRoute{packets: make([]*stack.PacketBuffer, 0, maxSize)}
}

// Dequeue removes the first element in the queue and returns it.
//
// If the queue is empty, then an error will be returned.
//
// TODO(https://gvisor.dev/issue/7338): Remove this and instead just return the
// list of packets from AddInstalledRoute.
func (p *PendingRoute) Dequeue() (*stack.PacketBuffer, error) {
	if len(p.packets) == 0 {
		return nil, errors.New("dequeue called on queue empty")
	}
	val := p.packets[0]
	p.packets[0] = nil
	p.packets = p.packets[1:]
	return val, nil
}

// IsEmpty returns true if the queue contains no more elements. Otherwise,
// returns false.
func (p *PendingRoute) IsEmpty() bool {
	return len(p.packets) == 0
}

// DefaultMaxPendingQueueSize corresponds to the number of elements that can be
// in the packet queue for a pending route.
//
// Matches the Linux default queue size:
// https://github.com/torvalds/linux/blob/26291c54e11/net/ipv6/ip6mr.c#L1186
const DefaultMaxPendingQueueSize uint8 = 3

// Config represents the options for configuring a RouteTable.
type Config struct {
	// MaxPendingQueueSize corresponds to the maximum number of queued packets
	// for a pending route.
	//
	// If the caller attempts to queue a packet and the queue already contains
	// MaxPendingQueueSize elements, then the packet will be rejected and should
	// not be forwarded.
	MaxPendingQueueSize uint8

	// Clock represents the clock that should be used to obtain the current time.
	//
	// This field is required and must have a non-nil value.
	Clock tcpip.Clock
}

// DefaultConfig returns the default configuration for the table.
func DefaultConfig(clock tcpip.Clock) Config {
	return Config{MaxPendingQueueSize: DefaultMaxPendingQueueSize, Clock: clock}
}

// Init initializes the RouteTable with the provided config.
//
// An error is returned if the config is not valid.
//
// Must be called before any other function on the table.
func (r *RouteTable) Init(config Config) error {
	r.installedMu.Lock()
	defer r.installedMu.Unlock()
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	if r.installedRoutes != nil {
		return ErrAlreadyInitialized
	}

	if config.Clock == nil {
		return ErrMissingClock
	}

	r.config = config
	r.installedRoutes = make(map[RouteKey]*InstalledRoute)
	r.pendingRoutes = make(map[RouteKey]PendingRoute)
	return nil
}

// NewInstalledRoute instatiates an installed route for the table.
func (r *RouteTable) NewInstalledRoute(inputInterface tcpip.NICID, outgoingInterfaces []OutgoingInterface) *InstalledRoute {
	return &InstalledRoute{
		expectedInputInterface: inputInterface,
		outgoingInterfaces:     outgoingInterfaces,
		lastUsedTimestamp:      r.config.Clock.NowMonotonic(),
	}
}

// GetRouteResult represents the result of calling
// RouteTable.GetRouteOrInsertPending.
type GetRouteResult struct {
	// PendingRouteState represents the observed state of any applicable
	// PendingRoute.
	PendingRouteState

	// InstalledRoute represents the existing installed route. This field will
	// only be populated if the PendingRouteState is PendingRouteStateNone.
	*InstalledRoute
}

// PendingRouteState represents the state of a PendingRoute as observed by the
// RouteTable.GetRouteOrInsertPending method.
type PendingRouteState uint8

const (
	// PendingRouteStateNone indicates that no pending route exists. In such a
	// case, the GetRouteResult will contain an InstalledRoute.
	PendingRouteStateNone PendingRouteState = iota

	// PendingRouteStateAppended indicates that the packet was queued in an
	// existing pending route.
	PendingRouteStateAppended

	// PendingRouteStateInstalled indicates that a pending route was newly
	// inserted into the RouteTable. In such a case, callers should typically
	// emit a missing route event.
	PendingRouteStateInstalled
)

func (e PendingRouteState) String() string {
	switch e {
	case PendingRouteStateNone:
		return "PendingRouteStateNone"
	case PendingRouteStateAppended:
		return "PendingRouteStateAppended"
	case PendingRouteStateInstalled:
		return "PendingRouteStateInstalled"
	default:
		return fmt.Sprintf("%d", uint8(e))
	}
}

// GetRouteOrInsertPending attempts to fetch the installed route that matches
// the provided key.
//
// If no matching installed route is found, then the pkt is queued in a
// pending route. The GetRouteResult.PendingRouteState will indicate whether
// the pkt was queued in a new pending route or an existing one.
//
// If the relevant pending route queue is at max capacity, then
// ErrNoBufferSpace is returned. In such a case, callers are typically expected
// to only deliver the pkt locally (if relevant).
func (r *RouteTable) GetRouteOrInsertPending(key RouteKey, pkt *stack.PacketBuffer) (GetRouteResult, error) {
	r.installedMu.RLock()
	defer r.installedMu.RUnlock()

	if route, ok := r.installedRoutes[key]; ok {
		return GetRouteResult{PendingRouteState: PendingRouteStateNone, InstalledRoute: route}, nil
	}

	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	pendingRoute, pendingRouteState := r.getOrCreatePendingRouteRLocked(key)
	if len(pendingRoute.packets) >= int(r.config.MaxPendingQueueSize) {
		// The incoming packet is rejected if the pending queue is already at max
		// capacity. This behavior matches the Linux implementation:
		// https://github.com/torvalds/linux/blob/ae085d7f936/net/ipv4/ipmr.c#L1147
		return GetRouteResult{}, ErrNoBufferSpace
	}
	pendingRoute.packets = append(pendingRoute.packets, pkt)
	r.pendingRoutes[key] = pendingRoute

	return GetRouteResult{PendingRouteState: pendingRouteState, InstalledRoute: nil}, nil
}

// +checklocks:r.pendingMu
func (r *RouteTable) getOrCreatePendingRouteRLocked(key RouteKey) (PendingRoute, PendingRouteState) {
	if pendingRoute, ok := r.pendingRoutes[key]; ok {
		return pendingRoute, PendingRouteStateAppended
	}

	pendingRoute := newPendingRoute(r.config.MaxPendingQueueSize)
	return pendingRoute, PendingRouteStateInstalled
}

// AddInstalledRoute adds the provided route to the table.
//
// Returns true if the route was previously in the pending state. Otherwise,
// returns false.
//
// If the route was previously pending, then the caller is responsible for
// flushing the returned pending route packet queue. Conversely, if the route
// was not pending, then any existing installed route will be overwritten.
func (r *RouteTable) AddInstalledRoute(key RouteKey, route *InstalledRoute) (PendingRoute, bool) {
	r.installedMu.Lock()
	defer r.installedMu.Unlock()
	r.installedRoutes[key] = route

	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	pendingRoute, ok := r.pendingRoutes[key]
	delete(r.pendingRoutes, key)
	return pendingRoute, ok
}

// RemoveInstalledRoute deletes the installed route that matches the provided
// key.
//
// Returns true if a route was removed. Otherwise returns false.
func (r *RouteTable) RemoveInstalledRoute(key RouteKey) bool {
	r.installedMu.Lock()
	defer r.installedMu.Unlock()

	if _, ok := r.installedRoutes[key]; ok {
		delete(r.installedRoutes, key)
		return true
	}

	return false
}

// GetLastUsedTimestamp returns a monotonic timestamp that represents the last
// time the route that matches the provided key was used or updated.
//
// Returns true if a matching route was found. Otherwise returns false.
func (r *RouteTable) GetLastUsedTimestamp(key RouteKey) (tcpip.MonotonicTime, bool) {
	r.installedMu.RLock()
	defer r.installedMu.RUnlock()

	if route, ok := r.installedRoutes[key]; ok {
		return route.LastUsedTimestamp(), true
	}
	return tcpip.MonotonicTime{}, false
}
