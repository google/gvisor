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
	"time"

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
	// cleanupPendingRoutesTimer is a timer that triggers a routine to remove
	// pending routes that are expired.
	// +checklocks:pendingMu
	cleanupPendingRoutesTimer tcpip.Timer
	// +checklocks:pendingMu
	isCleanupRoutineRunning bool

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

	// expiration is the timestamp at which the pending route should be expired.
	//
	// If this value is before the current time, then this pending route will
	// be dropped.
	expiration tcpip.MonotonicTime
}

func (p *PendingRoute) releasePackets() {
	for _, pkt := range p.packets {
		pkt.DecRef()
	}
}

func (p *PendingRoute) isExpired(currentTime tcpip.MonotonicTime) bool {
	return currentTime.After(p.expiration)
}

const (
	// DefaultMaxPendingQueueSize corresponds to the number of elements that can
	// be in the packet queue for a pending route.
	//
	// Matches the Linux default queue size:
	// https://github.com/torvalds/linux/blob/26291c54e11/net/ipv6/ip6mr.c#L1186
	DefaultMaxPendingQueueSize uint8 = 3

	// DefaultPendingRouteExpiration is the default maximum lifetime of a pending
	// route.
	//
	// Matches the Linux default:
	// https://github.com/torvalds/linux/blob/26291c54e11/net/ipv6/ip6mr.c#L991
	DefaultPendingRouteExpiration time.Duration = 10 * time.Second

	// DefaultCleanupInterval is the default frequency of the routine that
	// expires pending routes.
	//
	// Matches the Linux default:
	// https://github.com/torvalds/linux/blob/26291c54e11/net/ipv6/ip6mr.c#L793
	DefaultCleanupInterval time.Duration = 10 * time.Second
)

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
	return Config{
		MaxPendingQueueSize: DefaultMaxPendingQueueSize,
		Clock:               clock,
	}
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

// Close cleans up resources held by the table.
//
// Calling this will stop the cleanup routine and release any packets owned by
// the table.
func (r *RouteTable) Close() {
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	if r.cleanupPendingRoutesTimer != nil {
		r.cleanupPendingRoutesTimer.Stop()
	}

	for key, route := range r.pendingRoutes {
		delete(r.pendingRoutes, key)
		route.releasePackets()
	}
}

// maybeStopCleanupRoutine stops the pending routes cleanup routine if no
// pending routes exist.
//
// Returns true if the timer is not running. Otherwise, returns false.
//
// +checklocks:r.pendingMu
func (r *RouteTable) maybeStopCleanupRoutineLocked() bool {
	if !r.isCleanupRoutineRunning {
		return true
	}

	if len(r.pendingRoutes) == 0 {
		r.cleanupPendingRoutesTimer.Stop()
		r.isCleanupRoutineRunning = false
		return true
	}

	return false
}

func (r *RouteTable) cleanupPendingRoutes() {
	currentTime := r.config.Clock.NowMonotonic()
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	for key, route := range r.pendingRoutes {
		if route.isExpired(currentTime) {
			delete(r.pendingRoutes, key)
			route.releasePackets()
		}
	}

	if stopped := r.maybeStopCleanupRoutineLocked(); !stopped {
		r.cleanupPendingRoutesTimer.Reset(DefaultCleanupInterval)
	}
}

func (r *RouteTable) newPendingRoute() PendingRoute {
	return PendingRoute{
		packets:    make([]*stack.PacketBuffer, 0, r.config.MaxPendingQueueSize),
		expiration: r.config.Clock.NowMonotonic().Add(DefaultPendingRouteExpiration),
	}
}

// NewInstalledRoute instantiates an installed route for the table.
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
// If no matching installed route is found, then the pkt is cloned and queued
// in a pending route. The GetRouteResult.PendingRouteState will indicate
// whether the pkt was queued in a new pending route or an existing one.
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
	pendingRoute.packets = append(pendingRoute.packets, pkt.Clone())
	r.pendingRoutes[key] = pendingRoute

	if !r.isCleanupRoutineRunning {
		// The cleanup routine isn't running, but should be. Start it.
		if r.cleanupPendingRoutesTimer == nil {
			r.cleanupPendingRoutesTimer = r.config.Clock.AfterFunc(DefaultCleanupInterval, r.cleanupPendingRoutes)
		} else {
			r.cleanupPendingRoutesTimer.Reset(DefaultCleanupInterval)
		}
		r.isCleanupRoutineRunning = true
	}

	return GetRouteResult{PendingRouteState: pendingRouteState, InstalledRoute: nil}, nil
}

// +checklocks:r.pendingMu
func (r *RouteTable) getOrCreatePendingRouteRLocked(key RouteKey) (PendingRoute, PendingRouteState) {
	if pendingRoute, ok := r.pendingRoutes[key]; ok {
		return pendingRoute, PendingRouteStateAppended
	}
	return r.newPendingRoute(), PendingRouteStateInstalled
}

// AddInstalledRoute adds the provided route to the table.
//
// Packets that were queued while the route was in the pending state are
// returned. The caller assumes ownership of these packets and is responsible
// for forwarding and releasing them. If an installed route already exists for
// the provided key, then it is overwritten.
func (r *RouteTable) AddInstalledRoute(key RouteKey, route *InstalledRoute) []*stack.PacketBuffer {
	r.installedMu.Lock()
	defer r.installedMu.Unlock()
	r.installedRoutes[key] = route

	r.pendingMu.Lock()
	pendingRoute, ok := r.pendingRoutes[key]
	delete(r.pendingRoutes, key)
	// No need to reset the timer here. The cleanup routine is responsible for
	// doing so.
	_ = r.maybeStopCleanupRoutineLocked()
	r.pendingMu.Unlock()

	// Ignore the pending route if it is expired. It may be in this state since
	// the cleanup process is only run periodically.
	if !ok || pendingRoute.isExpired(r.config.Clock.NowMonotonic()) {
		pendingRoute.releasePackets()
		return nil
	}

	return pendingRoute.packets
}

// RemoveInstalledRoute deletes any installed route that matches the provided
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
