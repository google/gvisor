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
	installedRoutes map[stack.UnicastSourceAndMulticastDestination]*InstalledRoute

	pendingMu sync.RWMutex
	// +checklocks:pendingMu
	pendingRoutes map[stack.UnicastSourceAndMulticastDestination]PendingRoute
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

// InstalledRoute represents a route that is in the installed state.
//
// If a route is in the installed state, then it may be used to forward
// multicast packets.
type InstalledRoute struct {
	stack.MulticastRoute

	lastUsedTimestampMu sync.RWMutex
	// +checklocks:lastUsedTimestampMu
	lastUsedTimestamp tcpip.MonotonicTime
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

// PendingRoute represents a route that is in the "pending" state.
//
// A route is in the pending state if an installed route does not yet exist
// for the entry. For such routes, packets are added to an expiring queue until
// a route is installed.
type PendingRoute struct {
	packets []stack.PacketBufferPtr

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
	r.installedRoutes = make(map[stack.UnicastSourceAndMulticastDestination]*InstalledRoute)
	r.pendingRoutes = make(map[stack.UnicastSourceAndMulticastDestination]PendingRoute)

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
		packets:    make([]stack.PacketBufferPtr, 0, r.config.MaxPendingQueueSize),
		expiration: r.config.Clock.NowMonotonic().Add(DefaultPendingRouteExpiration),
	}
}

// NewInstalledRoute instantiates an installed route for the table.
func (r *RouteTable) NewInstalledRoute(route stack.MulticastRoute) *InstalledRoute {
	return &InstalledRoute{
		MulticastRoute:    route,
		lastUsedTimestamp: r.config.Clock.NowMonotonic(),
	}
}

// GetRouteResult represents the result of calling GetRouteOrInsertPending.
type GetRouteResult struct {
	// GetRouteResultState signals the result of calling GetRouteOrInsertPending.
	GetRouteResultState GetRouteResultState

	// InstalledRoute represents the existing installed route. This field will
	// only be populated if the GetRouteResultState is InstalledRouteFound.
	InstalledRoute *InstalledRoute
}

// GetRouteResultState signals the result of calling GetRouteOrInsertPending.
type GetRouteResultState uint8

const (
	// InstalledRouteFound indicates that an InstalledRoute was found.
	InstalledRouteFound GetRouteResultState = iota

	// PacketQueuedInPendingRoute indicates that the packet was queued in an
	// existing pending route.
	PacketQueuedInPendingRoute

	// NoRouteFoundAndPendingInserted indicates that no route was found and that
	// a pending route was newly inserted into the RouteTable.
	NoRouteFoundAndPendingInserted
)

func (e GetRouteResultState) String() string {
	switch e {
	case InstalledRouteFound:
		return "InstalledRouteFound"
	case PacketQueuedInPendingRoute:
		return "PacketQueuedInPendingRoute"
	case NoRouteFoundAndPendingInserted:
		return "NoRouteFoundAndPendingInserted"
	default:
		return fmt.Sprintf("%d", uint8(e))
	}
}

// GetRouteOrInsertPending attempts to fetch the installed route that matches
// the provided key.
//
// If no matching installed route is found, then the pkt is cloned and queued
// in a pending route. The GetRouteResult.GetRouteResultState will indicate
// whether the pkt was queued in a new pending route or an existing one.
//
// If the relevant pending route queue is at max capacity, then returns false.
// Otherwise, returns true.
func (r *RouteTable) GetRouteOrInsertPending(key stack.UnicastSourceAndMulticastDestination, pkt stack.PacketBufferPtr) (GetRouteResult, bool) {
	r.installedMu.RLock()
	defer r.installedMu.RUnlock()

	if route, ok := r.installedRoutes[key]; ok {
		return GetRouteResult{GetRouteResultState: InstalledRouteFound, InstalledRoute: route}, true
	}

	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	pendingRoute, getRouteResultState := r.getOrCreatePendingRouteRLocked(key)
	if len(pendingRoute.packets) >= int(r.config.MaxPendingQueueSize) {
		// The incoming packet is rejected if the pending queue is already at max
		// capacity. This behavior matches the Linux implementation:
		// https://github.com/torvalds/linux/blob/ae085d7f936/net/ipv4/ipmr.c#L1147
		return GetRouteResult{}, false
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

	return GetRouteResult{GetRouteResultState: getRouteResultState, InstalledRoute: nil}, true
}

// +checklocks:r.pendingMu
func (r *RouteTable) getOrCreatePendingRouteRLocked(key stack.UnicastSourceAndMulticastDestination) (PendingRoute, GetRouteResultState) {
	if pendingRoute, ok := r.pendingRoutes[key]; ok {
		return pendingRoute, PacketQueuedInPendingRoute
	}
	return r.newPendingRoute(), NoRouteFoundAndPendingInserted
}

// AddInstalledRoute adds the provided route to the table.
//
// Packets that were queued while the route was in the pending state are
// returned. The caller assumes ownership of these packets and is responsible
// for forwarding and releasing them. If an installed route already exists for
// the provided key, then it is overwritten.
func (r *RouteTable) AddInstalledRoute(key stack.UnicastSourceAndMulticastDestination, route *InstalledRoute) []stack.PacketBufferPtr {
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
func (r *RouteTable) RemoveInstalledRoute(key stack.UnicastSourceAndMulticastDestination) bool {
	r.installedMu.Lock()
	defer r.installedMu.Unlock()

	if _, ok := r.installedRoutes[key]; ok {
		delete(r.installedRoutes, key)
		return true
	}

	return false
}

// RemoveAllInstalledRoutes removes all installed routes from the table.
func (r *RouteTable) RemoveAllInstalledRoutes() {
	r.installedMu.Lock()
	defer r.installedMu.Unlock()

	for key := range r.installedRoutes {
		delete(r.installedRoutes, key)
	}
}

// GetLastUsedTimestamp returns a monotonic timestamp that represents the last
// time the route that matches the provided key was used or updated.
//
// Returns true if a matching route was found. Otherwise returns false.
func (r *RouteTable) GetLastUsedTimestamp(key stack.UnicastSourceAndMulticastDestination) (tcpip.MonotonicTime, bool) {
	r.installedMu.RLock()
	defer r.installedMu.RUnlock()

	if route, ok := r.installedRoutes[key]; ok {
		return route.LastUsedTimestamp(), true
	}
	return tcpip.MonotonicTime{}, false
}
