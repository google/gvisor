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
	"math"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	// defaultBaseReachableTime is the default base duration for computing the
	// random reachable time.
	//
	// Reachable time is the duration for which a neighbor is considered
	// reachable after a positive reachability confirmation is received. It is a
	// function of a uniformly distributed random value between the minimum and
	// maximum random factors, multiplied by the base reachable time. Using a
	// random component eliminates the possibility that Neighbor Unreachability
	// Detection messages will synchronize with each other.
	//
	// Default taken from REACHABLE_TIME of RFC 4861 section 10.
	defaultBaseReachableTime = 30 * time.Second

	// minimumBaseReachableTime is the minimum base duration for computing the
	// random reachable time.
	//
	// Minimum = 1ms
	minimumBaseReachableTime = time.Millisecond

	// defaultMinRandomFactor is the default minimum value of the random factor
	// used for computing reachable time.
	//
	// Default taken from MIN_RANDOM_FACTOR of RFC 4861 section 10.
	defaultMinRandomFactor = 0.5

	// defaultMaxRandomFactor is the default maximum value of the random factor
	// used for computing reachable time.
	//
	// The default value depends on the value of MinRandomFactor.
	// If MinRandomFactor is less than MAX_RANDOM_FACTOR of RFC 4861 section 10,
	// the value from the RFC will be used; otherwise, the default is
	// MinRandomFactor multiplied by three.
	defaultMaxRandomFactor = 1.5

	// defaultRetransmitTimer is the default amount of time to wait between
	// sending reachability probes.
	//
	// Default taken from RETRANS_TIMER of RFC 4861 section 10.
	defaultRetransmitTimer = time.Second

	// minimumRetransmitTimer is the minimum amount of time to wait between
	// sending reachability probes.
	//
	// Note, RFC 4861 does not impose a minimum Retransmit Timer, but we do here
	// to make sure the messages are not sent all at once. We also come to this
	// value because in the RetransmitTimer field of a Router Advertisement, a
	// value of 0 means unspecified, so the smallest valid value is 1. Note, the
	// unit of the RetransmitTimer field in the Router Advertisement is
	// milliseconds.
	minimumRetransmitTimer = time.Millisecond

	// defaultDelayFirstProbeTime is the default duration to wait for a
	// non-Neighbor-Discovery related protocol to reconfirm reachability after
	// entering the DELAY state. After this time, a reachability probe will be
	// sent and the entry will transition to the PROBE state.
	//
	// Default taken from DELAY_FIRST_PROBE_TIME of RFC 4861 section 10.
	defaultDelayFirstProbeTime = 5 * time.Second

	// defaultMaxMulticastProbes is the default number of reachabililty probes
	// to send before concluding negative reachability and deleting the neighbor
	// entry from the INCOMPLETE state.
	//
	// Default taken from MAX_MULTICAST_SOLICIT of RFC 4861 section 10.
	defaultMaxMulticastProbes = 3

	// defaultMaxUnicastProbes is the default number of reachability probes to
	// send before concluding retransmission from within the PROBE state should
	// cease and the entry SHOULD be deleted.
	//
	// Default taken from MAX_UNICASE_SOLICIT of RFC 4861 section 10.
	defaultMaxUnicastProbes = 3

	// defaultMaxAnycastDelayTime is the default time in which the stack SHOULD
	// delay sending a response for a random time between 0 and this time, if the
	// target address is an anycast address.
	//
	// Default taken from MAX_ANYCAST_DELAY_TIME of RFC 4861 section 10.
	defaultMaxAnycastDelayTime = time.Second

	// defaultMaxReachbilityConfirmations is the default amount of unsolicited
	// reachability confirmation messages a node MAY send to all-node multicast
	// address when it determines its link-layer address has changed.
	//
	// Default taken from MAX_NEIGHBOR_ADVERTISEMENT of RFC 4861 section 10.
	defaultMaxReachbilityConfirmations = 3
)

// NUDDispatcher is the interface integrators of netstack must implement to
// receive and handle NUD related events.
type NUDDispatcher interface {
	// OnNeighborAdded will be called when a new entry is added to a NIC's (with
	// ID nicID) neighbor table.
	//
	// This function is permitted to block indefinitely without interfering with
	// the stack's operation.
	//
	// May be called concurrently.
	OnNeighborAdded(tcpip.NICID, NeighborEntry)

	// OnNeighborChanged will be called when an entry in a NIC's (with ID nicID)
	// neighbor table changes state and/or link address.
	//
	// This function is permitted to block indefinitely without interfering with
	// the stack's operation.
	//
	// May be called concurrently.
	OnNeighborChanged(tcpip.NICID, NeighborEntry)

	// OnNeighborRemoved will be called when an entry is removed from a NIC's
	// (with ID nicID) neighbor table.
	//
	// This function is permitted to block indefinitely without interfering with
	// the stack's operation.
	//
	// May be called concurrently.
	OnNeighborRemoved(tcpip.NICID, NeighborEntry)
}

// ReachabilityConfirmationFlags describes the flags used within a reachability
// confirmation (e.g. ARP reply or Neighbor Advertisement for ARP or NDP,
// respectively).
type ReachabilityConfirmationFlags struct {
	// Solicited indicates that the advertisement was sent in response to a
	// reachability probe.
	Solicited bool

	// Override indicates that the reachability confirmation should override an
	// existing neighbor cache entry and update the cached link-layer address.
	// When Override is not set the confirmation will not update a cached
	// link-layer address, but will update an existing neighbor cache entry for
	// which no link-layer address is known.
	Override bool

	// IsRouter indicates that the sender is a router.
	IsRouter bool
}

// NUDHandler communicates external events to the Neighbor Unreachability
// Detection state machine, which is implemented per-interface. This is used by
// network endpoints to inform the Neighbor Cache of probes and confirmations.
type NUDHandler interface {
	// HandleProbe processes an incoming neighbor probe (e.g. ARP request or
	// Neighbor Solicitation for ARP or NDP, respectively). Validation of the
	// probe needs to be performed before calling this function since the
	// Neighbor Cache doesn't have access to view the NIC's assigned addresses.
	HandleProbe(remoteAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, remoteLinkAddr tcpip.LinkAddress, linkRes LinkAddressResolver)

	// HandleConfirmation processes an incoming neighbor confirmation (e.g. ARP
	// reply or Neighbor Advertisement for ARP or NDP, respectively).
	HandleConfirmation(addr tcpip.Address, linkAddr tcpip.LinkAddress, flags ReachabilityConfirmationFlags)

	// HandleUpperLevelConfirmation processes an incoming upper-level protocol
	// (e.g. TCP acknowledgements) reachability confirmation.
	HandleUpperLevelConfirmation(addr tcpip.Address)
}

// NUDConfigurations is the NUD configurations for the netstack. This is used
// by the neighbor cache to operate the NUD state machine on each device in the
// local network.
type NUDConfigurations struct {
	// BaseReachableTime is the base duration for computing the random reachable
	// time.
	//
	// Reachable time is the duration for which a neighbor is considered
	// reachable after a positive reachability confirmation is received. It is a
	// function of uniformly distributed random value between minRandomFactor and
	// maxRandomFactor multiplied by baseReachableTime. Using a random component
	// eliminates the possibility that Neighbor Unreachability Detection messages
	// will synchronize with each other.
	//
	// After this time, a neighbor entry will transition from REACHABLE to STALE
	// state.
	//
	// Must be greater than 0.
	BaseReachableTime time.Duration

	// LearnBaseReachableTime enables learning BaseReachableTime during runtime
	// from the neighbor discovery protocol, if supported.
	//
	// TODO(gvisor.dev/issue/2240): Implement this NUD configuration option.
	LearnBaseReachableTime bool

	// MinRandomFactor is the minimum value of the random factor used for
	// computing reachable time.
	//
	// See BaseReachbleTime for more information on computing the reachable time.
	//
	// Must be greater than 0.
	MinRandomFactor float32

	// MaxRandomFactor is the maximum value of the random factor used for
	// computing reachabile time.
	//
	// See BaseReachbleTime for more information on computing the reachable time.
	//
	// Must be great than or equal to MinRandomFactor.
	MaxRandomFactor float32

	// RetransmitTimer is the duration between retransmission of reachability
	// probes in the PROBE state.
	RetransmitTimer time.Duration

	// LearnRetransmitTimer enables learning RetransmitTimer during runtime from
	// the neighbor discovery protocol, if supported.
	//
	// TODO(gvisor.dev/issue/2241): Implement this NUD configuration option.
	LearnRetransmitTimer bool

	// DelayFirstProbeTime is the duration to wait for a non-Neighbor-Discovery
	// related protocol to reconfirm reachability after entering the DELAY state.
	// After this time, a reachability probe will be sent and the entry will
	// transition to the PROBE state.
	//
	// Must be greater than 0.
	DelayFirstProbeTime time.Duration

	// MaxMulticastProbes is the number of reachability probes to send before
	// concluding negative reachability and deleting the neighbor entry from the
	// INCOMPLETE state.
	//
	// Must be greater than 0.
	MaxMulticastProbes uint32

	// MaxUnicastProbes is the number of reachability probes to send before
	// concluding retransmission from within the PROBE state should cease and
	// entry SHOULD be deleted.
	//
	// Must be greater than 0.
	MaxUnicastProbes uint32

	// MaxAnycastDelayTime is the time in which the stack SHOULD delay sending a
	// response for a random time between 0 and this time, if the target address
	// is an anycast address.
	//
	// TODO(gvisor.dev/issue/2242): Use this option when sending solicited
	// neighbor confirmations to anycast addresses and proxying neighbor
	// confirmations.
	MaxAnycastDelayTime time.Duration

	// MaxReachabilityConfirmations is the number of unsolicited reachability
	// confirmation messages a node MAY send to all-node multicast address when
	// it determines its link-layer address has changed.
	//
	// TODO(gvisor.dev/issue/2246): Discuss if implementation of this NUD
	// configuration option is necessary.
	MaxReachabilityConfirmations uint32
}

// DefaultNUDConfigurations returns a NUDConfigurations populated with default
// values defined by RFC 4861 section 10.
func DefaultNUDConfigurations() NUDConfigurations {
	return NUDConfigurations{
		BaseReachableTime:            defaultBaseReachableTime,
		LearnBaseReachableTime:       true,
		MinRandomFactor:              defaultMinRandomFactor,
		MaxRandomFactor:              defaultMaxRandomFactor,
		RetransmitTimer:              defaultRetransmitTimer,
		LearnRetransmitTimer:         true,
		DelayFirstProbeTime:          defaultDelayFirstProbeTime,
		MaxMulticastProbes:           defaultMaxMulticastProbes,
		MaxUnicastProbes:             defaultMaxUnicastProbes,
		MaxAnycastDelayTime:          defaultMaxAnycastDelayTime,
		MaxReachabilityConfirmations: defaultMaxReachbilityConfirmations,
	}
}

// resetInvalidFields modifies an invalid NDPConfigurations with valid values.
// If invalid values are present in c, the corresponding default values will be
// used instead. This is needed to check, and conditionally fix, user-specified
// NUDConfigurations.
func (c *NUDConfigurations) resetInvalidFields() {
	if c.BaseReachableTime < minimumBaseReachableTime {
		c.BaseReachableTime = defaultBaseReachableTime
	}
	if c.MinRandomFactor <= 0 {
		c.MinRandomFactor = defaultMinRandomFactor
	}
	if c.MaxRandomFactor < c.MinRandomFactor {
		c.MaxRandomFactor = calcMaxRandomFactor(c.MinRandomFactor)
	}
	if c.RetransmitTimer < minimumRetransmitTimer {
		c.RetransmitTimer = defaultRetransmitTimer
	}
	if c.DelayFirstProbeTime == 0 {
		c.DelayFirstProbeTime = defaultDelayFirstProbeTime
	}
	if c.MaxMulticastProbes == 0 {
		c.MaxMulticastProbes = defaultMaxMulticastProbes
	}
	if c.MaxUnicastProbes == 0 {
		c.MaxUnicastProbes = defaultMaxUnicastProbes
	}
}

// calcMaxRandomFactor calculates the maximum value of the random factor used
// for computing reachable time. This function is necessary for when the
// default specified in RFC 4861 section 10 is less than the current
// MinRandomFactor.
//
// Assumes minRandomFactor is positive since validation of the minimum value
// should come before the validation of the maximum.
func calcMaxRandomFactor(minRandomFactor float32) float32 {
	if minRandomFactor > defaultMaxRandomFactor {
		return minRandomFactor * 3
	}
	return defaultMaxRandomFactor
}

// A Rand is a source of random numbers.
type Rand interface {
	// Float32 returns, as a float32, a pseudo-random number in [0.0,1.0).
	Float32() float32
}

// NUDState stores states needed for calculating reachable time.
type NUDState struct {
	rng Rand

	// mu protects the fields below.
	//
	// It is necessary for NUDState to handle its own locking since neighbor
	// entries may access the NUD state from within the goroutine spawned by
	// time.AfterFunc(). This goroutine may run concurrently with the main
	// process for controlling the neighbor cache and would otherwise introduce
	// race conditions if NUDState was not locked properly.
	mu sync.RWMutex

	config NUDConfigurations

	// reachableTime is the duration to wait for a REACHABLE entry to
	// transition into STALE after inactivity. This value is calculated with
	// the algorithm defined in RFC 4861 section 6.3.2.
	reachableTime time.Duration

	expiration            time.Time
	prevBaseReachableTime time.Duration
	prevMinRandomFactor   float32
	prevMaxRandomFactor   float32
}

// NewNUDState returns new NUDState using c as configuration and the specified
// random number generator for use in recomputing ReachableTime.
func NewNUDState(c NUDConfigurations, rng Rand) *NUDState {
	s := &NUDState{
		rng: rng,
	}
	s.config = c
	return s
}

// Config returns the NUD configuration.
func (s *NUDState) Config() NUDConfigurations {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// SetConfig replaces the existing NUD configurations with c.
func (s *NUDState) SetConfig(c NUDConfigurations) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = c
}

// ReachableTime returns the duration to wait for a REACHABLE entry to
// transition into STALE after inactivity. This value is recalculated for new
// values of BaseReachableTime, MinRandomFactor, and MaxRandomFactor using the
// algorithm defined in RFC 4861 section 6.3.2.
func (s *NUDState) ReachableTime() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Now().After(s.expiration) ||
		s.config.BaseReachableTime != s.prevBaseReachableTime ||
		s.config.MinRandomFactor != s.prevMinRandomFactor ||
		s.config.MaxRandomFactor != s.prevMaxRandomFactor {
		s.recomputeReachableTimeLocked()
	}
	return s.reachableTime
}

// recomputeReachableTimeLocked forces a recalculation of ReachableTime using
// the algorithm defined in RFC 4861 section 6.3.2.
//
// This SHOULD automatically be invoked during certain situations, as per
// RFC 4861 section 6.3.4:
//
//    If the received Reachable Time value is non-zero, the host SHOULD set its
//    BaseReachableTime variable to the received value.  If the new value
//    differs from the previous value, the host SHOULD re-compute a new random
//    ReachableTime value.  ReachableTime is computed as a uniformly
//    distributed random value between MIN_RANDOM_FACTOR and MAX_RANDOM_FACTOR
//    times the BaseReachableTime.  Using a random component eliminates the
//    possibility that Neighbor Unreachability Detection messages will
//    synchronize with each other.
//
//    In most cases, the advertised Reachable Time value will be the same in
//    consecutive Router Advertisements, and a host's BaseReachableTime rarely
//    changes.  In such cases, an implementation SHOULD ensure that a new
//    random value gets re-computed at least once every few hours.
//
// s.mu MUST be locked for writing.
func (s *NUDState) recomputeReachableTimeLocked() {
	s.prevBaseReachableTime = s.config.BaseReachableTime
	s.prevMinRandomFactor = s.config.MinRandomFactor
	s.prevMaxRandomFactor = s.config.MaxRandomFactor

	randomFactor := s.config.MinRandomFactor + s.rng.Float32()*(s.config.MaxRandomFactor-s.config.MinRandomFactor)

	// Check for overflow, given that minRandomFactor and maxRandomFactor are
	// guaranteed to be positive numbers.
	if float32(math.MaxInt64)/randomFactor < float32(s.config.BaseReachableTime) {
		s.reachableTime = time.Duration(math.MaxInt64)
	} else if randomFactor == 1 {
		// Avoid loss of precision when a large base reachable time is used.
		s.reachableTime = s.config.BaseReachableTime
	} else {
		reachableTime := int64(float32(s.config.BaseReachableTime) * randomFactor)
		s.reachableTime = time.Duration(reachableTime)
	}

	s.expiration = time.Now().Add(2 * time.Hour)
}
