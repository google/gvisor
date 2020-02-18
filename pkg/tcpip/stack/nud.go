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
	"math"
	"math/rand"
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
	// Default = 30s (from RFC 4861 section 10).
	defaultBaseReachableTime = 30 * time.Second

	// minimumBaseReachableTime is the minimum base duration for computing the
	// random reachable time.
	//
	// Minimum = 1ms
	minimumBaseReachableTime = time.Millisecond

	// defaultMinRandomFactor is the default minimum value of the random factor
	// used for computing reachable time.
	//
	// Default = 0.5 (from RFC 4861 section 10).
	defaultMinRandomFactor = 0.5

	// defaultMaxRandomFactor is the default maximum value of the random factor
	// used for computing reachable time.
	//
	// Default = 1.5 (from RFC 4861 section 10).
	defaultMaxRandomFactor = 1.5

	// defaultRetransmitTimer is the default amount of time to wait between
	// sending NDP Neighbor solicitation messages.
	//
	// Default = 1s (from RFC 4861 section 10).
	//
	// TODO(sbalana): Remove duplicate value either here or in ndp.go
	// defaultRetransmitTimer = time.Second

	// minimumRetransmitTimer is the minimum amount of time to wait between
	// sending reachability probes.
	//
	// Note, RFC 4861 does not impose a minimum Retransmit Timer, but we do here
	// to make sure the messages are not sent all at once. We also come to this
	// value because in the RetransmitTimer field of a Router Advertisement, a
	// value of 0 means unspecified, so the smallest valid value is 1. Note, the
	// unit of the RetransmitTimer field in the Router Advertisement is
	// milliseconds.
	//
	// Minimum = 1ms.
	//
	// TODO(sbalana): Remove duplicate value either here or in ndp.go
	// minimumRetransmitTimer = time.Millisecond

	// defaultDelayFirstProbeTime is the default duration to wait for a
	// non-Neighbor-Discovery related protocol to reconfirm reachability after
	// entering the DELAY state. After this time, a reachability probe will be
	// sent and the entry will transition to the PROBE state.
	//
	// Default = 5s (from RFC 4861 section 10).
	defaultDelayFirstProbeTime = 5 * time.Second

	// defaultMaxMulticastProbes is the default number of reachabililty probes
	// to send before concluding negative reachability and deleting the neighbor
	// entry from the INCOMPLETE state.
	//
	// Default = 3 (from RFC 4861 section 10).
	defaultMaxMulticastProbes = 3

	// defaultMaxUnicastProbes is the default number of reachability probes to
	// send before concluding retransmission from within the PROBE state should
	// cease and the entry SHOULD be deleted.
	//
	// Default = 3 (from RFC 4861 section 10).
	defaultMaxUnicastProbes = 3

	// defaultMaxAnycastDelayTime is the default time in which the stack SHOULD
	// delay sending a response for a random time between 0 and this time, if the
	// target address is an anycast address.
	//
	// Default = 1s (from RFC 4861 section 10).
	defaultMaxAnycastDelayTime = time.Second

	// defaultMaxReachbilityConfirmations is the default amount of unsolicited
	// reachability confirmation messages a node MAY send to all-node multicast
	// address when it determines its link-layer address has changed.
	//
	// Default = 3 (from RFC 4861 section 10).
	defaultMaxReachbilityConfirmations = 3

	// defaultUnreachableTime is the default duration for how long an entry will
	// remain in the FAILED state before being removed from the neighbor cache.
	defaultUnreachableTime = 5 * time.Second
)

// NUDDispatcher is the interface integrators of netstack must implement to
// receive and handle NUD related events.
type NUDDispatcher interface {
	// OnNeighborAdded will be called when a new entry is added to a NIC's (with
	// ID nicID) neighbor table.
	//
	// This function is permitted to block indefinately without interfering with
	// the stack's operation.
	OnNeighborAdded(nicID tcpip.NICID, ipAddr tcpip.Address, linkAddr tcpip.LinkAddress, state NeighborState)

	// OnNeighborStateChange will be called when an entry in a NIC's (with ID
	// nicID) neighbor table changes state.
	//
	// This function is permitted to block indefinately without interfering with
	// the stack's operation.
	OnNeighborStateChange(nicID tcpip.NICID, ipAddr tcpip.Address, linkAddr tcpip.LinkAddress, state NeighborState)

	// OnNeighborRemoved will be called when an entry is removed from a NIC's (with ID nicID) neighbor table.
	//
	// This function is permitted to block indefinately without interfering with
	// the stack's operation.
	OnNeighborRemoved(nicID tcpip.NICID, ipAddr tcpip.Address, linkAddr tcpip.LinkAddress, state NeighborState)
}

// NUDHandler communicates external events to the Neighbor Unreachability
// Detection state machine, which is implemented per-interface. This is used by
// network endpoints to inform the Neighbor Cache of probes and confirmations.
//
// TODO(sbalana): Provide a way for a transport endpoint to receive a signal
// that AddLinkAddress for a particular address has been called.
type NUDHandler interface {
	// HandleProbe processes an incomping neighbor probe (e.g. ARP request or
	// Neighbor Solicitation for ARP or NDP, respectively). Validation of the
	// probe needs to be performed before calling this function since the
	// Neighbor Cache doesn't have access to view the NIC's assigned addresses.
	HandleProbe(remoteAddr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, remoteLinkAddr tcpip.LinkAddress)

	// HandleConfirmation processes an incoming neighbor confirmation (e.g. ARP
	// reply or Neighbor Advertisement for ARP or NDP, respectively).
	HandleConfirmation(addr tcpip.Address, linkAddr tcpip.LinkAddress, solicited, override, isRouter bool)

	// HandleUpperLevelConfirmation processes an incoming upper-level protocol
	// (e.g. TCP acknowledgements) reachability confirmation.
	HandleUpperLevelConfirmation(addr tcpip.Address)
}

// NUDConfigurations is the NUD configurations for the netstack.
type NUDConfigurations struct {
	// BaseReachableTime is the base duration for computing the random reachable
	// time.
	//
	// Reachable time is the duration for which a neighbor is considered
	// reachable after a positive reachability confirmation is received. It is a
	// function of uniformly distributed random value between minRandomFactor and
	// maxRandomFactor multiplied by baseReachableTime. Using a random component
	// eliminates the possibility that Neighbor Unreachabilty Detection messages
	// will synchronize with each other.
	//
	// After this time, a neighbor entry will transition from REACHABLE to STALE
	// state.
	//
	// Must be greater than 0.
	BaseReachableTime time.Duration

	// LearnBaseReachableTime enables learning BaseReachableTime during runtime
	// from the neighbor discovery protocl, if suported.
	LearnBaseReachableTime bool

	// MinRandomFactor is the minimum value of the random factor used for
	// computing reachable time.
	//
	// See BaseReachbleTime for more information on computing the reachable time.
	//
	// Must be greater than 0.
	MinRandomFactor float32

	// MaxRandomFactor is the maximum value of the random factor used for computing reachabile time.
	//
	// See BaseReachbleTime for more information on computing the reachable time.
	//
	// Must be great than or equal to MinRandomFactor.
	MaxRandomFactor float32

	// RetransmitTimer is the duration between retransmission of reachability
	// probes in the PROBE state.
	RetransmitTimer time.Duration

	// LearnRetransmitTimer enables learning RetransmitTimer during runtime from
	// the neighbor discovery protocl, if suported.
	LearnRetransmitTimer bool

	// DelayFirstProbeTime is the duration to wait for a non-Neighbor-Discovery
	// related protocol to reconfirm reachabilty after entering the DELAY state.
	// After this time, a reachabilty probe will be sent and the entry will
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

	// MaxUnicastProbes is the number of reachabilty probes to send before
	// concluding retransmission from within the PROBE state should cease and
	// entry SHOULD be deleted.
	//
	// Must be greater than 0.
	MaxUnicastProbes uint32

	// MaxAnycastDelayTime is the time in which the stack SHOULD delay sending a
	// response for a random time between 0 and this time, if the target addresss
	// is an anycast address.
	MaxAnycastDelayTime time.Duration

	// MaxReachabilityConfirmations is the number of unsolicited reachability
	// confirmation messages a node MAY send to all-node multicast address when
	// it determines its link-layer address has changed.
	MaxReachabilityConfirmations uint32

	// UnreachableTime describes how long an entry will remain in the FAILED
	// state before being removed from the neighbor cache.
	UnreachableTime time.Duration

	// reachableTime is the duration to wait for a REACHABLE entry to transition
	// into STALE after inactivity. This value is calculated with the algorithm
	// defined in RFC 4861 section 6.3.2.
	reachableTime time.Duration
}

// DefaultNUDConfigurations returns a NUDConfigurations populated with default
// values.
func DefaultNUDConfigurations() *NUDConfigurations {
	return &NUDConfigurations{
		BaseReachableTime:            defaultBaseReachableTime,
		LearnBaseReachableTime:       true,
		MinRandomFactor:              defaultMinRandomFactor,
		MaxRandomFactor:              defaultMaxRandomFactor,
		LearnRetransmitTimer:         true,
		DelayFirstProbeTime:          defaultDelayFirstProbeTime,
		MaxMulticastProbes:           defaultMaxMulticastProbes,
		MaxUnicastProbes:             defaultMaxUnicastProbes,
		MaxAnycastDelayTime:          defaultMaxAnycastDelayTime,
		MaxReachabilityConfirmations: defaultMaxReachbilityConfirmations,
		UnreachableTime:              defaultUnreachableTime,

		reachableTime: calcReachableTime(defaultBaseReachableTime, defaultMinRandomFactor, defaultMaxRandomFactor),
	}
}

// validate modifies an NDPConfigurations with valid values. If invalid values
// are present in c, the corresponding default values will be used instead.
//
// If RetransmitTimer is less than minimumRetransmitTimer, then a value of
// defaultRetransmitTimer will be used.
func (c *NUDConfigurations) validate() {
	recomputeReachableTime := false
	if c.BaseReachableTime < minimumBaseReachableTime {
		c.BaseReachableTime = defaultBaseReachableTime
		recomputeReachableTime = true
	}
	if c.MinRandomFactor <= 0 {
		c.MinRandomFactor = defaultMinRandomFactor
		recomputeReachableTime = true
	}
	if c.MaxRandomFactor < c.MinRandomFactor {
		c.MaxRandomFactor = defaultMaxRandomFactor
		recomputeReachableTime = true
	}
	if recomputeReachableTime {
		c.reachableTime = calcReachableTime(c.BaseReachableTime, c.MinRandomFactor, c.MaxRandomFactor)
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
	if c.UnreachableTime == 0 {
		c.UnreachableTime = defaultUnreachableTime
	}
}

// calcReachableTime calculates the duration to wait for a REACHABLE entry to
// transition into STALE after inactivity. This function follows the algorithm
// defined in RFC 4861 seciton 6.3.2.
func calcReachableTime(base time.Duration, minRandomFactor, maxRandomFactor float32) time.Duration {
	randomFactor := minRandomFactor + rand.Float32()*(maxRandomFactor-minRandomFactor)
	reachableTime := int64(float32(base) * randomFactor)

	// Check for overflow; it helps that minRandomFactor and maxRandomFactor are
	// guaranteed to be positive numbers.
	if reachableTime < 0 {
		return time.Duration(math.MaxInt64)
	}

	return time.Duration(reachableTime)
}
