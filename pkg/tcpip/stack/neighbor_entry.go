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
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// NeighborEntry describes a neighboring device in the local network.
type NeighborEntry struct {
	Addr      tcpip.Address
	LocalAddr tcpip.Address
	LinkAddr  tcpip.LinkAddress
	State     NeighborState
	UpdatedAt time.Time
}

// NeighborState defines the state of a NeighborEntry within the Neighbor
// Unreachability Detection state machine, as per RFC 4861 section 7.3.2.
type NeighborState uint8

const (
	// Unknown means reachability has not been verified yet. This is the initial
	// state of entries that have been created automatically by the Neighbor
	// Unreachability Detection state machine.
	Unknown NeighborState = iota
	// Incomplete means that there is an outstanding request to resolve the
	// address.
	Incomplete
	// Reachable means the path to the neighbor is functioning properly for both
	// receive and transmit paths.
	Reachable
	// Stale means reachability to the neighbor is unknown, but packets are still
	// able to be transmitted to the possibly stale link address.
	Stale
	// Delay means reachability to the neighbor is unknown and pending
	// confirmation from an upper-level protocol like TCP, but packets are still
	// able to be transmitted to the possibly stale link address.
	Delay
	// Probe means a reachability confirmation is actively being sought by
	// periodically retransmitting reachability probes until a reachability
	// confirmation is received, or until the max amount of probes has been sent.
	Probe
	// Static describes entries that have been explicitly added by the user. They
	// do not expire and are not deleted until explicitly removed.
	Static
	// Failed means traffic should not be sent to this neighbor since attempts of
	// reachability have returned inconclusive.
	Failed
)

// neighborEntry implements a neighbor entry's individual node behavior, as per
// RFC 4861 section 7.3.3. Neighbor Unreachability Detection operates in
// parallel with the sending of packets to a neighbor, necessitating the
// entry's lock to be acquired for all operations.
type neighborEntry struct {
	neighborEntryEntry

	nic *NIC

	// linkRes provides the functionality to send reachability probes, used in
	// Neighbor Unreachability Detection.
	linkRes LinkAddressResolver

	// nudState points to the Neighbor Unreachability Detection configuration.
	nudState *NUDState

	// mu protects the fields below.
	mu sync.RWMutex

	neigh NeighborEntry

	// wakers is a set of waiters for address resolution result. Anytime state
	// transitions out of incomplete these waiters are notified. It is nil iff
	// address resolution is ongoing and no clients are waiting for the result.
	wakers map[*sleep.Waker]struct{}

	// done is used to allow callers to wait on address resolution. It is nil
	// iff nudState is not Reachable and address resolution is not yet in
	// progress.
	done chan struct{}

	isRouter bool
	job      *tcpip.Job
}

// newNeighborEntry creates a neighbor cache entry starting at the default
// state, Unknown. Transition out of Unknown by calling either
// `handlePacketQueuedLocked` or `handleProbeLocked` on the newly created
// neighborEntry.
func newNeighborEntry(nic *NIC, remoteAddr tcpip.Address, localAddr tcpip.Address, nudState *NUDState, linkRes LinkAddressResolver) *neighborEntry {
	return &neighborEntry{
		nic:      nic,
		linkRes:  linkRes,
		nudState: nudState,
		neigh: NeighborEntry{
			Addr:      remoteAddr,
			LocalAddr: localAddr,
			State:     Unknown,
		},
	}
}

// newStaticNeighborEntry creates a neighbor cache entry starting at the Static
// state. The entry can only transition out of Static by directly calling
// `setStateLocked`.
func newStaticNeighborEntry(nic *NIC, addr tcpip.Address, linkAddr tcpip.LinkAddress, state *NUDState) *neighborEntry {
	if nic.stack.nudDisp != nil {
		nic.stack.nudDisp.OnNeighborAdded(nic.id, addr, linkAddr, Static, time.Now())
	}
	return &neighborEntry{
		nic:      nic,
		nudState: state,
		neigh: NeighborEntry{
			Addr:      addr,
			LinkAddr:  linkAddr,
			State:     Static,
			UpdatedAt: time.Now(),
		},
	}
}

// addWaker adds w to the list of wakers waiting for address resolution.
// Assumes the entry has already been appropriately locked.
func (e *neighborEntry) addWakerLocked(w *sleep.Waker) {
	if w == nil {
		return
	}
	if e.wakers == nil {
		e.wakers = make(map[*sleep.Waker]struct{})
	}
	e.wakers[w] = struct{}{}
}

// notifyWakersLocked notifies those waiting for address resolution, whether it
// succeeded or failed. Assumes the entry has already been appropriately locked.
func (e *neighborEntry) notifyWakersLocked() {
	for w := range e.wakers {
		w.Assert()
	}
	e.wakers = nil
	if ch := e.done; ch != nil {
		close(ch)
		e.done = nil
	}
}

// dispatchAddEventLocked signals to stack's NUD Dispatcher that the entry has
// been added.
func (e *neighborEntry) dispatchAddEventLocked(nextState NeighborState) {
	if nudDisp := e.nic.stack.nudDisp; nudDisp != nil {
		nudDisp.OnNeighborAdded(e.nic.id, e.neigh.Addr, e.neigh.LinkAddr, nextState, time.Now())
	}
}

// dispatchChangeEventLocked signals to stack's NUD Dispatcher that the entry
// has changed state or link-layer address.
func (e *neighborEntry) dispatchChangeEventLocked(nextState NeighborState) {
	if nudDisp := e.nic.stack.nudDisp; nudDisp != nil {
		nudDisp.OnNeighborChanged(e.nic.id, e.neigh.Addr, e.neigh.LinkAddr, nextState, time.Now())
	}
}

// dispatchRemoveEventLocked signals to stack's NUD Dispatcher that the entry
// has been removed.
func (e *neighborEntry) dispatchRemoveEventLocked() {
	if nudDisp := e.nic.stack.nudDisp; nudDisp != nil {
		nudDisp.OnNeighborRemoved(e.nic.id, e.neigh.Addr, e.neigh.LinkAddr, e.neigh.State, time.Now())
	}
}

// setStateLocked transitions the entry to the specified state immediately.
//
// Follows the logic defined in RFC 4861 section 7.3.3.
//
// e.mu MUST be locked.
func (e *neighborEntry) setStateLocked(next NeighborState) {
	// Cancel the previously scheduled action, if there is one. Entries in
	// Unknown, Stale, or Static state do not have scheduled actions.
	if timer := e.job; timer != nil {
		timer.Cancel()
	}

	prev := e.neigh.State
	e.neigh.State = next
	e.neigh.UpdatedAt = time.Now()
	config := e.nudState.Config()

	switch next {
	case Incomplete:
		var retryCounter uint32
		var sendMulticastProbe func()

		sendMulticastProbe = func() {
			if retryCounter == config.MaxMulticastProbes {
				// "If no Neighbor Advertisement is received after
				// MAX_MULTICAST_SOLICIT solicitations, address resolution has failed.
				// The sender MUST return ICMP destination unreachable indications with
				// code 3 (Address Unreachable) for each packet queued awaiting address
				// resolution." - RFC 4861 section 7.2.2
				//
				// There is no need to send an ICMP destination unreachable indication
				// since the failure to resolve the address is expected to only occur
				// on this node. Thus, redirecting traffic is currently not supported.
				//
				// "If the error occurs on a node other than the node originating the
				// packet, an ICMP error message is generated. If the error occurs on
				// the originating node, an implementation is not required to actually
				// create and send an ICMP error packet to the source, as long as the
				// upper-layer sender is notified through an appropriate mechanism
				// (e.g. return value from a procedure call). Note, however, that an
				// implementation may find it convenient in some cases to return errors
				// to the sender by taking the offending packet, generating an ICMP
				// error message, and then delivering it (locally) through the generic
				// error-handling routines.' - RFC 4861 section 2.1
				e.dispatchRemoveEventLocked()
				e.setStateLocked(Failed)
				return
			}

			if err := e.linkRes.LinkAddressRequest(e.neigh.Addr, e.neigh.LocalAddr, "", e.nic); err != nil {
				// There is no need to log the error here; the NUD implementation may
				// assume a working link. A valid link should be the responsibility of
				// the NIC/stack.LinkEndpoint.
				e.dispatchRemoveEventLocked()
				e.setStateLocked(Failed)
				return
			}

			retryCounter++
			e.job = e.nic.stack.newJob(&e.mu, sendMulticastProbe)
			e.job.Schedule(config.RetransmitTimer)
		}

		sendMulticastProbe()

	case Reachable:
		e.job = e.nic.stack.newJob(&e.mu, func() {
			e.dispatchChangeEventLocked(Stale)
			e.setStateLocked(Stale)
		})
		e.job.Schedule(e.nudState.ReachableTime())

	case Delay:
		e.job = e.nic.stack.newJob(&e.mu, func() {
			e.dispatchChangeEventLocked(Probe)
			e.setStateLocked(Probe)
		})
		e.job.Schedule(config.DelayFirstProbeTime)

	case Probe:
		var retryCounter uint32
		var sendUnicastProbe func()

		sendUnicastProbe = func() {
			if retryCounter == config.MaxUnicastProbes {
				e.dispatchRemoveEventLocked()
				e.setStateLocked(Failed)
				return
			}

			if err := e.linkRes.LinkAddressRequest(e.neigh.Addr, e.neigh.LocalAddr, e.neigh.LinkAddr, e.nic); err != nil {
				e.dispatchRemoveEventLocked()
				e.setStateLocked(Failed)
				return
			}

			retryCounter++
			if retryCounter == config.MaxUnicastProbes {
				e.dispatchRemoveEventLocked()
				e.setStateLocked(Failed)
				return
			}

			e.job = e.nic.stack.newJob(&e.mu, sendUnicastProbe)
			e.job.Schedule(config.RetransmitTimer)
		}

		sendUnicastProbe()

	case Failed:
		e.notifyWakersLocked()
		e.job = e.nic.stack.newJob(&e.mu, func() {
			e.nic.neigh.removeEntryLocked(e)
		})
		e.job.Schedule(config.UnreachableTime)

	case Unknown, Stale, Static:
		// Do nothing

	default:
		panic(fmt.Sprintf("Invalid state transition from %q to %q", prev, next))
	}
}

// handlePacketQueuedLocked advances the state machine according to a packet
// being queued for outgoing transmission.
//
// Follows the logic defined in RFC 4861 section 7.3.3.
func (e *neighborEntry) handlePacketQueuedLocked() {
	switch e.neigh.State {
	case Unknown:
		e.dispatchAddEventLocked(Incomplete)
		e.setStateLocked(Incomplete)

	case Stale:
		e.dispatchChangeEventLocked(Delay)
		e.setStateLocked(Delay)

	case Incomplete, Reachable, Delay, Probe, Static, Failed:
		// Do nothing

	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.neigh.State))
	}
}

// handleProbeLocked processes an incoming neighbor probe (e.g. ARP request or
// Neighbor Solicitation for ARP or NDP, respectively).
//
// Follows the logic defined in RFC 4861 section 7.2.3.
func (e *neighborEntry) handleProbeLocked(remoteLinkAddr tcpip.LinkAddress) {
	// Probes MUST be silently discarded if the target address is tentative, does
	// not exist, or not bound to the NIC as per RFC 4861 section 7.2.3. These
	// checks MUST be done by the NetworkEndpoint.

	switch e.neigh.State {
	case Unknown, Incomplete, Failed:
		e.neigh.LinkAddr = remoteLinkAddr
		e.dispatchAddEventLocked(Stale)
		e.setStateLocked(Stale)
		e.notifyWakersLocked()

	case Reachable, Delay, Probe:
		if e.neigh.LinkAddr != remoteLinkAddr {
			e.neigh.LinkAddr = remoteLinkAddr
			e.dispatchChangeEventLocked(Stale)
			e.setStateLocked(Stale)
		}

	case Stale:
		if e.neigh.LinkAddr != remoteLinkAddr {
			e.neigh.LinkAddr = remoteLinkAddr
			e.dispatchChangeEventLocked(Stale)
		}

	case Static:
		// Do nothing

	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.neigh.State))
	}
}

// handleConfirmationLocked processes an incoming neighbor confirmation
// (e.g. ARP reply or Neighbor Advertisement for ARP or NDP, respectively).
//
// Follows the state machine defined by RFC 4861 section 7.2.5.
//
// TODO(gvisor.dev/issue/2277): To protect against ARP poisoning and other
// attacks against NDP functions, Secure Neighbor Discovery (SEND) Protocol
// should be deployed where preventing access to the broadcast segment might
// not be possible. SEND uses RSA key pairs to produce Cryptographically
// Generated Addresses (CGA), as defined in RFC 3972. This ensures that the
// claimed source of an NDP message is the owner of the claimed address.
func (e *neighborEntry) handleConfirmationLocked(linkAddr tcpip.LinkAddress, flags ReachabilityConfirmationFlags) {
	switch e.neigh.State {
	case Incomplete:
		if len(linkAddr) == 0 {
			// "If the link layer has addresses and no Target Link-Layer Address
			// option is included, the receiving node SHOULD silently discard the
			// received advertisement." - RFC 4861 section 7.2.5
			break
		}

		e.neigh.LinkAddr = linkAddr
		if flags.Solicited {
			e.dispatchChangeEventLocked(Reachable)
			e.setStateLocked(Reachable)
		} else {
			e.dispatchChangeEventLocked(Stale)
			e.setStateLocked(Stale)
		}
		e.isRouter = flags.IsRouter
		e.notifyWakersLocked()

		// "Note that the Override flag is ignored if the entry is in the
		// INCOMPLETE state." - RFC 4861 section 7.2.5

	case Reachable, Stale, Delay, Probe:
		isLinkAddrDifferent := len(linkAddr) != 0 && e.neigh.LinkAddr != linkAddr

		if isLinkAddrDifferent {
			if !flags.Override {
				if e.neigh.State == Reachable {
					e.dispatchChangeEventLocked(Stale)
					e.setStateLocked(Stale)
				}
				break
			}

			e.neigh.LinkAddr = linkAddr

			if !flags.Solicited {
				if e.neigh.State != Stale {
					e.dispatchChangeEventLocked(Stale)
					e.setStateLocked(Stale)
				} else {
					// Notify the LinkAddr change, even though NUD state hasn't changed.
					e.dispatchChangeEventLocked(e.neigh.State)
				}
				break
			}
		}

		if flags.Solicited && (flags.Override || !isLinkAddrDifferent) {
			if e.neigh.State != Reachable {
				e.dispatchChangeEventLocked(Reachable)
			}
			// Set state to Reachable again to refresh timers.
			e.setStateLocked(Reachable)
			e.notifyWakersLocked()
		}

		if e.isRouter && !flags.IsRouter && header.IsV6UnicastAddress(e.neigh.Addr) {
			// "In those cases where the IsRouter flag changes from TRUE to FALSE as
			// a result of this update, the node MUST remove that router from the
			// Default Router List and update the Destination Cache entries for all
			// destinations using that neighbor as a router as specified in Section
			// 7.3.3.  This is needed to detect when a node that is used as a router
			// stops forwarding packets due to being configured as a host."
			//  - RFC 4861 section 7.2.5
			//
			// TODO(gvisor.dev/issue/4085): Remove the special casing we do for IPv6
			// here.
			ep, ok := e.nic.networkEndpoints[header.IPv6ProtocolNumber]
			if !ok {
				panic(fmt.Sprintf("have a neighbor entry for an IPv6 router but no IPv6 network endpoint"))
			}

			if ndpEP, ok := ep.(NDPEndpoint); ok {
				ndpEP.InvalidateDefaultRouter(e.neigh.Addr)
			}
		}
		e.isRouter = flags.IsRouter

	case Unknown, Failed, Static:
		// Do nothing

	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.neigh.State))
	}
}

// handleUpperLevelConfirmationLocked processes an incoming upper-level protocol
// (e.g. TCP acknowledgements) reachability confirmation.
func (e *neighborEntry) handleUpperLevelConfirmationLocked() {
	switch e.neigh.State {
	case Reachable, Stale, Delay, Probe:
		if e.neigh.State != Reachable {
			e.dispatchChangeEventLocked(Reachable)
			// Set state to Reachable again to refresh timers.
		}
		e.setStateLocked(Reachable)

	case Unknown, Incomplete, Failed, Static:
		// Do nothing

	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.neigh.State))
	}
}
