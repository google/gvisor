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

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// immediateDuration is a duration of zero for scheduling work that needs to
	// be done immediately but asynchronously to avoid deadlock.
	immediateDuration time.Duration = 0
)

// NeighborEntry describes a neighboring device in the local network.
type NeighborEntry struct {
	Addr           tcpip.Address
	LinkAddr       tcpip.LinkAddress
	State          NeighborState
	UpdatedAtNanos int64
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
	// Failed means recent attempts of reachability have returned inconclusive.
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

	// done is closed when address resolution is complete. It is nil iff s is
	// incomplete and resolution is not yet in progress.
	done chan struct{}

	// onResolve is called with the result of address resolution.
	onResolve []func(tcpip.LinkAddress, bool)

	isRouter bool
	job      *tcpip.Job
}

// newNeighborEntry creates a neighbor cache entry starting at the default
// state, Unknown. Transition out of Unknown by calling either
// `handlePacketQueuedLocked` or `handleProbeLocked` on the newly created
// neighborEntry.
func newNeighborEntry(nic *NIC, remoteAddr tcpip.Address, nudState *NUDState, linkRes LinkAddressResolver) *neighborEntry {
	return &neighborEntry{
		nic:      nic,
		linkRes:  linkRes,
		nudState: nudState,
		neigh: NeighborEntry{
			Addr:  remoteAddr,
			State: Unknown,
		},
	}
}

// newStaticNeighborEntry creates a neighbor cache entry starting at the
// Static state. The entry can only transition out of Static by directly
// calling `setStateLocked`.
func newStaticNeighborEntry(nic *NIC, addr tcpip.Address, linkAddr tcpip.LinkAddress, state *NUDState) *neighborEntry {
	entry := NeighborEntry{
		Addr:           addr,
		LinkAddr:       linkAddr,
		State:          Static,
		UpdatedAtNanos: nic.stack.clock.NowNanoseconds(),
	}
	if nic.stack.nudDisp != nil {
		nic.stack.nudDisp.OnNeighborAdded(nic.id, entry)
	}
	return &neighborEntry{
		nic:      nic,
		nudState: state,
		neigh:    entry,
	}
}

// notifyCompletionLocked notifies those waiting for address resolution, with
// the link address if resolution completed successfully.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) notifyCompletionLocked(succeeded bool) {
	for _, callback := range e.onResolve {
		callback(e.neigh.LinkAddr, succeeded)
	}
	e.onResolve = nil
	if ch := e.done; ch != nil {
		close(ch)
		e.done = nil
	}
}

// dispatchAddEventLocked signals to stack's NUD Dispatcher that the entry has
// been added.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) dispatchAddEventLocked() {
	if nudDisp := e.nic.stack.nudDisp; nudDisp != nil {
		nudDisp.OnNeighborAdded(e.nic.id, e.neigh)
	}
}

// dispatchChangeEventLocked signals to stack's NUD Dispatcher that the entry
// has changed state or link-layer address.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) dispatchChangeEventLocked() {
	if nudDisp := e.nic.stack.nudDisp; nudDisp != nil {
		nudDisp.OnNeighborChanged(e.nic.id, e.neigh)
	}
}

// dispatchRemoveEventLocked signals to stack's NUD Dispatcher that the entry
// has been removed.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) dispatchRemoveEventLocked() {
	if nudDisp := e.nic.stack.nudDisp; nudDisp != nil {
		nudDisp.OnNeighborRemoved(e.nic.id, e.neigh)
	}
}

// cancelJobLocked cancels the currently scheduled action, if there is one.
// Entries in Unknown, Stale, or Static state do not have a scheduled action.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) cancelJobLocked() {
	if job := e.job; job != nil {
		job.Cancel()
	}
}

// removeLocked prepares the entry for removal.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) removeLocked() {
	e.neigh.UpdatedAtNanos = e.nic.stack.clock.NowNanoseconds()
	e.dispatchRemoveEventLocked()
	e.cancelJobLocked()
	e.notifyCompletionLocked(false /* succeeded */)
}

// setStateLocked transitions the entry to the specified state immediately.
//
// Follows the logic defined in RFC 4861 section 7.3.3.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) setStateLocked(next NeighborState) {
	e.cancelJobLocked()

	prev := e.neigh.State
	e.neigh.State = next
	e.neigh.UpdatedAtNanos = e.nic.stack.clock.NowNanoseconds()
	config := e.nudState.Config()

	switch next {
	case Incomplete:
		panic(fmt.Sprintf("should never transition to Incomplete with setStateLocked; neigh = %#v, prev state = %s", e.neigh, prev))

	case Reachable:
		e.job = e.nic.stack.newJob(&e.mu, func() {
			e.setStateLocked(Stale)
			e.dispatchChangeEventLocked()
		})
		e.job.Schedule(e.nudState.ReachableTime())

	case Delay:
		e.job = e.nic.stack.newJob(&e.mu, func() {
			e.setStateLocked(Probe)
			e.dispatchChangeEventLocked()
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

			if err := e.linkRes.LinkAddressRequest(e.neigh.Addr, "" /* localAddr */, e.neigh.LinkAddr, e.nic); err != nil {
				e.dispatchRemoveEventLocked()
				e.setStateLocked(Failed)
				return
			}

			retryCounter++
			e.job = e.nic.stack.newJob(&e.mu, sendUnicastProbe)
			e.job.Schedule(config.RetransmitTimer)
		}

		// Send a probe in another gorountine to free this thread of execution
		// for finishing the state transition. This is necessary to avoid
		// deadlock where sending and processing probes are done synchronously,
		// such as loopback and integration tests.
		e.job = e.nic.stack.newJob(&e.mu, sendUnicastProbe)
		e.job.Schedule(immediateDuration)

	case Failed:
		e.notifyCompletionLocked(false /* succeeded */)

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
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) handlePacketQueuedLocked(localAddr tcpip.Address) {
	switch e.neigh.State {
	case Failed:
		e.nic.stats.Neighbor.FailedEntryLookups.Increment()

		fallthrough
	case Unknown:
		e.neigh.State = Incomplete
		e.neigh.UpdatedAtNanos = e.nic.stack.clock.NowNanoseconds()

		e.dispatchAddEventLocked()

		config := e.nudState.Config()

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
				// error-handling routines." - RFC 4861 section 2.1
				e.dispatchRemoveEventLocked()
				e.setStateLocked(Failed)
				return
			}

			// As per RFC 4861 section 7.2.2:
			//
			//  If the source address of the packet prompting the solicitation is the
			//  same as one of the addresses assigned to the outgoing interface, that
			//  address SHOULD be placed in the IP Source Address of the outgoing
			//  solicitation.
			//
			if err := e.linkRes.LinkAddressRequest(e.neigh.Addr, localAddr, "", e.nic); err != nil {
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

		// Send a probe in another gorountine to free this thread of execution
		// for finishing the state transition. This is necessary to avoid
		// deadlock where sending and processing probes are done synchronously,
		// such as loopback and integration tests.
		e.job = e.nic.stack.newJob(&e.mu, sendMulticastProbe)
		e.job.Schedule(immediateDuration)

	case Stale:
		e.setStateLocked(Delay)
		e.dispatchChangeEventLocked()

	case Incomplete, Reachable, Delay, Probe, Static:
		// Do nothing
	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.neigh.State))
	}
}

// handleProbeLocked processes an incoming neighbor probe (e.g. ARP request or
// Neighbor Solicitation for ARP or NDP, respectively).
//
// Follows the logic defined in RFC 4861 section 7.2.3.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) handleProbeLocked(remoteLinkAddr tcpip.LinkAddress) {
	// Probes MUST be silently discarded if the target address is tentative, does
	// not exist, or not bound to the NIC as per RFC 4861 section 7.2.3. These
	// checks MUST be done by the NetworkEndpoint.

	switch e.neigh.State {
	case Unknown, Failed:
		e.neigh.LinkAddr = remoteLinkAddr
		e.setStateLocked(Stale)
		e.dispatchAddEventLocked()

	case Incomplete:
		// "If an entry already exists, and the cached link-layer address
		// differs from the one in the received Source Link-Layer option, the
		// cached address should be replaced by the received address, and the
		// entry's reachability state MUST be set to STALE."
		//  - RFC 4861 section 7.2.3
		e.neigh.LinkAddr = remoteLinkAddr
		e.setStateLocked(Stale)
		e.notifyCompletionLocked(true /* succeeded */)
		e.dispatchChangeEventLocked()

	case Reachable, Delay, Probe:
		if e.neigh.LinkAddr != remoteLinkAddr {
			e.neigh.LinkAddr = remoteLinkAddr
			e.setStateLocked(Stale)
			e.dispatchChangeEventLocked()
		}

	case Stale:
		if e.neigh.LinkAddr != remoteLinkAddr {
			e.neigh.LinkAddr = remoteLinkAddr
			e.dispatchChangeEventLocked()
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
//
// Precondition: e.mu MUST be locked.
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
			e.setStateLocked(Reachable)
		} else {
			e.setStateLocked(Stale)
		}
		e.dispatchChangeEventLocked()
		e.isRouter = flags.IsRouter
		e.notifyCompletionLocked(true /* succeeded */)

		// "Note that the Override flag is ignored if the entry is in the
		// INCOMPLETE state." - RFC 4861 section 7.2.5

	case Reachable, Stale, Delay, Probe:
		isLinkAddrDifferent := len(linkAddr) != 0 && e.neigh.LinkAddr != linkAddr

		if isLinkAddrDifferent {
			if !flags.Override {
				if e.neigh.State == Reachable {
					e.setStateLocked(Stale)
					e.dispatchChangeEventLocked()
				}
				break
			}

			e.neigh.LinkAddr = linkAddr

			if !flags.Solicited {
				if e.neigh.State != Stale {
					e.setStateLocked(Stale)
					e.dispatchChangeEventLocked()
				} else {
					// Notify the LinkAddr change, even though NUD state hasn't changed.
					e.dispatchChangeEventLocked()
				}
				break
			}
		}

		if flags.Solicited && (flags.Override || !isLinkAddrDifferent) {
			wasReachable := e.neigh.State == Reachable
			// Set state to Reachable again to refresh timers.
			e.setStateLocked(Reachable)
			e.notifyCompletionLocked(true /* succeeded */)
			if !wasReachable {
				e.dispatchChangeEventLocked()
			}
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
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) handleUpperLevelConfirmationLocked() {
	switch e.neigh.State {
	case Reachable, Stale, Delay, Probe:
		wasReachable := e.neigh.State == Reachable
		// Set state to Reachable again to refresh timers.
		e.setStateLocked(Reachable)
		if !wasReachable {
			e.dispatchChangeEventLocked()
		}

	case Unknown, Incomplete, Failed, Static:
		// Do nothing

	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.neigh.State))
	}
}
