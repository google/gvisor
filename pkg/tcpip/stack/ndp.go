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
	"fmt"
	"log"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// defaultDupAddrDetectTransmits is the default number of NDP Neighbor
	// Solicitation messages to send when doing Duplicate Address Detection
	// for a tentative address.
	//
	// Default = 1 (from RFC 4862 section 5.1)
	defaultDupAddrDetectTransmits = 1

	// defaultRetransmitTimer is the default amount of time to wait between
	// sending NDP Neighbor solicitation messages.
	//
	// Default = 1s (from RFC 4861 section 10).
	defaultRetransmitTimer = time.Second

	// minimumRetransmitTimer is the minimum amount of time to wait between
	// sending NDP Neighbor solicitation messages. Note, RFC 4861 does
	// not impose a minimum Retransmit Timer, but we do here to make sure
	// the messages are not sent all at once. We also come to this value
	// because in the RetransmitTimer field of a Router Advertisement, a
	// value of 0 means unspecified, so the smallest valid value is 1.
	// Note, the unit of the RetransmitTimer field in the Router
	// Advertisement is milliseconds.
	//
	// Min = 1ms.
	minimumRetransmitTimer = time.Millisecond
)

// NDPDispatcher is the interface integrators of netstack must implement to
// receive and handle NDP related events.
type NDPDispatcher interface {
	// OnDuplicateAddressDetectionStatus will be called when the DAD process
	// for an address (addr) on a NIC (with ID nicid) completes. resolved
	// will be set to true if DAD completed successfully (no duplicate addr
	// detected); false otherwise (addr was detected to be a duplicate on
	// the link the NIC is a part of, or it was stopped for some other
	// reason, such as the address being removed). If an error occured
	// during DAD, err will be set and resolved must be ignored.
	//
	// This function is permitted to block indefinitely without interfering
	// with the stack's operation.
	OnDuplicateAddressDetectionStatus(nicid tcpip.NICID, addr tcpip.Address, resolved bool, err *tcpip.Error)
}

// NDPConfigurations is the NDP configurations for the netstack.
type NDPConfigurations struct {
	// The number of Neighbor Solicitation messages to send when doing
	// Duplicate Address Detection for a tentative address.
	//
	// Note, a value of zero effectively disables DAD.
	DupAddrDetectTransmits uint8

	// The amount of time to wait between sending Neighbor solicitation
	// messages.
	//
	// Must be greater than 0.5s.
	RetransmitTimer time.Duration
}

// DefaultNDPConfigurations returns an NDPConfigurations populated with
// default values.
func DefaultNDPConfigurations() NDPConfigurations {
	return NDPConfigurations{
		DupAddrDetectTransmits: defaultDupAddrDetectTransmits,
		RetransmitTimer:        defaultRetransmitTimer,
	}
}

// validate modifies an NDPConfigurations with valid values. If invalid values
// are present in c, the corresponding default values will be used instead.
//
// If RetransmitTimer is less than minimumRetransmitTimer, then a value of
// defaultRetransmitTimer will be used.
func (c *NDPConfigurations) validate() {
	if c.RetransmitTimer < minimumRetransmitTimer {
		c.RetransmitTimer = defaultRetransmitTimer
	}
}

// ndpState is the per-interface NDP state.
type ndpState struct {
	// The NIC this ndpState is for.
	nic *NIC

	// configs is the per-interface NDP configurations.
	configs NDPConfigurations

	// The DAD state to send the next NS message, or resolve the address.
	dad map[tcpip.Address]dadState
}

// dadState holds the Duplicate Address Detection timer and channel to signal
// to the DAD goroutine that DAD should stop.
type dadState struct {
	// The DAD timer to send the next NS message, or resolve the address.
	timer *time.Timer

	// Used to let the DAD timer know that it has been stopped.
	//
	// Must only be read from or written to while protected by the lock of
	// the NIC this dadState is associated with.
	done *bool
}

// startDuplicateAddressDetection performs Duplicate Address Detection.
//
// This function must only be called by IPv6 addresses that are currently
// tentative.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) startDuplicateAddressDetection(addr tcpip.Address, ref *referencedNetworkEndpoint) *tcpip.Error {
	// addr must be a valid unicast IPv6 address.
	if !header.IsV6UnicastAddress(addr) {
		return tcpip.ErrAddressFamilyNotSupported
	}

	// Should not attempt to perform DAD on an address that is currently in
	// the DAD process.
	if _, ok := ndp.dad[addr]; ok {
		// Should never happen because we should only ever call this
		// function for newly created addresses. If we attemped to
		// "add" an address that already existed, we would returned an
		// error since we attempted to add a duplicate address, or its
		// reference count would have been increased without doing the
		// work that would have been done for an address that was brand
		// new. See NIC.addPermanentAddressLocked.
		panic(fmt.Sprintf("ndpdad: already performing DAD for addr %s on NIC(%d)", addr, ndp.nic.ID()))
	}

	remaining := ndp.configs.DupAddrDetectTransmits

	{
		done, err := ndp.doDuplicateAddressDetection(addr, remaining, ref)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}

	remaining--

	var done bool
	var timer *time.Timer
	timer = time.AfterFunc(ndp.configs.RetransmitTimer, func() {
		var d bool
		var err *tcpip.Error

		// doDadIteration does a single iteration of the DAD loop.
		//
		// Returns true if the integrator needs to be informed of DAD
		// completing.
		doDadIteration := func() bool {
			ndp.nic.mu.Lock()
			defer ndp.nic.mu.Unlock()

			if done {
				// If we reach this point, it means that the DAD
				// timer fired after another goroutine already
				// obtained the NIC lock and stopped DAD before
				// this function obtained the NIC lock. Simply
				// return here and do nothing further.
				return false
			}

			ref, ok := ndp.nic.endpoints[NetworkEndpointID{addr}]
			if !ok {
				// This should never happen.
				// We should have an endpoint for addr since we
				// are still performing DAD on it. If the
				// endpoint does not exist, but we are doing DAD
				// on it, then we started DAD at some point, but
				// forgot to stop it when the endpoint was
				// deleted.
				panic(fmt.Sprintf("ndpdad: unrecognized addr %s for NIC(%d)", addr, ndp.nic.ID()))
			}

			d, err = ndp.doDuplicateAddressDetection(addr, remaining, ref)
			if err != nil || d {
				delete(ndp.dad, addr)

				if err != nil {
					log.Printf("ndpdad: Error occured during DAD iteration for addr (%s) on NIC(%d); err = %s", addr, ndp.nic.ID(), err)
				}

				// Let the integrator know DAD has completed.
				return true
			}

			remaining--
			timer.Reset(ndp.nic.stack.ndpConfigs.RetransmitTimer)
			return false
		}

		if doDadIteration() && ndp.nic.stack.ndpDisp != nil {
			ndp.nic.stack.ndpDisp.OnDuplicateAddressDetectionStatus(ndp.nic.ID(), addr, d, err)
		}
	})

	ndp.dad[addr] = dadState{
		timer: timer,
		done:  &done,
	}

	return nil
}

// doDuplicateAddressDetection is called on every iteration of the timer, and
// when DAD starts.
//
// It handles resolving the address (if there are no more NS to send), or
// sending the next NS if there are more NS to send.
//
// This function must only be called by IPv6 addresses that are currently
// tentative.
//
// The NIC that ndp belongs to (n) MUST be locked.
//
// Returns true if DAD has resolved; false if DAD is still ongoing.
func (ndp *ndpState) doDuplicateAddressDetection(addr tcpip.Address, remaining uint8, ref *referencedNetworkEndpoint) (bool, *tcpip.Error) {
	if ref.getKind() != permanentTentative {
		// The endpoint should still be marked as tentative
		// since we are still performing DAD on it.
		panic(fmt.Sprintf("ndpdad: addr %s is not tentative on NIC(%d)", addr, ndp.nic.ID()))
	}

	if remaining == 0 {
		// DAD has resolved.
		ref.setKind(permanent)
		return true, nil
	}

	// Send a new NS.
	snmc := header.SolicitedNodeAddr(addr)
	snmcRef, ok := ndp.nic.endpoints[NetworkEndpointID{snmc}]
	if !ok {
		// This should never happen as if we have the
		// address, we should have the solicited-node
		// address.
		panic(fmt.Sprintf("ndpdad: NIC(%d) is not in the solicited-node multicast group (%s) but it has addr %s", ndp.nic.ID(), snmc, addr))
	}

	// Use the unspecified address as the source address when performing
	// DAD.
	r := makeRoute(header.IPv6ProtocolNumber, header.IPv6Any, snmc, ndp.nic.linkEP.LinkAddress(), snmcRef, false, false)

	hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.ICMPv6NeighborSolicitMinimumSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborSolicitMinimumSize))
	pkt.SetType(header.ICMPv6NeighborSolicit)
	ns := header.NDPNeighborSolicit(pkt.NDPPayload())
	ns.SetTargetAddress(addr)
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

	sent := r.Stats().ICMP.V6PacketsSent
	if err := r.WritePacket(nil, hdr, buffer.VectorisedView{}, NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: header.NDPHopLimit, TOS: DefaultTOS}); err != nil {
		sent.Dropped.Increment()
		return false, err
	}
	sent.NeighborSolicit.Increment()

	return false, nil
}

// stopDuplicateAddressDetection ends a running Duplicate Address Detection
// process. Note, this may leave the DAD process for a tentative address in
// such a state forever, unless some other external event resolves the DAD
// process (receiving an NA from the true owner of addr, or an NS for addr
// (implying another node is attempting to use addr)). It is up to the caller
// of this function to handle such a scenario. Normally, addr will be removed
// from n right after this function returns or the address successfully
// resolved.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) stopDuplicateAddressDetection(addr tcpip.Address) {
	dad, ok := ndp.dad[addr]
	if !ok {
		// Not currently performing DAD on addr, just return.
		return
	}

	if dad.timer != nil {
		dad.timer.Stop()
		dad.timer = nil

		*dad.done = true
		dad.done = nil
	}

	delete(ndp.dad, addr)

	// Let the integrator know DAD did not resolve.
	if ndp.nic.stack.ndpDisp != nil {
		go ndp.nic.stack.ndpDisp.OnDuplicateAddressDetectionStatus(ndp.nic.ID(), addr, false, nil)
	}
}
