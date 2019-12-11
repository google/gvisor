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

	// defaultHandleRAs is the default configuration for whether or not to
	// handle incoming Router Advertisements as a host.
	//
	// Default = true.
	defaultHandleRAs = true

	// defaultDiscoverDefaultRouters is the default configuration for
	// whether or not to discover default routers from incoming Router
	// Advertisements, as a host.
	//
	// Default = true.
	defaultDiscoverDefaultRouters = true

	// defaultDiscoverOnLinkPrefixes is the default configuration for
	// whether or not to discover on-link prefixes from incoming Router
	// Advertisements' Prefix Information option, as a host.
	//
	// Default = true.
	defaultDiscoverOnLinkPrefixes = true

	// defaultAutoGenGlobalAddresses is the default configuration for
	// whether or not to generate global IPv6 addresses in response to
	// receiving a new Prefix Information option with its Autonomous
	// Address AutoConfiguration flag set, as a host.
	//
	// Default = true.
	defaultAutoGenGlobalAddresses = true

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

	// MaxDiscoveredDefaultRouters is the maximum number of discovered
	// default routers. The stack should stop discovering new routers after
	// discovering MaxDiscoveredDefaultRouters routers.
	//
	// This value MUST be at minimum 2 as per RFC 4861 section 6.3.4, and
	// SHOULD be more.
	//
	// Max = 10.
	MaxDiscoveredDefaultRouters = 10

	// MaxDiscoveredOnLinkPrefixes is the maximum number of discovered
	// on-link prefixes. The stack should stop discovering new on-link
	// prefixes after discovering MaxDiscoveredOnLinkPrefixes on-link
	// prefixes.
	//
	// Max = 10.
	MaxDiscoveredOnLinkPrefixes = 10

	// validPrefixLenForAutoGen is the expected prefix length that an
	// address can be generated for. Must be 64 bits as the interface
	// identifier (IID) is 64 bits and an IPv6 address is 128 bits, so
	// 128 - 64 = 64.
	validPrefixLenForAutoGen = 64
)

var (
	// MinPrefixInformationValidLifetimeForUpdate is the minimum Valid
	// Lifetime to update the valid lifetime of a generated address by
	// SLAAC.
	//
	// This is exported as a variable (instead of a constant) so tests
	// can update it to a smaller value.
	//
	// Min = 2hrs.
	MinPrefixInformationValidLifetimeForUpdate = 2 * time.Hour
)

// NDPDispatcher is the interface integrators of netstack must implement to
// receive and handle NDP related events.
type NDPDispatcher interface {
	// OnDuplicateAddressDetectionStatus will be called when the DAD process
	// for an address (addr) on a NIC (with ID nicID) completes. resolved
	// will be set to true if DAD completed successfully (no duplicate addr
	// detected); false otherwise (addr was detected to be a duplicate on
	// the link the NIC is a part of, or it was stopped for some other
	// reason, such as the address being removed). If an error occured
	// during DAD, err will be set and resolved must be ignored.
	//
	// This function is permitted to block indefinitely without interfering
	// with the stack's operation.
	OnDuplicateAddressDetectionStatus(nicID tcpip.NICID, addr tcpip.Address, resolved bool, err *tcpip.Error)

	// OnDefaultRouterDiscovered will be called when a new default router is
	// discovered. Implementations must return true along with a new valid
	// route table if the newly discovered router should be remembered. If
	// an implementation returns false, the second return value will be
	// ignored.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnDefaultRouterDiscovered(nicID tcpip.NICID, addr tcpip.Address) (bool, []tcpip.Route)

	// OnDefaultRouterInvalidated will be called when a discovered default
	// router is invalidated. Implementers must return a new valid route
	// table.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnDefaultRouterInvalidated(nicID tcpip.NICID, addr tcpip.Address) []tcpip.Route

	// OnOnLinkPrefixDiscovered will be called when a new on-link prefix is
	// discovered. Implementations must return true along with a new valid
	// route table if the newly discovered on-link prefix should be
	// remembered. If an implementation returns false, the second return
	// value will be ignored.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnOnLinkPrefixDiscovered(nicID tcpip.NICID, prefix tcpip.Subnet) (bool, []tcpip.Route)

	// OnOnLinkPrefixInvalidated will be called when a discovered on-link
	// prefix is invalidated. Implementers must return a new valid route
	// table.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnOnLinkPrefixInvalidated(nicID tcpip.NICID, prefix tcpip.Subnet) []tcpip.Route

	// OnAutoGenAddress will be called when a new prefix with its
	// autonomous address-configuration flag set has been received and SLAAC
	// has been performed. Implementations may prevent the stack from
	// assigning the address to the NIC by returning false.
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnAutoGenAddress(tcpip.NICID, tcpip.AddressWithPrefix) bool

	// OnAutoGenAddressInvalidated will be called when an auto-generated
	// address (as part of SLAAC) has been invalidated.
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnAutoGenAddressInvalidated(tcpip.NICID, tcpip.AddressWithPrefix)

	// OnRecursiveDNSServerOption will be called when an NDP option with
	// recursive DNS servers has been received. Note, addrs may contain
	// link-local addresses.
	//
	// It is up to the caller to use the DNS Servers only for their valid
	// lifetime. OnRecursiveDNSServerOption may be called for new or
	// already known DNS servers. If called with known DNS servers, their
	// valid lifetimes must be refreshed to lifetime (it may be increased,
	// decreased, or completely invalidated when lifetime = 0).
	OnRecursiveDNSServerOption(nicID tcpip.NICID, addrs []tcpip.Address, lifetime time.Duration)
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

	// HandleRAs determines whether or not Router Advertisements will be
	// processed.
	HandleRAs bool

	// DiscoverDefaultRouters determines whether or not default routers will
	// be discovered from Router Advertisements. This configuration is
	// ignored if HandleRAs is false.
	DiscoverDefaultRouters bool

	// DiscoverOnLinkPrefixes determines whether or not on-link prefixes
	// will be discovered from Router Advertisements' Prefix Information
	// option. This configuration is ignored if HandleRAs is false.
	DiscoverOnLinkPrefixes bool

	// AutoGenGlobalAddresses determines whether or not global IPv6
	// addresses will be generated for a NIC in response to receiving a new
	// Prefix Information option with its Autonomous Address
	// AutoConfiguration flag set, as a host, as per RFC 4862 (SLAAC).
	//
	// Note, if an address was already generated for some unique prefix, as
	// part of SLAAC, this option does not affect whether or not the
	// lifetime(s) of the generated address changes; this option only
	// affects the generation of new addresses as part of SLAAC.
	AutoGenGlobalAddresses bool
}

// DefaultNDPConfigurations returns an NDPConfigurations populated with
// default values.
func DefaultNDPConfigurations() NDPConfigurations {
	return NDPConfigurations{
		DupAddrDetectTransmits: defaultDupAddrDetectTransmits,
		RetransmitTimer:        defaultRetransmitTimer,
		HandleRAs:              defaultHandleRAs,
		DiscoverDefaultRouters: defaultDiscoverDefaultRouters,
		DiscoverOnLinkPrefixes: defaultDiscoverOnLinkPrefixes,
		AutoGenGlobalAddresses: defaultAutoGenGlobalAddresses,
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

	// The default routers discovered through Router Advertisements.
	defaultRouters map[tcpip.Address]defaultRouterState

	// The on-link prefixes discovered through Router Advertisements' Prefix
	// Information option.
	onLinkPrefixes map[tcpip.Subnet]onLinkPrefixState

	// The addresses generated by SLAAC.
	autoGenAddresses map[tcpip.Address]autoGenAddressState
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

// defaultRouterState holds data associated with a default router discovered by
// a Router Advertisement (RA).
type defaultRouterState struct {
	invalidationTimer *time.Timer

	// Used to inform the timer not to invalidate the default router (R) in
	// a race condition (T1 is a goroutine that handles an RA from R and T2
	// is the goroutine that handles R's invalidation timer firing):
	//   T1: Receive a new RA from R
	//   T1: Obtain the NIC's lock before processing the RA
	//   T2: R's invalidation timer fires, and gets blocked on obtaining the
	//       NIC's lock
	//   T1: Refreshes/extends R's lifetime & releases NIC's lock
	//   T2: Obtains NIC's lock & invalidates R immediately
	//
	// To resolve this, T1 will check to see if the timer already fired, and
	// inform the timer using doNotInvalidate to not invalidate R, so that
	// once T2 obtains the lock, it will see that it is set to true and do
	// nothing further.
	doNotInvalidate *bool
}

// onLinkPrefixState holds data associated with an on-link prefix discovered by
// a Router Advertisement's Prefix Information option (PI) when the NDP
// configurations was configured to do so.
type onLinkPrefixState struct {
	invalidationTimer *time.Timer

	// Used to signal the timer not to invalidate the on-link prefix (P) in
	// a race condition (T1 is a goroutine that handles a PI for P and T2
	// is the goroutine that handles P's invalidation timer firing):
	//   T1: Receive a new PI for P
	//   T1: Obtain the NIC's lock before processing the PI
	//   T2: P's invalidation timer fires, and gets blocked on obtaining the
	//       NIC's lock
	//   T1: Refreshes/extends P's lifetime & releases NIC's lock
	//   T2: Obtains NIC's lock & invalidates P immediately
	//
	// To resolve this, T1 will check to see if the timer already fired, and
	// inform the timer using doNotInvalidate to not invalidate P, so that
	// once T2 obtains the lock, it will see that it is set to true and do
	// nothing further.
	doNotInvalidate *bool
}

// autoGenAddressState holds data associated with an address generated via
// SLAAC.
type autoGenAddressState struct {
	invalidationTimer *time.Timer

	// Used to signal the timer not to invalidate the SLAAC address (A) in
	// a race condition (T1 is a goroutine that handles a PI for A and T2
	// is the goroutine that handles A's invalidation timer firing):
	//   T1: Receive a new PI for A
	//   T1: Obtain the NIC's lock before processing the PI
	//   T2: A's invalidation timer fires, and gets blocked on obtaining the
	//       NIC's lock
	//   T1: Refreshes/extends A's lifetime & releases NIC's lock
	//   T2: Obtains NIC's lock & invalidates A immediately
	//
	// To resolve this, T1 will check to see if the timer already fired, and
	// inform the timer using doNotInvalidate to not invalidate A, so that
	// once T2 obtains the lock, it will see that it is set to true and do
	// nothing further.
	doNotInvalidate *bool

	// Nonzero only when the address is not valid forever (invalidationTimer
	// is not nil).
	validUntil time.Time
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
	if err := r.WritePacket(nil, NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: header.NDPHopLimit, TOS: DefaultTOS}, tcpip.PacketBuffer{
		Header: hdr,
	}); err != nil {
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

// handleRA handles a Router Advertisement message that arrived on the NIC
// this ndp is for. Does nothing if the NIC is configured to not handle RAs.
//
// The NIC that ndp belongs to and its associated stack MUST be locked.
func (ndp *ndpState) handleRA(ip tcpip.Address, ra header.NDPRouterAdvert) {
	// Is the NIC configured to handle RAs at all?
	//
	// Currently, the stack does not determine router interface status on a
	// per-interface basis; it is a stack-wide configuration, so we check
	// stack's forwarding flag to determine if the NIC is a routing
	// interface.
	if !ndp.configs.HandleRAs || ndp.nic.stack.forwarding {
		return
	}

	// Is the NIC configured to discover default routers?
	if ndp.configs.DiscoverDefaultRouters {
		rtr, ok := ndp.defaultRouters[ip]
		rl := ra.RouterLifetime()
		switch {
		case !ok && rl != 0:
			// This is a new default router we are discovering.
			//
			// Only remember it if we currently know about less than
			// MaxDiscoveredDefaultRouters routers.
			if len(ndp.defaultRouters) < MaxDiscoveredDefaultRouters {
				ndp.rememberDefaultRouter(ip, rl)
			}

		case ok && rl != 0:
			// This is an already discovered default router. Update
			// the invalidation timer.
			timer := rtr.invalidationTimer

			// We should ALWAYS have an invalidation timer for a
			// discovered router.
			if timer == nil {
				panic("ndphandlera: RA invalidation timer should not be nil")
			}

			if !timer.Stop() {
				// If we reach this point, then we know the
				// timer fired after we already took the NIC
				// lock. Inform the timer not to invalidate the
				// router when it obtains the lock as we just
				// got a new RA that refreshes its lifetime to a
				// non-zero value. See
				// defaultRouterState.doNotInvalidate for more
				// details.
				*rtr.doNotInvalidate = true
			}

			timer.Reset(rl)

		case ok && rl == 0:
			// We know about the router but it is no longer to be
			// used as a default router so invalidate it.
			ndp.invalidateDefaultRouter(ip)
		}
	}

	// TODO(b/141556115): Do (RetransTimer, ReachableTime)) Parameter
	//                    Discovery.

	// We know the options is valid as far as wire format is concerned since
	// we got the Router Advertisement, as documented by this fn. Given this
	// we do not check the iterator for errors on calls to Next.
	it, _ := ra.Options().Iter(false)
	for opt, done, _ := it.Next(); !done; opt, done, _ = it.Next() {
		switch opt := opt.(type) {
		case header.NDPRecursiveDNSServer:
			if ndp.nic.stack.ndpDisp == nil {
				continue
			}

			ndp.nic.stack.ndpDisp.OnRecursiveDNSServerOption(ndp.nic.ID(), opt.Addresses(), opt.Lifetime())

		case header.NDPPrefixInformation:
			prefix := opt.Subnet()

			// Is the prefix a link-local?
			if header.IsV6LinkLocalAddress(prefix.ID()) {
				// ...Yes, skip as per RFC 4861 section 6.3.4,
				// and RFC 4862 section 5.5.3.b (for SLAAC).
				continue
			}

			// Is the Prefix Length 0?
			if prefix.Prefix() == 0 {
				// ...Yes, skip as this is an invalid prefix
				// as all IPv6 addresses cannot be on-link.
				continue
			}

			if opt.OnLinkFlag() {
				ndp.handleOnLinkPrefixInformation(opt)
			}

			if opt.AutonomousAddressConfigurationFlag() {
				ndp.handleAutonomousPrefixInformation(opt)
			}
		}

		// TODO(b/141556115): Do (MTU) Parameter Discovery.
	}
}

// invalidateDefaultRouter invalidates a discovered default router.
//
// The NIC that ndp belongs to and its associated stack MUST be locked.
func (ndp *ndpState) invalidateDefaultRouter(ip tcpip.Address) {
	rtr, ok := ndp.defaultRouters[ip]

	// Is the router still discovered?
	if !ok {
		// ...Nope, do nothing further.
		return
	}

	rtr.invalidationTimer.Stop()
	rtr.invalidationTimer = nil
	*rtr.doNotInvalidate = true
	rtr.doNotInvalidate = nil

	delete(ndp.defaultRouters, ip)

	// Let the integrator know a discovered default router is invalidated.
	if ndp.nic.stack.ndpDisp != nil {
		ndp.nic.stack.routeTable = ndp.nic.stack.ndpDisp.OnDefaultRouterInvalidated(ndp.nic.ID(), ip)
	}
}

// rememberDefaultRouter remembers a newly discovered default router with IPv6
// link-local address ip with lifetime rl.
//
// The router identified by ip MUST NOT already be known by the NIC.
//
// The NIC that ndp belongs to and its associated stack MUST be locked.
func (ndp *ndpState) rememberDefaultRouter(ip tcpip.Address, rl time.Duration) {
	if ndp.nic.stack.ndpDisp == nil {
		return
	}

	// Inform the integrator when we discovered a default router.
	remember, routeTable := ndp.nic.stack.ndpDisp.OnDefaultRouterDiscovered(ndp.nic.ID(), ip)
	if !remember {
		// Informed by the integrator to not remember the router, do
		// nothing further.
		return
	}

	// Used to signal the timer not to invalidate the default router (R) in
	// a race condition. See defaultRouterState.doNotInvalidate for more
	// details.
	var doNotInvalidate bool

	ndp.defaultRouters[ip] = defaultRouterState{
		invalidationTimer: time.AfterFunc(rl, func() {
			ndp.nic.stack.mu.Lock()
			defer ndp.nic.stack.mu.Unlock()
			ndp.nic.mu.Lock()
			defer ndp.nic.mu.Unlock()

			if doNotInvalidate {
				doNotInvalidate = false
				return
			}

			ndp.invalidateDefaultRouter(ip)
		}),
		doNotInvalidate: &doNotInvalidate,
	}

	ndp.nic.stack.routeTable = routeTable
}

// rememberOnLinkPrefix remembers a newly discovered on-link prefix with IPv6
// address with prefix prefix with lifetime l.
//
// The prefix identified by prefix MUST NOT already be known.
//
// The NIC that ndp belongs to and its associated stack MUST be locked.
func (ndp *ndpState) rememberOnLinkPrefix(prefix tcpip.Subnet, l time.Duration) {
	if ndp.nic.stack.ndpDisp == nil {
		return
	}

	// Inform the integrator when we discovered an on-link prefix.
	remember, routeTable := ndp.nic.stack.ndpDisp.OnOnLinkPrefixDiscovered(ndp.nic.ID(), prefix)
	if !remember {
		// Informed by the integrator to not remember the prefix, do
		// nothing further.
		return
	}

	// Used to signal the timer not to invalidate the on-link prefix (P) in
	// a race condition. See onLinkPrefixState.doNotInvalidate for more
	// details.
	var doNotInvalidate bool
	var timer *time.Timer

	// Only create a timer if the lifetime is not infinite.
	if l < header.NDPInfiniteLifetime {
		timer = ndp.prefixInvalidationCallback(prefix, l, &doNotInvalidate)
	}

	ndp.onLinkPrefixes[prefix] = onLinkPrefixState{
		invalidationTimer: timer,
		doNotInvalidate:   &doNotInvalidate,
	}

	ndp.nic.stack.routeTable = routeTable
}

// invalidateOnLinkPrefix invalidates a discovered on-link prefix.
//
// The NIC that ndp belongs to and its associated stack MUST be locked.
func (ndp *ndpState) invalidateOnLinkPrefix(prefix tcpip.Subnet) {
	s, ok := ndp.onLinkPrefixes[prefix]

	// Is the on-link prefix still discovered?
	if !ok {
		// ...Nope, do nothing further.
		return
	}

	if s.invalidationTimer != nil {
		s.invalidationTimer.Stop()
		s.invalidationTimer = nil
		*s.doNotInvalidate = true
	}

	s.doNotInvalidate = nil

	delete(ndp.onLinkPrefixes, prefix)

	// Let the integrator know a discovered on-link prefix is invalidated.
	if ndp.nic.stack.ndpDisp != nil {
		ndp.nic.stack.routeTable = ndp.nic.stack.ndpDisp.OnOnLinkPrefixInvalidated(ndp.nic.ID(), prefix)
	}
}

// prefixInvalidationCallback returns a new on-link prefix invalidation timer
// for prefix that fires after vl.
//
// doNotInvalidate is used to signal the timer when it fires at the same time
// that a prefix's valid lifetime gets refreshed. See
// onLinkPrefixState.doNotInvalidate for more details.
func (ndp *ndpState) prefixInvalidationCallback(prefix tcpip.Subnet, vl time.Duration, doNotInvalidate *bool) *time.Timer {
	return time.AfterFunc(vl, func() {
		ndp.nic.stack.mu.Lock()
		defer ndp.nic.stack.mu.Unlock()
		ndp.nic.mu.Lock()
		defer ndp.nic.mu.Unlock()

		if *doNotInvalidate {
			*doNotInvalidate = false
			return
		}

		ndp.invalidateOnLinkPrefix(prefix)
	})
}

// handleOnLinkPrefixInformation handles a Prefix Information option with
// its on-link flag set, as per RFC 4861 section 6.3.4.
//
// handleOnLinkPrefixInformation assumes that the prefix this pi is for is
// not the link-local prefix and the on-link flag is set.
//
// The NIC that ndp belongs to and its associated stack MUST be locked.
func (ndp *ndpState) handleOnLinkPrefixInformation(pi header.NDPPrefixInformation) {
	prefix := pi.Subnet()
	prefixState, ok := ndp.onLinkPrefixes[prefix]
	vl := pi.ValidLifetime()

	if !ok && vl == 0 {
		// Don't know about this prefix but it has a zero valid
		// lifetime, so just ignore.
		return
	}

	if !ok && vl != 0 {
		// This is a new on-link prefix we are discovering
		//
		// Only remember it if we currently know about less than
		// MaxDiscoveredOnLinkPrefixes on-link prefixes.
		if ndp.configs.DiscoverOnLinkPrefixes && len(ndp.onLinkPrefixes) < MaxDiscoveredOnLinkPrefixes {
			ndp.rememberOnLinkPrefix(prefix, vl)
		}
		return
	}

	if ok && vl == 0 {
		// We know about the on-link prefix, but it is
		// no longer to be considered on-link, so
		// invalidate it.
		ndp.invalidateOnLinkPrefix(prefix)
		return
	}

	// This is an already discovered on-link prefix with a
	// new non-zero valid lifetime.
	// Update the invalidation timer.
	timer := prefixState.invalidationTimer

	if timer == nil && vl >= header.NDPInfiniteLifetime {
		// Had infinite valid lifetime before and
		// continues to have an invalid lifetime. Do
		// nothing further.
		return
	}

	if timer != nil && !timer.Stop() {
		// If we reach this point, then we know the timer alread fired
		// after we took the NIC lock. Inform the timer to not
		// invalidate the prefix once it obtains the lock as we just
		// got a new PI that refreshes its lifetime to a non-zero value.
		// See onLinkPrefixState.doNotInvalidate for more details.
		*prefixState.doNotInvalidate = true
	}

	if vl >= header.NDPInfiniteLifetime {
		// Prefix is now valid forever so we don't need
		// an invalidation timer.
		prefixState.invalidationTimer = nil
		ndp.onLinkPrefixes[prefix] = prefixState
		return
	}

	if timer != nil {
		// We already have a timer so just reset it to
		// expire after the new valid lifetime.
		timer.Reset(vl)
		return
	}

	// We do not have a timer so just create a new one.
	prefixState.invalidationTimer = ndp.prefixInvalidationCallback(prefix, vl, prefixState.doNotInvalidate)
	ndp.onLinkPrefixes[prefix] = prefixState
}

// handleAutonomousPrefixInformation handles a Prefix Information option with
// its autonomous flag set, as per RFC 4862 section 5.5.3.
//
// handleAutonomousPrefixInformation assumes that the prefix this pi is for is
// not the link-local prefix and the autonomous flag is set.
//
// The NIC that ndp belongs to and its associated stack MUST be locked.
func (ndp *ndpState) handleAutonomousPrefixInformation(pi header.NDPPrefixInformation) {
	vl := pi.ValidLifetime()
	pl := pi.PreferredLifetime()

	// If the preferred lifetime is greater than the valid lifetime,
	// silently ignore the Prefix Information option, as per RFC 4862
	// section 5.5.3.c.
	if pl > vl {
		return
	}

	prefix := pi.Subnet()

	// Check if we already have an auto-generated address for prefix.
	for _, ref := range ndp.nic.endpoints {
		if ref.protocol != header.IPv6ProtocolNumber {
			continue
		}

		if ref.configType != slaac {
			continue
		}

		addr := ref.ep.ID().LocalAddress
		refAddrWithPrefix := tcpip.AddressWithPrefix{Address: addr, PrefixLen: ref.ep.PrefixLen()}
		if refAddrWithPrefix.Subnet() != prefix {
			continue
		}

		//
		// At this point, we know we are refreshing a SLAAC generated
		// IPv6 address with the prefix, prefix. Do the work as outlined
		// by RFC 4862 section 5.5.3.e.
		//

		addrState, ok := ndp.autoGenAddresses[addr]
		if !ok {
			panic(fmt.Sprintf("must have an autoGenAddressess entry for the SLAAC generated IPv6 address %s", addr))
		}

		// TODO(b/143713887): Handle deprecating auto-generated address
		//                    after the preferred lifetime.

		// As per RFC 4862 section 5.5.3.e, the valid lifetime of the
		// address generated by SLAAC is as follows:
		//
		// 1) If the received Valid Lifetime is greater than 2 hours or
		//    greater than RemainingLifetime, set the valid lifetime of
		//    the address to the advertised Valid Lifetime.
		//
		// 2) If RemainingLifetime is less than or equal to 2 hours,
		//    ignore the advertised Valid Lifetime.
		//
		// 3) Otherwise, reset the valid lifetime of the address to 2
		//    hours.

		// Handle the infinite valid lifetime separately as we do not
		// keep a timer in this case.
		if vl >= header.NDPInfiniteLifetime {
			if addrState.invalidationTimer != nil {
				// Valid lifetime was finite before, but now it
				// is valid forever.
				if !addrState.invalidationTimer.Stop() {
					*addrState.doNotInvalidate = true
				}
				addrState.invalidationTimer = nil
				addrState.validUntil = time.Time{}
				ndp.autoGenAddresses[addr] = addrState
			}

			return
		}

		var effectiveVl time.Duration
		var rl time.Duration

		// If the address was originally set to be valid forever,
		// assume the remaining time to be the maximum possible value.
		if addrState.invalidationTimer == nil {
			rl = header.NDPInfiniteLifetime
		} else {
			rl = time.Until(addrState.validUntil)
		}

		if vl > MinPrefixInformationValidLifetimeForUpdate || vl > rl {
			effectiveVl = vl
		} else if rl <= MinPrefixInformationValidLifetimeForUpdate {
			ndp.autoGenAddresses[addr] = addrState
			return
		} else {
			effectiveVl = MinPrefixInformationValidLifetimeForUpdate
		}

		if addrState.invalidationTimer == nil {
			addrState.invalidationTimer = ndp.autoGenAddrInvalidationTimer(addr, effectiveVl, addrState.doNotInvalidate)
		} else {
			if !addrState.invalidationTimer.Stop() {
				*addrState.doNotInvalidate = true
			}
			addrState.invalidationTimer.Reset(effectiveVl)
		}

		addrState.validUntil = time.Now().Add(effectiveVl)
		ndp.autoGenAddresses[addr] = addrState
		return
	}

	// We do not already have an address within the prefix, prefix. Do the
	// work as outlined by RFC 4862 section 5.5.3.d if n is configured
	// to auto-generated global addresses by SLAAC.

	// Are we configured to auto-generate new global addresses?
	if !ndp.configs.AutoGenGlobalAddresses {
		return
	}

	// If we do not already have an address for this prefix and the valid
	// lifetime is 0, no need to do anything further, as per RFC 4862
	// section 5.5.3.d.
	if vl == 0 {
		return
	}

	// Make sure the prefix is valid (as far as its length is concerned) to
	// generate a valid IPv6 address from an interface identifier (IID), as
	// per RFC 4862 sectiion 5.5.3.d.
	if prefix.Prefix() != validPrefixLenForAutoGen {
		return
	}

	// Only attempt to generate an interface-specific IID if we have a valid
	// link address.
	//
	// TODO(b/141011931): Validate a LinkEndpoint's link address
	// (provided by LinkEndpoint.LinkAddress) before reaching this
	// point.
	linkAddr := ndp.nic.linkEP.LinkAddress()
	if !header.IsValidUnicastEthernetAddress(linkAddr) {
		return
	}

	// Generate an address within prefix from the EUI-64 of ndp's NIC's
	// Ethernet MAC address.
	addrBytes := make([]byte, header.IPv6AddressSize)
	copy(addrBytes[:header.IIDOffsetInIPv6Address], prefix.ID()[:header.IIDOffsetInIPv6Address])
	header.EthernetAdddressToEUI64IntoBuf(linkAddr, addrBytes[header.IIDOffsetInIPv6Address:])
	addr := tcpip.Address(addrBytes)
	addrWithPrefix := tcpip.AddressWithPrefix{
		Address:   addr,
		PrefixLen: validPrefixLenForAutoGen,
	}

	// If the nic already has this address, do nothing further.
	if ndp.nic.hasPermanentAddrLocked(addr) {
		return
	}

	// Inform the integrator that we have a new SLAAC address.
	if ndp.nic.stack.ndpDisp == nil {
		return
	}
	if !ndp.nic.stack.ndpDisp.OnAutoGenAddress(ndp.nic.ID(), addrWithPrefix) {
		// Informed by the integrator not to add the address.
		return
	}

	if _, err := ndp.nic.addAddressLocked(tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: addrWithPrefix,
	}, FirstPrimaryEndpoint, permanent, slaac); err != nil {
		panic(err)
	}

	// Setup the timers to deprecate and invalidate this newly generated
	// address.

	// TODO(b/143713887): Handle deprecating auto-generated addresses
	//                    after the preferred lifetime.

	var doNotInvalidate bool
	var vTimer *time.Timer
	if vl < header.NDPInfiniteLifetime {
		vTimer = ndp.autoGenAddrInvalidationTimer(addr, vl, &doNotInvalidate)
	}

	ndp.autoGenAddresses[addr] = autoGenAddressState{
		invalidationTimer: vTimer,
		doNotInvalidate:   &doNotInvalidate,
		validUntil:        time.Now().Add(vl),
	}
}

// invalidateAutoGenAddress invalidates an auto-generated address.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) invalidateAutoGenAddress(addr tcpip.Address) {
	if !ndp.cleanupAutoGenAddrResourcesAndNotify(addr) {
		return
	}

	ndp.nic.removePermanentAddressLocked(addr)
}

// cleanupAutoGenAddrResourcesAndNotify cleans up an invalidated auto-generated
// address's resources from ndp. If the stack has an NDP dispatcher, it will
// be notified that addr has been invalidated.
//
// Returns true if ndp had resources for addr to cleanup.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) cleanupAutoGenAddrResourcesAndNotify(addr tcpip.Address) bool {
	state, ok := ndp.autoGenAddresses[addr]

	if !ok {
		return false
	}

	if state.invalidationTimer != nil {
		state.invalidationTimer.Stop()
		state.invalidationTimer = nil
		*state.doNotInvalidate = true
	}

	state.doNotInvalidate = nil

	delete(ndp.autoGenAddresses, addr)

	if ndp.nic.stack.ndpDisp != nil {
		ndp.nic.stack.ndpDisp.OnAutoGenAddressInvalidated(ndp.nic.ID(), tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: validPrefixLenForAutoGen,
		})
	}

	return true
}

// autoGenAddrInvalidationTimer returns a new invalidation timer for an
// auto-generated address that fires after vl.
//
// doNotInvalidate is used to inform the timer when it fires at the same time
// that an auto-generated address's valid lifetime gets refreshed. See
// autoGenAddrState.doNotInvalidate for more details.
func (ndp *ndpState) autoGenAddrInvalidationTimer(addr tcpip.Address, vl time.Duration, doNotInvalidate *bool) *time.Timer {
	return time.AfterFunc(vl, func() {
		ndp.nic.mu.Lock()
		defer ndp.nic.mu.Unlock()

		if *doNotInvalidate {
			*doNotInvalidate = false
			return
		}

		ndp.invalidateAutoGenAddress(addr)
	})
}
