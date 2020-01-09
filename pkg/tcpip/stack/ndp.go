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
	// discovered. Implementations must return true if the newly discovered
	// router should be remembered.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnDefaultRouterDiscovered(nicID tcpip.NICID, addr tcpip.Address) bool

	// OnDefaultRouterInvalidated will be called when a discovered default
	// router that was remembered is invalidated.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnDefaultRouterInvalidated(nicID tcpip.NICID, addr tcpip.Address)

	// OnOnLinkPrefixDiscovered will be called when a new on-link prefix is
	// discovered. Implementations must return true if the newly discovered
	// on-link prefix should be remembered.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnOnLinkPrefixDiscovered(nicID tcpip.NICID, prefix tcpip.Subnet) bool

	// OnOnLinkPrefixInvalidated will be called when a discovered on-link
	// prefix that was remembered is invalidated.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	OnOnLinkPrefixInvalidated(nicID tcpip.NICID, prefix tcpip.Subnet)

	// OnAutoGenAddress will be called when a new prefix with its
	// autonomous address-configuration flag set has been received and SLAAC
	// has been performed. Implementations may prevent the stack from
	// assigning the address to the NIC by returning false.
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnAutoGenAddress(tcpip.NICID, tcpip.AddressWithPrefix) bool

	// OnAutoGenAddressDeprecated will be called when an auto-generated
	// address (as part of SLAAC) has been deprecated, but is still
	// considered valid. Note, if an address is invalidated at the same
	// time it is deprecated, the deprecation event MAY be omitted.
	//
	// This function is not permitted to block indefinitely. It must not
	// call functions on the stack itself.
	OnAutoGenAddressDeprecated(tcpip.NICID, tcpip.AddressWithPrefix)

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
	invalidationTimer tcpip.CancellableTimer
}

// onLinkPrefixState holds data associated with an on-link prefix discovered by
// a Router Advertisement's Prefix Information option (PI) when the NDP
// configurations was configured to do so.
type onLinkPrefixState struct {
	invalidationTimer tcpip.CancellableTimer
}

// autoGenAddressState holds data associated with an address generated via
// SLAAC.
type autoGenAddressState struct {
	// A reference to the referencedNetworkEndpoint that this autoGenAddressState
	// is holding state for.
	ref *referencedNetworkEndpoint

	deprecationTimer  tcpip.CancellableTimer
	invalidationTimer tcpip.CancellableTimer

	// Nonzero only when the address is not valid forever.
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
// The NIC that ndp belongs to MUST be locked.
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
			rtr.invalidationTimer.StopLocked()
			rtr.invalidationTimer.Reset(rl)
			ndp.defaultRouters[ip] = rtr

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
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) invalidateDefaultRouter(ip tcpip.Address) {
	rtr, ok := ndp.defaultRouters[ip]

	// Is the router still discovered?
	if !ok {
		// ...Nope, do nothing further.
		return
	}

	rtr.invalidationTimer.StopLocked()

	delete(ndp.defaultRouters, ip)

	// Let the integrator know a discovered default router is invalidated.
	if ndpDisp := ndp.nic.stack.ndpDisp; ndpDisp != nil {
		ndpDisp.OnDefaultRouterInvalidated(ndp.nic.ID(), ip)
	}
}

// rememberDefaultRouter remembers a newly discovered default router with IPv6
// link-local address ip with lifetime rl.
//
// The router identified by ip MUST NOT already be known by the NIC.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) rememberDefaultRouter(ip tcpip.Address, rl time.Duration) {
	ndpDisp := ndp.nic.stack.ndpDisp
	if ndpDisp == nil {
		return
	}

	// Inform the integrator when we discovered a default router.
	if !ndpDisp.OnDefaultRouterDiscovered(ndp.nic.ID(), ip) {
		// Informed by the integrator to not remember the router, do
		// nothing further.
		return
	}

	state := defaultRouterState{
		invalidationTimer: tcpip.MakeCancellableTimer(&ndp.nic.mu, func() {
			ndp.invalidateDefaultRouter(ip)
		}),
	}

	state.invalidationTimer.Reset(rl)

	ndp.defaultRouters[ip] = state
}

// rememberOnLinkPrefix remembers a newly discovered on-link prefix with IPv6
// address with prefix prefix with lifetime l.
//
// The prefix identified by prefix MUST NOT already be known.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) rememberOnLinkPrefix(prefix tcpip.Subnet, l time.Duration) {
	ndpDisp := ndp.nic.stack.ndpDisp
	if ndpDisp == nil {
		return
	}

	// Inform the integrator when we discovered an on-link prefix.
	if !ndpDisp.OnOnLinkPrefixDiscovered(ndp.nic.ID(), prefix) {
		// Informed by the integrator to not remember the prefix, do
		// nothing further.
		return
	}

	state := onLinkPrefixState{
		invalidationTimer: tcpip.MakeCancellableTimer(&ndp.nic.mu, func() {
			ndp.invalidateOnLinkPrefix(prefix)
		}),
	}

	if l < header.NDPInfiniteLifetime {
		state.invalidationTimer.Reset(l)
	}

	ndp.onLinkPrefixes[prefix] = state
}

// invalidateOnLinkPrefix invalidates a discovered on-link prefix.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) invalidateOnLinkPrefix(prefix tcpip.Subnet) {
	s, ok := ndp.onLinkPrefixes[prefix]

	// Is the on-link prefix still discovered?
	if !ok {
		// ...Nope, do nothing further.
		return
	}

	s.invalidationTimer.StopLocked()

	delete(ndp.onLinkPrefixes, prefix)

	// Let the integrator know a discovered on-link prefix is invalidated.
	if ndpDisp := ndp.nic.stack.ndpDisp; ndpDisp != nil {
		ndpDisp.OnOnLinkPrefixInvalidated(ndp.nic.ID(), prefix)
	}
}

// handleOnLinkPrefixInformation handles a Prefix Information option with
// its on-link flag set, as per RFC 4861 section 6.3.4.
//
// handleOnLinkPrefixInformation assumes that the prefix this pi is for is
// not the link-local prefix and the on-link flag is set.
//
// The NIC that ndp belongs to MUST be locked.
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
	//
	// Update the invalidation timer.

	prefixState.invalidationTimer.StopLocked()

	if vl < header.NDPInfiniteLifetime {
		// Prefix is valid for a finite lifetime, reset the timer to expire after
		// the new valid lifetime.
		prefixState.invalidationTimer.Reset(vl)
	}

	ndp.onLinkPrefixes[prefix] = prefixState
}

// handleAutonomousPrefixInformation handles a Prefix Information option with
// its autonomous flag set, as per RFC 4862 section 5.5.3.
//
// handleAutonomousPrefixInformation assumes that the prefix this pi is for is
// not the link-local prefix and the autonomous flag is set.
//
// The NIC that ndp belongs to MUST be locked.
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
	for addr, addrState := range ndp.autoGenAddresses {
		refAddrWithPrefix := tcpip.AddressWithPrefix{Address: addr, PrefixLen: addrState.ref.ep.PrefixLen()}
		if refAddrWithPrefix.Subnet() != prefix {
			continue
		}

		// At this point, we know we are refreshing a SLAAC generated IPv6 address
		// with the prefix prefix. Do the work as outlined by RFC 4862 section
		// 5.5.3.e.
		ndp.refreshAutoGenAddressLifetimes(addr, pl, vl)
		return
	}

	// We do not already have an address within the prefix, prefix. Do the
	// work as outlined by RFC 4862 section 5.5.3.d if n is configured
	// to auto-generated global addresses by SLAAC.
	ndp.newAutoGenAddress(prefix, pl, vl)
}

// newAutoGenAddress generates a new SLAAC address with the provided lifetimes
// for prefix.
//
// pl is the new preferred lifetime. vl is the new valid lifetime.
func (ndp *ndpState) newAutoGenAddress(prefix tcpip.Subnet, pl, vl time.Duration) {
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

	addrBytes := []byte(prefix.ID())
	if oIID := ndp.nic.stack.opaqueIIDOpts; oIID.NICNameFromID != nil {
		addrBytes = header.AppendOpaqueInterfaceIdentifier(addrBytes[:header.IIDOffsetInIPv6Address], prefix, oIID.NICNameFromID(ndp.nic.ID(), ndp.nic.name), 0 /* dadCounter */, oIID.SecretKey)
	} else {
		// Only attempt to generate an interface-specific IID if we have a valid
		// link address.
		//
		// TODO(b/141011931): Validate a LinkEndpoint's link address (provided by
		// LinkEndpoint.LinkAddress) before reaching this point.
		linkAddr := ndp.nic.linkEP.LinkAddress()
		if !header.IsValidUnicastEthernetAddress(linkAddr) {
			return
		}

		// Generate an address within prefix from the modified EUI-64 of ndp's NIC's
		// Ethernet MAC address.
		header.EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, addrBytes[header.IIDOffsetInIPv6Address:])
	}
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
	ndpDisp := ndp.nic.stack.ndpDisp
	if ndpDisp == nil {
		return
	}
	if !ndpDisp.OnAutoGenAddress(ndp.nic.ID(), addrWithPrefix) {
		// Informed by the integrator not to add the address.
		return
	}

	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: addrWithPrefix,
	}
	// If the preferred lifetime is zero, then the address should be considered
	// deprecated.
	deprecated := pl == 0
	ref, err := ndp.nic.addAddressLocked(protocolAddr, FirstPrimaryEndpoint, permanent, slaac, deprecated)
	if err != nil {
		log.Fatalf("ndp: error when adding address %s: %s", protocolAddr, err)
	}

	state := autoGenAddressState{
		ref: ref,
		deprecationTimer: tcpip.MakeCancellableTimer(&ndp.nic.mu, func() {
			addrState, ok := ndp.autoGenAddresses[addr]
			if !ok {
				log.Fatalf("ndp: must have an autoGenAddressess entry for the SLAAC generated IPv6 address %s", addr)
			}
			addrState.ref.deprecated = true
			ndp.notifyAutoGenAddressDeprecated(addr)
		}),
		invalidationTimer: tcpip.MakeCancellableTimer(&ndp.nic.mu, func() {
			ndp.invalidateAutoGenAddress(addr)
		}),
	}

	// Setup the initial timers to deprecate and invalidate this newly generated
	// address.

	if !deprecated && pl < header.NDPInfiniteLifetime {
		state.deprecationTimer.Reset(pl)
	}

	if vl < header.NDPInfiniteLifetime {
		state.invalidationTimer.Reset(vl)
		state.validUntil = time.Now().Add(vl)
	}

	ndp.autoGenAddresses[addr] = state
}

// refreshAutoGenAddressLifetimes refreshes the lifetime of a SLAAC generated
// address addr.
//
// pl is the new preferred lifetime. vl is the new valid lifetime.
func (ndp *ndpState) refreshAutoGenAddressLifetimes(addr tcpip.Address, pl, vl time.Duration) {
	addrState, ok := ndp.autoGenAddresses[addr]
	if !ok {
		log.Fatalf("ndp: SLAAC state not found to refresh lifetimes for %s", addr)
	}
	defer func() { ndp.autoGenAddresses[addr] = addrState }()

	// If the preferred lifetime is zero, then the address should be considered
	// deprecated.
	deprecated := pl == 0
	wasDeprecated := addrState.ref.deprecated
	addrState.ref.deprecated = deprecated

	// Only send the deprecation event if the deprecated status for addr just
	// changed from non-deprecated to deprecated.
	if !wasDeprecated && deprecated {
		ndp.notifyAutoGenAddressDeprecated(addr)
	}

	// If addr was preferred for some finite lifetime before, stop the deprecation
	// timer so it can be reset.
	addrState.deprecationTimer.StopLocked()

	// Reset the deprecation timer if addr has a finite preferred lifetime.
	if !deprecated && pl < header.NDPInfiniteLifetime {
		addrState.deprecationTimer.Reset(pl)
	}

	// As per RFC 4862 section 5.5.3.e, the valid lifetime of the address
	//
	//
	// 1) If the received Valid Lifetime is greater than 2 hours or greater than
	//    RemainingLifetime, set the valid lifetime of the address to the
	//    advertised Valid Lifetime.
	//
	// 2) If RemainingLifetime is less than or equal to 2 hours, ignore the
	//    advertised Valid Lifetime.
	//
	// 3) Otherwise, reset the valid lifetime of the address to 2 hours.

	// Handle the infinite valid lifetime separately as we do not keep a timer in
	// this case.
	if vl >= header.NDPInfiniteLifetime {
		addrState.invalidationTimer.StopLocked()
		addrState.validUntil = time.Time{}
		return
	}

	var effectiveVl time.Duration
	var rl time.Duration

	// If the address was originally set to be valid forever, assume the remaining
	// time to be the maximum possible value.
	if addrState.validUntil == (time.Time{}) {
		rl = header.NDPInfiniteLifetime
	} else {
		rl = time.Until(addrState.validUntil)
	}

	if vl > MinPrefixInformationValidLifetimeForUpdate || vl > rl {
		effectiveVl = vl
	} else if rl <= MinPrefixInformationValidLifetimeForUpdate {
		return
	} else {
		effectiveVl = MinPrefixInformationValidLifetimeForUpdate
	}

	addrState.invalidationTimer.StopLocked()
	addrState.invalidationTimer.Reset(effectiveVl)
	addrState.validUntil = time.Now().Add(effectiveVl)
}

// notifyAutoGenAddressDeprecated notifies the stack's NDP dispatcher that addr
// has been deprecated.
func (ndp *ndpState) notifyAutoGenAddressDeprecated(addr tcpip.Address) {
	if ndpDisp := ndp.nic.stack.ndpDisp; ndpDisp != nil {
		ndpDisp.OnAutoGenAddressDeprecated(ndp.nic.ID(), tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: validPrefixLenForAutoGen,
		})
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

	state.deprecationTimer.StopLocked()
	state.invalidationTimer.StopLocked()
	delete(ndp.autoGenAddresses, addr)

	if ndpDisp := ndp.nic.stack.ndpDisp; ndpDisp != nil {
		ndpDisp.OnAutoGenAddressInvalidated(ndp.nic.ID(), tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: validPrefixLenForAutoGen,
		})
	}

	return true
}

// cleanupHostOnlyState cleans up any state that is only useful for hosts.
//
// cleanupHostOnlyState MUST be called when ndp's NIC is transitioning from a
// host to a router. This function will invalidate all discovered on-link
// prefixes, discovered routers, and auto-generated addresses as routers do not
// normally process Router Advertisements to discover default routers and
// on-link prefixes, and auto-generate addresses via SLAAC.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) cleanupHostOnlyState() {
	for addr, _ := range ndp.autoGenAddresses {
		ndp.invalidateAutoGenAddress(addr)
	}

	if got := len(ndp.autoGenAddresses); got != 0 {
		log.Fatalf("ndp: still have auto-generated addresses after cleaning up, found = %d", got)
	}

	for prefix, _ := range ndp.onLinkPrefixes {
		ndp.invalidateOnLinkPrefix(prefix)
	}

	if got := len(ndp.onLinkPrefixes); got != 0 {
		log.Fatalf("ndp: still have discovered on-link prefixes after cleaning up, found = %d", got)
	}

	for router, _ := range ndp.defaultRouters {
		ndp.invalidateDefaultRouter(router)
	}

	if got := len(ndp.defaultRouters); got != 0 {
		log.Fatalf("ndp: still have discovered default routers after cleaning up, found = %d", got)
	}
}
