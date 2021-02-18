// Copyright 2021 The gVisor Authors.
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

// Package ipv4 contains the implementation of the ipv4 network protocol.
package ipv4

import (
	"fmt"
	"math"
	"reflect"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/network/hash"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/fragmentation"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// ReassembleTimeout is the time a packet stays in the reassembly
	// system before being evicted.
	// As per RFC 791 section 3.2:
	//   The current recommendation for the initial timer setting is 15 seconds.
	//   This may be changed as experience with this protocol accumulates.
	//
	// Considering that it is an old recommendation, we use the same reassembly
	// timeout that linux defines, which is 30 seconds:
	// https://github.com/torvalds/linux/blob/47ec5303d73ea344e84f46660fff693c57641386/include/net/ip.h#L138
	ReassembleTimeout = 30 * time.Second

	// ProtocolNumber is the ipv4 protocol number.
	ProtocolNumber = header.IPv4ProtocolNumber

	// MaxTotalSize is maximum size that can be encoded in the 16-bit
	// TotalLength field of the ipv4 header.
	MaxTotalSize = 0xffff

	// DefaultTTL is the default time-to-live value for this endpoint.
	DefaultTTL = 64

	// buckets is the number of identifier buckets.
	buckets = 2048

	// The size of a fragment block, in bytes, as per RFC 791 section 3.1,
	// page 14.
	fragmentblockSize = 8
)

var ipv4BroadcastAddr = header.IPv4Broadcast.WithPrefix()

var _ stack.LinkResolvableNetworkEndpoint = (*endpoint)(nil)
var _ stack.GroupAddressableEndpoint = (*endpoint)(nil)
var _ stack.AddressableEndpoint = (*endpoint)(nil)
var _ stack.NetworkEndpoint = (*endpoint)(nil)

type endpoint struct {
	nic        stack.NetworkInterface
	dispatcher stack.TransportDispatcher
	protocol   *protocol
	stats      sharedStats

	// enabled is set to 1 when the enpoint is enabled and 0 when it is
	// disabled.
	//
	// Must be accessed using atomic operations.
	enabled uint32

	mu struct {
		sync.RWMutex

		addressableEndpointState stack.AddressableEndpointState
		igmp                     igmpState
	}
}

// HandleLinkResolutionFailure implements stack.LinkResolvableNetworkEndpoint.
func (e *endpoint) HandleLinkResolutionFailure(pkt *stack.PacketBuffer) {
	// handleControl expects the entire offending packet to be in the packet
	// buffer's data field.
	pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buffer.NewVectorisedView(pkt.Size(), pkt.Views()),
	})
	pkt.NICID = e.nic.ID()
	pkt.NetworkProtocolNumber = ProtocolNumber
	// Use the same control type as an ICMPv4 destination host unreachable error
	// since the host is considered unreachable if we cannot resolve the link
	// address to the next hop.
	e.handleControl(&icmpv4DestinationHostUnreachableSockError{}, pkt)
}

// NewEndpoint creates a new ipv4 endpoint.
func (p *protocol) NewEndpoint(nic stack.NetworkInterface, dispatcher stack.TransportDispatcher) stack.NetworkEndpoint {
	e := &endpoint{
		nic:        nic,
		dispatcher: dispatcher,
		protocol:   p,
	}
	e.mu.Lock()
	e.mu.addressableEndpointState.Init(e)
	e.mu.igmp.init(e)
	e.mu.Unlock()

	tcpip.InitStatCounters(reflect.ValueOf(&e.stats.localStats).Elem())

	stackStats := p.stack.Stats()
	e.stats.ip.Init(&e.stats.localStats.IP, &stackStats.IP)
	e.stats.icmp.init(&e.stats.localStats.ICMP, &stackStats.ICMP.V4)
	e.stats.igmp.init(&e.stats.localStats.IGMP, &stackStats.IGMP)

	p.mu.Lock()
	p.mu.eps[nic.ID()] = e
	p.mu.Unlock()

	return e
}

func (p *protocol) findEndpointWithAddress(addr tcpip.Address) *endpoint {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, e := range p.mu.eps {
		if addressEndpoint := e.AcquireAssignedAddress(addr, false /* allowTemp */, stack.NeverPrimaryEndpoint); addressEndpoint != nil {
			addressEndpoint.DecRef()
			return e
		}
	}

	return nil
}

func (p *protocol) forgetEndpoint(nicID tcpip.NICID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.mu.eps, nicID)
}

// Enable implements stack.NetworkEndpoint.
func (e *endpoint) Enable() tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If the NIC is not enabled, the endpoint can't do anything meaningful so
	// don't enable the endpoint.
	if !e.nic.Enabled() {
		return &tcpip.ErrNotPermitted{}
	}

	// If the endpoint is already enabled, there is nothing for it to do.
	if !e.setEnabled(true) {
		return nil
	}

	// Create an endpoint to receive broadcast packets on this interface.
	ep, err := e.mu.addressableEndpointState.AddAndAcquirePermanentAddress(ipv4BroadcastAddr, stack.NeverPrimaryEndpoint, stack.AddressConfigStatic, false /* deprecated */)
	if err != nil {
		return err
	}
	// We have no need for the address endpoint.
	ep.DecRef()

	// Groups may have been joined while the endpoint was disabled, or the
	// endpoint may have left groups from the perspective of IGMP when the
	// endpoint was disabled. Either way, we need to let routers know to
	// send us multicast traffic.
	e.mu.igmp.initializeAll()

	// As per RFC 1122 section 3.3.7, all hosts should join the all-hosts
	// multicast group. Note, the IANA calls the all-hosts multicast group the
	// all-systems multicast group.
	if err := e.joinGroupLocked(header.IPv4AllSystems); err != nil {
		// joinGroupLocked only returns an error if the group address is not a valid
		// IPv4 multicast address.
		panic(fmt.Sprintf("e.joinGroupLocked(%s): %s", header.IPv4AllSystems, err))
	}

	return nil
}

// Enabled implements stack.NetworkEndpoint.
func (e *endpoint) Enabled() bool {
	return e.nic.Enabled() && e.isEnabled()
}

// isEnabled returns true if the endpoint is enabled, regardless of the
// enabled status of the NIC.
func (e *endpoint) isEnabled() bool {
	return atomic.LoadUint32(&e.enabled) == 1
}

// setEnabled sets the enabled status for the endpoint.
//
// Returns true if the enabled status was updated.
func (e *endpoint) setEnabled(v bool) bool {
	if v {
		return atomic.SwapUint32(&e.enabled, 1) == 0
	}
	return atomic.SwapUint32(&e.enabled, 0) == 1
}

// Disable implements stack.NetworkEndpoint.
func (e *endpoint) Disable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disableLocked()
}

func (e *endpoint) disableLocked() {
	if !e.isEnabled() {
		return
	}

	// The endpoint may have already left the multicast group.
	switch err := e.leaveGroupLocked(header.IPv4AllSystems); err.(type) {
	case nil, *tcpip.ErrBadLocalAddress:
	default:
		panic(fmt.Sprintf("unexpected error when leaving group = %s: %s", header.IPv4AllSystems, err))
	}

	// Leave groups from the perspective of IGMP so that routers know that
	// we are no longer interested in the group.
	e.mu.igmp.softLeaveAll()

	// The address may have already been removed.
	switch err := e.mu.addressableEndpointState.RemovePermanentAddress(ipv4BroadcastAddr.Address); err.(type) {
	case nil, *tcpip.ErrBadLocalAddress:
	default:
		panic(fmt.Sprintf("unexpected error when removing address = %s: %s", ipv4BroadcastAddr.Address, err))
	}

	// Reset the IGMP V1 present flag.
	//
	// If the node comes back up on the same network, it will re-learn that it
	// needs to perform IGMPv1.
	e.mu.igmp.resetV1Present()

	if !e.setEnabled(false) {
		panic("should have only done work to disable the endpoint if it was enabled")
	}
}

// DefaultTTL is the default time-to-live value for this endpoint.
func (e *endpoint) DefaultTTL() uint8 {
	return e.protocol.DefaultTTL()
}

// MTU implements stack.NetworkEndpoint.MTU. It returns the link-layer MTU minus
// the network layer max header length.
func (e *endpoint) MTU() uint32 {
	networkMTU, err := calculateNetworkMTU(e.nic.MTU(), header.IPv4MinimumSize)
	if err != nil {
		return 0
	}
	return networkMTU
}

// MaxHeaderLength returns the maximum length needed by ipv4 headers (and
// underlying protocols).
func (e *endpoint) MaxHeaderLength() uint16 {
	return e.nic.MaxHeaderLength() + header.IPv4MaximumHeaderSize
}

// NetworkProtocolNumber implements stack.NetworkEndpoint.NetworkProtocolNumber.
func (e *endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return e.protocol.Number()
}

func (e *endpoint) addIPHeader(srcAddr, dstAddr tcpip.Address, pkt *stack.PacketBuffer, params stack.NetworkHeaderParams, options header.IPv4OptionsSerializer) tcpip.Error {
	hdrLen := header.IPv4MinimumSize
	var optLen int
	if options != nil {
		optLen = int(options.Length())
	}
	hdrLen += optLen
	if hdrLen > header.IPv4MaximumHeaderSize {
		return &tcpip.ErrMessageTooLong{}
	}
	ip := header.IPv4(pkt.NetworkHeader().Push(hdrLen))
	length := pkt.Size()
	if length > math.MaxUint16 {
		return &tcpip.ErrMessageTooLong{}
	}
	// RFC 6864 section 4.3 mandates uniqueness of ID values for non-atomic
	// datagrams. Since the DF bit is never being set here, all datagrams
	// are non-atomic and need an ID.
	id := atomic.AddUint32(&e.protocol.ids[hashRoute(srcAddr, dstAddr, params.Protocol, e.protocol.hashIV)%buckets], 1)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(length),
		ID:          uint16(id),
		TTL:         params.TTL,
		TOS:         params.TOS,
		Protocol:    uint8(params.Protocol),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Options:     options,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	pkt.NetworkProtocolNumber = ProtocolNumber
	return nil
}

// handleFragments fragments pkt and calls the handler function on each
// fragment. It returns the number of fragments handled and the number of
// fragments left to be processed. The IP header must already be present in the
// original packet.
func (e *endpoint) handleFragments(r *stack.Route, gso *stack.GSO, networkMTU uint32, pkt *stack.PacketBuffer, handler func(*stack.PacketBuffer) tcpip.Error) (int, int, tcpip.Error) {
	// Round the MTU down to align to 8 bytes.
	fragmentPayloadSize := networkMTU &^ 7
	networkHeader := header.IPv4(pkt.NetworkHeader().View())
	pf := fragmentation.MakePacketFragmenter(pkt, fragmentPayloadSize, pkt.AvailableHeaderBytes()+len(networkHeader))

	var n int
	for {
		fragPkt, more := buildNextFragment(&pf, networkHeader)
		if err := handler(fragPkt); err != nil {
			return n, pf.RemainingFragmentCount() + 1, err
		}
		n++
		if !more {
			return n, pf.RemainingFragmentCount(), nil
		}
	}
}

// WritePacket writes a packet to the given destination address and protocol.
func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, params stack.NetworkHeaderParams, pkt *stack.PacketBuffer) tcpip.Error {
	if err := e.addIPHeader(r.LocalAddress, r.RemoteAddress, pkt, params, nil /* options */); err != nil {
		return err
	}

	// iptables filtering. All packets that reach here are locally
	// generated.
	outNicName := e.protocol.stack.FindNICNameFromID(e.nic.ID())
	if ok := e.protocol.stack.IPTables().Check(stack.Output, pkt, gso, r, "" /* preroutingAddr */, "" /* inNicName */, outNicName); !ok {
		// iptables is telling us to drop the packet.
		e.stats.ip.IPTablesOutputDropped.Increment()
		return nil
	}

	// If the packet is manipulated as per NAT Output rules, handle packet
	// based on destination address and do not send the packet to link
	// layer.
	//
	// TODO(gvisor.dev/issue/170): We should do this for every
	// packet, rather than only NATted packets, but removing this check
	// short circuits broadcasts before they are sent out to other hosts.
	if pkt.NatDone {
		netHeader := header.IPv4(pkt.NetworkHeader().View())
		if ep := e.protocol.findEndpointWithAddress(netHeader.DestinationAddress()); ep != nil {
			// Since we rewrote the packet but it is being routed back to us, we
			// can safely assume the checksum is valid.
			ep.handleLocalPacket(pkt, true /* canSkipRXChecksum */)
			return nil
		}
	}

	return e.writePacket(r, gso, pkt, false /* headerIncluded */)
}

func (e *endpoint) writePacket(r *stack.Route, gso *stack.GSO, pkt *stack.PacketBuffer, headerIncluded bool) tcpip.Error {
	if r.Loop&stack.PacketLoop != 0 {
		// If the packet was generated by the stack (not a raw/packet endpoint
		// where a packet may be written with the header included), then we can
		// safely assume the checksum is valid.
		e.handleLocalPacket(pkt, !headerIncluded /* canSkipRXChecksum */)
	}
	if r.Loop&stack.PacketOut == 0 {
		return nil
	}

	stats := e.stats.ip

	networkMTU, err := calculateNetworkMTU(e.nic.MTU(), uint32(pkt.NetworkHeader().View().Size()))
	if err != nil {
		stats.OutgoingPacketErrors.Increment()
		return err
	}

	if packetMustBeFragmented(pkt, networkMTU, gso) {
		sent, remain, err := e.handleFragments(r, gso, networkMTU, pkt, func(fragPkt *stack.PacketBuffer) tcpip.Error {
			// TODO(gvisor.dev/issue/3884): Evaluate whether we want to send each
			// fragment one by one using WritePacket() (current strategy) or if we
			// want to create a PacketBufferList from the fragments and feed it to
			// WritePackets(). It'll be faster but cost more memory.
			return e.nic.WritePacket(r, gso, ProtocolNumber, fragPkt)
		})
		stats.PacketsSent.IncrementBy(uint64(sent))
		stats.OutgoingPacketErrors.IncrementBy(uint64(remain))
		return err
	}

	if err := e.nic.WritePacket(r, gso, ProtocolNumber, pkt); err != nil {
		stats.OutgoingPacketErrors.Increment()
		return err
	}
	stats.PacketsSent.Increment()
	return nil
}

// WritePackets implements stack.NetworkEndpoint.WritePackets.
func (e *endpoint) WritePackets(r *stack.Route, gso *stack.GSO, pkts stack.PacketBufferList, params stack.NetworkHeaderParams) (int, tcpip.Error) {
	if r.Loop&stack.PacketLoop != 0 {
		panic("multiple packets in local loop")
	}
	if r.Loop&stack.PacketOut == 0 {
		return pkts.Len(), nil
	}

	stats := e.stats.ip

	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		if err := e.addIPHeader(r.LocalAddress, r.RemoteAddress, pkt, params, nil /* options */); err != nil {
			return 0, err
		}

		networkMTU, err := calculateNetworkMTU(e.nic.MTU(), uint32(pkt.NetworkHeader().View().Size()))
		if err != nil {
			stats.OutgoingPacketErrors.IncrementBy(uint64(pkts.Len()))
			return 0, err
		}

		if packetMustBeFragmented(pkt, networkMTU, gso) {
			// Keep track of the packet that is about to be fragmented so it can be
			// removed once the fragmentation is done.
			originalPkt := pkt
			if _, _, err := e.handleFragments(r, gso, networkMTU, pkt, func(fragPkt *stack.PacketBuffer) tcpip.Error {
				// Modify the packet list in place with the new fragments.
				pkts.InsertAfter(pkt, fragPkt)
				pkt = fragPkt
				return nil
			}); err != nil {
				panic(fmt.Sprintf("e.handleFragments(_, _, %d, _, _) = %s", networkMTU, err))
			}
			// Remove the packet that was just fragmented and process the rest.
			pkts.Remove(originalPkt)
		}
	}

	outNicName := e.protocol.stack.FindNICNameFromID(e.nic.ID())
	// iptables filtering. All packets that reach here are locally
	// generated.
	dropped, natPkts := e.protocol.stack.IPTables().CheckPackets(stack.Output, pkts, gso, r, "", outNicName)
	stats.IPTablesOutputDropped.IncrementBy(uint64(len(dropped)))
	for pkt := range dropped {
		pkts.Remove(pkt)
	}

	// The NAT-ed packets may now be destined for us.
	locallyDelivered := 0
	for pkt := range natPkts {
		ep := e.protocol.findEndpointWithAddress(header.IPv4(pkt.NetworkHeader().View()).DestinationAddress())
		if ep == nil {
			// The NAT-ed packet is still destined for some remote node.
			continue
		}

		// Do not send the locally destined packet out the NIC.
		pkts.Remove(pkt)

		// Deliver the packet locally.
		ep.handleLocalPacket(pkt, true /* canSkipRXChecksum */)
		locallyDelivered++

	}

	// The rest of the packets can be delivered to the NIC as a batch.
	pktsLen := pkts.Len()
	written, err := e.nic.WritePackets(r, gso, pkts, ProtocolNumber)
	stats.PacketsSent.IncrementBy(uint64(written))
	stats.OutgoingPacketErrors.IncrementBy(uint64(pktsLen - written))

	// Dropped packets aren't errors, so include them in the return value.
	return locallyDelivered + written + len(dropped), err
}

// WriteHeaderIncludedPacket implements stack.NetworkEndpoint.
func (e *endpoint) WriteHeaderIncludedPacket(r *stack.Route, pkt *stack.PacketBuffer) tcpip.Error {
	// The packet already has an IP header, but there are a few required
	// checks.
	h, ok := pkt.Data.PullUp(header.IPv4MinimumSize)
	if !ok {
		return &tcpip.ErrMalformedHeader{}
	}

	hdrLen := header.IPv4(h).HeaderLength()
	if hdrLen < header.IPv4MinimumSize {
		return &tcpip.ErrMalformedHeader{}
	}

	h, ok = pkt.Data.PullUp(int(hdrLen))
	if !ok {
		return &tcpip.ErrMalformedHeader{}
	}
	ip := header.IPv4(h)

	// Always set the total length.
	pktSize := pkt.Data.Size()
	ip.SetTotalLength(uint16(pktSize))

	// Set the source address when zero.
	if ip.SourceAddress() == header.IPv4Any {
		ip.SetSourceAddress(r.LocalAddress)
	}

	// Set the destination. If the packet already included a destination, it will
	// be part of the route anyways.
	ip.SetDestinationAddress(r.RemoteAddress)

	// Set the packet ID when zero.
	if ip.ID() == 0 {
		// RFC 6864 section 4.3 mandates uniqueness of ID values for
		// non-atomic datagrams, so assign an ID to all such datagrams
		// according to the definition given in RFC 6864 section 4.
		if ip.Flags()&header.IPv4FlagDontFragment == 0 || ip.Flags()&header.IPv4FlagMoreFragments != 0 || ip.FragmentOffset() > 0 {
			ip.SetID(uint16(atomic.AddUint32(&e.protocol.ids[hashRoute(r.LocalAddress, r.RemoteAddress, 0 /* protocol */, e.protocol.hashIV)%buckets], 1)))
		}
	}

	// Always set the checksum.
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())

	// Populate the packet buffer's network header and don't allow an invalid
	// packet to be sent.
	//
	// Note that parsing only makes sure that the packet is well formed as per the
	// wire format. We also want to check if the header's fields are valid before
	// sending the packet.
	if !parse.IPv4(pkt) || !header.IPv4(pkt.NetworkHeader().View()).IsValid(pktSize) {
		return &tcpip.ErrMalformedHeader{}
	}

	return e.writePacket(r, nil /* gso */, pkt, true /* headerIncluded */)
}

// forwardPacket attempts to forward a packet to its final destination.
func (e *endpoint) forwardPacket(pkt *stack.PacketBuffer) tcpip.Error {
	h := header.IPv4(pkt.NetworkHeader().View())
	ttl := h.TTL()
	if ttl == 0 {
		// As per RFC 792 page 6, Time Exceeded Message,
		//
		//  If the gateway processing a datagram finds the time to live field
		//  is zero it must discard the datagram.  The gateway may also notify
		//  the source host via the time exceeded message.
		return e.protocol.returnError(&icmpReasonTTLExceeded{}, pkt)
	}

	if opts := h.Options(); len(opts) != 0 {
		newOpts, _, optProblem := e.processIPOptions(pkt, opts, &optionUsageForward{})
		if optProblem != nil {
			if optProblem.NeedICMP {
				_ = e.protocol.returnError(&icmpReasonParamProblem{
					pointer:    optProblem.Pointer,
					forwarding: true,
				}, pkt)
				e.protocol.stack.Stats().MalformedRcvdPackets.Increment()
				e.stats.ip.MalformedPacketsReceived.Increment()
			}
			return nil // option problems are not reported locally.
		}
		copied := copy(opts, newOpts)
		if copied != len(newOpts) {
			panic(fmt.Sprintf("copied %d bytes of new options, expected %d bytes", copied, len(newOpts)))
		}
		// Since in forwarding we handle all options, including copying those we
		// do not recognise, the options region should remain the same size which
		// simplifies processing. As we MAY receive a packet with a lot of padded
		// bytes after the "end of options list" byte, make sure we copy
		// them as the legal padding value (0).
		for i := copied; i < len(opts); i++ {
			// Pad with 0 (EOL). RFC 791 page 23 says "The padding is zero".
			opts[i] = byte(header.IPv4OptionListEndType)
		}
	}

	dstAddr := h.DestinationAddress()

	// Check if the destination is owned by the stack.
	if ep := e.protocol.findEndpointWithAddress(dstAddr); ep != nil {
		ep.handlePacket(pkt)
		return nil
	}

	r, err := e.protocol.stack.FindRoute(0, "", dstAddr, ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		return err
	}
	defer r.Release()

	// We need to do a deep copy of the IP packet because
	// WriteHeaderIncludedPacket takes ownership of the packet buffer, but we do
	// not own it.
	newHdr := header.IPv4(stack.PayloadSince(pkt.NetworkHeader()))

	// As per RFC 791 page 30, Time to Live,
	//
	//   This field must be decreased at each point that the internet header
	//   is processed to reflect the time spent processing the datagram.
	//   Even if no local information is available on the time actually
	//   spent, the field must be decremented by 1.
	newHdr.SetTTL(ttl - 1)

	return r.WriteHeaderIncludedPacket(stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Data:               buffer.View(newHdr).ToVectorisedView(),
	}))
}

// HandlePacket is called by the link layer when new ipv4 packets arrive for
// this endpoint.
func (e *endpoint) HandlePacket(pkt *stack.PacketBuffer) {
	stats := e.stats.ip

	stats.PacketsReceived.Increment()

	if !e.isEnabled() {
		stats.DisabledPacketsReceived.Increment()
		return
	}

	if !e.protocol.parse(pkt) {
		stats.MalformedPacketsReceived.Increment()
		return
	}

	if !e.nic.IsLoopback() {
		if e.protocol.stack.HandleLocal() {
			addressEndpoint := e.AcquireAssignedAddress(header.IPv4(pkt.NetworkHeader().View()).SourceAddress(), e.nic.Promiscuous(), stack.CanBePrimaryEndpoint)
			if addressEndpoint != nil {
				addressEndpoint.DecRef()

				// The source address is one of our own, so we never should have gotten
				// a packet like this unless HandleLocal is false or our NIC is the
				// loopback interface.
				stats.InvalidSourceAddressesReceived.Increment()
				return
			}
		}

		// Loopback traffic skips the prerouting chain.
		inNicName := e.protocol.stack.FindNICNameFromID(e.nic.ID())
		if ok := e.protocol.stack.IPTables().Check(stack.Prerouting, pkt, nil, nil, e.MainAddress().Address, inNicName, "" /* outNicName */); !ok {
			// iptables is telling us to drop the packet.
			stats.IPTablesPreroutingDropped.Increment()
			return
		}
	}

	e.handlePacket(pkt)
}

func (e *endpoint) handleLocalPacket(pkt *stack.PacketBuffer, canSkipRXChecksum bool) {
	stats := e.stats.ip

	stats.PacketsReceived.Increment()

	pkt = pkt.CloneToInbound()
	if e.protocol.parse(pkt) {
		pkt.RXTransportChecksumValidated = canSkipRXChecksum
		e.handlePacket(pkt)
		return
	}

	stats.MalformedPacketsReceived.Increment()
}

// handlePacket is like HandlePacket except it does not perform the prerouting
// iptables hook.
func (e *endpoint) handlePacket(pkt *stack.PacketBuffer) {
	pkt.NICID = e.nic.ID()
	stats := e.stats

	h := header.IPv4(pkt.NetworkHeader().View())
	if !h.IsValid(pkt.Data.Size() + pkt.NetworkHeader().View().Size() + pkt.TransportHeader().View().Size()) {
		stats.ip.MalformedPacketsReceived.Increment()
		return
	}

	// There has been some confusion regarding verifying checksums. We need
	// just look for negative 0 (0xffff) as the checksum, as it's not possible to
	// get positive 0 (0) for the checksum. Some bad implementations could get it
	// when doing entry replacement in the early days of the Internet,
	// however the lore that one needs to check for both persists.
	//
	// RFC 1624 section 1 describes the source of this confusion as:
	//     [the partial recalculation method described in RFC 1071] computes a
	//     result for certain cases that differs from the one obtained from
	//     scratch (one's complement of one's complement sum of the original
	//     fields).
	//
	// However RFC 1624 section 5 clarifies that if using the verification method
	// "recommended by RFC 1071, it does not matter if an intermediate system
	// generated a -0 instead of +0".
	//
	// RFC1071 page 1 specifies the verification method as:
	//	  (3)  To check a checksum, the 1's complement sum is computed over the
	//        same set of octets, including the checksum field.  If the result
	//        is all 1 bits (-0 in 1's complement arithmetic), the check
	//        succeeds.
	if h.CalculateChecksum() != 0xffff {
		stats.ip.MalformedPacketsReceived.Increment()
		return
	}

	srcAddr := h.SourceAddress()
	dstAddr := h.DestinationAddress()

	// As per RFC 1122 section 3.2.1.3:
	//   When a host sends any datagram, the IP source address MUST
	//   be one of its own IP addresses (but not a broadcast or
	//   multicast address).
	if srcAddr == header.IPv4Broadcast || header.IsV4MulticastAddress(srcAddr) {
		stats.ip.InvalidSourceAddressesReceived.Increment()
		return
	}
	// Make sure the source address is not a subnet-local broadcast address.
	if addressEndpoint := e.AcquireAssignedAddress(srcAddr, false /* createTemp */, stack.NeverPrimaryEndpoint); addressEndpoint != nil {
		subnet := addressEndpoint.Subnet()
		addressEndpoint.DecRef()
		if subnet.IsBroadcast(srcAddr) {
			stats.ip.InvalidSourceAddressesReceived.Increment()
			return
		}
	}

	// Before we do any processing, note if the packet was received as some
	// sort of broadcast. The destination address should be an address we own
	// or a group we joined.
	if addressEndpoint := e.AcquireAssignedAddress(dstAddr, e.nic.Promiscuous(), stack.CanBePrimaryEndpoint); addressEndpoint != nil {
		subnet := addressEndpoint.AddressWithPrefix().Subnet()
		addressEndpoint.DecRef()
		pkt.NetworkPacketInfo.LocalAddressBroadcast = subnet.IsBroadcast(dstAddr) || dstAddr == header.IPv4Broadcast
	} else if !e.IsInGroup(dstAddr) {
		if !e.protocol.Forwarding() {
			stats.ip.InvalidDestinationAddressesReceived.Increment()
			return
		}
		_ = e.forwardPacket(pkt)
		return
	}

	// iptables filtering. All packets that reach here are intended for
	// this machine and will not be forwarded.
	inNicName := e.protocol.stack.FindNICNameFromID(e.nic.ID())
	if ok := e.protocol.stack.IPTables().Check(stack.Input, pkt, nil, nil, "" /* preroutingAddr */, inNicName, "" /* outNicName */); !ok {
		// iptables is telling us to drop the packet.
		stats.ip.IPTablesInputDropped.Increment()
		return
	}

	if h.More() || h.FragmentOffset() != 0 {
		if pkt.Data.Size()+pkt.TransportHeader().View().Size() == 0 {
			// Drop the packet as it's marked as a fragment but has
			// no payload.
			stats.ip.MalformedPacketsReceived.Increment()
			stats.ip.MalformedFragmentsReceived.Increment()
			return
		}
		if opts := h.Options(); len(opts) != 0 {
			// If there are options we need to check them before we do assembly
			// or we could be assembling errant packets. However we do not change the
			// options as that could lead to double processing later.
			if _, _, optProblem := e.processIPOptions(pkt, opts, &optionUsageVerify{}); optProblem != nil {
				if optProblem.NeedICMP {
					_ = e.protocol.returnError(&icmpReasonParamProblem{
						pointer: optProblem.Pointer,
					}, pkt)
					e.protocol.stack.Stats().MalformedRcvdPackets.Increment()
					e.stats.ip.MalformedPacketsReceived.Increment()
				}
				return
			}
		}
		// The packet is a fragment, let's try to reassemble it.
		start := h.FragmentOffset()
		// Drop the fragment if the size of the reassembled payload would exceed the
		// maximum payload size.
		//
		// Note that this addition doesn't overflow even on 32bit architecture
		// because pkt.Data.Size() should not exceed 65535 (the max IP datagram
		// size). Otherwise the packet would've been rejected as invalid before
		// reaching here.
		if int(start)+pkt.Data.Size() > header.IPv4MaximumPayloadSize {
			stats.ip.MalformedPacketsReceived.Increment()
			stats.ip.MalformedFragmentsReceived.Increment()
			return
		}

		proto := h.Protocol()
		resPkt, _, ready, err := e.protocol.fragmentation.Process(
			// As per RFC 791 section 2.3, the identification value is unique
			// for a source-destination pair and protocol.
			fragmentation.FragmentID{
				Source:      h.SourceAddress(),
				Destination: h.DestinationAddress(),
				ID:          uint32(h.ID()),
				Protocol:    proto,
			},
			start,
			start+uint16(pkt.Data.Size())-1,
			h.More(),
			proto,
			pkt,
		)
		if err != nil {
			stats.ip.MalformedPacketsReceived.Increment()
			stats.ip.MalformedFragmentsReceived.Increment()
			return
		}
		if !ready {
			return
		}
		pkt = resPkt
		h = header.IPv4(pkt.NetworkHeader().View())

		// The reassembler doesn't take care of fixing up the header, so we need
		// to do it here.
		h.SetTotalLength(uint16(pkt.Data.Size() + len((h))))
		h.SetFlagsFragmentOffset(0, 0)
	}
	stats.ip.PacketsDelivered.Increment()

	p := h.TransportProtocol()
	if p == header.ICMPv4ProtocolNumber {
		// TODO(gvisor.dev/issues/3810): when we sort out ICMP and transport
		// headers, the setting of the transport number here should be
		// unnecessary and removed.
		pkt.TransportProtocolNumber = p
		e.handleICMP(pkt)
		return
	}
	// ICMP handles options itself but do it here for all remaining destinations.
	var hasRouterAlertOption bool
	if opts := h.Options(); len(opts) != 0 {
		newOpts, processedOpts, optProblem := e.processIPOptions(pkt, opts, &optionUsageReceive{})
		if optProblem != nil {
			if optProblem.NeedICMP {
				_ = e.protocol.returnError(&icmpReasonParamProblem{
					pointer: optProblem.Pointer,
				}, pkt)
				e.protocol.stack.Stats().MalformedRcvdPackets.Increment()
				stats.ip.MalformedPacketsReceived.Increment()
			}
			return
		}
		hasRouterAlertOption = processedOpts.routerAlert
		copied := copy(opts, newOpts)
		if copied != len(newOpts) {
			panic(fmt.Sprintf("copied %d bytes of new options, expected %d bytes", copied, len(newOpts)))
		}
		for i := copied; i < len(opts); i++ {
			// Pad with 0 (EOL). RFC 791 page 23 says "The padding is zero".
			opts[i] = byte(header.IPv4OptionListEndType)
		}
	}
	if p == header.IGMPProtocolNumber {
		e.mu.Lock()
		e.mu.igmp.handleIGMP(pkt, hasRouterAlertOption)
		e.mu.Unlock()
		return
	}

	switch res := e.dispatcher.DeliverTransportPacket(p, pkt); res {
	case stack.TransportPacketHandled:
	case stack.TransportPacketDestinationPortUnreachable:
		// As per RFC: 1122 Section 3.2.2.1 A host SHOULD generate Destination
		//   Unreachable messages with code:
		//     3 (Port Unreachable), when the designated transport protocol
		//     (e.g., UDP) is unable to demultiplex the datagram but has no
		//     protocol mechanism to inform the sender.
		_ = e.protocol.returnError(&icmpReasonPortUnreachable{}, pkt)
	case stack.TransportPacketProtocolUnreachable:
		// As per RFC: 1122 Section 3.2.2.1
		//   A host SHOULD generate Destination Unreachable messages with code:
		//     2 (Protocol Unreachable), when the designated transport protocol
		//     is not supported
		_ = e.protocol.returnError(&icmpReasonProtoUnreachable{}, pkt)
	default:
		panic(fmt.Sprintf("unrecognized result from DeliverTransportPacket = %d", res))
	}
}

// Close cleans up resources associated with the endpoint.
func (e *endpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.disableLocked()
	e.mu.addressableEndpointState.Cleanup()

	e.protocol.forgetEndpoint(e.nic.ID())
}

// AddAndAcquirePermanentAddress implements stack.AddressableEndpoint.
func (e *endpoint) AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, peb stack.PrimaryEndpointBehavior, configType stack.AddressConfigType, deprecated bool) (stack.AddressEndpoint, tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	ep, err := e.mu.addressableEndpointState.AddAndAcquirePermanentAddress(addr, peb, configType, deprecated)
	if err == nil {
		e.mu.igmp.sendQueuedReports()
	}
	return ep, err
}

// RemovePermanentAddress implements stack.AddressableEndpoint.
func (e *endpoint) RemovePermanentAddress(addr tcpip.Address) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.addressableEndpointState.RemovePermanentAddress(addr)
}

// MainAddress implements stack.AddressableEndpoint.
func (e *endpoint) MainAddress() tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.MainAddress()
}

// AcquireAssignedAddress implements stack.AddressableEndpoint.
func (e *endpoint) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior) stack.AddressEndpoint {
	e.mu.Lock()
	defer e.mu.Unlock()

	loopback := e.nic.IsLoopback()
	return e.mu.addressableEndpointState.AcquireAssignedAddressOrMatching(localAddr, func(addressEndpoint stack.AddressEndpoint) bool {
		subnet := addressEndpoint.Subnet()
		// IPv4 has a notion of a subnet broadcast address and considers the
		// loopback interface bound to an address's whole subnet (on linux).
		return subnet.IsBroadcast(localAddr) || (loopback && subnet.Contains(localAddr))
	}, allowTemp, tempPEB)
}

// AcquireOutgoingPrimaryAddress implements stack.AddressableEndpoint.
func (e *endpoint) AcquireOutgoingPrimaryAddress(remoteAddr tcpip.Address, allowExpired bool) stack.AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.acquireOutgoingPrimaryAddressRLocked(remoteAddr, allowExpired)
}

// acquireOutgoingPrimaryAddressRLocked is like AcquireOutgoingPrimaryAddress
// but with locking requirements
//
// Precondition: igmp.ep.mu must be read locked.
func (e *endpoint) acquireOutgoingPrimaryAddressRLocked(remoteAddr tcpip.Address, allowExpired bool) stack.AddressEndpoint {
	return e.mu.addressableEndpointState.AcquireOutgoingPrimaryAddress(remoteAddr, allowExpired)
}

// PrimaryAddresses implements stack.AddressableEndpoint.
func (e *endpoint) PrimaryAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.PrimaryAddresses()
}

// PermanentAddresses implements stack.AddressableEndpoint.
func (e *endpoint) PermanentAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.PermanentAddresses()
}

// JoinGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) JoinGroup(addr tcpip.Address) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.joinGroupLocked(addr)
}

// joinGroupLocked is like JoinGroup but with locking requirements.
//
// Precondition: e.mu must be locked.
func (e *endpoint) joinGroupLocked(addr tcpip.Address) tcpip.Error {
	if !header.IsV4MulticastAddress(addr) {
		return &tcpip.ErrBadAddress{}
	}

	e.mu.igmp.joinGroup(addr)
	return nil
}

// LeaveGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) LeaveGroup(addr tcpip.Address) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.leaveGroupLocked(addr)
}

// leaveGroupLocked is like LeaveGroup but with locking requirements.
//
// Precondition: e.mu must be locked.
func (e *endpoint) leaveGroupLocked(addr tcpip.Address) tcpip.Error {
	return e.mu.igmp.leaveGroup(addr)
}

// IsInGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) IsInGroup(addr tcpip.Address) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.igmp.isInGroup(addr)
}

// Stats implements stack.NetworkEndpoint.
func (e *endpoint) Stats() stack.NetworkEndpointStats {
	return &e.stats.localStats
}

var _ stack.ForwardingNetworkProtocol = (*protocol)(nil)
var _ stack.NetworkProtocol = (*protocol)(nil)
var _ fragmentation.TimeoutHandler = (*protocol)(nil)

type protocol struct {
	stack *stack.Stack

	mu struct {
		sync.RWMutex

		// eps is keyed by NICID to allow protocol methods to retrieve an endpoint
		// when handling a packet, by looking at which NIC handled the packet.
		eps map[tcpip.NICID]*endpoint
	}

	// defaultTTL is the current default TTL for the protocol. Only the
	// uint8 portion of it is meaningful.
	//
	// Must be accessed using atomic operations.
	defaultTTL uint32

	// forwarding is set to 1 when the protocol has forwarding enabled and 0
	// when it is disabled.
	//
	// Must be accessed using atomic operations.
	forwarding uint32

	ids    []uint32
	hashIV uint32

	fragmentation *fragmentation.Fragmentation

	options Options
}

// Number returns the ipv4 protocol number.
func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

// MinimumPacketSize returns the minimum valid ipv4 packet size.
func (p *protocol) MinimumPacketSize() int {
	return header.IPv4MinimumSize
}

// DefaultPrefixLen returns the IPv4 default prefix length.
func (p *protocol) DefaultPrefixLen() int {
	return header.IPv4AddressSize * 8
}

// ParseAddresses implements NetworkProtocol.ParseAddresses.
func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.IPv4(v)
	return h.SourceAddress(), h.DestinationAddress()
}

// SetOption implements NetworkProtocol.SetOption.
func (p *protocol) SetOption(option tcpip.SettableNetworkProtocolOption) tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		p.SetDefaultTTL(uint8(*v))
		return nil
	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

// Option implements NetworkProtocol.Option.
func (p *protocol) Option(option tcpip.GettableNetworkProtocolOption) tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		*v = tcpip.DefaultTTLOption(p.DefaultTTL())
		return nil
	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

// SetDefaultTTL sets the default TTL for endpoints created with this protocol.
func (p *protocol) SetDefaultTTL(ttl uint8) {
	atomic.StoreUint32(&p.defaultTTL, uint32(ttl))
}

// DefaultTTL returns the default TTL for endpoints created with this protocol.
func (p *protocol) DefaultTTL() uint8 {
	return uint8(atomic.LoadUint32(&p.defaultTTL))
}

// Close implements stack.TransportProtocol.Close.
func (*protocol) Close() {}

// Wait implements stack.TransportProtocol.Wait.
func (*protocol) Wait() {}

// parse is like Parse but also attempts to parse the transport layer.
//
// Returns true if the network header was successfully parsed.
func (p *protocol) parse(pkt *stack.PacketBuffer) bool {
	transProtoNum, hasTransportHdr, ok := p.Parse(pkt)
	if !ok {
		return false
	}

	if hasTransportHdr {
		switch err := p.stack.ParsePacketBufferTransport(transProtoNum, pkt); err {
		case stack.ParsedOK:
		case stack.UnknownTransportProtocol, stack.TransportLayerParseError:
			// The transport layer will handle unknown protocols and transport layer
			// parsing errors.
		default:
			panic(fmt.Sprintf("unexpected error parsing transport header = %d", err))
		}
	}

	return true
}

// Parse implements stack.NetworkProtocol.Parse.
func (*protocol) Parse(pkt *stack.PacketBuffer) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool) {
	if ok := parse.IPv4(pkt); !ok {
		return 0, false, false
	}

	ipHdr := header.IPv4(pkt.NetworkHeader().View())
	return ipHdr.TransportProtocol(), !ipHdr.More() && ipHdr.FragmentOffset() == 0, true
}

// Forwarding implements stack.ForwardingNetworkProtocol.
func (p *protocol) Forwarding() bool {
	return uint8(atomic.LoadUint32(&p.forwarding)) == 1
}

// SetForwarding implements stack.ForwardingNetworkProtocol.
func (p *protocol) SetForwarding(v bool) {
	if v {
		atomic.StoreUint32(&p.forwarding, 1)
	} else {
		atomic.StoreUint32(&p.forwarding, 0)
	}
}

// calculateNetworkMTU calculates the network-layer payload MTU based on the
// link-layer payload mtu.
func calculateNetworkMTU(linkMTU, networkHeaderSize uint32) (uint32, tcpip.Error) {
	if linkMTU < header.IPv4MinimumMTU {
		return 0, &tcpip.ErrInvalidEndpointState{}
	}

	// As per RFC 791 section 3.1, an IPv4 header cannot exceed 60 bytes in
	// length:
	//   The maximal internet header is 60 octets, and a typical internet header
	//   is 20 octets, allowing a margin for headers of higher level protocols.
	if networkHeaderSize > header.IPv4MaximumHeaderSize {
		return 0, &tcpip.ErrMalformedHeader{}
	}

	networkMTU := linkMTU
	if networkMTU > MaxTotalSize {
		networkMTU = MaxTotalSize
	}

	return networkMTU - uint32(networkHeaderSize), nil
}

func packetMustBeFragmented(pkt *stack.PacketBuffer, networkMTU uint32, gso *stack.GSO) bool {
	payload := pkt.TransportHeader().View().Size() + pkt.Data.Size()
	return (gso == nil || gso.Type == stack.GSONone) && uint32(payload) > networkMTU
}

// addressToUint32 translates an IPv4 address into its little endian uint32
// representation.
//
// This function does the same thing as binary.LittleEndian.Uint32 but operates
// on a tcpip.Address (a string) without the need to convert it to a byte slice,
// which would cause an allocation.
func addressToUint32(addr tcpip.Address) uint32 {
	_ = addr[3] // bounds check hint to compiler
	return uint32(addr[0]) | uint32(addr[1])<<8 | uint32(addr[2])<<16 | uint32(addr[3])<<24
}

// hashRoute calculates a hash value for the given source/destination pair using
// the addresses, transport protocol number and a 32-bit number to generate the
// hash.
func hashRoute(srcAddr, dstAddr tcpip.Address, protocol tcpip.TransportProtocolNumber, hashIV uint32) uint32 {
	a := addressToUint32(srcAddr)
	b := addressToUint32(dstAddr)
	return hash.Hash3Words(a, b, uint32(protocol), hashIV)
}

// Options holds options to configure a new protocol.
type Options struct {
	// IGMP holds options for IGMP.
	IGMP IGMPOptions
}

// NewProtocolWithOptions returns an IPv4 network protocol.
func NewProtocolWithOptions(opts Options) stack.NetworkProtocolFactory {
	ids := make([]uint32, buckets)

	// Randomly initialize hashIV and the ids.
	r := hash.RandN32(1 + buckets)
	for i := range ids {
		ids[i] = r[i]
	}
	hashIV := r[buckets]

	return func(s *stack.Stack) stack.NetworkProtocol {
		p := &protocol{
			stack:      s,
			ids:        ids,
			hashIV:     hashIV,
			defaultTTL: DefaultTTL,
			options:    opts,
		}
		p.fragmentation = fragmentation.NewFragmentation(fragmentblockSize, fragmentation.HighFragThreshold, fragmentation.LowFragThreshold, ReassembleTimeout, s.Clock(), p)
		p.mu.eps = make(map[tcpip.NICID]*endpoint)
		return p
	}
}

// NewProtocol is equivalent to NewProtocolWithOptions with an empty Options.
func NewProtocol(s *stack.Stack) stack.NetworkProtocol {
	return NewProtocolWithOptions(Options{})(s)
}

func buildNextFragment(pf *fragmentation.PacketFragmenter, originalIPHeader header.IPv4) (*stack.PacketBuffer, bool) {
	fragPkt, offset, copied, more := pf.BuildNextFragment()
	fragPkt.NetworkProtocolNumber = ProtocolNumber

	originalIPHeaderLength := len(originalIPHeader)
	nextFragIPHeader := header.IPv4(fragPkt.NetworkHeader().Push(originalIPHeaderLength))
	fragPkt.NetworkProtocolNumber = ProtocolNumber

	if copied := copy(nextFragIPHeader, originalIPHeader); copied != len(originalIPHeader) {
		panic(fmt.Sprintf("wrong number of bytes copied into fragmentIPHeaders: got = %d, want = %d", copied, originalIPHeaderLength))
	}

	flags := originalIPHeader.Flags()
	if more {
		flags |= header.IPv4FlagMoreFragments
	}
	nextFragIPHeader.SetFlagsFragmentOffset(flags, uint16(offset))
	nextFragIPHeader.SetTotalLength(uint16(nextFragIPHeader.HeaderLength()) + uint16(copied))
	nextFragIPHeader.SetChecksum(0)
	nextFragIPHeader.SetChecksum(^nextFragIPHeader.CalculateChecksum())

	return fragPkt, more
}

// optionAction describes possible actions that may be taken on an option
// while processing it.
type optionAction uint8

const (
	// optionRemove says that the option should not be in the output option set.
	optionRemove optionAction = iota

	// optionProcess says that the option should be fully processed.
	optionProcess

	// optionVerify says the option should be checked and passed unchanged.
	optionVerify

	// optionPass says to pass the output set without checking.
	optionPass
)

// optionActions list what to do for each option in a given scenario.
type optionActions struct {
	// timestamp controls what to do with a Timestamp option.
	timestamp optionAction

	// recordRoute controls what to do with a Record Route option.
	recordRoute optionAction

	// routerAlert controls what to do with a Router Alert option.
	routerAlert optionAction

	// unknown controls what to do with an unknown option.
	unknown optionAction
}

// optionsUsage specifies the ways options may be operated upon for a given
// scenario during packet processing.
type optionsUsage interface {
	actions() optionActions
}

// optionUsageVerify implements optionsUsage for when we just want to check
// fragments. Don't change anything, just check and reject if bad. No
// replacement options are generated.
type optionUsageVerify struct{}

// actions implements optionsUsage.
func (*optionUsageVerify) actions() optionActions {
	return optionActions{
		timestamp:   optionVerify,
		recordRoute: optionVerify,
		routerAlert: optionVerify,
		unknown:     optionRemove,
	}
}

// optionUsageReceive implements optionsUsage for packets we will pass
// to the transport layer (with the exception of Echo requests).
type optionUsageReceive struct{}

// actions implements optionsUsage.
func (*optionUsageReceive) actions() optionActions {
	return optionActions{
		timestamp:   optionProcess,
		recordRoute: optionProcess,
		routerAlert: optionVerify,
		unknown:     optionPass,
	}
}

// optionUsageForward implements optionsUsage for packets about to be forwarded.
// All options are passed on regardless of whether we recognise them, however
// we do process the Timestamp and Record Route options.
type optionUsageForward struct{}

// actions implements optionsUsage.
func (*optionUsageForward) actions() optionActions {
	return optionActions{
		timestamp:   optionProcess,
		recordRoute: optionProcess,
		routerAlert: optionVerify,
		unknown:     optionPass,
	}
}

// optionUsageEcho implements optionsUsage for echo packet processing.
// Only Timestamp and RecordRoute are processed and sent back.
type optionUsageEcho struct{}

// actions implements optionsUsage.
func (*optionUsageEcho) actions() optionActions {
	return optionActions{
		timestamp:   optionProcess,
		recordRoute: optionProcess,
		routerAlert: optionVerify,
		unknown:     optionRemove,
	}
}

// handleTimestamp does any required processing on a Timestamp option
// in place.
func handleTimestamp(tsOpt header.IPv4OptionTimestamp, localAddress tcpip.Address, clock tcpip.Clock, usage optionsUsage) *header.IPv4OptParameterProblem {
	flags := tsOpt.Flags()
	var entrySize uint8
	switch flags {
	case header.IPv4OptionTimestampOnlyFlag:
		entrySize = header.IPv4OptionTimestampSize
	case
		header.IPv4OptionTimestampWithIPFlag,
		header.IPv4OptionTimestampWithPredefinedIPFlag:
		entrySize = header.IPv4OptionTimestampWithAddrSize
	default:
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptTSOFLWAndFLGOffset,
			NeedICMP: true,
		}
	}

	pointer := tsOpt.Pointer()
	// RFC 791 page 22 states: "The smallest legal value is 5."
	// Since the pointer is 1 based, and the header is 4 bytes long the
	// pointer must point beyond the header therefore 4 or less is bad.
	if pointer <= header.IPv4OptionTimestampHdrLength {
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptTSPointerOffset,
			NeedICMP: true,
		}
	}
	// To simplify processing below, base further work on the array of timestamps
	// beyond the header, rather than on the whole option. Also to aid
	// calculations set 'nextSlot' to be 0 based as in the packet it is 1 based.
	nextSlot := pointer - (header.IPv4OptionTimestampHdrLength + 1)
	optLen := tsOpt.Size()
	dataLength := optLen - header.IPv4OptionTimestampHdrLength

	// In the section below, we verify the pointer, length and overflow counter
	// fields of the option. The distinction is in which byte you return as being
	// in error in the ICMP packet. Offsets 1 (length), 2 pointer)
	// or 3 (overflowed counter).
	//
	// The following RFC sections cover this section:
	//
	// RFC 791 (page 22):
	//    If there is some room but not enough room for a full timestamp
	//    to be inserted, or the overflow count itself overflows, the
	//    original datagram is considered to be in error and is discarded.
	//    In either case an ICMP parameter problem message may be sent to
	//    the source host [3].
	//
	// You can get this situation in two ways. Firstly if the data area is not
	// a multiple of the entry size or secondly, if the pointer is not at a
	// multiple of the entry size. The wording of the RFC suggests that
	// this is not an error until you actually run out of space.
	if pointer > optLen {
		// RFC 791 (page 22) says we should switch to using the overflow count.
		//    If the timestamp data area is already full (the pointer exceeds
		//    the length) the datagram is forwarded without inserting the
		//    timestamp, but the overflow count is incremented by one.
		if flags == header.IPv4OptionTimestampWithPredefinedIPFlag {
			// By definition we have nothing to do.
			return nil
		}

		if tsOpt.IncOverflow() != 0 {
			return nil
		}
		// The overflow count is also full.
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptTSOFLWAndFLGOffset,
			NeedICMP: true,
		}
	}
	if nextSlot+entrySize > dataLength {
		// The data area isn't full but there isn't room for a new entry.
		// Either Length or Pointer could be bad.
		if false {
			// We must select Pointer for Linux compatibility, even if
			// only the length is bad.
			// The Linux code is at (in October 2020)
			// https://github.com/torvalds/linux/blob/bbf5c979011a099af5dc76498918ed7df445635b/net/ipv4/ip_options.c#L367-L370
			//		if (optptr[2]+3 > optlen) {
			//			pp_ptr = optptr + 2;
			//			goto error;
			//		}
			// which doesn't distinguish between which of optptr[2] or optlen
			// is wrong, but just arbitrarily decides on optptr+2.
			if dataLength%entrySize != 0 {
				// The Data section size should be a multiple of the expected
				// timestamp entry size.
				return &header.IPv4OptParameterProblem{
					Pointer:  header.IPv4OptionLengthOffset,
					NeedICMP: false,
				}
			}
			// If the size is OK, the pointer must be corrupted.
		}
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptTSPointerOffset,
			NeedICMP: true,
		}
	}

	if usage.actions().timestamp == optionProcess {
		tsOpt.UpdateTimestamp(localAddress, clock)
	}
	return nil
}

// handleRecordRoute checks and processes a Record route option. It is much
// like the timestamp type 1 option, but without timestamps. The passed in
// address is stored in the option in the correct spot if possible.
func handleRecordRoute(rrOpt header.IPv4OptionRecordRoute, localAddress tcpip.Address, usage optionsUsage) *header.IPv4OptParameterProblem {
	optlen := rrOpt.Size()

	if optlen < header.IPv4AddressSize+header.IPv4OptionRecordRouteHdrLength {
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptionLengthOffset,
			NeedICMP: true,
		}
	}

	pointer := rrOpt.Pointer()
	// RFC 791 page 20 states:
	//      The pointer is relative to this option, and the
	//      smallest legal value for the pointer is 4.
	// Since the pointer is 1 based, and the header is 3 bytes long the
	// pointer must point beyond the header therefore 3 or less is bad.
	if pointer <= header.IPv4OptionRecordRouteHdrLength {
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptRRPointerOffset,
			NeedICMP: true,
		}
	}

	// RFC 791 page 21 says
	//       If the route data area is already full (the pointer exceeds the
	//       length) the datagram is forwarded without inserting the address
	//       into the recorded route. If there is some room but not enough
	//       room for a full address to be inserted, the original datagram is
	//       considered to be in error and is discarded.  In either case an
	//       ICMP parameter problem message may be sent to the source
	//       host.
	// The use of the words "In either case" suggests that a 'full' RR option
	// could generate an ICMP at every hop after it fills up. We chose to not
	// do this (as do most implementations). It is probable that the inclusion
	// of these words is a copy/paste error from the timestamp option where
	// there are two failure reasons given.
	if pointer > optlen {
		return nil
	}

	// The data area isn't full but there isn't room for a new entry.
	// Either Length or Pointer could be bad. We must select Pointer for Linux
	// compatibility, even if only the length is bad. NB. pointer is 1 based.
	if pointer+header.IPv4AddressSize > optlen+1 {
		if false {
			// This is what we would do if we were not being Linux compatible.
			// Check for bad pointer or length value. Must be a multiple of 4 after
			// accounting for the 3 byte header and not within that header.
			// RFC 791, page 20 says:
			//       The pointer is relative to this option, and the
			//       smallest legal value for the pointer is 4.
			//
			//       A recorded route is composed of a series of internet addresses.
			//       Each internet address is 32 bits or 4 octets.
			// Linux skips this test so we must too.  See Linux code at:
			// https://github.com/torvalds/linux/blob/bbf5c979011a099af5dc76498918ed7df445635b/net/ipv4/ip_options.c#L338-L341
			//    if (optptr[2]+3 > optlen) {
			//      pp_ptr = optptr + 2;
			//      goto error;
			//    }
			if (optlen-header.IPv4OptionRecordRouteHdrLength)%header.IPv4AddressSize != 0 {
				// Length is bad, not on integral number of slots.
				return &header.IPv4OptParameterProblem{
					Pointer:  header.IPv4OptionLengthOffset,
					NeedICMP: true,
				}
			}
			// If not length, the fault must be with the pointer.
		}
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptRRPointerOffset,
			NeedICMP: true,
		}
	}
	if usage.actions().recordRoute == optionVerify {
		return nil
	}
	rrOpt.StoreAddress(localAddress)
	return nil
}

// handleRouterAlert performs sanity checks on a Router Alert option.
func handleRouterAlert(raOpt header.IPv4OptionRouterAlert) *header.IPv4OptParameterProblem {
	// Only the zero value is acceptable, as per RFC 2113, section 2.1:
	//   Value:  A two octet code with the following values:
	//     0 - Router shall examine packet
	//     1-65535 - Reserved
	if raOpt.Value() != header.IPv4OptionRouterAlertValue {
		return &header.IPv4OptParameterProblem{
			Pointer:  header.IPv4OptionRouterAlertValueOffset,
			NeedICMP: true,
		}
	}
	return nil
}

type optionTracker struct {
	timestamp   bool
	recordRoute bool
	routerAlert bool
}

// processIPOptions parses the IPv4 options and produces a new set of options
// suitable for use in the next step of packet processing as informed by usage.
// The original will not be touched.
//
// If there were no errors during parsing, the new set of options is returned as
// a new buffer.
func (e *endpoint) processIPOptions(pkt *stack.PacketBuffer, orig header.IPv4Options, usage optionsUsage) (header.IPv4Options, optionTracker, *header.IPv4OptParameterProblem) {
	stats := e.stats.ip
	opts := header.IPv4Options(orig)
	optIter := opts.MakeIterator()

	// Except NOP, each option must only appear at most once (RFC 791 section 3.1,
	// at the definition of every type).
	// Keep track of each option we find to enable duplicate option detection.
	var seenOptions [math.MaxUint8 + 1]bool

	// TODO(https://gvisor.dev/issue/4586): This will need tweaking when we start
	// really forwarding packets as we may need to get two addresses, for rx and
	// tx interfaces. We will also have to take usage into account.
	prefixedAddress, ok := e.protocol.stack.GetMainNICAddress(e.nic.ID(), ProtocolNumber)
	localAddress := prefixedAddress.Address
	if !ok {
		h := header.IPv4(pkt.NetworkHeader().View())
		dstAddr := h.DestinationAddress()
		if pkt.NetworkPacketInfo.LocalAddressBroadcast || header.IsV4MulticastAddress(dstAddr) {
			return nil, optionTracker{}, &header.IPv4OptParameterProblem{
				NeedICMP: false,
			}
		}
		localAddress = dstAddr
	}

	var optionsProcessed optionTracker
	for {
		option, done, optProblem := optIter.Next()
		if done || optProblem != nil {
			return optIter.Finalize(), optionsProcessed, optProblem
		}
		optType := option.Type()
		if optType == header.IPv4OptionNOPType {
			optIter.PushNOPOrEnd(optType)
			continue
		}
		if optType == header.IPv4OptionListEndType {
			optIter.PushNOPOrEnd(optType)
			return optIter.Finalize(), optionsProcessed, nil
		}

		// check for repeating options (multiple NOPs are OK)
		if seenOptions[optType] {
			return nil, optionTracker{}, &header.IPv4OptParameterProblem{
				Pointer:  optIter.ErrCursor,
				NeedICMP: true,
			}
		}
		seenOptions[optType] = true

		optLen, optProblem := func() (int, *header.IPv4OptParameterProblem) {
			switch option := option.(type) {
			case *header.IPv4OptionTimestamp:
				stats.OptionTimestampReceived.Increment()
				optionsProcessed.timestamp = true
				if usage.actions().timestamp != optionRemove {
					clock := e.protocol.stack.Clock()
					newBuffer := optIter.InitReplacement(option)
					optProblem := handleTimestamp(header.IPv4OptionTimestamp(newBuffer), localAddress, clock, usage)
					return len(newBuffer), optProblem
				}

			case *header.IPv4OptionRecordRoute:
				stats.OptionRecordRouteReceived.Increment()
				optionsProcessed.recordRoute = true
				if usage.actions().recordRoute != optionRemove {
					newBuffer := optIter.InitReplacement(option)
					optProblem := handleRecordRoute(header.IPv4OptionRecordRoute(newBuffer), localAddress, usage)
					return len(newBuffer), optProblem
				}

			case *header.IPv4OptionRouterAlert:
				stats.OptionRouterAlertReceived.Increment()
				optionsProcessed.routerAlert = true
				if usage.actions().routerAlert != optionRemove {
					newBuffer := optIter.InitReplacement(option)
					optProblem := handleRouterAlert(header.IPv4OptionRouterAlert(newBuffer))
					return len(newBuffer), optProblem
				}

			default:
				stats.OptionUnknownReceived.Increment()
				if usage.actions().unknown == optionPass {
					return len(optIter.InitReplacement(option)), nil
				}
			}
			return 0, nil
		}()

		if optProblem != nil {
			optProblem.Pointer += optIter.ErrCursor
			return nil, optionTracker{}, optProblem
		}
		optIter.ConsumeBuffer(optLen)
	}
}
