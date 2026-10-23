// Copyright 2026 The gVisor Authors.
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
	"encoding/binary"
	"slices"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// This file passes bridged IPv4 and IPv6 frames through the IPv4 and IPv6
// netfilter hooks, as Linux's br_netfilter does
// (net/bridge/br_netfilter_hooks.c, net/bridge/br_netfilter_ipv6.c).

// arpHeaderSize is the size of Linux's struct arphdr, the fixed part of an
// ARP header.
const arpHeaderSize = 8

// forwardAllowed returns whether a frame received on p may be forwarded. As
// br_nf_forward_arp does, a forwarded ARP frame too short for an ARP header
// is dropped when bridge-nf-call-arptables is set.
func (p *bridgePort) forwardAllowed(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) bool {
	return protocol != header.ARPProtocolNumber ||
		pkt.Data().Size() >= arpHeaderSize ||
		!p.nic.stack.bridgeNFCallARPTables.Load()
}

// bridgeNetfilterActive returns whether s has iptables or nftables rules.
// Without rules, the hooks accept every packet without tracking it.
func bridgeNetfilterActive(s *Stack) bool {
	return s.tables.isModified() || (s.NFTables() != nil && s.IsNFTablesConfigured())
}

// preRouting validates a frame received on p and passes it through the IPv4
// or IPv6 Prerouting hook, as br_nf_pre_routing does. f is where the bridge
// sends the frame, and is looked up again if the hook changes the frame's
// destination link address. It returns whether the caller goes on to bridge
// the frame.
func (p *bridgePort) preRouting(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer, f *bridgeForwarding) bool {
	s := p.nic.stack
	var af AddressFamily
	switch protocol {
	case header.IPv4ProtocolNumber:
		if !s.bridgeNFCallIPTables.Load() {
			return true
		}
		af = IP
	case header.IPv6ProtocolNumber:
		if !s.bridgeNFCallIP6Tables.Load() {
			return true
		}
		af = IP6
	default:
		return true
	}
	netProto, ok := s.networkProtocols[protocol]
	if !ok {
		return true
	}
	var valid bool
	if protocol == header.IPv4ProtocolNumber {
		valid = bridgeValidateIPv4(pkt)
	} else {
		valid = bridgeValidateIPv6(pkt)
	}
	if !valid {
		s.stats.IP.MalformedPacketsReceived.Increment()
		return false
	}
	if !bridgeNetfilterActive(s) {
		return true
	}

	brNIC, ok := f.d.(*nic)
	if !ok {
		return true
	}
	pktType := f.pktType

	// As in setup_pre_routing, the hooks see a frame for another host as one
	// for this host, received on the bridge.
	pkt.bridge = bridgeInfo{physIn: p.nic.id, pktType: pktType}
	pkt.PktType = pktType
	if pktType == tcpip.PacketOtherHost {
		pkt.PktType = tcpip.PacketHost
	}
	pkt.InputNICID = brNIC.id
	pkt.RXChecksumValidated = p.nic.NetworkLinkEndpoint.Capabilities()&CapabilityRXChecksumOffload != 0
	transProto, hasTransportHeader, ok := netProto.Parse(pkt)
	if !ok {
		return false
	}
	if hasTransportHeader {
		s.parseBridgedTransport(transProto, pkt)
	}

	origDst := pkt.Network().DestinationAddress()
	addressEP, _ := brNIC.getNetworkEndpoint(protocol).(AddressableEndpoint)
	if !s.tables.CheckPrerouting(pkt, addressEP, brNIC.name) {
		s.stats.IP.IPTablesPreroutingDropped.Increment()
		return false
	}
	if nft := s.NFTables(); nft != nil && s.IsNFTablesConfigured() {
		if !nft.CheckPrerouting(pkt, nil /* route */, af) {
			return false
		}
	}
	pkt.PktType = pktType
	if pkt.Network().DestinationAddress() == origDst {
		return true
	}
	if !p.preRoutingFinishDNAT(brNIC, protocol, pkt) {
		return false
	}
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	p.bridge.mu.RLock()
	*f = p.lookupLocked(eth.SourceAddress(), eth.DestinationAddress())
	p.bridge.mu.RUnlock()
	return true
}

// parseBridgedTransport parses the transport header of a bridged packet.
func (s *Stack) parseBridgedTransport(proto tcpip.TransportProtocolNumber, pkt *PacketBuffer) {
	switch proto {
	case header.ICMPv4ProtocolNumber:
		if _, ok := pkt.TransportHeader().Consume(header.ICMPv4MinimumSize); ok {
			pkt.TransportProtocolNumber = proto
		}
	case header.ICMPv6ProtocolNumber:
		if _, ok := pkt.TransportHeader().Consume(header.ICMPv6MinimumSize); ok {
			pkt.TransportProtocolNumber = proto
		}
	default:
		s.ParsePacketBufferTransport(proto, pkt)
	}
}

// bridgeValidateIPv4 checks the IPv4 header of a bridged frame and trims the
// frame to the length in the header, as br_validate_ipv4 does.
func bridgeValidateIPv4(pkt *PacketBuffer) bool {
	b, ok := pkt.Data().PullUp(header.IPv4MinimumSize)
	if !ok {
		return false
	}
	h := header.IPv4(b)
	hdrLen := int(h.HeaderLength())
	if hdrLen < header.IPv4MinimumSize || header.IPVersion(h) != header.IPv4Version {
		return false
	}
	if b, ok = pkt.Data().PullUp(hdrLen); !ok {
		return false
	}
	h = header.IPv4(b)
	if !h.IsChecksumValid() {
		return false
	}
	totalLen := int(h.TotalLength())
	if pkt.Data().Size() < totalLen || totalLen < hdrLen {
		return false
	}
	pkt.Data().CapLength(totalLen)
	return true
}

// bridgeValidateIPv6 checks the IPv6 header of a bridged frame and trims the
// frame to the length in the header, as br_validate_ipv6 does.
func bridgeValidateIPv6(pkt *PacketBuffer) bool {
	b, ok := pkt.Data().PullUp(header.IPv6MinimumSize)
	if !ok {
		return false
	}
	h := header.IPv6(b)
	if header.IPVersion(h) != header.IPv6Version {
		return false
	}
	payloadLen := int(h.PayloadLength())
	if h.NextHeader() == uint8(header.IPv6HopByHopOptionsExtHdrIdentifier) {
		if payloadLen, ok = bridgeCheckHopByHopLength(pkt, payloadLen); !ok {
			return false
		}
	}
	totalLen := header.IPv6MinimumSize + payloadLen
	if pkt.Data().Size() < totalLen {
		return false
	}
	pkt.Data().CapLength(totalLen)
	return true
}

// bridgeCheckHopByHopLength checks the Hop-by-Hop Options header of an IPv6
// packet with payload length payloadLen and returns the payload length that
// a Jumbo Payload option in it sets, as nf_ip6_check_hbh_len does.
func bridgeCheckHopByHopLength(pkt *PacketBuffer, payloadLen int) (int, bool) {
	const (
		pad1  = 0
		jumbo = 0xc2
	)
	off := header.IPv6MinimumSize
	b, ok := pkt.Data().PullUp(off + 8)
	if !ok {
		return 0, false
	}
	length := (int(b[off+1]) + 1) * 8
	if b, ok = pkt.Data().PullUp(off + length); !ok {
		return 0, false
	}
	off += 2
	length -= 2
	for length > 0 {
		if b[off] == pad1 {
			off++
			length--
			continue
		}
		if length < 2 {
			return 0, false
		}
		optLen := int(b[off+1]) + 2
		if optLen > length {
			return 0, false
		}
		if b[off] == jumbo {
			if b[off+1] != 4 || off&3 != 2 {
				return 0, false
			}
			jumboLen := int(binary.BigEndian.Uint32(b[off+2:]))
			if jumboLen <= header.IPv6MaximumPayloadSize || header.IPv6(b).PayloadLength() != 0 {
				return 0, false
			}
			if jumboLen > pkt.Data().Size()-header.IPv6MinimumSize {
				return 0, false
			}
			payloadLen = jumboLen
		}
		off += optLen
		length -= optLen
	}
	return payloadLen, true
}

// preRoutingFinishDNAT handles a frame whose destination address the
// Prerouting hook changed, as br_nf_pre_routing_finish and
// br_nf_pre_routing_finish_ipv6 do. A frame for an address that is routed
// out of the bridge stays bridged; it is sent to the link address of that
// address. Any other frame is passed up to be delivered or routed. It returns
// whether the caller goes on to bridge the frame.
func (p *bridgePort) preRoutingFinishDNAT(brNIC *nic, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) bool {
	s := p.nic.stack
	r, ok := s.bridgedDNATRoute(brNIC, protocol, pkt.Network().DestinationAddress())
	if !ok {
		return false
	}
	if r == nil {
		eth := header.Ethernet(pkt.LinkHeader().Slice())
		eth.SetDestinationAddress(brNIC.LinkAddress())
		pkt.PktType = tcpip.PacketHost
		pkt.bridge.pktType = tcpip.PacketHost
		return true
	}
	defer r.Release()

	// Linux sends a frame whose neighbour is resolved to that neighbour right
	// away, as br_nf_pre_routing_finish_bridge does, and queues any other frame
	// on the neighbour of the bridge, whose transmit sends the frame to the
	// resolved address (br_nf_dev_xmit).
	info, _, err := r.resolvedFields(nil)
	switch err.(type) {
	case nil:
		eth := header.Ethernet(pkt.LinkHeader().Slice())
		eth.SetDestinationAddress(info.RemoteLinkAddress)
		return true
	case *tcpip.ErrWouldBlock:
		// The bridge sends the frame from its own address, so keep the
		// source address to restore it, as nf_bridge_info's neigh_header
		// does. If link resolution fails, the network layer sends an ICMP
		// host unreachable to the source, as arp_error_report and
		// ndisc_error_report do through dst_link_failure.
		eth := header.Ethernet(pkt.LinkHeader().Slice())
		pkt.bridge.srcMAC = eth.SourceAddress()
		pkt.bridge.dnat = true
		pkt.NetworkPacketInfo.IsForwardedPacket = true
		_ = brNIC.linkResQueue.enqueue(r, pkt)
		return false
	default:
		return false
	}
}

// bridgedDNATRoute returns the route out of the bridge for a frame DNATed to
// dst that stays bridged, or nil for a frame that is passed up. It returns
// false for a frame that is dropped.
//
// As in ip_route_input, IPv4 routes a non-local address only when forwarding
// is enabled on the bridge, and leaves routing errors to the network layer. A
// local, broadcast or multicast address is delivered locally, so it is never
// bridged. IPv6 routes regardless of forwarding, and drops a frame without a
// route. Neither needs an address on the bridge; the route takes its source
// address from another interface then, see
// bridgeRouteFromOtherInterfaceRLocked.
func (s *Stack) bridgedDNATRoute(brNIC *nic, protocol tcpip.NetworkProtocolNumber, dst tcpip.Address) (*Route, bool) {
	if s.CheckLocalAddress(0 /* nicID */, protocol, dst) != 0 || header.IsV4MulticastAddress(dst) || header.IsV6MulticastAddress(dst) || dst == header.IPv4Broadcast {
		return nil, true
	}
	if protocol == header.IPv4ProtocolNumber {
		if forwarding, err := s.NICForwarding(brNIC.id, protocol); err != nil || !forwarding {
			return nil, true
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var (
		route tcpip.Route
		found bool
	)
	s.routeMu.RLock()
	for rt := s.routeTable.Front(); rt != nil; rt = rt.Next() {
		if !rt.Destination.Contains(dst) {
			continue
		}
		if n, ok := s.nics[rt.NIC]; ok && n.Enabled() {
			route, found = *rt, true
			break
		}
	}
	s.routeMu.RUnlock()
	if !found {
		return nil, protocol == header.IPv4ProtocolNumber
	}
	if route.NIC != brNIC.id {
		return nil, true
	}
	var r *Route
	if ep := s.getAddressEP(brNIC, tcpip.Address{}, dst, route.SourceHint, protocol); ep != nil {
		r = constructAndValidateRoute(protocol, ep, brNIC, brNIC, route.Gateway, tcpip.Address{}, dst, s.handleLocal, false /* multicastLoop */, route.MTU)
	} else {
		r = s.bridgeRouteFromOtherInterfaceRLocked(brNIC, protocol, dst, route)
	}
	if r == nil {
		return nil, protocol == header.IPv4ProtocolNumber
	}
	if r.IsOutboundBroadcast() {
		r.Release()
		return nil, true
	}
	return r, true
}

// bridgeRouteFromOtherInterfaceRLocked returns a route out of brNIC with the
// address of another interface. As in inet_select_addr, the interfaces are
// tried in index order, and loopback addresses, which have host scope, are
// skipped. A route with the address of another interface is only valid if that
// interface forwards, so the first valid one is returned.
//
// +checklocksread:s.mu
func (s *Stack) bridgeRouteFromOtherInterfaceRLocked(brNIC *nic, protocol tcpip.NetworkProtocolNumber, dst tcpip.Address, route tcpip.Route) *Route {
	ids := make([]tcpip.NICID, 0, len(s.nics))
	for id := range s.nics {
		if id != brNIC.id {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		n := s.nics[id]
		ep := s.getAddressEP(n, tcpip.Address{}, dst, route.SourceHint, protocol)
		if ep == nil {
			continue
		}
		if addr := ep.AddressWithPrefix().Address; header.IsV4LoopbackAddress(addr) || header.IsV6LoopbackAddress(addr) {
			ep.DecRef()
			continue
		}
		r := constructAndValidateRoute(protocol, ep, n, brNIC, route.Gateway, tcpip.Address{}, dst, s.handleLocal, false /* multicastLoop */, route.MTU)
		if r == nil {
			continue
		}
		if r.isValidForOutgoing() {
			return r
		}
		r.Release()
	}
	return nil
}

// bridgeFrameCopy returns a deep copy of a frame that went through the
// Prerouting hook of a bridge, with the same headers parsed.
func bridgeFrameCopy(pkt *PacketBuffer, reserve int) *PacketBuffer {
	payload := BufferSince(pkt.LinkHeader())
	defer payload.Release()
	newPkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: reserve,
		Payload:            payload.DeepClone(),
	})
	mustConsume(newPkt.LinkHeader(), len(pkt.LinkHeader().Slice()))
	mustConsume(newPkt.NetworkHeader(), len(pkt.NetworkHeader().Slice()))
	mustConsume(newPkt.TransportHeader(), len(pkt.TransportHeader().Slice()))
	newPkt.NetworkProtocolNumber = pkt.NetworkProtocolNumber
	newPkt.TransportProtocolNumber = pkt.TransportProtocolNumber
	newPkt.PktType = pkt.PktType
	newPkt.InputNICID = pkt.InputNICID
	newPkt.RXChecksumValidated = pkt.RXChecksumValidated
	newPkt.GSOOptions = pkt.GSOOptions
	newPkt.Mark = pkt.Mark
	newPkt.tuple = pkt.tuple
	newPkt.dnatDone = pkt.dnatDone
	newPkt.snatDone = pkt.snatDone
	newPkt.bridge = pkt.bridge
	return newPkt
}

func mustConsume(h PacketHeader, size int) {
	if _, ok := h.Consume(size); !ok {
		panic("expected to consume a header of a copy of the packet")
	}
}

// forwardNetfilter sends a frame that went through the Prerouting hook out of
// the port to, after the Forward and Postrouting hooks. As in
// br_nf_forward_ip and br_nf_post_routing, the hooks see the bridge as both
// the input and the output interface.
//
// The hooks may rewrite the frame, so a frame that is also sent elsewhere
// (shared) is copied first, as NAT unshares the clones br_flood and
// br_handle_frame_finish make. So is a frame without room for the headers of
// the port it is sent out of.
func (p *bridgePort) forwardNetfilter(brNIC *nic, to *bridgePort, pkt *PacketBuffer, shared bool) {
	s := p.nic.stack
	newPkt := pkt
	if reserve := int(to.nic.MaxHeaderLength()); shared || pkt.AvailableHeaderBytes() < reserve {
		newPkt = bridgeFrameCopy(pkt, reserve)
		defer newPkt.DecRef()
	}
	newPkt.bridge.physOut = to.nic.id
	if newPkt.PktType == tcpip.PacketOtherHost {
		newPkt.PktType = tcpip.PacketHost
	}
	af := IP
	if newPkt.NetworkProtocolNumber == header.IPv6ProtocolNumber {
		af = IP6
	}
	nft := s.NFTables()
	if nft != nil && !s.IsNFTablesConfigured() {
		nft = nil
	}
	if !s.tables.CheckForward(newPkt, brNIC.name, brNIC.name) {
		s.stats.IP.IPTablesForwardDropped.Increment()
		return
	}
	if nft != nil && !nft.CheckForward(newPkt, nil /* route */, brNIC.id, af) {
		return
	}
	addressEP, _ := brNIC.getNetworkEndpoint(newPkt.NetworkProtocolNumber).(AddressableEndpoint)
	if !s.tables.CheckPostrouting(newPkt, nil /* route */, addressEP, brNIC.name) {
		s.stats.IP.IPTablesPostroutingDropped.Increment()
		return
	}
	if nft != nil && !nft.CheckPostrouting(newPkt, nil /* route */, brNIC.id, af) {
		return
	}
	to.nic.writeRawPacket(newPkt)
}

// writeBridgedDNAT sends a frame that waited for the link address of the host
// it was DNATed to, as br_nf_pre_routing_finish_bridge_slow does.
func (b *BridgeEndpoint) writeBridgedDNAT(pkt *PacketBuffer) {
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	eth.SetSourceAddress(pkt.bridge.srcMAC)
	pkt.bridge.dnat = false
	pkt.bridge.srcMAC = ""
	pkt.PktType = pkt.bridge.pktType
	b.mu.RLock()
	p, ok := b.ports[pkt.bridge.physIn]
	var f bridgeForwarding
	if ok {
		f = p.lookupLocked(eth.SourceAddress(), eth.DestinationAddress()) // +checklocksforce: p.bridge is b.
	}
	b.mu.RUnlock()
	if ok {
		p.handleFrameFinish(pkt.NetworkProtocolNumber, pkt, &f)
	}
}
