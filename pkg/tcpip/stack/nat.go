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
	"math"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// NATType represents the type of NAT.
type NATType int

const (
	// SNAT is source NAT.
	SNAT NATType = iota
	// DNAT is destination NAT.
	DNAT
	// NATUnknown is unknown NAT type.
	NATUnknown
)

// ToNATType converts a uint8 to a NATType.
func ToNATType(t uint8) NATType {
	switch t {
	case 0:
		return SNAT
	case 1:
		return DNAT
	}
	return NATUnknown
}

func (natType NATType) String() string {
	switch natType {
	case SNAT:
		return "SNAT"
	case DNAT:
		return "DNAT"
	default:
		return "NATUnknown"
	}
}

// NfNATPriority returns the priority of the NAT hook.
// Check `ipv4/ipv6_nat_ops` in nf_nat_proto.c.
func NfNATPriority(hook NFHook) (int, bool) {
	switch hook {
	case NFPrerouting:
		// NF_IP_PRI_NAT_DST
		return -100, true
	case NFPostrouting:
		// NF_IP_PRI_NAT_SRC
		return 100, true
	case NFOutput:
		// NF_IP_PRI_NAT_DST
		return -100, true
	case NFInput:
		// NF_IP_PRI_NAT_SRC
		return 100, true
	}
	// NAT is not supported for other hooks.
	return 0, false
}

// NfHookToNATType returns the applicable NAT type
// for the given netfilter hook.
func NfHookToNATType(hook NFHook) NATType {
	switch hook {
	case NFPrerouting, NFOutput:
		return DNAT
	case NFInput, NFPostrouting:
		return SNAT
	}
	return NATUnknown
}

// handlePacketOpts contains the options for handlePacket.
type handlePacketOpts struct {
	fullChecksum       bool
	updatePseudoHeader bool
	natType            NATType
}

// handlePacket attempts to handle a packet and perform NAT if the connection
// has had NAT performed on it.
//
// Returns true if the packet can skip the NAT table.
func handlePacket(pkt *PacketBuffer, opts *handlePacketOpts) bool {
	if opts == nil || opts.natType == NATUnknown {
		return false
	}
	netHdr, transHdr, isICMPError, ok := pkt.GetHeaders()
	if !ok {
		return false
	}

	natDone := &pkt.snatDone
	dnat := false
	if opts.natType == DNAT {
		natDone = &pkt.dnatDone
		dnat = true
	}

	if *natDone {
		panic(fmt.Sprintf("packet already had NAT: %s performed; pkt=%#v", opts.natType, pkt))
	}

	// TODO(gvisor.dev/issue/5748): TCP checksums on inbound packets should be
	// validated if checksum offloading is off. It may require IP defrag if the
	// packets are fragmented.

	reply := pkt.tuple.reply
	cn := pkt.tuple.conn

	tid, manip := func() (tupleID, manipType) {
		cn.mu.RLock()
		defer cn.mu.RUnlock()

		if reply {
			tid := cn.original.tupleID

			if dnat {
				return tid, cn.sourceManip
			}
			return tid, cn.destinationManip
		}

		tid := cn.reply.tupleID
		if dnat {
			return tid, cn.destinationManip
		}
		return tid, cn.sourceManip
	}()
	switch manip {
	case manipNotPerformed:
		return false
	case manipPerformedNoop:
		*natDone = true
		return true
	case manipPerformed:
	default:
		panic(fmt.Sprintf("unhandled manip = %d", manip))
	}

	newPort := tid.dstPortOrEchoReplyIdent
	newAddr := tid.dstAddr
	if dnat {
		newPort = tid.srcPortOrEchoRequestIdent
		newAddr = tid.srcAddr
	}

	UpdateHeaders(
		netHdr,
		transHdr,
		!dnat != isICMPError,
		opts.fullChecksum,
		opts.updatePseudoHeader,
		newPort,
		newAddr,
	)

	*natDone = true

	if !isICMPError {
		return true
	}

	// We performed NAT on (erroneous) packet that triggered an ICMP response, but
	// not the ICMP packet itself.
	switch pkt.TransportProtocolNumber {
	case header.ICMPv4ProtocolNumber:
		icmp := header.ICMPv4(pkt.TransportHeader().Slice())
		// TODO(https://gvisor.dev/issue/6788): Incrementally update ICMP checksum.
		icmp.SetChecksum(0)
		icmp.SetChecksum(header.ICMPv4Checksum(icmp, pkt.Data().Checksum()))

		network := header.IPv4(pkt.NetworkHeader().Slice())
		if dnat {
			network.SetDestinationAddressWithChecksumUpdate(tid.srcAddr)
		} else {
			network.SetSourceAddressWithChecksumUpdate(tid.dstAddr)
		}
	case header.ICMPv6ProtocolNumber:
		network := header.IPv6(pkt.NetworkHeader().Slice())
		srcAddr := network.SourceAddress()
		dstAddr := network.DestinationAddress()
		if dnat {
			dstAddr = tid.srcAddr
		} else {
			srcAddr = tid.dstAddr
		}

		icmp := header.ICMPv6(pkt.TransportHeader().Slice())
		// TODO(https://gvisor.dev/issue/6788): Incrementally update ICMP checksum.
		icmp.SetChecksum(0)
		payload := pkt.Data()
		icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmp,
			Src:         srcAddr,
			Dst:         dstAddr,
			PayloadCsum: payload.Checksum(),
			PayloadLen:  payload.Size(),
		}))

		if dnat {
			network.SetDestinationAddress(dstAddr)
		} else {
			network.SetSourceAddress(srcAddr)
		}
	}

	return true
}

// IPTHandlePacket handles and applies NAT to the packet if required.
func IPTHandlePacket(pkt *PacketBuffer, hook Hook, r *Route) bool {
	opts := handlePacketOpts{
		fullChecksum:       false,
		updatePseudoHeader: false,
		natType:            SNAT,
	}
	requiresTXTransportChecksum := false
	if r != nil {
		requiresTXTransportChecksum = r.RequiresTXTransportChecksum()
	}
	switch hook {
	case Prerouting:
		opts.fullChecksum = true
		opts.updatePseudoHeader = true
		opts.natType = DNAT
	case Input:
	case Forward:
		panic("should not handle packet in the forwarding hook")
	case Output:
		opts.natType = DNAT
		fallthrough
	case Postrouting:
		if pkt.TransportProtocolNumber == header.TCPProtocolNumber && pkt.GSOOptions.Type != GSONone && pkt.GSOOptions.NeedsCsum {
			opts.updatePseudoHeader = true
		} else if requiresTXTransportChecksum {
			opts.fullChecksum = true
			opts.updatePseudoHeader = true
		}
	default:
		panic(fmt.Sprintf("unrecognized hook = %d", hook))
	}

	return handlePacket(pkt, &opts)
}

// PortOrIdentRange represents a range of ports or idents
// range to use for NAT.
type PortOrIdentRange struct {
	Start uint16
	Size  uint32
}

// ConfigureNAT setups up the connection for the specified NAT and rewrites the
// packet.
//
// If NAT has already been performed on the connection, then the packet will
// be rewritten with the NAT performed on the connection, ignoring the passed
// address and port range.
//
// Generally, only the first packet of a connection reaches this method; other
// packets will be manipulated without needing to modify the connection.
func (cn *conn) ConfigureNAT(pkt *PacketBuffer, portsOrIdents PortOrIdentRange, natAddress tcpip.Address, natType NATType, changePort, changeAddress bool) bool {
	lastPortOrIdentU32 := uint32(portsOrIdents.Start) + portsOrIdents.Size - 1
	if lastPortOrIdentU32 > math.MaxUint16 {
		log.Warningf("got lastPortOrIdent = %d, want <= MaxUint16(=%d); portsOrIdents=%#v", lastPortOrIdentU32, math.MaxUint16, portsOrIdents)
		return false
	}
	lastPortOrIdent := uint16(lastPortOrIdentU32)

	cn.mu.Lock()
	defer cn.mu.Unlock()

	var manip *manipType
	var address *tcpip.Address
	var portOrIdent *uint16
	if natType == DNAT {
		manip = &cn.destinationManip
		address = &cn.reply.tupleID.srcAddr
		portOrIdent = &cn.reply.tupleID.srcPortOrEchoRequestIdent
	} else {
		manip = &cn.sourceManip
		address = &cn.reply.tupleID.dstAddr
		portOrIdent = &cn.reply.tupleID.dstPortOrEchoReplyIdent
	}

	if *manip != manipNotPerformed {
		return true
	}
	*manip = manipPerformed
	if changeAddress {
		*address = natAddress
	}

	// Everything below here is port-fiddling.
	if !changePort {
		return true
	}

	// Does the current port/ident fit in the range?
	if portsOrIdents.Start <= *portOrIdent && *portOrIdent <= lastPortOrIdent {
		// Yes, is the current reply tuple unique?
		//
		// Or, does the reply tuple refer to the same connection as the current one that
		// we are NATing? This would apply, for example, to a self-connected socket,
		// where the original and reply tuples are identical.
		other := cn.ct.connForTID(cn.reply.tupleID)
		if other == nil || other.conn == cn {
			// Yes! No need to change the port.
			return true
		}
	}

	// Try our best to find a port/ident that results in a unique reply tuple.
	//
	// We limit the number of attempts to find a unique tuple to not waste a lot
	// of time looking for a unique tuple.
	//
	// Matches linux behaviour introduced in
	// https://github.com/torvalds/linux/commit/a504b703bb1da526a01593da0e4be2af9d9f5fa8.
	const maxAttemptsForInitialRound uint32 = 128
	const minAttemptsToContinue = 16

	allowedInitialAttempts := maxAttemptsForInitialRound
	if allowedInitialAttempts > portsOrIdents.Size {
		allowedInitialAttempts = portsOrIdents.Size
	}

	for maxAttempts := allowedInitialAttempts; ; maxAttempts /= 2 {
		// Start reach round with a random initial port/ident offset.
		randOffset := cn.ct.rng.Uint32()

		for i := uint32(0); i < maxAttempts; i++ {
			newPortOrIdentU32 := uint32(portsOrIdents.Start) + (randOffset+i)%portsOrIdents.Size
			if newPortOrIdentU32 > math.MaxUint16 {
				log.Warningf("got newPortOrIdentU32 = %d, want <= MaxUint16(=%d); portsOrIdents=%#v", newPortOrIdentU32, math.MaxUint16, portsOrIdents)
				continue
			}

			*portOrIdent = uint16(newPortOrIdentU32)

			if other := cn.ct.connForTID(cn.reply.tupleID); other == nil {
				// We found a unique tuple!
				return true
			}
		}

		if maxAttempts == portsOrIdents.Size {
			// We already tried all the ports/idents in the range so no need to keep
			// trying.
			return false
		}

		if maxAttempts < minAttemptsToContinue {
			return false
		}
	}

	// We did not find a unique tuple, use the last used port anyways.
	// TODO(https://gvisor.dev/issue/6850): Handle not finding a unique tuple
	// better (e.g. remove the connection and drop the packet).
}

// IPTPerformNAT performs NAT on the packet and updates the connection.
// Used by IPTables.
func IPTPerformNAT(pkt *PacketBuffer, hook Hook, r *Route, portsOrIdents PortOrIdentRange, natAddress tcpip.Address, dnat, changePort, changeAddress bool) {
	// Make sure the packet is re-written after performing NAT.
	defer func() {
		// handlePacket returns true if the packet may skip the NAT table as the
		// connection is already NATed, but if we reach this point we must be in the
		// NAT table, so the return value is useless for us.
		_ = IPTHandlePacket(pkt, hook, r)
	}()
	cn := pkt.tuple.conn
	natType := SNAT
	if dnat {
		natType = DNAT
	}
	_ = cn.ConfigureNAT(pkt, portsOrIdents, natAddress, natType, changePort, changeAddress)
}

// IPTMaybePerformNoopNAT can apply NAT or configure a no-op NAT.
// If NAT has not been configured for this connection, either mark the
// connection as configured for "no-op NAT", in the case of DNAT, or, in the
// case of SNAT, perform source port remapping so that source ports used by
// locally-generated traffic do not conflict with ports occupied by existing NAT
// bindings.
//
// Note that in the typical case this is also a no-op, because `snatAction`
// will do nothing if the original tuple is already unique.
func IPTMaybePerformNoopNAT(pkt *PacketBuffer, hook Hook, r *Route, dnat bool) {
	cn := pkt.tuple.conn
	cn.mu.Lock()
	var manip *manipType
	if dnat {
		manip = &cn.destinationManip
	} else {
		manip = &cn.sourceManip
	}
	if *manip != manipNotPerformed {
		cn.mu.Unlock()
		_ = IPTHandlePacket(pkt, hook, r)
		return
	}
	if dnat {
		*manip = manipPerformedNoop
		cn.mu.Unlock()
		_ = IPTHandlePacket(pkt, hook, r)
		return
	}
	cn.mu.Unlock()

	// At this point, we know that NAT has not yet been performed on this
	// connection, and the DNAT case has been handled with a no-op. For SNAT, we
	// simply perform source port remapping to ensure that source ports for
	// locally generated traffic do not clash with ports used by existing NAT
	// bindings.
	_, _ = snatAction(pkt, hook, r, 0, tcpip.Address{}, true /* changePort */, false /* changeAddress */)
}

// NFTApplyNAT applies NAT to the packet and updates the connection.
// Similar to IPTHandlePacket but for NFTables hooks.
func NFTApplyNAT(pkt *PacketBuffer, hook NFHook, rt *Route) bool {
	requiresTXTransportChecksum := false
	if rt != nil {
		requiresTXTransportChecksum = rt.RequiresTXTransportChecksum()
	}
	opts := handlePacketOpts{
		fullChecksum:       false,
		updatePseudoHeader: false,
		natType:            SNAT,
	}
	switch hook {
	case NFPrerouting:
		opts.fullChecksum = true
		opts.updatePseudoHeader = true
		opts.natType = DNAT
	case NFInput:
	case NFForward:
		panic("should not handle packet in the forwarding hook")
	case NFOutput:
		opts.natType = DNAT
		fallthrough
	case NFPostrouting:
		if pkt.TransportProtocolNumber == header.TCPProtocolNumber && pkt.GSOOptions.Type != GSONone && pkt.GSOOptions.NeedsCsum {
			opts.updatePseudoHeader = true
		} else if requiresTXTransportChecksum {
			opts.fullChecksum = true
			opts.updatePseudoHeader = true
		}
	default:
		panic(fmt.Sprintf("unrecognized hook = %d", hook))
	}

	return handlePacket(pkt, &opts)
}

// IsNATConfigured returns whether NAT has been configured for the given NAT type.
func (cn *conn) IsNATConfigured(natType NATType) bool {
	cn.mu.RLock()
	defer cn.mu.RUnlock()
	switch natType {
	case SNAT:
		return cn.sourceManip != manipNotPerformed
	case DNAT:
		return cn.destinationManip != manipNotPerformed
	}
	return false
}

// ConfigureNoopNAT configures the connection for no-op NAT.
// Similar to the func `IPTMaybePerformNoopNAT` except that this one only configures NO-OP NAT and is independent of IPTables.
func (cn *conn) ConfigureNoopNAT(pkt *PacketBuffer, natType NATType) bool {
	cn.mu.Lock()
	var manip *manipType
	if natType == DNAT {
		manip = &cn.destinationManip
	} else {
		manip = &cn.sourceManip
	}

	if *manip != manipNotPerformed {
		cn.mu.Unlock()
		return true
	}

	if natType == DNAT {
		*manip = manipPerformedNoop
		cn.mu.Unlock()
		return true
	}
	cn.mu.Unlock()

	// At this point, we know that NAT has not yet been performed on this
	// connection, and the DNAT case has been handled with a no-op. For SNAT, we
	// simply perform source port remapping to ensure that source ports for
	// locally generated traffic do not clash with ports used by existing NAT
	// bindings.

	portsOrIdents := PortOrIdentRange{Start: 0, Size: math.MaxUint16 + 1}

	// However, we need to extract the port from packet.
	var port uint16
	switch pkt.TransportProtocolNumber {
	case header.UDPProtocolNumber:
		port = header.UDP(pkt.TransportHeader().Slice()).SourcePort()
	case header.TCPProtocolNumber:
		port = header.TCP(pkt.TransportHeader().Slice()).SourcePort()
	}

	if port != 0 {
		portsOrIdents = targetPortRangeForTCPAndUDP(port)
	}

	return cn.ConfigureNAT(pkt, portsOrIdents, tcpip.Address{}, natType, true /* changePort */, false /* changeAddress */)
}
