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

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// handlePacket attempts to handle a packet and perform NAT if the connection
// has had NAT performed on it.
//
// Returns true if the packet can skip the NAT table.
func handlePacket(pkt *PacketBuffer, hook Hook, rt *Route) bool {
	netHdr, transHdr, isICMPError, ok := getHeaders(pkt)
	if !ok {
		return false
	}

	fullChecksum := false
	updatePseudoHeader := false
	natDone := &pkt.snatDone
	dnat := false
	switch hook {
	case Prerouting:
		// Packet came from outside the stack so it must have a checksum set
		// already.
		fullChecksum = true
		updatePseudoHeader = true

		natDone = &pkt.dnatDone
		dnat = true
	case Input:
	case Forward:
		panic("should not handle packet in the forwarding hook")
	case Output:
		natDone = &pkt.dnatDone
		dnat = true
		fallthrough
	case Postrouting:
		if pkt.TransportProtocolNumber == header.TCPProtocolNumber && pkt.GSOOptions.Type != GSONone && pkt.GSOOptions.NeedsCsum {
			updatePseudoHeader = true
		} else if rt.RequiresTXTransportChecksum() {
			fullChecksum = true
			updatePseudoHeader = true
		}
	default:
		panic(fmt.Sprintf("unrecognized hook = %d", hook))
	}

	if *natDone {
		panic(fmt.Sprintf("packet already had NAT(dnat=%t) performed at hook=%s; pkt=%#v", dnat, hook, pkt))
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

	rewritePacket(
		netHdr,
		transHdr,
		!dnat != isICMPError,
		fullChecksum,
		updatePseudoHeader,
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

type portOrIdentRange struct {
	start uint16
	size  uint32
}

// iptPerformNAT setups up the connection for the specified NAT and rewrites the
// packet.
//
// If NAT has already been performed on the connection, then the packet will
// be rewritten with the NAT performed on the connection, ignoring the passed
// address and port range.
//
// Generally, only the first packet of a connection reaches this method; other
// packets will be manipulated without needing to modify the connection.
// Used by IPTables.
func iptPerformNAT(pkt *PacketBuffer, hook Hook, r *Route, portsOrIdents portOrIdentRange, natAddress tcpip.Address, dnat, changePort, changeAddress bool) {
	lastPortOrIdent := func() uint16 {
		lastPortOrIdent := uint32(portsOrIdents.start) + portsOrIdents.size - 1
		if lastPortOrIdent > math.MaxUint16 {
			panic(fmt.Sprintf("got lastPortOrIdent = %d, want <= MaxUint16(=%d); portsOrIdents=%#v", lastPortOrIdent, math.MaxUint16, portsOrIdents))
		}
		return uint16(lastPortOrIdent)
	}()

	// Make sure the packet is re-written after performing NAT.
	defer func() {
		// handlePacket returns true if the packet may skip the NAT table as the
		// connection is already NATed, but if we reach this point we must be in the
		// NAT table, so the return value is useless for us.
		_ = handlePacket(pkt, hook, r)
	}()

	cn := pkt.tuple.conn
	cn.mu.Lock()
	defer cn.mu.Unlock()

	var manip *manipType
	var address *tcpip.Address
	var portOrIdent *uint16
	if dnat {
		manip = &cn.destinationManip
		address = &cn.reply.tupleID.srcAddr
		portOrIdent = &cn.reply.tupleID.srcPortOrEchoRequestIdent
	} else {
		manip = &cn.sourceManip
		address = &cn.reply.tupleID.dstAddr
		portOrIdent = &cn.reply.tupleID.dstPortOrEchoReplyIdent
	}

	if *manip != manipNotPerformed {
		return
	}
	*manip = manipPerformed
	if changeAddress {
		*address = natAddress
	}

	// Everything below here is port-fiddling.
	if !changePort {
		return
	}

	// Does the current port/ident fit in the range?
	if portsOrIdents.start <= *portOrIdent && *portOrIdent <= lastPortOrIdent {
		// Yes, is the current reply tuple unique?
		//
		// Or, does the reply tuple refer to the same connection as the current one that
		// we are NATing? This would apply, for example, to a self-connected socket,
		// where the original and reply tuples are identical.
		other := cn.ct.connForTID(cn.reply.tupleID)
		if other == nil || other.conn == cn {
			// Yes! No need to change the port.
			return
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
	if allowedInitialAttempts > portsOrIdents.size {
		allowedInitialAttempts = portsOrIdents.size
	}

	for maxAttempts := allowedInitialAttempts; ; maxAttempts /= 2 {
		// Start reach round with a random initial port/ident offset.
		randOffset := cn.ct.rand.Uint32()

		for i := uint32(0); i < maxAttempts; i++ {
			newPortOrIdentU32 := uint32(portsOrIdents.start) + (randOffset+i)%portsOrIdents.size
			if newPortOrIdentU32 > math.MaxUint16 {
				panic(fmt.Sprintf("got newPortOrIdentU32 = %d, want <= MaxUint16(=%d); portsOrIdents=%#v, randOffset=%d", newPortOrIdentU32, math.MaxUint16, portsOrIdents, randOffset))
			}

			*portOrIdent = uint16(newPortOrIdentU32)

			if other := cn.ct.connForTID(cn.reply.tupleID); other == nil {
				// We found a unique tuple!
				return
			}
		}

		if maxAttempts == portsOrIdents.size {
			// We already tried all the ports/idents in the range so no need to keep
			// trying.
			return
		}

		if maxAttempts < minAttemptsToContinue {
			return
		}
	}

	// We did not find a unique tuple, use the last used port anyways.
	// TODO(https://gvisor.dev/issue/6850): Handle not finding a unique tuple
	// better (e.g. remove the connection and drop the packet).
}

// If NAT has not been configured for this connection, either mark the
// connection as configured for "no-op NAT", in the case of DNAT, or, in the
// case of SNAT, perform source port remapping so that source ports used by
// locally-generated traffic do not conflict with ports occupied by existing NAT
// bindings.
//
// Note that in the typical case this is also a no-op, because `snatAction`
// will do nothing if the original tuple is already unique.
func iptMaybePerformNoopNAT(pkt *PacketBuffer, hook Hook, r *Route, dnat bool) {
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
		_ = handlePacket(pkt, hook, r)
		return
	}
	if dnat {
		*manip = manipPerformedNoop
		cn.mu.Unlock()
		_ = handlePacket(pkt, hook, r)
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
