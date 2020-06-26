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
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcpconntrack"
)

// Connection tracking is used to track and manipulate packets for NAT rules.
// The connection is created for a packet if it does not exist. Every
// connection contains two tuples (original and reply). The tuples are
// manipulated if there is a matching NAT rule. The packet is modified by
// looking at the tuples in the Prerouting and Output hooks.
//
// Currently, only TCP tracking is supported.

// Direction of the tuple.
type direction int

const (
	dirOriginal direction = iota
	dirReply
)

// Manipulation type for the connection.
type manipType int

const (
	manipDstPrerouting manipType = iota
	manipDstOutput
)

// tuple holds a connection's identifying and manipulating data in one
// direction. It is immutable.
type tuple struct {
	tupleID

	// conn is the connection tracking entry this tuple belongs to.
	conn *conn

	// direction is the direction of the tuple.
	direction direction
}

// tupleID uniquely identifies a connection in one direction. It currently
// contains enough information to distinguish between any TCP or UDP
// connection, and will need to be extended to support other protocols.
type tupleID struct {
	srcAddr    tcpip.Address
	srcPort    uint16
	dstAddr    tcpip.Address
	dstPort    uint16
	transProto tcpip.TransportProtocolNumber
	netProto   tcpip.NetworkProtocolNumber
}

// reply creates the reply tupleID.
func (ti tupleID) reply() tupleID {
	return tupleID{
		srcAddr:    ti.dstAddr,
		srcPort:    ti.dstPort,
		dstAddr:    ti.srcAddr,
		dstPort:    ti.srcPort,
		transProto: ti.transProto,
		netProto:   ti.netProto,
	}
}

// conn is a tracked connection.
type conn struct {
	// original is the tuple in original direction. It is immutable.
	original tuple

	// reply is the tuple in reply direction. It is immutable.
	reply tuple

	// manip indicates if the packet should be manipulated. It is immutable.
	manip manipType

	// tcbHook indicates if the packet is inbound or outbound to
	// update the state of tcb. It is immutable.
	tcbHook Hook

	// mu protects tcb.
	mu sync.Mutex

	// tcb is TCB control block. It is used to keep track of states
	// of tcp connection and is protected by mu.
	tcb tcpconntrack.TCB
}

// ConnTrack tracks all connections created for NAT rules. Most users are
// expected to only call handlePacket and createConnFor.
type ConnTrack struct {
	// mu protects conns.
	mu sync.RWMutex

	// conns maintains a map of tuples needed for connection tracking for
	// iptables NAT rules. It is protected by mu.
	conns map[tupleID]tuple
}

// packetToTupleID converts packet to a tuple ID. It fails when pkt lacks a valid
// TCP header.
func packetToTupleID(pkt *PacketBuffer) (tupleID, *tcpip.Error) {
	// TODO(gvisor.dev/issue/170): Need to support for other
	// protocols as well.
	netHeader := header.IPv4(pkt.NetworkHeader)
	if netHeader == nil || netHeader.TransportProtocol() != header.TCPProtocolNumber {
		return tupleID{}, tcpip.ErrUnknownProtocol
	}
	tcpHeader := header.TCP(pkt.TransportHeader)
	if tcpHeader == nil {
		return tupleID{}, tcpip.ErrUnknownProtocol
	}

	return tupleID{
		srcAddr:    netHeader.SourceAddress(),
		srcPort:    tcpHeader.SourcePort(),
		dstAddr:    netHeader.DestinationAddress(),
		dstPort:    tcpHeader.DestinationPort(),
		transProto: netHeader.TransportProtocol(),
		netProto:   header.IPv4ProtocolNumber,
	}, nil
}

// newConn creates new connection.
func newConn(orig, reply tupleID, manip manipType, hook Hook) *conn {
	conn := conn{
		manip:   manip,
		tcbHook: hook,
	}
	conn.original = tuple{conn: &conn, tupleID: orig}
	conn.reply = tuple{conn: &conn, tupleID: reply, direction: dirReply}
	return &conn
}

// connFor gets the conn for pkt if it exists, or returns nil
// if it does not. It returns an error when pkt does not contain a valid TCP
// header.
// TODO(gvisor.dev/issue/170): Only TCP packets are supported. Need to support
// other transport protocols.
func (ct *ConnTrack) connFor(pkt *PacketBuffer) (*conn, direction) {
	tid, err := packetToTupleID(pkt)
	if err != nil {
		return nil, dirOriginal
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	tuple, ok := ct.conns[tid]
	if !ok {
		return nil, dirOriginal
	}
	return tuple.conn, tuple.direction
}

// createConnFor creates a new conn for pkt.
func (ct *ConnTrack) createConnFor(pkt *PacketBuffer, hook Hook, rt RedirectTarget) *conn {
	tid, err := packetToTupleID(pkt)
	if err != nil {
		return nil
	}
	if hook != Prerouting && hook != Output {
		return nil
	}

	// Create a new connection and change the port as per the iptables
	// rule. This tuple will be used to manipulate the packet in
	// handlePacket.
	replyTID := tid.reply()
	replyTID.srcAddr = rt.MinIP
	replyTID.srcPort = rt.MinPort
	var manip manipType
	switch hook {
	case Prerouting:
		manip = manipDstPrerouting
	case Output:
		manip = manipDstOutput
	}
	conn := newConn(tid, replyTID, manip, hook)

	// Add the changed tuple to the map.
	// TODO(gvisor.dev/issue/170): Need to support collisions using linked
	// list.
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.conns[tid] = conn.original
	ct.conns[replyTID] = conn.reply

	return conn
}

// handlePacketPrerouting manipulates ports for packets in Prerouting hook.
// TODO(gvisor.dev/issue/170): Change address for Prerouting hook.
func handlePacketPrerouting(pkt *PacketBuffer, conn *conn, dir direction) {
	netHeader := header.IPv4(pkt.NetworkHeader)
	tcpHeader := header.TCP(pkt.TransportHeader)

	// For prerouting redirection, packets going in the original direction
	// have their destinations modified and replies have their sources
	// modified.
	switch dir {
	case dirOriginal:
		port := conn.reply.srcPort
		tcpHeader.SetDestinationPort(port)
		netHeader.SetDestinationAddress(conn.reply.srcAddr)
	case dirReply:
		port := conn.original.dstPort
		tcpHeader.SetSourcePort(port)
		netHeader.SetSourceAddress(conn.original.dstAddr)
	}

	netHeader.SetChecksum(0)
	netHeader.SetChecksum(^netHeader.CalculateChecksum())
}

// handlePacketOutput manipulates ports for packets in Output hook.
func handlePacketOutput(pkt *PacketBuffer, conn *conn, gso *GSO, r *Route, dir direction) {
	netHeader := header.IPv4(pkt.NetworkHeader)
	tcpHeader := header.TCP(pkt.TransportHeader)

	// For output redirection, packets going in the original direction
	// have their destinations modified and replies have their sources
	// modified. For prerouting redirection, we only reach this point
	// when replying, so packet sources are modified.
	if conn.manip == manipDstOutput && dir == dirOriginal {
		port := conn.reply.srcPort
		tcpHeader.SetDestinationPort(port)
		netHeader.SetDestinationAddress(conn.reply.srcAddr)
	} else {
		port := conn.original.dstPort
		tcpHeader.SetSourcePort(port)
		netHeader.SetSourceAddress(conn.original.dstAddr)
	}

	// Calculate the TCP checksum and set it.
	tcpHeader.SetChecksum(0)
	hdr := &pkt.Header
	length := uint16(pkt.Data.Size()+hdr.UsedLength()) - uint16(netHeader.HeaderLength())
	xsum := r.PseudoHeaderChecksum(header.TCPProtocolNumber, length)
	if gso != nil && gso.NeedsCsum {
		tcpHeader.SetChecksum(xsum)
	} else if r.Capabilities()&CapabilityTXChecksumOffload == 0 {
		xsum = header.ChecksumVVWithOffset(pkt.Data, xsum, int(tcpHeader.DataOffset()), pkt.Data.Size())
		tcpHeader.SetChecksum(^tcpHeader.CalculateChecksum(xsum))
	}

	netHeader.SetChecksum(0)
	netHeader.SetChecksum(^netHeader.CalculateChecksum())
}

// handlePacket will manipulate the port and address of the packet if the
// connection exists.
func (ct *ConnTrack) handlePacket(pkt *PacketBuffer, hook Hook, gso *GSO, r *Route) {
	if pkt.NatDone {
		return
	}

	if hook != Prerouting && hook != Output {
		return
	}

	conn, dir := ct.connFor(pkt)
	if conn == nil {
		// Connection not found for the packet or the packet is invalid.
		return
	}

	switch hook {
	case Prerouting:
		handlePacketPrerouting(pkt, conn, dir)
	case Output:
		handlePacketOutput(pkt, conn, gso, r, dir)
	}
	pkt.NatDone = true

	// Update the state of tcb.
	// TODO(gvisor.dev/issue/170): Add support in tcpcontrack to handle
	// other tcp states.
	conn.mu.Lock()
	defer conn.mu.Unlock()
	var st tcpconntrack.Result
	tcpHeader := header.TCP(pkt.TransportHeader)
	if conn.tcb.IsEmpty() {
		conn.tcb.Init(tcpHeader)
		conn.tcbHook = hook
	} else {
		switch hook {
		case conn.tcbHook:
			st = conn.tcb.UpdateStateOutbound(tcpHeader)
		default:
			st = conn.tcb.UpdateStateInbound(tcpHeader)
		}
	}

	// Delete conn if tcp connection is closed.
	if st == tcpconntrack.ResultClosedByPeer || st == tcpconntrack.ResultClosedBySelf || st == tcpconntrack.ResultReset {
		ct.deleteConn(conn)
	}
}

// deleteConn deletes the connection.
func (ct *ConnTrack) deleteConn(conn *conn) {
	if conn == nil {
		return
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	delete(ct.conns, conn.original.tupleID)
	delete(ct.conns, conn.reply.tupleID)
}
