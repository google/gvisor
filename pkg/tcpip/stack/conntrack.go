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
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcpconntrack"
)

// Connection tracking is used to track and manipulate packets for NAT rules.
// The connection is created for a packet if it does not exist. Every connection
// contains two tuples (original and reply). The tuples are manipulated if there
// is a matching NAT rule. The packet is modified by looking at the tuples in the
// Prerouting and Output hooks.

// Direction of the tuple.
type ctDirection int

const (
	dirOriginal ctDirection = iota
	dirReply
)

// Manipulation type for the connection.
type manipType int

const (
	manipNone manipType = iota
	manipDstPrerouting
	manipDstOutput
)

// connTrackMutable is the manipulatable part of the tuple.
type connTrackMutable struct {
	// addr is source address of the tuple. It is set according to the NAT
	// rules, then is immutable.
	addr tcpip.Address

	// port is source port of the tuple. It is set according to the NAT
	// rules, then is immutable.
	port uint16

	// protocol is network layer protocol. It is set according to the NAT
	// rules, then is immutable.
	protocol tcpip.NetworkProtocolNumber
}

// connTrackImmutable is the non-manipulatable part of the tuple.
type connTrackImmutable struct {
	// addr is destination address of the tuple. It is set according to the
	// NAT rules, then is immutable.en is immutable.
	addr tcpip.Address

	// direction is direction (original or reply) of the tuple. It is set
	// according to the NAT rules, then is immutable. then is immutable.
	direction ctDirection

	// port is destination port of the tuple. It is set according to the
	// NAT rules, then is immutable.
	port uint16

	// protocol is transport layer protocol. It is set according to the NAT
	// rules, then is immutable.
	protocol tcpip.TransportProtocolNumber
}

// connTrackTuple represents the tuple which is created from the
// packet.
type connTrackTuple struct {
	// dst is non-manipulatable part of the tuple. It is set according to
	// the NAT rules, then is immutable.
	dst connTrackImmutable

	// src is manipulatable part of the tuple. It is set according to the
	// NAT rules, then is immutable.
	src connTrackMutable
}

// connTrackTupleHolder is the container of tuple and connection.
type ConnTrackTupleHolder struct {
	// conn is pointer to the connection tracking entry. It is set
	// according to the NAT rules, then is immutable.
	conn *connTrack

	// tuple is original or reply tuple. It is set according to the NAT
	// rules, then is immutable.
	tuple connTrackTuple
}

// connTrack is the connection.
type connTrack struct {
	// originalTupleHolder contains tuple in original direction. It is set
	// according to the NAT rules, then is immutable.
	originalTupleHolder ConnTrackTupleHolder

	// replyTupleHolder contains tuple in reply direction. It is set
	// according to the NAT rules, then is immutable.
	replyTupleHolder ConnTrackTupleHolder

	// manip indicates if the packet should be manipulated. It is set at
	// initialization, then is immutable.
	manip manipType

	// tcbHook indicates if the packet is inbound or outbound to
	// update the state of tcb. It is set at initialization and is
	// immutable.
	tcbHook Hook

	mu struct {
		sync.Mutex

		// tcb is TCP control block. It is used to keep track of states
		// of tcp connection. It is protected by mu.
		tcb tcpconntrack.TCB

		// lastUsed is the last time the connection saw a relevant
		// packet, and is updated by each packet on the connection. It
		// is protected by mu.
		lastUsed time.Time
	}
}

// timedOut returns whether the connection timed out based on its state.
func (ct *connTrack) timedOut(now time.Time) bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.mu.tcb.State() == tcpconntrack.ResultAlive {
		// Use the same default as Linux, which doesn't delete
		// established connections for 5(!) days.
		return now.Sub(ct.mu.lastUsed) > 5*24*time.Hour
	}
	// Use the same default as Linux, which lets connections in most states
	// other than established remain for <= 120 seconds.
	return now.Sub(ct.mu.lastUsed) > 120*time.Second
}

// update the connection tracking state.
//
// Precondition: ct.mu must be held if ct is shared between goroutines.
func (ct *connTrack) update(tcpHeader header.TCP, hook Hook) {
	// Update the state of tcb. tcb assumes it's always initialized on the
	// client. However, we only need to know whether the connection is
	// established or not, so the client/server distinction isn't important.
	// TODO(gvisor.dev/issue/170): Add support in tcpconntrack to handle
	// other tcp states.
	if ct.mu.tcb.IsEmpty() {
		ct.mu.tcb.Init(tcpHeader)
	} else if hook == ct.tcbHook {
		ct.mu.tcb.UpdateStateOutbound(tcpHeader)
	} else {
		ct.mu.tcb.UpdateStateInbound(tcpHeader)
	}
}

// ConnTrackTable contains a map of all existing connections created for
// NAT rules.
type ConnTrackTable struct {
	// connMu protects ctMap.
	connMu sync.RWMutex

	// ctMap maintains a map of tuples needed for connection tracking
	// for iptables NAT rules. The key for the map is an integer calculated
	// using seed, source address, destination address, source port and
	// destination port.
	ctMap map[uint32]ConnTrackTupleHolder

	// seed is a one-time random value initialized at stack startup
	// and is used in calculation of hash key for connection tracking
	// table. It is immutable.
	seed uint32
}

// packetToTuple converts packet to a tuple in original direction.
func packetToTuple(pkt *PacketBuffer, hook Hook) (connTrackTuple, *tcpip.Error) {
	var tuple connTrackTuple

	netHeader := header.IPv4(pkt.NetworkHeader)
	// TODO(gvisor.dev/issue/170): Need to support for other
	// protocols as well.
	if netHeader == nil || netHeader.TransportProtocol() != header.TCPProtocolNumber {
		return tuple, tcpip.ErrUnknownProtocol
	}
	tcpHeader := header.TCP(pkt.TransportHeader)
	if tcpHeader == nil {
		return tuple, tcpip.ErrUnknownProtocol
	}

	tuple.src.addr = netHeader.SourceAddress()
	tuple.src.port = tcpHeader.SourcePort()
	tuple.src.protocol = header.IPv4ProtocolNumber

	tuple.dst.addr = netHeader.DestinationAddress()
	tuple.dst.port = tcpHeader.DestinationPort()
	tuple.dst.protocol = netHeader.TransportProtocol()

	return tuple, nil
}

// getReplyTuple creates reply tuple for the given tuple.
func getReplyTuple(tuple connTrackTuple) connTrackTuple {
	var replyTuple connTrackTuple
	replyTuple.src.addr = tuple.dst.addr
	replyTuple.src.port = tuple.dst.port
	replyTuple.src.protocol = tuple.src.protocol
	replyTuple.dst.addr = tuple.src.addr
	replyTuple.dst.port = tuple.src.port
	replyTuple.dst.protocol = tuple.dst.protocol
	replyTuple.dst.direction = dirReply

	return replyTuple
}

// newConn creates new connection.
func newConn(tuple, replyTuple connTrackTuple, manip manipType, hook Hook) *connTrack {
	var conn connTrack
	conn.mu.lastUsed = time.Now()
	conn.originalTupleHolder.tuple = tuple
	conn.originalTupleHolder.conn = &conn
	conn.replyTupleHolder.tuple = replyTuple
	conn.replyTupleHolder.conn = &conn
	conn.manip = manip
	conn.tcbHook = hook
	return &conn
}

// getTupleHash returns hash of the tuple. The fields used for
// generating hash are seed (generated once for stack), source address,
// destination address, source port and destination ports.
func (ct *ConnTrackTable) getTupleHash(tuple connTrackTuple) uint32 {
	h := jenkins.Sum32(ct.seed)
	h.Write([]byte(tuple.src.addr))
	h.Write([]byte(tuple.dst.addr))
	portBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBuf, tuple.src.port)
	h.Write([]byte(portBuf))
	binary.LittleEndian.PutUint16(portBuf, tuple.dst.port)
	h.Write([]byte(portBuf))

	return h.Sum32()
}

// connTrackForPacket gets the connTrack for pkt if it exists, or returns nil
// if it does not.
// TODO(gvisor.dev/issue/170): Only TCP packets are supported. Need to support other
// transport protocols.
func (ct *ConnTrackTable) connTrackForPacket(pkt *PacketBuffer, hook Hook) (*connTrack, ctDirection) {
	tuple, err := packetToTuple(pkt, hook)
	if err != nil {
		return nil, dirOriginal
	}
	hash := ct.getTupleHash(tuple)

	ct.connMu.Lock()
	defer ct.connMu.Unlock()

	tupleHolder, ok := ct.ctMap[hash]
	if !ok {
		return nil, dirOriginal
	}

	// The connection may have timed out.
	if tupleHolder.conn.timedOut(time.Now()) {
		replyTuple := tupleHolder.conn.replyTupleHolder.tuple
		replyHash := ct.getTupleHash(replyTuple)
		delete(ct.ctMap, hash)
		delete(ct.ctMap, replyHash)
		return nil, dirOriginal
	}

	return tupleHolder.conn, tupleHolder.tuple.dst.direction
}

// createConnTrackForPacket creates a new connTrack for pkt.
func (ct *ConnTrackTable) createConnTrackForPacket(pkt *PacketBuffer, hook Hook, rt RedirectTarget) *connTrack {
	tuple, err := packetToTuple(pkt, hook)
	if err != nil {
		return nil
	}
	hash := ct.getTupleHash(tuple)

	// Create a new connection and change the port as per the iptables
	// rule. This tuple will be used to manipulate the packet in
	// HandlePacket.
	replyTuple := getReplyTuple(tuple)
	replyTuple.src.addr = rt.MinIP
	replyTuple.src.port = rt.MinPort
	replyHash := ct.getTupleHash(replyTuple)
	var manip manipType
	switch hook {
	case Prerouting:
		manip = manipDstPrerouting
	case Output:
		manip = manipDstOutput
	default:
		panic(fmt.Sprintf("NAT only apples to Prerouting and Output, but found %d", hook))
	}
	conn := newConn(tuple, replyTuple, manip, hook)

	// Add the changed tuple to the map.
	// TODO(gvisor.dev/issue/170): Need to support collisions using linked
	// list.
	ct.connMu.Lock()
	defer ct.connMu.Unlock()
	ct.ctMap[hash] = conn.originalTupleHolder
	ct.ctMap[replyHash] = conn.replyTupleHolder

	return conn
}

// handlePacketPrerouting manipulates ports for packets in Prerouting hook.
func handlePacketPrerouting(pkt *PacketBuffer, conn *connTrack, dir ctDirection) {
	// If this is a noop entry, don't do anything.
	if conn.manip == manipNone {
		return
	}

	netHeader := header.IPv4(pkt.NetworkHeader)
	tcpHeader := header.TCP(pkt.TransportHeader)

	// For prerouting redirection, packets going in the original direction
	// have their destinations modified and replies have their sources
	// modified.
	switch dir {
	case dirOriginal:
		port := conn.replyTupleHolder.tuple.src.port
		tcpHeader.SetDestinationPort(port)
		netHeader.SetDestinationAddress(conn.replyTupleHolder.tuple.src.addr)
	case dirReply:
		port := conn.originalTupleHolder.tuple.dst.port
		tcpHeader.SetSourcePort(port)
		netHeader.SetSourceAddress(conn.originalTupleHolder.tuple.dst.addr)
	}

	// TODO(gvisor.dev/issue/170): TCP checksums aren't usually validated
	// on inbound packets, so we don't recalculate them. However, we should
	// support cases when they are validated, e.g. when we can't offload
	// receive checksumming.

	netHeader.SetChecksum(0)
	netHeader.SetChecksum(^netHeader.CalculateChecksum())
}

// handlePacketOutput manipulates ports for packets in Output hook.
func handlePacketOutput(pkt *PacketBuffer, conn *connTrack, gso *GSO, r *Route, dir ctDirection) {
	// If this is a noop entry, don't do anything.
	if conn.manip == manipNone {
		return
	}

	netHeader := header.IPv4(pkt.NetworkHeader)
	tcpHeader := header.TCP(pkt.TransportHeader)

	// For output redirection, packets going in the original direction
	// have their destinations modified and replies have their sources
	// modified. For prerouting redirection, we only reach this point
	// when replying, so packet sources are modified.
	if conn.manip == manipDstOutput && dir == dirOriginal {
		port := conn.replyTupleHolder.tuple.src.port
		tcpHeader.SetDestinationPort(port)
		netHeader.SetDestinationAddress(conn.replyTupleHolder.tuple.src.addr)
	} else {
		port := conn.originalTupleHolder.tuple.dst.port
		tcpHeader.SetSourcePort(port)
		netHeader.SetSourceAddress(conn.originalTupleHolder.tuple.dst.addr)
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

// MaybeInsertNoop tries to insert a no-op connection entry to keep connections
// from getting clobbered when replies arrive. It only inserts if there isn't
// already a connection for pkt.
//
// This should be called after traversing iptables rules only, to ensure that
// pkt.NatDone is set correctly.
func (ct *ConnTrackTable) MaybeInsertNoop(pkt *PacketBuffer, hook Hook) {
	// If there were a rule applying to this packet, it would be marked
	// with NatDone.
	if pkt.NatDone {
		return
	}

	// NAT only works in the Prerouting and Output hookds.
	if hook != Prerouting && hook != Output {
		return
	}

	// We only track TCP connections.
	if netHeader := header.IPv4(pkt.NetworkHeader); netHeader == nil || netHeader.TransportProtocol() != header.TCPProtocolNumber || pkt.TransportHeader == nil {
		return
	}

	// This is the first packet we're seeing for the TCP connection. Insert
	// the noop entry (an identity mapping) so that the response doesn't
	// get NATed, breaking the connection.

	// Get the TCP tuples and hashes uniquely identifying the connection.
	tuple, err := packetToTuple(pkt, hook)
	if err != nil {
		return
	}
	hash := ct.getTupleHash(tuple)
	replyTuple := getReplyTuple(tuple)
	replyHash := ct.getTupleHash(replyTuple)
	conn := newConn(tuple, replyTuple, manipNone, hook)
	conn.update(header.TCP(pkt.TransportHeader), hook)

	// Add tupleHolders to the map. Packets that are a part of this
	// connection won't be NATed regardless of their direction.
	ct.connMu.Lock()
	defer ct.connMu.Unlock()
	ct.ctMap[hash] = conn.originalTupleHolder
	ct.ctMap[replyHash] = conn.replyTupleHolder
}

// HandlePacket will manipulate the port and address of the packet if the
// connection exists. Returns whether, after the packet traverses the tables,
// it should create a new entry in the table.
func (ct *ConnTrackTable) HandlePacket(pkt *PacketBuffer, hook Hook, gso *GSO, r *Route) bool {
	if pkt.NatDone {
		return false
	}

	if hook != Prerouting && hook != Output {
		return false
	}

	conn, dir := ct.connTrackForPacket(pkt, hook)
	// Connection or Rule not found for the packet.
	if conn == nil {
		return true
	}

	// TODO(gvisor.dev/issue/170): Need to support for other transport
	// protocols as well.
	if netHeader := header.IPv4(pkt.NetworkHeader); netHeader == nil || netHeader.TransportProtocol() != header.TCPProtocolNumber {
		return false
	}

	tcpHeader := header.TCP(pkt.TransportHeader)
	if tcpHeader == nil {
		return false
	}

	switch hook {
	case Prerouting:
		handlePacketPrerouting(pkt, conn, dir)
	case Output:
		handlePacketOutput(pkt, conn, gso, r, dir)
	default:
		panic(fmt.Sprintf("NAT only handles the Prerouting and Output hook, but was invoked on hook %d", hook))
	}
	pkt.NatDone = true

	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Mark the connection as having been used recently so it isn't reaped.
	conn.mu.lastUsed = time.Now()
	// Update connection state.
	conn.update(tcpHeader, hook)

	return false
}

// reap deletes timed out entries from the conntrack map.
func (ct *ConnTrackTable) reap() {
	// Find unused connections.
	// TODO(gvisor.dev/issue/170): This can be more finely controlled, as
	// it is in Linux via sysctl.
	now := time.Now()

	ct.connMu.Lock()
	defer ct.connMu.Unlock()

	var deadConns []uint32
	for hash, holder := range ct.ctMap {
		if holder.conn.timedOut(now) {
			deadConns = append(deadConns, hash)
		}
	}

	// Remove unused connections.
	for _, hash := range deadConns {
		delete(ct.ctMap, hash)
	}
}
