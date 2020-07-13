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
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
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

// Our hash table has 16K buckets.
// TODO(gvisor.dev/issue/170): These should be tunable.
const numBuckets = 1 << 14

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
//
// +stateify savable
type tuple struct {
	// tupleEntry is used to build an intrusive list of tuples.
	tupleEntry

	tupleID

	// conn is the connection tracking entry this tuple belongs to.
	conn *conn

	// direction is the direction of the tuple.
	direction direction
}

// tupleID uniquely identifies a connection in one direction. It currently
// contains enough information to distinguish between any TCP or UDP
// connection, and will need to be extended to support other protocols.
//
// +stateify savable
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
//
// +stateify savable
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
	mu sync.Mutex `state:"nosave"`

	// tcb is TCB control block. It is used to keep track of states
	// of tcp connection and is protected by mu.
	tcb tcpconntrack.TCB

	// lastUsed is the last time the connection saw a relevant packet, and
	// is updated by each packet on the connection. It is protected by mu.
	lastUsed time.Time `state:".(unixTime)"`
}

// timedOut returns whether the connection timed out based on its state.
func (cn *conn) timedOut(now time.Time) bool {
	const establishedTimeout = 5 * 24 * time.Hour
	const defaultTimeout = 120 * time.Second
	cn.mu.Lock()
	defer cn.mu.Unlock()
	if cn.tcb.State() == tcpconntrack.ResultAlive {
		// Use the same default as Linux, which doesn't delete
		// established connections for 5(!) days.
		return now.Sub(cn.lastUsed) > establishedTimeout
	}
	// Use the same default as Linux, which lets connections in most states
	// other than established remain for <= 120 seconds.
	return now.Sub(cn.lastUsed) > defaultTimeout
}

// ConnTrack tracks all connections created for NAT rules. Most users are
// expected to only call handlePacket and createConnFor.
//
// ConnTrack keeps all connections in a slice of buckets, each of which holds a
// linked list of tuples. This gives us some desirable properties:
// - Each bucket has its own lock, lessening lock contention.
// - The slice is large enough that lists stay short (<10 elements on average).
//   Thus traversal is fast.
// - During linked list traversal we reap expired connections. This amortizes
//   the cost of reaping them and makes reapUnused faster.
//
// Locks are ordered by their location in the buckets slice. That is, a
// goroutine that locks buckets[i] can only lock buckets[j] s.t. i < j.
//
// +stateify savable
type ConnTrack struct {
	// seed is a one-time random value initialized at stack startup
	// and is used in the calculation of hash keys for the list of buckets.
	// It is immutable.
	seed uint32

	// mu protects the buckets slice, but not buckets' contents. Only take
	// the write lock if you are modifying the slice or saving for S/R.
	mu sync.RWMutex `state:"nosave"`

	// buckets is protected by mu.
	buckets []bucket
}

// +stateify savable
type bucket struct {
	// mu protects tuples.
	mu     sync.Mutex `state:"nosave"`
	tuples tupleList
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
		manip:    manip,
		tcbHook:  hook,
		lastUsed: time.Now(),
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

	bucket := ct.bucket(tid)
	now := time.Now()

	ct.mu.RLock()
	defer ct.mu.RUnlock()
	ct.buckets[bucket].mu.Lock()
	defer ct.buckets[bucket].mu.Unlock()

	// Iterate over the tuples in a bucket, cleaning up any unused
	// connections we find.
	for other := ct.buckets[bucket].tuples.Front(); other != nil; other = other.Next() {
		// Clean up any timed-out connections we happen to find.
		if ct.reapTupleLocked(other, bucket, now) {
			// The tuple expired.
			continue
		}
		if tid == other.tupleID {
			return other.conn, other.direction
		}
	}

	return nil, dirOriginal
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

	// Lock the buckets in the correct order.
	tupleBucket := ct.bucket(tid)
	replyBucket := ct.bucket(replyTID)
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	if tupleBucket < replyBucket {
		ct.buckets[tupleBucket].mu.Lock()
		ct.buckets[replyBucket].mu.Lock()
	} else if tupleBucket > replyBucket {
		ct.buckets[replyBucket].mu.Lock()
		ct.buckets[tupleBucket].mu.Lock()
	} else {
		// Both tuples are in the same bucket.
		ct.buckets[tupleBucket].mu.Lock()
	}

	// Add the tuple to the map.
	ct.buckets[tupleBucket].tuples.PushFront(&conn.original)
	ct.buckets[replyBucket].tuples.PushFront(&conn.reply)

	// Unlocking can happen in any order.
	ct.buckets[tupleBucket].mu.Unlock()
	if tupleBucket != replyBucket {
		ct.buckets[replyBucket].mu.Unlock()
	}

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

	// Mark the connection as having been used recently so it isn't reaped.
	conn.lastUsed = time.Now()
	// Update connection state.
	if tcpHeader := header.TCP(pkt.TransportHeader); conn.tcb.IsEmpty() {
		conn.tcb.Init(tcpHeader)
		conn.tcbHook = hook
	} else if hook == conn.tcbHook {
		conn.tcb.UpdateStateOutbound(tcpHeader)
	} else {
		conn.tcb.UpdateStateInbound(tcpHeader)
	}
}

// bucket gets the conntrack bucket for a tupleID.
func (ct *ConnTrack) bucket(id tupleID) int {
	h := jenkins.Sum32(ct.seed)
	h.Write([]byte(id.srcAddr))
	h.Write([]byte(id.dstAddr))
	shortBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(shortBuf, id.srcPort)
	h.Write([]byte(shortBuf))
	binary.LittleEndian.PutUint16(shortBuf, id.dstPort)
	h.Write([]byte(shortBuf))
	binary.LittleEndian.PutUint16(shortBuf, uint16(id.transProto))
	h.Write([]byte(shortBuf))
	binary.LittleEndian.PutUint16(shortBuf, uint16(id.netProto))
	h.Write([]byte(shortBuf))
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return int(h.Sum32()) % len(ct.buckets)
}

// reapUnused deletes timed out entries from the conntrack map. The rules for
// reaping are:
// - Most reaping occurs in connFor, which is called on each packet. connFor
//   cleans up the bucket the packet's connection maps to. Thus calls to
//   reapUnused should be fast.
// - Each call to reapUnused traverses a fraction of the conntrack table.
//   Specifically, it traverses len(ct.buckets)/fractionPerReaping.
// - After reaping, reapUnused decides when it should next run based on the
//   ratio of expired connections to examined connections. If the ratio is
//   greater than maxExpiredPct, it schedules the next run quickly. Otherwise it
//   slightly increases the interval between runs.
// - maxFullTraversal caps the time it takes to traverse the entire table.
//
// reapUnused returns the next bucket that should be checked and the time after
// which it should be called again.
func (ct *ConnTrack) reapUnused(start int, prevInterval time.Duration) (int, time.Duration) {
	// TODO(gvisor.dev/issue/170): This can be more finely controlled, as
	// it is in Linux via sysctl.
	const fractionPerReaping = 128
	const maxExpiredPct = 50
	const maxFullTraversal = 60 * time.Second
	const minInterval = 10 * time.Millisecond
	const maxInterval = maxFullTraversal / fractionPerReaping

	now := time.Now()
	checked := 0
	expired := 0
	var idx int
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	for i := 0; i < len(ct.buckets)/fractionPerReaping; i++ {
		idx = (i + start) % len(ct.buckets)
		ct.buckets[idx].mu.Lock()
		for tuple := ct.buckets[idx].tuples.Front(); tuple != nil; tuple = tuple.Next() {
			checked++
			if ct.reapTupleLocked(tuple, idx, now) {
				expired++
			}
		}
		ct.buckets[idx].mu.Unlock()
	}
	// We already checked buckets[idx].
	idx++

	// If half or more of the connections are expired, the table has gotten
	// stale. Reschedule quickly.
	expiredPct := 0
	if checked != 0 {
		expiredPct = expired * 100 / checked
	}
	if expiredPct > maxExpiredPct {
		return idx, minInterval
	}
	if interval := prevInterval + minInterval; interval <= maxInterval {
		// Increment the interval between runs.
		return idx, interval
	}
	// We've hit the maximum interval.
	return idx, maxInterval
}

// reapTupleLocked tries to remove tuple and its reply from the table. It
// returns whether the tuple's connection has timed out.
//
// Preconditions: ct.mu is locked for reading and bucket is locked.
func (ct *ConnTrack) reapTupleLocked(tuple *tuple, bucket int, now time.Time) bool {
	if !tuple.conn.timedOut(now) {
		return false
	}

	// To maintain lock order, we can only reap these tuples if the reply
	// appears later in the table.
	replyBucket := ct.bucket(tuple.reply())
	if bucket > replyBucket {
		return true
	}

	// Don't re-lock if both tuples are in the same bucket.
	differentBuckets := bucket != replyBucket
	if differentBuckets {
		ct.buckets[replyBucket].mu.Lock()
	}

	// We have the buckets locked and can remove both tuples.
	if tuple.direction == dirOriginal {
		ct.buckets[replyBucket].tuples.Remove(&tuple.conn.reply)
	} else {
		ct.buckets[replyBucket].tuples.Remove(&tuple.conn.original)
	}
	ct.buckets[bucket].tuples.Remove(tuple)

	// Don't re-unlock if both tuples are in the same bucket.
	if differentBuckets {
		ct.buckets[replyBucket].mu.Unlock()
	}

	return true
}
