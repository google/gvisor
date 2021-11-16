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
	"math/rand"
	"sync"
	"sync/atomic"
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
// looking at the tuples in each hook.
//
// Currently, only TCP tracking is supported.

// Our hash table has 16K buckets.
const numBuckets = 1 << 14

const (
	establishedTimeout   time.Duration = 5 * 24 * time.Hour
	unestablishedTimeout time.Duration = 120 * time.Second
)

// tuple holds a connection's identifying and manipulating data in one
// direction. It is immutable.
//
// +stateify savable
type tuple struct {
	// tupleEntry is used to build an intrusive list of tuples.
	tupleEntry

	// conn is the connection tracking entry this tuple belongs to.
	conn *conn

	// reply is true iff the tuple's direction is opposite that of the first
	// packet seen on the connection.
	reply bool

	mu sync.RWMutex `state:"nosave"`
	// +checklocks:mu
	tupleID tupleID
}

func (t *tuple) id() tupleID {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.tupleID
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

type manipType int

const (
	// manipNotPerformed indicates that NAT has not been performed.
	manipNotPerformed manipType = iota

	// manipPerformed indicates that NAT was performed.
	manipPerformed

	// manipPerformedNoop indicates that NAT was performed but it was a no-op.
	manipPerformedNoop
)

type finalizeResult uint32

const (
	// A finalizeResult must be explicitly set so we don't make use of the zero
	// value.
	_ finalizeResult = iota

	finalizeResultSuccess
	finalizeResultConflict
)

// conn is a tracked connection.
//
// +stateify savable
type conn struct {
	ct *ConnTrack

	// original is the tuple in original direction. It is immutable.
	original tuple

	// reply is the tuple in reply direction.
	reply tuple

	finalizeOnce sync.Once
	// Holds a finalizeResult.
	//
	// +checkatomics
	finalizeResult uint32

	mu sync.RWMutex `state:"nosave"`
	// sourceManip indicates the source manipulation type.
	//
	// +checklocks:mu
	sourceManip manipType
	// destinationManip indicates the destination's manipulation type.
	//
	// +checklocks:mu
	destinationManip manipType

	stateMu sync.RWMutex `state:"nosave"`
	// tcb is TCB control block. It is used to keep track of states
	// of tcp connection.
	//
	// +checklocks:stateMu
	tcb tcpconntrack.TCB
	// lastUsed is the last time the connection saw a relevant packet, and
	// is updated by each packet on the connection.
	//
	// +checklocks:stateMu
	lastUsed tcpip.MonotonicTime
}

// timedOut returns whether the connection timed out based on its state.
func (cn *conn) timedOut(now tcpip.MonotonicTime) bool {
	cn.stateMu.RLock()
	defer cn.stateMu.RUnlock()
	if cn.tcb.State() == tcpconntrack.ResultAlive {
		// Use the same default as Linux, which doesn't delete
		// established connections for 5(!) days.
		return now.Sub(cn.lastUsed) > establishedTimeout
	}
	// Use the same default as Linux, which lets connections in most states
	// other than established remain for <= 120 seconds.
	return now.Sub(cn.lastUsed) > unestablishedTimeout
}

// update the connection tracking state.
func (cn *conn) update(pkt *PacketBuffer, reply bool) {
	cn.stateMu.Lock()
	defer cn.stateMu.Unlock()

	// Mark the connection as having been used recently so it isn't reaped.
	cn.lastUsed = cn.ct.clock.NowMonotonic()

	if pkt.TransportProtocolNumber != header.TCPProtocolNumber {
		return
	}

	tcpHeader := header.TCP(pkt.TransportHeader().View())

	// Update the state of tcb. tcb assumes it's always initialized on the
	// client. However, we only need to know whether the connection is
	// established or not, so the client/server distinction isn't important.
	if cn.tcb.IsEmpty() {
		cn.tcb.Init(tcpHeader)
		return
	}

	if reply {
		cn.tcb.UpdateStateReply(tcpHeader)
	} else {
		cn.tcb.UpdateStateOriginal(tcpHeader)
	}
}

// ConnTrack tracks all connections created for NAT rules. Most users are
// expected to only call handlePacket, insertRedirectConn, and maybeInsertNoop.
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

	// clock provides timing used to determine conntrack reapings.
	clock tcpip.Clock
	rand  *rand.Rand

	mu sync.RWMutex `state:"nosave"`
	// mu protects the buckets slice, but not buckets' contents. Only take
	// the write lock if you are modifying the slice or saving for S/R.
	//
	// +checklocks:mu
	buckets []bucket
}

// +stateify savable
type bucket struct {
	mu sync.RWMutex `state:"nosave"`
	// +checklocks:mu
	tuples tupleList
}

// A netAndTransHeadersFunc returns the network and transport headers found
// in an ICMP payload. The transport layer's payload will not be returned.
//
// May panic if the packet does not hold the transport header.
type netAndTransHeadersFunc func(icmpPayload []byte, minTransHdrLen int) (netHdr header.Network, transHdrBytes []byte)

func v4NetAndTransHdr(icmpPayload []byte, minTransHdrLen int) (header.Network, []byte) {
	netHdr := header.IPv4(icmpPayload)
	// Do not use netHdr.Payload() as we might not hold the full packet
	// in the ICMP error; Payload() panics if the buffer is smaller than
	// the total length specified in the IPv4 header.
	transHdr := icmpPayload[netHdr.HeaderLength():]
	return netHdr, transHdr[:minTransHdrLen]
}

func v6NetAndTransHdr(icmpPayload []byte, minTransHdrLen int) (header.Network, []byte) {
	netHdr := header.IPv6(icmpPayload)
	// Do not use netHdr.Payload() as we might not hold the full packet
	// in the ICMP error; Payload() panics if the IP payload is smaller than
	// the payload length specified in the IPv6 header.
	transHdr := icmpPayload[header.IPv6MinimumSize:]
	return netHdr, transHdr[:minTransHdrLen]
}

func getEmbeddedNetAndTransHeaders(pkt *PacketBuffer, netHdrLength int, getNetAndTransHdr netAndTransHeadersFunc, transProto tcpip.TransportProtocolNumber) (header.Network, header.ChecksummableTransport, bool) {
	switch transProto {
	case header.TCPProtocolNumber:
		if netAndTransHeader, ok := pkt.Data().PullUp(netHdrLength + header.TCPMinimumSize); ok {
			netHeader, transHeaderBytes := getNetAndTransHdr(netAndTransHeader, header.TCPMinimumSize)
			return netHeader, header.TCP(transHeaderBytes), true
		}
	case header.UDPProtocolNumber:
		if netAndTransHeader, ok := pkt.Data().PullUp(netHdrLength + header.UDPMinimumSize); ok {
			netHeader, transHeaderBytes := getNetAndTransHdr(netAndTransHeader, header.UDPMinimumSize)
			return netHeader, header.UDP(transHeaderBytes), true
		}
	}
	return nil, nil, false
}

func getHeaders(pkt *PacketBuffer) (netHdr header.Network, transHdr header.ChecksummableTransport, isICMPError bool, ok bool) {
	switch pkt.TransportProtocolNumber {
	case header.TCPProtocolNumber:
		if tcpHeader := header.TCP(pkt.TransportHeader().View()); len(tcpHeader) >= header.TCPMinimumSize {
			return pkt.Network(), tcpHeader, false, true
		}
	case header.UDPProtocolNumber:
		if udpHeader := header.UDP(pkt.TransportHeader().View()); len(udpHeader) >= header.UDPMinimumSize {
			return pkt.Network(), udpHeader, false, true
		}
	case header.ICMPv4ProtocolNumber:
		h, ok := pkt.Data().PullUp(header.IPv4MinimumSize)
		if !ok {
			panic(fmt.Sprintf("should have a valid IPv4 packet; only have %d bytes, want at least %d bytes", pkt.Data().Size(), header.IPv4MinimumSize))
		}

		if header.IPv4(h).HeaderLength() > header.IPv4MinimumSize {
			// TODO(https://gvisor.dev/issue/6765): Handle IPv4 options.
			panic("should have dropped packets with IPv4 options")
		}

		if netHdr, transHdr, ok := getEmbeddedNetAndTransHeaders(pkt, header.IPv4MinimumSize, v4NetAndTransHdr, pkt.tuple.id().transProto); ok {
			return netHdr, transHdr, true, true
		}
	case header.ICMPv6ProtocolNumber:
		h, ok := pkt.Data().PullUp(header.IPv6MinimumSize)
		if !ok {
			panic(fmt.Sprintf("should have a valid IPv6 packet; only have %d bytes, want at least %d bytes", pkt.Data().Size(), header.IPv6MinimumSize))
		}

		// We do not support extension headers in ICMP errors so the next header
		// in the IPv6 packet should be a tracked protocol if we reach this point.
		//
		// TODO(https://gvisor.dev/issue/6789): Support extension headers.
		transProto := pkt.tuple.id().transProto
		if got := header.IPv6(h).TransportProtocol(); got != transProto {
			panic(fmt.Sprintf("got TransportProtocol() = %d, want = %d", got, transProto))
		}

		if netHdr, transHdr, ok := getEmbeddedNetAndTransHeaders(pkt, header.IPv6MinimumSize, v6NetAndTransHdr, transProto); ok {
			return netHdr, transHdr, true, true
		}
	}

	return nil, nil, false, false
}

func getTupleIDForRegularPacket(netHdr header.Network, netProto tcpip.NetworkProtocolNumber, transHdr header.Transport, transProto tcpip.TransportProtocolNumber) tupleID {
	return tupleID{
		srcAddr:    netHdr.SourceAddress(),
		srcPort:    transHdr.SourcePort(),
		dstAddr:    netHdr.DestinationAddress(),
		dstPort:    transHdr.DestinationPort(),
		transProto: transProto,
		netProto:   netProto,
	}
}

func getTupleIDForPacketInICMPError(pkt *PacketBuffer, getNetAndTransHdr netAndTransHeadersFunc, netProto tcpip.NetworkProtocolNumber, netLen int, transProto tcpip.TransportProtocolNumber) (tupleID, bool) {
	if netHdr, transHdr, ok := getEmbeddedNetAndTransHeaders(pkt, netLen, getNetAndTransHdr, transProto); ok {
		return tupleID{
			srcAddr:    netHdr.DestinationAddress(),
			srcPort:    transHdr.DestinationPort(),
			dstAddr:    netHdr.SourceAddress(),
			dstPort:    transHdr.SourcePort(),
			transProto: transProto,
			netProto:   netProto,
		}, true
	}

	return tupleID{}, false
}

func getTupleID(pkt *PacketBuffer) (tid tupleID, isICMPError bool, ok bool) {
	switch pkt.TransportProtocolNumber {
	case header.TCPProtocolNumber:
		if transHeader := header.TCP(pkt.TransportHeader().View()); len(transHeader) >= header.TCPMinimumSize {
			return getTupleIDForRegularPacket(pkt.Network(), pkt.NetworkProtocolNumber, transHeader, pkt.TransportProtocolNumber), false, true
		}
	case header.UDPProtocolNumber:
		if transHeader := header.UDP(pkt.TransportHeader().View()); len(transHeader) >= header.UDPMinimumSize {
			return getTupleIDForRegularPacket(pkt.Network(), pkt.NetworkProtocolNumber, transHeader, pkt.TransportProtocolNumber), false, true
		}
	case header.ICMPv4ProtocolNumber:
		icmp := header.ICMPv4(pkt.TransportHeader().View())
		if len(icmp) < header.ICMPv4MinimumSize {
			return tupleID{}, false, false
		}

		switch icmp.Type() {
		case header.ICMPv4DstUnreachable, header.ICMPv4TimeExceeded, header.ICMPv4ParamProblem:
		default:
			return tupleID{}, false, false
		}

		h, ok := pkt.Data().PullUp(header.IPv4MinimumSize)
		if !ok {
			return tupleID{}, false, false
		}

		ipv4 := header.IPv4(h)
		if ipv4.HeaderLength() > header.IPv4MinimumSize {
			// TODO(https://gvisor.dev/issue/6765): Handle IPv4 options.
			return tupleID{}, false, false
		}

		if tid, ok := getTupleIDForPacketInICMPError(pkt, v4NetAndTransHdr, header.IPv4ProtocolNumber, header.IPv4MinimumSize, ipv4.TransportProtocol()); ok {
			return tid, true, true
		}
	case header.ICMPv6ProtocolNumber:
		icmp := header.ICMPv6(pkt.TransportHeader().View())
		if len(icmp) < header.ICMPv6MinimumSize {
			return tupleID{}, false, false
		}

		switch icmp.Type() {
		case header.ICMPv6DstUnreachable, header.ICMPv6PacketTooBig, header.ICMPv6TimeExceeded, header.ICMPv6ParamProblem:
		default:
			return tupleID{}, false, false
		}

		h, ok := pkt.Data().PullUp(header.IPv6MinimumSize)
		if !ok {
			return tupleID{}, false, false
		}

		// TODO(https://gvisor.dev/issue/6789): Handle extension headers.
		if tid, ok := getTupleIDForPacketInICMPError(pkt, v6NetAndTransHdr, header.IPv6ProtocolNumber, header.IPv6MinimumSize, header.IPv6(h).TransportProtocol()); ok {
			return tid, true, true
		}
	}

	return tupleID{}, false, false
}

func (ct *ConnTrack) init() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.buckets = make([]bucket, numBuckets)
}

// getConnAndUpdate attempts to get a connection or creates one if no
// connection exists for the packet and packet's protocol is trackable.
//
// If the packet's protocol is trackable, the connection's state is updated to
// match the contents of the packet.
func (ct *ConnTrack) getConnAndUpdate(pkt *PacketBuffer) *tuple {
	// Get or (maybe) create a connection.
	t := func() *tuple {
		tid, isICMPError, ok := getTupleID(pkt)
		if !ok {
			return nil
		}

		bktID := ct.bucket(tid)

		ct.mu.RLock()
		bkt := &ct.buckets[bktID]
		ct.mu.RUnlock()

		now := ct.clock.NowMonotonic()
		if t := bkt.connForTID(tid, now); t != nil {
			return t
		}

		if isICMPError {
			// Do not create a noop entry in response to an ICMP error.
			return nil
		}

		bkt.mu.Lock()
		defer bkt.mu.Unlock()

		// Make sure a connection wasn't added between when we last checked the
		// bucket and acquired the bucket's write lock.
		if t := bkt.connForTIDRLocked(tid, now); t != nil {
			return t
		}

		// This is the first packet we're seeing for the connection. Create an entry
		// for this new connection.
		conn := &conn{
			ct:       ct,
			original: tuple{tupleID: tid},
			reply:    tuple{tupleID: tid.reply(), reply: true},
			lastUsed: now,
		}
		conn.original.conn = conn
		conn.reply.conn = conn

		// For now, we only map an entry for the packet's original tuple as NAT may be
		// performed on this connection. Until the packet goes through all the hooks
		// and its final address/port is known, we cannot know what the response
		// packet's addresses/ports will look like.
		//
		// This is okay because the destination cannot send its response until it
		// receives the packet; the packet will only be received once all the hooks
		// have been performed.
		//
		// See (*conn).finalize.
		bkt.tuples.PushFront(&conn.original)
		return &conn.original
	}()
	if t != nil {
		t.conn.update(pkt, t.reply)
	}
	return t
}

func (ct *ConnTrack) connForTID(tid tupleID) *tuple {
	bktID := ct.bucket(tid)

	ct.mu.RLock()
	bkt := &ct.buckets[bktID]
	ct.mu.RUnlock()

	return bkt.connForTID(tid, ct.clock.NowMonotonic())
}

func (bkt *bucket) connForTID(tid tupleID, now tcpip.MonotonicTime) *tuple {
	bkt.mu.RLock()
	defer bkt.mu.RUnlock()
	return bkt.connForTIDRLocked(tid, now)
}

// +checklocksread:bkt.mu
func (bkt *bucket) connForTIDRLocked(tid tupleID, now tcpip.MonotonicTime) *tuple {
	for other := bkt.tuples.Front(); other != nil; other = other.Next() {
		if tid == other.id() && !other.conn.timedOut(now) {
			return other
		}
	}
	return nil
}

func (ct *ConnTrack) finalize(cn *conn) finalizeResult {
	ct.mu.RLock()
	buckets := ct.buckets
	ct.mu.RUnlock()

	{
		tid := cn.reply.id()
		id := ct.bucket(tid)

		bkt := &buckets[id]
		bkt.mu.Lock()
		if bkt.connForTIDRLocked(tid, ct.clock.NowMonotonic()) == nil {
			bkt.tuples.PushFront(&cn.reply)
			bkt.mu.Unlock()
			return finalizeResultSuccess
		}
		bkt.mu.Unlock()
	}

	// Another connection for the reply already exists. Remove the original and
	// let the caller know we failed.
	//
	// TODO(https://gvisor.dev/issue/6850): Investigate handling this clash
	// better.

	tid := cn.original.id()
	id := ct.bucket(tid)
	bkt := &buckets[id]
	bkt.mu.Lock()
	defer bkt.mu.Unlock()
	bkt.tuples.Remove(&cn.original)
	return finalizeResultConflict
}

func (cn *conn) getFinalizeResult() finalizeResult {
	return finalizeResult(atomic.LoadUint32(&cn.finalizeResult))
}

// finalize attempts to finalize the connection and returns true iff the
// connection was successfully finalized.
//
// If the connection failed to finalize, the caller should drop the packet
// associated with the connection.
//
// If multiple goroutines attempt to finalize at the same time, only one
// goroutine will perform the work to finalize the connection, but all
// goroutines will block until the finalizing goroutine finishes finalizing.
func (cn *conn) finalize() bool {
	cn.finalizeOnce.Do(func() {
		atomic.StoreUint32(&cn.finalizeResult, uint32(cn.ct.finalize(cn)))
	})

	switch res := cn.getFinalizeResult(); res {
	case finalizeResultSuccess:
		return true
	case finalizeResultConflict:
		return false
	default:
		panic(fmt.Sprintf("unhandled result = %d", res))
	}
}

func (cn *conn) maybePerformNoopNAT(dnat bool) {
	cn.mu.Lock()
	defer cn.mu.Unlock()

	var manip *manipType
	if dnat {
		manip = &cn.destinationManip
	} else {
		manip = &cn.sourceManip
	}

	if *manip == manipNotPerformed {
		*manip = manipPerformedNoop
	}
}

type portRange struct {
	start uint16
	size  uint16
}

// performNAT setups up the connection for the specified NAT and rewrites the
// packet.
//
// If NAT has already been performed on the connection, then the packet will
// be rewritten with the NAT performed on the connection, ignoring the passed
// address and port range.
//
// Generally, only the first packet of a connection reaches this method; other
// packets will be manipulated without needing to modify the connection.
func (cn *conn) performNAT(pkt *PacketBuffer, hook Hook, r *Route, ports portRange, natAddress tcpip.Address, dnat bool) {
	// Make sure the packet is re-written after performing NAT.
	defer func() {
		// handlePacket returns true if the packet may skip the NAT table as the
		// connection is already NATed, but if we reach this point we must be in the
		// NAT table, so the return value is useless for us.
		_ = cn.handlePacket(pkt, hook, r)
	}()

	cn.mu.Lock()
	defer cn.mu.Unlock()

	cn.reply.mu.Lock()
	defer cn.reply.mu.Unlock()

	var manip *manipType
	var address *tcpip.Address
	var port *uint16
	if dnat {
		manip = &cn.destinationManip
		address = &cn.reply.tupleID.srcAddr
		port = &cn.reply.tupleID.srcPort
	} else {
		manip = &cn.sourceManip
		address = &cn.reply.tupleID.dstAddr
		port = &cn.reply.tupleID.dstPort
	}

	if *manip != manipNotPerformed {
		return
	}
	*manip = manipPerformed
	*address = natAddress

	// Does the current port fit in the range?
	if end := ports.start + ports.size - 1; *port >= ports.start && *port <= end {
		// Yes, is the current reply tuple unique?
		if other := cn.ct.connForTID(cn.reply.tupleID); other == nil {
			// Yes! No need to change the port.
			return
		}
	}

	// Try our best to find a port that results in a unique reply tuple.
	//
	// We limit the number of attempts to find a unique tuple to not waste a lot
	// of time looking for a unique tuple.
	//
	// Matches linux behaviour introduced in
	// https://github.com/torvalds/linux/commit/a504b703bb1da526a01593da0e4be2af9d9f5fa8.
	const maxAttemptsForInitialRound uint16 = 128
	const minAttemptsToContinue = 16

	allowedInitialAttempts := maxAttemptsForInitialRound
	if allowedInitialAttempts > ports.size {
		allowedInitialAttempts = ports.size
	}

	for maxAttempts := allowedInitialAttempts; ; maxAttempts /= 2 {
		// Start reach round with a random initial port in the range.
		initial := ports.start + uint16(cn.ct.rand.Uint32())%ports.size

		for i := uint16(0); i < maxAttempts; i++ {
			*port = initial + i%ports.size

			if other := cn.ct.connForTID(cn.reply.tupleID); other == nil {
				// We found a unique tuple!
				return
			}
		}

		if maxAttempts == ports.size {
			// We already tried all the ports in the range so no need to keep trying.
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

// handlePacket attempts to handle a packet and perform NAT if the connection
// has had NAT performed on it.
//
// Returns true if the packet can skip the NAT table.
func (cn *conn) handlePacket(pkt *PacketBuffer, hook Hook, rt *Route) bool {
	netHdr, transHdr, isICMPError, ok := getHeaders(pkt)
	if !ok {
		return false
	}

	fullChecksum := false
	updatePseudoHeader := false
	natDone := &pkt.SNATDone
	dnat := false
	switch hook {
	case Prerouting:
		// Packet came from outside the stack so it must have a checksum set
		// already.
		fullChecksum = true
		updatePseudoHeader = true

		natDone = &pkt.DNATDone
		dnat = true
	case Input:
	case Forward:
		panic("should not handle packet in the forwarding hook")
	case Output:
		natDone = &pkt.DNATDone
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

	tid, manip := func() (tupleID, manipType) {
		cn.mu.RLock()
		defer cn.mu.RUnlock()

		if reply {
			tid := cn.original.id()

			if dnat {
				return tid, cn.sourceManip
			}
			return tid, cn.destinationManip
		}

		tid := cn.reply.id()
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

	newPort := tid.dstPort
	newAddr := tid.dstAddr
	if dnat {
		newPort = tid.srcPort
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
		icmp := header.ICMPv4(pkt.TransportHeader().View())
		// TODO(https://gvisor.dev/issue/6788): Incrementally update ICMP checksum.
		icmp.SetChecksum(0)
		icmp.SetChecksum(header.ICMPv4Checksum(icmp, pkt.Data().AsRange().Checksum()))

		network := header.IPv4(pkt.NetworkHeader().View())
		if dnat {
			network.SetDestinationAddressWithChecksumUpdate(tid.srcAddr)
		} else {
			network.SetSourceAddressWithChecksumUpdate(tid.dstAddr)
		}
	case header.ICMPv6ProtocolNumber:
		network := header.IPv6(pkt.NetworkHeader().View())
		srcAddr := network.SourceAddress()
		dstAddr := network.DestinationAddress()
		if dnat {
			dstAddr = tid.srcAddr
		} else {
			srcAddr = tid.dstAddr
		}

		icmp := header.ICMPv6(pkt.TransportHeader().View())
		// TODO(https://gvisor.dev/issue/6788): Incrementally update ICMP checksum.
		icmp.SetChecksum(0)
		payload := pkt.Data()
		icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmp,
			Src:         srcAddr,
			Dst:         dstAddr,
			PayloadCsum: payload.AsRange().Checksum(),
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
	const fractionPerReaping = 128
	const maxExpiredPct = 50
	const maxFullTraversal = 60 * time.Second
	const minInterval = 10 * time.Millisecond
	const maxInterval = maxFullTraversal / fractionPerReaping

	now := ct.clock.NowMonotonic()
	checked := 0
	expired := 0
	var idx int
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	for i := 0; i < len(ct.buckets)/fractionPerReaping; i++ {
		idx = (i + start) % len(ct.buckets)
		bkt := &ct.buckets[idx]
		bkt.mu.Lock()
		for tuple := bkt.tuples.Front(); tuple != nil; {
			// reapTupleLocked updates tuple's next pointer so we grab it here.
			nextTuple := tuple.Next()

			checked++
			if ct.reapTupleLocked(tuple, idx, bkt, now) {
				expired++
			}

			tuple = nextTuple
		}
		bkt.mu.Unlock()
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
// Precondition: ct.mu is read locked and bkt.mu is write locked.
// +checklocksread:ct.mu
// +checklocks:bkt.mu
func (ct *ConnTrack) reapTupleLocked(reapingTuple *tuple, bktID int, bkt *bucket, now tcpip.MonotonicTime) bool {
	if !reapingTuple.conn.timedOut(now) {
		return false
	}

	var otherTuple *tuple
	if reapingTuple.reply {
		otherTuple = &reapingTuple.conn.original
	} else {
		otherTuple = &reapingTuple.conn.reply
	}

	otherTupleBktID := ct.bucket(otherTuple.id())
	replyTupleInserted := reapingTuple.conn.getFinalizeResult() == finalizeResultSuccess

	// To maintain lock order, we can only reap both tuples if the tuple for the
	// other direction appears later in the table.
	if bktID > otherTupleBktID && replyTupleInserted {
		return true
	}

	bkt.tuples.Remove(reapingTuple)

	if !replyTupleInserted {
		// The other tuple is the reply which has not yet been inserted.
		return true
	}

	// Reap the other connection.
	if bktID == otherTupleBktID {
		// Don't re-lock if both tuples are in the same bucket.
		bkt.tuples.Remove(otherTuple)
	} else {
		otherTupleBkt := &ct.buckets[otherTupleBktID]
		otherTupleBkt.mu.Lock()
		otherTupleBkt.tuples.Remove(otherTuple)
		otherTupleBkt.mu.Unlock()
	}

	return true
}

func (ct *ConnTrack) originalDst(epID TransportEndpointID, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber) (tcpip.Address, uint16, tcpip.Error) {
	// Lookup the connection. The reply's original destination
	// describes the original address.
	tid := tupleID{
		srcAddr:    epID.LocalAddress,
		srcPort:    epID.LocalPort,
		dstAddr:    epID.RemoteAddress,
		dstPort:    epID.RemotePort,
		transProto: transProto,
		netProto:   netProto,
	}
	t := ct.connForTID(tid)
	if t == nil {
		// Not a tracked connection.
		return "", 0, &tcpip.ErrNotConnected{}
	}

	t.conn.mu.RLock()
	defer t.conn.mu.RUnlock()
	if t.conn.destinationManip == manipNotPerformed {
		// Unmanipulated destination.
		return "", 0, &tcpip.ErrInvalidOptionValue{}
	}

	id := t.conn.original.id()
	return id.dstAddr, id.dstPort, nil
}
