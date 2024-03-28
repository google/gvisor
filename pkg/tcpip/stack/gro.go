// Copyright 2022 The gVisor Authors.
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
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TODO(b/256037250): Enable by default.
// TODO(b/256037250): We parse headers here. We should save those headers in
// PacketBuffers so they don't have to be re-parsed later.
// TODO(b/256037250): I still see the occasional SACK block in the zero-loss
// benchmark, which should not happen.
// TODO(b/256037250): Some dispatchers, e.g. XDP and RecvMmsg, can receive
// multiple packets at a time. Even if the GRO interval is 0, there is an
// opportunity for coalescing.
// TODO(b/256037250): We're doing some header parsing here, which presents the
// opportunity to skip it later.
// TODO(b/256037250): We may be able to remove locking by pairing
// groDispatchers with link endpoint dispatchers.
// TODO(b/256037250): Do we actually need the fancy data structure?
// TODO(b/256037250): Can we pass a packet list up the stack too?

// TODO(b/256037250): Go through and re-evaluate now that all locking is dead.

const (
	// groNBuckets is the number of GRO buckets.
	groNBuckets = 8

	groNBucketsMask = groNBuckets - 1

	// groBucketSize is the size of each GRO bucket.
	groBucketSize = 8

	// groMaxPacketSize is the maximum size of a GRO'd packet.
	groMaxPacketSize = 1 << 16 // 65KB.
)

// A groBucket holds packets that are undergoing GRO.
type groBucket struct {
	// count is the number of packets in the bucket.
	count int

	// packets is the linked list of packets.
	packets groPacketList

	// packetsPrealloc and allocIdxs are used to preallocate and reuse
	// groPacket structs and avoid allocation.
	packetsPrealloc [groBucketSize]groPacket

	allocIdxs [groBucketSize]int
}

func (gb *groBucket) full() bool {
	return gb.count == groBucketSize
}

// insert inserts pkt into the bucket.
func (gb *groBucket) insert(pkt *PacketBuffer, ipHdr []byte, tcpHdr header.TCP) {
	groPkt := &gb.packetsPrealloc[gb.allocIdxs[gb.count]]
	*groPkt = groPacket{
		pkt:           pkt,
		ipHdr:         ipHdr,
		tcpHdr:        tcpHdr,
		initialLength: pkt.Data().Size(), // pkt.Data() contains network header.
		idx:           groPkt.idx,
	}
	gb.count++
	gb.packets.PushBack(groPkt)
}

// removeOldest removes the oldest packet from gb and returns the contained
// PacketBuffer. gb must not be empty.
func (gb *groBucket) removeOldest() *PacketBuffer {
	pkt := gb.packets.Front()
	gb.packets.Remove(pkt)
	gb.count--
	gb.allocIdxs[gb.count] = pkt.idx
	ret := pkt.pkt
	pkt.reset()
	return ret
}

// removeOne removes a packet from gb. It also resets pkt to its zero value.
func (gb *groBucket) removeOne(pkt *groPacket) {
	gb.packets.Remove(pkt)
	gb.count--
	gb.allocIdxs[gb.count] = pkt.idx
	pkt.reset()
}

// findGROPacket4 returns the groPkt that matches ipHdr and tcpHdr, or nil if
// none exists. It also returns whether the groPkt should be flushed based on
// differences between the two headers.
func (gb *groBucket) findGROPacket4(pkt *PacketBuffer, ipHdr header.IPv4, tcpHdr header.TCP) (*groPacket, bool) {
	for groPkt := gb.packets.Front(); groPkt != nil; groPkt = groPkt.Next() {
		// Do the addresses match?
		groIPHdr := header.IPv4(groPkt.ipHdr)
		if ipHdr.SourceAddress() != groIPHdr.SourceAddress() || ipHdr.DestinationAddress() != groIPHdr.DestinationAddress() {
			continue
		}

		// Do the ports match?
		if tcpHdr.SourcePort() != groPkt.tcpHdr.SourcePort() || tcpHdr.DestinationPort() != groPkt.tcpHdr.DestinationPort() {
			continue
		}

		// We've found a packet of the same flow.

		// IP checks.
		TOS, _ := ipHdr.TOS()
		groTOS, _ := groIPHdr.TOS()
		if ipHdr.TTL() != groIPHdr.TTL() || TOS != groTOS {
			return groPkt, true
		}

		// TCP checks.
		if shouldFlushTCP(groPkt, tcpHdr) {
			return groPkt, true
		}

		// There's an upper limit on coalesced packet size.
		if pkt.Data().Size()-header.IPv4MinimumSize-int(tcpHdr.DataOffset())+groPkt.pkt.Data().Size() >= groMaxPacketSize {
			return groPkt, true
		}

		return groPkt, false
	}

	return nil, false
}

// findGROPacket6 returns the groPkt that matches ipHdr and tcpHdr, or nil if
// none exists. It also returns whether the groPkt should be flushed based on
// differences between the two headers.
func (gb *groBucket) findGROPacket6(pkt *PacketBuffer, ipHdr header.IPv6, tcpHdr header.TCP) (*groPacket, bool) {
	for groPkt := gb.packets.Front(); groPkt != nil; groPkt = groPkt.Next() {
		// Do the addresses match?
		groIPHdr := header.IPv6(groPkt.ipHdr)
		if ipHdr.SourceAddress() != groIPHdr.SourceAddress() || ipHdr.DestinationAddress() != groIPHdr.DestinationAddress() {
			continue
		}

		// Need to check that headers are the same except:
		// - Traffic class, a difference of which causes a flush.
		// - Hop limit, a difference of which causes a flush.
		// - Length, which is checked later.
		// - Version, which is checked by an earlier call to IsValid().
		trafficClass, flowLabel := ipHdr.TOS()
		groTrafficClass, groFlowLabel := groIPHdr.TOS()
		if flowLabel != groFlowLabel || ipHdr.NextHeader() != groIPHdr.NextHeader() {
			continue
		}
		// Unlike IPv4, IPv6 packets with extension headers can be coalesced.
		if !bytes.Equal(ipHdr[header.IPv6MinimumSize:], groIPHdr[header.IPv6MinimumSize:]) {
			continue
		}

		// Do the ports match?
		if tcpHdr.SourcePort() != groPkt.tcpHdr.SourcePort() || tcpHdr.DestinationPort() != groPkt.tcpHdr.DestinationPort() {
			continue
		}

		// We've found a packet of the same flow.

		// TCP checks.
		if shouldFlushTCP(groPkt, tcpHdr) {
			return groPkt, true
		}

		// Do the traffic class and hop limit match?
		if trafficClass != groTrafficClass || ipHdr.HopLimit() != groIPHdr.HopLimit() {
			return groPkt, true
		}

		// This limit is artificial for IPv6 -- we could allow even
		// larger packets via jumbograms.
		if pkt.Data().Size()-len(ipHdr)-int(tcpHdr.DataOffset())+groPkt.pkt.Data().Size() >= groMaxPacketSize {
			return groPkt, true
		}

		return groPkt, false
	}

	return nil, false
}

func (gb *groBucket) found(gd *groDispatcher, groPkt *groPacket, flushGROPkt bool, pkt *PacketBuffer, ipHdr []byte, tcpHdr header.TCP, updateIPHdr func([]byte, int)) {
	// Flush groPkt or merge the packets.
	pktSize := pkt.Data().Size()
	flags := tcpHdr.Flags()
	dataOff := tcpHdr.DataOffset()
	tcpPayloadSize := pkt.Data().Size() - len(ipHdr) - int(dataOff)
	if flushGROPkt {
		// Flush the existing GRO packet.
		pkt := groPkt.pkt
		gb.removeOne(groPkt)
		gd.handlePacket(pkt)
		pkt.DecRef()
		groPkt = nil
	} else if groPkt != nil {
		// Merge pkt in to GRO packet.
		pkt.Data().TrimFront(len(ipHdr) + int(dataOff))
		groPkt.pkt.Data().Merge(pkt.Data())
		// Update the IP total length.
		updateIPHdr(groPkt.ipHdr, tcpPayloadSize)
		// Add flags from the packet to the GRO packet.
		groPkt.tcpHdr.SetFlags(uint8(groPkt.tcpHdr.Flags() | (flags & (header.TCPFlagFin | header.TCPFlagPsh))))

		pkt = nil
	}

	// Flush if the packet isn't the same size as the previous packets or
	// if certain flags are set. The reason for checking size equality is:
	// - If the packet is smaller than the others, this is likely the end
	//   of some message. Peers will send MSS-sized packets until they have
	//   insufficient data to do so.
	// - If the packet is larger than the others, this packet is either
	//   malformed, a local GSO packet, or has already been handled by host
	//   GRO.
	flush := header.TCPFlags(flags)&(header.TCPFlagUrg|header.TCPFlagPsh|header.TCPFlagRst|header.TCPFlagSyn|header.TCPFlagFin) != 0
	flush = flush || tcpPayloadSize == 0
	if groPkt != nil {
		flush = flush || pktSize != groPkt.initialLength
	}

	switch {
	case flush && groPkt != nil:
		// A merge occurred and we need to flush groPkt.
		pkt := groPkt.pkt
		gb.removeOne(groPkt) // is this ever called without handlePacket?
		gd.handlePacket(pkt)
		pkt.DecRef()
	case flush && groPkt == nil:
		// No merge occurred and the incoming packet needs to be flushed.
		gd.handlePacket(pkt)
	case !flush && groPkt == nil:
		// New flow and we don't need to flush. Insert pkt into GRO.
		if gb.full() {
			// Head is always the oldest packet
			toFlush := gb.removeOldest()
			gb.insert(pkt.IncRef(), ipHdr, tcpHdr)
			gd.handlePacket(toFlush)
			toFlush.DecRef()
		} else {
			gb.insert(pkt.IncRef(), ipHdr, tcpHdr)
		}
	default:
		// A merge occurred and we don't need to flush anything.
	}
}

// A groPacket is packet undergoing GRO. It may be several packets coalesced
// together.
type groPacket struct {
	// groPacketEntry is an intrusive list.
	groPacketEntry

	// pkt is the coalesced packet.
	pkt *PacketBuffer

	// ipHdr is the IP (v4 or v6) header for the coalesced packet.
	ipHdr []byte

	// tcpHdr is the TCP header for the coalesced packet.
	tcpHdr header.TCP

	// initialLength is the length of the first packet in the flow. It is
	// used as a best-effort guess at MSS: senders will send MSS-sized
	// packets until they run out of data, so we coalesce as long as
	// packets are the same size.
	initialLength int

	// idx is the groPacket's index in its bucket packetsPrealloc. It is
	// immutable.
	idx int
}

// reset resets all mutable fields of the groPacket.
func (pk *groPacket) reset() {
	*pk = groPacket{
		idx: pk.idx,
	}
}

// payloadSize is the payload size of the coalesced packet, which does not
// include the network or transport headers.
func (pk *groPacket) payloadSize() int {
	return pk.pkt.Data().Size() - len(pk.ipHdr) - int(pk.tcpHdr.DataOffset())
}

// groDispatcher coalesces incoming packets to increase throughput.
type groDispatcher struct {
	enabled bool

	buckets [groNBuckets]groBucket

	ep4 NetworkEndpoint // TODO: ipv4.Endpoint
	ep6 NetworkEndpoint // TODO: ipv6.Endpoint
}

func (gd *groDispatcher) init(enabled bool, ep4, ep6 NetworkEndpoint) {
	gd.enabled = enabled
	gd.ep4 = ep4
	gd.ep6 = ep6
	for i := range gd.buckets {
		bucket := &gd.buckets[i]
		for j := range bucket.packetsPrealloc {
			bucket.allocIdxs[j] = j
			bucket.packetsPrealloc[j].idx = j
		}
	}
}

// dispatch sends pkt up the stack after it undergoes GRO coalescing.
// TODO: This assumes IPv4 and IPv6 are always enabeld. Can we just do that?
func (gd *groDispatcher) dispatch(pkts PacketBufferList, nic *nic) {
	gd.dispatchWithFlush(pkts, nic, true)
}

func (gd *groDispatcher) dispatchWithFlush(pkts PacketBufferList, nic *nic, flush bool) {
	// TODO: for stats, add count of coalesced packets
	// log.Printf("pkts: %d", pkts.Len())
	// Is there anything to actually do?
	if !gd.enabled || pkts.Len() == 1 {
		for _, pkt := range pkts.AsSlice() {
			switch pkt.NetworkProtocolNumber {
			case header.IPv4ProtocolNumber:
				gd.ep4.HandlePacket(pkt)
			case header.IPv6ProtocolNumber:
				gd.ep6.HandlePacket(pkt)
			default:
				slowHandle(pkt, nic)
			}
		}
		return
	}

	for _, pkt := range pkts.AsSlice() {
		switch pkt.NetworkProtocolNumber {
		case header.IPv4ProtocolNumber:
			gd.dispatch4(pkt)
		case header.IPv6ProtocolNumber:
			gd.dispatch6(pkt)
		default:
			slowHandle(pkt, nic)
		}
	}

	// Always flush. We could wait and try to coalesce more packets, but at
	// this point we've already gotten multiple packets from a link
	// endpoint. And, analogous to how Linux lets packets accumulate under
	// NAPI while waiting for a softirq thread to read batched packets,
	// we've waited to get scheduled (by some combination of Go and Linux)
	// after being notified of incoming packets. Introducing further delay
	// may degrade performance with little upside.
	if flush {
		gd.flush()
	}
}

func slowHandle(pkt *PacketBuffer, nic *nic) {
	networkEndpoint := nic.getNetworkEndpoint(pkt.NetworkProtocolNumber)
	if networkEndpoint == nil {
		nic.stats.unknownL3ProtocolRcvdPacketCounts.Increment(uint64(pkt.NetworkProtocolNumber))
		return
	}
	networkEndpoint.HandlePacket(pkt)
}

func (gd *groDispatcher) dispatch4(pkt *PacketBuffer) {
	// Immediately get the IPv4 and TCP headers. We need a way to hash the
	// packet into its bucket, which requires addresses and ports. Linux
	// simply gets a hash passed by hardware, but we're not so lucky.

	// We only GRO TCP packets. The check for the transport protocol number
	// is done below so that we can PullUp both the IP and TCP headers
	// together.
	hdrBytes, ok := pkt.Data().PullUp(header.IPv4MinimumSize + header.TCPMinimumSize)
	if !ok {
		gd.ep4.HandlePacket(pkt)
		return
	}
	ipHdr := header.IPv4(hdrBytes)

	// We don't handle fragments. That should be the vast majority of
	// traffic, and simplifies handling.
	if ipHdr.FragmentOffset() != 0 || ipHdr.Flags()&header.IPv4FlagMoreFragments != 0 {
		gd.ep4.HandlePacket(pkt)
		return
	}

	// We only handle TCP packets without IP options.
	if ipHdr.HeaderLength() != header.IPv4MinimumSize || tcpip.TransportProtocolNumber(ipHdr.Protocol()) != header.TCPProtocolNumber {
		gd.ep4.HandlePacket(pkt)
		return
	}
	tcpHdr := header.TCP(hdrBytes[header.IPv4MinimumSize:])
	ipHdr = ipHdr[:header.IPv4MinimumSize]
	dataOff := tcpHdr.DataOffset()
	if dataOff < header.TCPMinimumSize {
		// Malformed packet: will be handled further up the stack.
		gd.ep4.HandlePacket(pkt)
		return
	}
	hdrBytes, ok = pkt.Data().PullUp(header.IPv4MinimumSize + int(dataOff))
	if !ok {
		// Malformed packet: will be handled further up the stack.
		gd.ep4.HandlePacket(pkt)
		return
	}

	tcpHdr = header.TCP(hdrBytes[header.IPv4MinimumSize:])

	// If either checksum is bad, flush the packet. Since we don't know
	// what bits were flipped, we can't identify this packet with a flow.
	if !pkt.RXChecksumValidated {
		if !ipHdr.IsValid(pkt.Data().Size()) || !ipHdr.IsChecksumValid() {
			gd.ep4.HandlePacket(pkt)
			return
		}
		payloadChecksum := pkt.Data().ChecksumAtOffset(header.IPv4MinimumSize + int(dataOff))
		tcpPayloadSize := pkt.Data().Size() - header.IPv4MinimumSize - int(dataOff)
		if !tcpHdr.IsChecksumValid(ipHdr.SourceAddress(), ipHdr.DestinationAddress(), payloadChecksum, uint16(tcpPayloadSize)) {
			gd.ep4.HandlePacket(pkt)
			return
		}
		// We've validated the checksum, no reason for others to do it
		// again.
		pkt.RXChecksumValidated = true
	}

	// Now we can get the bucket for the packet.
	bucket := &gd.buckets[gd.bucketForPacket4(ipHdr, tcpHdr)&groNBucketsMask]
	groPkt, flushGROPkt := bucket.findGROPacket4(pkt, ipHdr, tcpHdr)
	bucket.found(gd, groPkt, flushGROPkt, pkt, ipHdr, tcpHdr, updateIPv4Hdr)
}

func (gd *groDispatcher) dispatch6(pkt *PacketBuffer) {
	// Immediately get the IPv6 and TCP headers. We need a way to hash the
	// packet into its bucket, which requires addresses and ports. Linux
	// simply gets a hash passed by hardware, but we're not so lucky.

	hdrBytes, ok := pkt.Data().PullUp(header.IPv6MinimumSize)
	if !ok {
		gd.ep6.HandlePacket(pkt)
		return
	}
	ipHdr := header.IPv6(hdrBytes)

	// Getting the IP header (+ extension headers) size is a bit of a pain
	// on IPv6.
	transProto := tcpip.TransportProtocolNumber(ipHdr.NextHeader())
	buf := pkt.Data().ToBuffer()
	buf.TrimFront(header.IPv6MinimumSize)
	it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(transProto), buf)
	ipHdrSize := int(header.IPv6MinimumSize)
	for {
		transProto = tcpip.TransportProtocolNumber(it.NextHeaderIdentifier())
		extHdr, done, err := it.Next()
		if err != nil {
			gd.ep6.HandlePacket(pkt)
			return
		}
		if done {
			break
		}
		switch extHdr.(type) {
		// We can GRO these, so just skip over them.
		case header.IPv6HopByHopOptionsExtHdr:
		case header.IPv6RoutingExtHdr:
		case header.IPv6DestinationOptionsExtHdr:
		default:
			// This is either a TCP header or something we can't handle.
			ipHdrSize = int(it.HeaderOffset())
			done = true
		}
		extHdr.Release()
		if done {
			break
		}
	}

	hdrBytes, ok = pkt.Data().PullUp(ipHdrSize + header.TCPMinimumSize)
	if !ok {
		gd.ep6.HandlePacket(pkt)
		return
	}
	ipHdr = header.IPv6(hdrBytes[:ipHdrSize])

	// We only handle TCP packets.
	if transProto != header.TCPProtocolNumber {
		gd.ep6.HandlePacket(pkt)
		return
	}
	tcpHdr := header.TCP(hdrBytes[ipHdrSize:])
	dataOff := tcpHdr.DataOffset()
	if dataOff < header.TCPMinimumSize {
		// Malformed packet: will be handled further up the stack.
		gd.ep6.HandlePacket(pkt)
		return
	}

	hdrBytes, ok = pkt.Data().PullUp(ipHdrSize + int(dataOff))
	if !ok {
		// Malformed packet: will be handled further up the stack.
		gd.ep6.HandlePacket(pkt)
		return
	}
	tcpHdr = header.TCP(hdrBytes[ipHdrSize:])

	// If either checksum is bad, flush the packet. Since we don't know
	// what bits were flipped, we can't identify this packet with a flow.
	if !pkt.RXChecksumValidated {
		if !ipHdr.IsValid(pkt.Data().Size()) {
			gd.ep6.HandlePacket(pkt)
			return
		}
		payloadChecksum := pkt.Data().ChecksumAtOffset(ipHdrSize + int(dataOff))
		tcpPayloadSize := pkt.Data().Size() - ipHdrSize - int(dataOff)
		if !tcpHdr.IsChecksumValid(ipHdr.SourceAddress(), ipHdr.DestinationAddress(), payloadChecksum, uint16(tcpPayloadSize)) {
			gd.ep6.HandlePacket(pkt)
			return
		}
		// We've validated the checksum, no reason for others to do it
		// again.
		pkt.RXChecksumValidated = true
	}

	// Now we can get the bucket for the packet.
	bucket := &gd.buckets[gd.bucketForPacket4(ipHdr, tcpHdr)&groNBucketsMask]
	groPkt, flushGROPkt := bucket.findGROPacket6(pkt, ipHdr, tcpHdr)
	bucket.found(gd, groPkt, flushGROPkt, pkt, ipHdr, tcpHdr, updateIPv6Hdr)
}

func (gd *groDispatcher) bucketForPacket4(ipHdr header.IPv4, tcpHdr header.TCP) int {
	// TODO(b/256037250): Use jenkins or checksum. Write a test to print
	// distribution.
	var sum int
	srcAddr := ipHdr.SourceAddress()
	for _, val := range srcAddr.AsSlice() {
		sum += int(val)
	}
	dstAddr := ipHdr.DestinationAddress()
	for _, val := range dstAddr.AsSlice() {
		sum += int(val)
	}
	sum += int(tcpHdr.SourcePort())
	sum += int(tcpHdr.DestinationPort())
	return sum
}

func (gd *groDispatcher) bucketForPacket6(ipHdr header.IPv6, tcpHdr header.TCP) int {
	// TODO(b/256037250): Use jenkins or checksum. Write a test to print
	// distribution.
	var sum int
	srcAddr := ipHdr.SourceAddress()
	for _, val := range srcAddr.AsSlice() {
		sum += int(val)
	}
	dstAddr := ipHdr.DestinationAddress()
	for _, val := range dstAddr.AsSlice() {
		sum += int(val)
	}
	sum += int(tcpHdr.SourcePort())
	sum += int(tcpHdr.DestinationPort())
	return sum
}

// flush sends all packets up the stack.
func (gd *groDispatcher) flush() {
	for i := range gd.buckets {
		for groPkt := gd.buckets[i].packets.Front(); groPkt != nil; groPkt = groPkt.Next() {
			pkt := groPkt.pkt
			gd.buckets[i].removeOne(groPkt) // TODO: Batch? We're removing all of them.
			gd.handlePacket(pkt)
			pkt.DecRef()
		}
	}
}

func (gd *groDispatcher) handlePacket(pkt *PacketBuffer) {
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		gd.ep4.HandlePacket(pkt)
	case header.IPv6ProtocolNumber:
		gd.ep6.HandlePacket(pkt)
	default:
		panic(fmt.Sprintf("unhandled protocol %d in GRO", pkt.NetworkProtocolNumber))
	}
}

// String implements fmt.Stringer.
func (gd *groDispatcher) String() string {
	ret := "GRO state: \n"
	for i := range gd.buckets {
		bucket := &gd.buckets[i]
		ret += fmt.Sprintf("bucket %d: %d packets: ", i, bucket.count)
		for groPkt := bucket.packets.Front(); groPkt != nil; groPkt = groPkt.Next() {
			ret += fmt.Sprintf("%d, ", groPkt.pkt.Data().Size())
		}
		ret += "\n"
	}
	return ret
}

// shouldFlushTCP returns whether the TCP headers indicate that groPkt should
// be flushed
func shouldFlushTCP(groPkt *groPacket, tcpHdr header.TCP) bool {
	flags := tcpHdr.Flags()
	groPktFlags := groPkt.tcpHdr.Flags()
	dataOff := tcpHdr.DataOffset()
	if flags&header.TCPFlagCwr != 0 || // Is congestion control occurring?
		(flags^groPktFlags)&^(header.TCPFlagCwr|header.TCPFlagFin|header.TCPFlagPsh) != 0 || // Do the flags differ besides CRW, FIN, and PSH?
		tcpHdr.AckNumber() != groPkt.tcpHdr.AckNumber() || // Do the ACKs match?
		dataOff != groPkt.tcpHdr.DataOffset() || // Are the TCP headers the same length?
		groPkt.tcpHdr.SequenceNumber()+uint32(groPkt.payloadSize()) != tcpHdr.SequenceNumber() { // Does the incoming packet match the expected sequence number?
		return true
	}
	// The options, including timestamps, must be identical.
	return !bytes.Equal(tcpHdr[header.TCPMinimumSize:], groPkt.tcpHdr[header.TCPMinimumSize:])
}

func updateIPv4Hdr(ipHdrBytes []byte, newBytes int) {
	ipHdr := header.IPv4(ipHdrBytes)
	ipHdr.SetTotalLength(ipHdr.TotalLength() + uint16(newBytes))
}

func updateIPv6Hdr(ipHdrBytes []byte, newBytes int) {
	ipHdr := header.IPv6(ipHdrBytes)
	ipHdr.SetPayloadLength(ipHdr.PayloadLength() + uint16(newBytes))
}
