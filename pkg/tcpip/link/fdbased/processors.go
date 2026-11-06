// Copyright 2024 The gVisor Authors.
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

//go:build linux
// +build linux

package fdbased

import (
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/stack/gro"
)

type processor struct {
	mu processorMutex
	// +checklocks:mu
	pkts stack.PacketBufferList

	// +checklocks:mu
	queueClosed bool

	gro         gro.GRO
	sleeper     sleep.Sleeper
	packetWaker sleep.Waker
	closeWaker  sleep.Waker
}

func (p *processor) start() {
	for {
		switch w := p.sleeper.Fetch(true); {
		case w == &p.packetWaker:
			p.deliverPackets()
		case w == &p.closeWaker:
			p.mu.Lock()
			p.pkts.Reset()
			p.mu.Unlock()
			return
		}
	}
}

func (p *processor) deliverPackets() {
	p.mu.Lock()
	for p.pkts.Len() > 0 {
		pkt := p.pkts.PopFront()
		p.mu.Unlock()
		p.gro.Enqueue(pkt)
		pkt.DecRef()
		p.mu.Lock()
	}
	p.mu.Unlock()
	p.gro.Flush()
}

// A processorManager belongs to one receive loop.
type processorManager struct {
	processors []processor
	seed       uint32
	ready      []bool
}

// start creates the packet queues and starts their background workers.
func (m *processorManager) start(count int, groEnabled bool, dispatcher stack.NetworkDispatcher) {
	m.processors = make([]processor, count)
	m.seed = rand.Uint32()
	m.ready = make([]bool, count)
	for i := range m.processors {
		p := &m.processors[i]
		p.gro.Init(groEnabled)
		p.gro.Dispatcher = dispatcher
	}
	workers := m.backgroundProcessors()
	for i := range workers {
		p := &workers[i]
		p.sleeper.AddWaker(&p.packetWaker)
		p.sleeper.AddWaker(&p.closeWaker)
		go p.start()
	}
}

// backgroundProcessors returns the processors that run in their own goroutines.
// With a single processor, the receive loop drains its queue in wakeReady.
func (m *processorManager) backgroundProcessors() []processor {
	if len(m.processors) == 1 {
		return nil
	}
	return m.processors
}

func (m *processorManager) connectionHash(cid *connectionID) uint32 {
	var payload [4]byte
	binary.LittleEndian.PutUint16(payload[0:], cid.srcPort)
	binary.LittleEndian.PutUint16(payload[2:], cid.dstPort)

	h := jenkins.Sum32(m.seed)
	h.Write(payload[:])
	h.Write(cid.srcAddr)
	h.Write(cid.dstAddr)
	return h.Sum32()
}

// queuePacket queues a packet to be delivered to the appropriate processor.
func (m *processorManager) queuePacket(pkt *stack.PacketBuffer, hasEthHeader bool) {
	var pIdx uint32
	cid, nonConnectionPkt := tcpipConnectionID(pkt)
	if !hasEthHeader {
		if nonConnectionPkt {
			// If there's no eth header this should be a standard tcpip packet. If
			// it isn't the packet is invalid so drop it.
			return
		}
		pkt.NetworkProtocolNumber = cid.proto
	}
	if len(m.processors) == 1 || nonConnectionPkt {
		// If the packet is not associated with an active connection, use the
		// first processor.
		pIdx = 0
	} else {
		pIdx = m.connectionHash(&cid) % uint32(len(m.processors))
	}
	p := &m.processors[pIdx]
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.queueClosed {
		return
	}
	p.pkts.PushBack(pkt.IncRef())
	m.ready[pIdx] = true
}

type connectionID struct {
	srcAddr, dstAddr []byte
	srcPort, dstPort uint16
	proto            tcpip.NetworkProtocolNumber
}

// tcpipConnectionID returns a tcpip connection id tuple based on the data found
// in the packet. It returns true if the packet is not associated with an active
// connection (e.g ARP, NDP, etc). The method assumes link headers have already
// been processed if they were present.
func tcpipConnectionID(pkt *stack.PacketBuffer) (connectionID, bool) {
	var cid connectionID
	h, ok := pkt.Data().PullUp(1)
	if !ok {
		// Skip this packet.
		return cid, true
	}

	const tcpSrcDstPortLen = 4
	switch header.IPVersion(h) {
	case header.IPv4Version:
		hdrLen := header.IPv4(h).HeaderLength()
		if hdrLen < header.IPv4MinimumSize {
			// The header is too short to hold the addresses and ports that the
			// connection ID is derived from; reading them would read past the end
			// of the header. The packet is malformed, so drop it.
			return cid, true
		}
		h, ok = pkt.Data().PullUp(int(hdrLen) + tcpSrcDstPortLen)
		if !ok {
			return cid, true
		}
		ipHdr := header.IPv4(h[:hdrLen])
		tcpHdr := header.TCP(h[hdrLen:][:tcpSrcDstPortLen])

		cid.srcAddr = ipHdr.SourceAddressSlice()
		cid.dstAddr = ipHdr.DestinationAddressSlice()
		// All fragment packets need to be processed by the same goroutine, so
		// only record the TCP ports if this is not a fragment packet.
		if ipHdr.IsValid(pkt.Data().Size()) && !ipHdr.More() && ipHdr.FragmentOffset() == 0 {
			cid.srcPort = tcpHdr.SourcePort()
			cid.dstPort = tcpHdr.DestinationPort()
		}
		cid.proto = header.IPv4ProtocolNumber
	case header.IPv6Version:
		h, ok = pkt.Data().PullUp(header.IPv6FixedHeaderSize + tcpSrcDstPortLen)
		if !ok {
			return cid, true
		}
		ipHdr := header.IPv6(h)
		cid.srcAddr = ipHdr.SourceAddressSlice()
		cid.dstAddr = ipHdr.DestinationAddressSlice()
		cid.proto = header.IPv6ProtocolNumber

		if !header.IsExtensionHeader(ipHdr.NextHeader()) {
			// Known transport protocols(not just TCP) store the src and dst ports
			// in the first 4 bytes after the IPv6 fixed header.
			tcpHdr := header.TCP(h[header.IPv6FixedHeaderSize:][:tcpSrcDstPortLen])
			cid.srcPort = tcpHdr.SourcePort()
			cid.dstPort = tcpHdr.DestinationPort()
		} else {
			// Slow path for IPv6 extension headers :(.
			dataBuf := pkt.Data().ToBuffer()
			dataBuf.TrimFront(header.IPv6MinimumSize)
			it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(ipHdr.NextHeader()), dataBuf)
			defer it.Release()
			// All fragment packets need to be processed by the same goroutine, so
			// only record the ports if this is not a fragment packet.
			var isFragment bool
			for {
				hdr, done, err := it.Next()
				if done || err != nil {
					break
				}
				if fh, ok := hdr.(header.IPv6FragmentExtHdr); ok && !fh.IsAtomic() {
					isFragment = true
				}
				hdr.Release()
			}
			if !isFragment {
				h, ok = pkt.Data().PullUp(int(it.HeaderOffset()) + tcpSrcDstPortLen)
				if !ok {
					return cid, true
				}
				// Known transport protocols store the src and dst ports
				//  in the first 4 bytes after the IPv6 fixed header.
				tcpHdr := header.TCP(h[it.HeaderOffset():][:tcpSrcDstPortLen])
				cid.srcPort = tcpHdr.SourcePort()
				cid.dstPort = tcpHdr.DestinationPort()
			}
		}
	default:
		return cid, true
	}
	return cid, false
}

// detach discards pending packets. A reader already returning from its
// receive syscall must drop that batch too. Workers can still deliver packets they
// have already taken off their queues, including packets held by GRO.
func (m *processorManager) detach() {
	for i := range m.processors {
		p := &m.processors[i]
		p.mu.Lock()
		p.queueClosed = true
		p.pkts.Reset()
		p.mu.Unlock()
	}
}

func (m *processorManager) close() {
	workers := m.backgroundProcessors()
	for i := range workers {
		workers[i].closeWaker.Assert()
	}
}

// wakeReady wakes up all processors that have a packet queued. If there is only
// one processor, the method delivers the packet inline without waking a
// goroutine.
func (m *processorManager) wakeReady() {
	workers := m.backgroundProcessors()
	for i, ready := range m.ready {
		if !ready {
			continue
		}
		if len(workers) != 0 {
			workers[i].packetWaker.Assert()
		} else {
			m.processors[i].deliverPackets()
		}
		m.ready[i] = false
	}
}
