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
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/stack/gro"
)

type processor struct {
	mu sync.Mutex
	// +checklocks:mu
	pkts stack.PacketBufferList

	e           *endpoint
	gro         gro.GRO
	sleeper     sleep.Sleeper
	packetWaker sleep.Waker
	closeWaker  sleep.Waker
}

func (p *processor) start(wg *sync.WaitGroup) {
	defer wg.Done()
	defer p.sleeper.Done()
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
	p.e.mu.RLock()
	p.gro.Dispatcher = p.e.dispatcher
	p.e.mu.RUnlock()
	if p.gro.Dispatcher == nil {
		p.mu.Lock()
		p.pkts.Reset()
		p.mu.Unlock()
		return
	}

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

// processorManager handles starting, closing, and queuing packets on processor
// goroutines.
type processorManager struct {
	processors []processor
	seed       uint32
	wg         sync.WaitGroup
	e          *endpoint
	ready      []bool
}

// newProcessorManager creates a new processor manager.
func newProcessorManager(opts *Options, e *endpoint) *processorManager {
	m := &processorManager{}
	m.seed = rand.Uint32()
	m.ready = make([]bool, opts.ProcessorsPerChannel)
	m.processors = make([]processor, opts.ProcessorsPerChannel)
	m.e = e
	m.wg.Add(opts.ProcessorsPerChannel)

	for i := range m.processors {
		p := &m.processors[i]
		p.sleeper.AddWaker(&p.packetWaker)
		p.sleeper.AddWaker(&p.closeWaker)
		p.gro.Init(opts.GRO)
		p.e = e
	}

	return m
}

// start starts the processor goroutines if the processor manager is configured
// with more than one processor.
func (m *processorManager) start() {
	for i := range m.processors {
		p := &m.processors[i]
		// Only start processor in a separate goroutine if we have multiple of them.
		if len(m.processors) > 1 {
			go p.start(&m.wg)
		}
	}
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
	pkt.IncRef()
	p.pkts.PushBack(pkt)
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

		var tcpHdr header.TCP
		if tcpip.TransportProtocolNumber(ipHdr.NextHeader()) == header.TCPProtocolNumber {
			tcpHdr = header.TCP(h[header.IPv6FixedHeaderSize:][:tcpSrcDstPortLen])
		} else {
			// Slow path for IPv6 extension headers :(.
			dataBuf := pkt.Data().ToBuffer()
			dataBuf.TrimFront(header.IPv6MinimumSize)
			it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(ipHdr.NextHeader()), dataBuf)
			defer it.Release()
			for {
				hdr, done, err := it.Next()
				if done || err != nil {
					break
				}
				hdr.Release()
			}
			h, ok = pkt.Data().PullUp(int(it.HeaderOffset()) + tcpSrcDstPortLen)
			if !ok {
				return cid, true
			}
			tcpHdr = header.TCP(h[it.HeaderOffset():][:tcpSrcDstPortLen])
		}
		cid.srcAddr = ipHdr.SourceAddressSlice()
		cid.dstAddr = ipHdr.DestinationAddressSlice()
		cid.srcPort = tcpHdr.SourcePort()
		cid.dstPort = tcpHdr.DestinationPort()
		cid.proto = header.IPv6ProtocolNumber
	default:
		return cid, true
	}
	return cid, false
}

func (m *processorManager) close() {
	if len(m.processors) < 2 {
		return
	}
	for i := range m.processors {
		p := &m.processors[i]
		p.closeWaker.Assert()
	}
}

// wakeReady wakes up all processors that have a packet queued. If there is only
// one processor, the method delivers the packet inline without waking a
// goroutine.
func (m *processorManager) wakeReady() {
	for i, ready := range m.ready {
		if !ready {
			continue
		}
		p := &m.processors[i]
		if len(m.processors) > 1 {
			p.packetWaker.Assert()
		} else {
			p.deliverPackets()
		}
		m.ready[i] = false
	}
}
