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

package nested

import (
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// CaptureBufferSize is the number of packets stored in a `CaptureEndpoint`'s buffer.
const CaptureBufferSize = 128

var _ stack.NetworkDispatcher = (*CaptureEndpoint)(nil)
var _ stack.LinkEndpoint = (*CaptureEndpoint)(nil)

// NewCaptureEndpoint returns a CaptureEndpoint that wraps an inner link endpoint.
func NewCaptureEndpoint(ep stack.LinkEndpoint) *CaptureEndpoint {
	var e CaptureEndpoint
	e.Endpoint.Init(ep, &e)
	e.packets = newPacketRingBuffer(CaptureBufferSize)
	return &e
}

// CaptureEndpoint is an Endpoint that captures incoming and outgoing packets in a rolling window
// for debugging.
type CaptureEndpoint struct {
	Endpoint
	packets   packetRingBuffer
	packetsMu sync.Mutex // Protects packets, but not Endpoint
}

// CapturedPacket holds a captured packet buffer and the time at which it was captured.
type CapturedPacket struct {
	Pkt  *stack.PacketBuffer
	Time time.Time
}

// WritePackets implements LinkWriter.
func (e *CaptureEndpoint) WritePackets(packets stack.PacketBufferList) (int, tcpip.Error) {
	e.packetsMu.Lock()
	e.packets.pushPackets(packets.AsSlice())
	e.packetsMu.Unlock()

	return e.Endpoint.WritePackets(packets)
}

// GetCapturedPackets returns the CaptureBufferSize most recently-captured packets.
//
// Entries may be if fewer than CaptureBufferSize packets have ever been captured.
func (e *CaptureEndpoint) GetCapturedPackets() ([]CapturedPacket, []CapturedPacket) {
	e.packetsMu.Lock()
	defer e.packetsMu.Unlock()
	return e.packets.getPackets()
}

// ClearCapturedPackets clears the captured packets and decrements their reference counts.
func (e *CaptureEndpoint) ClearCapturedPackets() {
	e.packetsMu.Lock()
	defer e.packetsMu.Unlock()
	e.packets.clear()
}

// The zero value of packetRingBuffer is not valid for use; use newPacketRingBuffer instead.
type packetRingBuffer struct {
	// The index in packets of where we should write the next packet.
	next int

	// packets is initialized to contain entries with a nil Pkt field; code operating on it must not
	// assume that any given entry's Pkt field is a non-nil pointer.
	packets []CapturedPacket
}

func newPacketRingBuffer(size int) packetRingBuffer {
	return packetRingBuffer{next: 0, packets: make([]CapturedPacket, size)}
}

func (b *packetRingBuffer) pushPackets(packets []*stack.PacketBuffer) {
	now := time.Now()

	// If we are trying to add more packets than we have space for, only add the ones at the end of
	// packets.
	drop := len(packets) - len(b.packets)
	if drop > 0 {
		packets = packets[drop:]
	}

	for _, p := range packets {
		old := b.packets[b.next]
		if old.Pkt != nil {
			old.Pkt.DecRef()
		}

		p.IncRef()
		b.packets[b.next] = CapturedPacket{Pkt: p, Time: now}
		b.next = (b.next + 1) % len(b.packets)
	}
}

func (b *packetRingBuffer) getPackets() ([]CapturedPacket, []CapturedPacket) {
	return b.packets[b.next:], b.packets[:b.next]
}

func (b *packetRingBuffer) clear() {
	for i, p := range b.packets {
		if p.Pkt != nil {
			p.Pkt.DecRef()
		}
		b.packets[i].Pkt = nil
	}
}
