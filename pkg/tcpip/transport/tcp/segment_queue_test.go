// Copyright 2026 The gVisor Authors.
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

package tcp

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type queuedSegmentMetadata struct {
	ID                      stack.TransportEndpointID
	SequenceNumber          seqnum.Value
	AckNumber               seqnum.Value
	Flags                   header.TCPFlags
	Window                  seqnum.Size
	Checksum                uint16
	ChecksumValid           bool
	Options                 []byte
	ParsedOptions           header.TCPOptions
	NICID                   tcpip.NICID
	NetworkProtocolNumber   tcpip.NetworkProtocolNumber
	TransportProtocolNumber tcpip.TransportProtocolNumber
	NetworkPacketInfo       stack.NetworkPacketInfo
	NetworkHeader           []byte
	TransportHeader         []byte
}

func queuedSegmentMetadataOf(s *segment) queuedSegmentMetadata {
	return queuedSegmentMetadata{
		ID:                      s.id,
		SequenceNumber:          s.sequenceNumber,
		AckNumber:               s.ackNumber,
		Flags:                   s.flags,
		Window:                  s.window,
		Checksum:                s.csum,
		ChecksumValid:           s.csumValid,
		Options:                 append([]byte(nil), s.options...),
		ParsedOptions:           s.parsedOptions,
		NICID:                   s.pkt.NICID,
		NetworkProtocolNumber:   s.pkt.NetworkProtocolNumber,
		TransportProtocolNumber: s.pkt.TransportProtocolNumber,
		NetworkPacketInfo:       s.pkt.NetworkPacketInfo,
		NetworkHeader:           append([]byte(nil), s.pkt.NetworkHeader().Slice()...),
		TransportHeader:         append([]byte(nil), s.pkt.TransportHeader().Slice()...),
	}
}

// incomingQueuedSegment constructs a valid packet with headers and a large
// payload sharing one allocation. The caller owns the returned reference.
func incomingQueuedSegment(t *testing.T) *segment {
	t.Helper()
	const payloadSize = 4096
	const tcpHeaderSize = header.TCPMinimumSize + 12
	const packetSize = header.IPv4MinimumSize + tcpHeaderSize + payloadSize
	src := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	dst := tcpip.AddrFrom4([4]byte{192, 0, 2, 2})
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithView(buffer.NewViewSize(packetSize)),
	})
	defer pkt.DecRef()
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.TransportProtocolNumber = header.TCPProtocolNumber
	pkt.NICID = 7

	netBytes, ok := pkt.NetworkHeader().Consume(header.IPv4MinimumSize)
	if !ok {
		t.Fatal("failed to consume IPv4 header")
	}
	ip := header.IPv4(netBytes)
	ip.Encode(&header.IPv4Fields{
		TotalLength: packetSize,
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcpBytes, ok := pkt.TransportHeader().Consume(tcpHeaderSize)
	if !ok {
		t.Fatal("failed to consume TCP header")
	}
	tcpHeader := header.TCP(tcpBytes)
	tcpHeader.Encode(&header.TCPFields{
		SrcPort:    1234,
		DstPort:    5678,
		SeqNum:     100,
		AckNum:     200,
		DataOffset: tcpHeaderSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 30000,
	})
	opts := tcpBytes[header.TCPMinimumSize:]
	opts[0], opts[1] = header.TCPOptionNOP, header.TCPOptionNOP
	header.EncodeTSOption(123, 456, opts[2:])
	// The zero-filled payload contributes zero to the checksum.
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, tcpHeaderSize+payloadSize)
	tcpHeader.SetChecksum(^tcpHeader.CalculateChecksum(xsum))
	var clock faketime.NullClock
	s, err := newIncomingSegment(stack.TransportEndpointID{
		LocalAddress:  dst,
		LocalPort:     5678,
		RemoteAddress: src,
		RemotePort:    1234,
	}, &clock, pkt)
	if err != nil {
		t.Fatalf("newIncomingSegment: %s", err)
	}
	if !s.csumValid {
		s.DecRef()
		t.Fatal("incoming segment checksum is invalid")
	}
	return s
}

func droppedQueuedSegment(t *testing.T) (*segment, *Endpoint, queuedSegmentMetadata) {
	t.Helper()
	s := incomingQueuedSegment(t)
	wantMetadata := queuedSegmentMetadataOf(s)
	ep := &Endpoint{}
	const payloadSize = 4096
	ep.ops.SetReceiveBufferSize(payloadSize, false /* notify */)
	const initialMemUsed = payloadSize + 1
	ep.rcvMemUsed.Store(initialMemUsed)
	t.Cleanup(func() {
		s.DecRef()
		if got := ep.receiveMemUsed(); got != initialMemUsed {
			t.Errorf("receiveMemUsed after releasing segment = %d, want %d", got, initialMemUsed)
		}
	})
	q := segmentQueue{ep: ep}
	if !q.enqueue(s) {
		t.Fatal("full receive queue refused segment metadata")
	}
	queued := q.dequeue()
	if queued != s {
		if queued != nil {
			queued.DecRef()
		}
		t.Fatal("dequeue did not return the enqueued segment")
	}
	queued.DecRef()
	if got, want := ep.receiveMemUsed(), initialMemUsed+s.segMemSize(); got != want {
		t.Errorf("receiveMemUsed = %d, want %d", got, want)
	}
	return s, ep, wantMetadata
}

func TestSegmentQueueDroppedOwnedPayloadAccounting(t *testing.T) {
	s := incomingQueuedSegment(t)
	ep := &Endpoint{}
	const bufferSize = 4096
	ep.ops.SetReceiveBufferSize(bufferSize, false /* notify */)
	t.Cleanup(func() {
		s.DecRef()
		if got := ep.receiveMemUsed(); got != 0 {
			t.Errorf("receiveMemUsed after releasing segment = %d, want 0", got)
		}
	})
	q := segmentQueue{ep: ep}
	if !q.enqueue(s) {
		t.Fatal("empty receive queue refused segment")
	}
	queued := q.dequeue()
	if queued != s {
		if queued != nil {
			queued.DecRef()
		}
		t.Fatal("dequeue did not return the enqueued segment")
	}
	queued.DecRef()
	if s.dataDropped {
		t.Fatal("payload was dropped by an empty receive queue")
	}
	if got, want := ep.receiveMemUsed(), s.segMemSize(); got != want {
		t.Errorf("receiveMemUsed before requeue = %d, want %d", got, want)
	}
	if ep.receiveMemUsed() <= bufferSize {
		t.Fatal("segment did not fill the receive buffer")
	}
	// Like an ACK carrying data at handshake completion, the dequeued
	// segment retains its owner while being requeued into a full buffer.
	if !q.enqueue(s) {
		t.Fatal("full receive queue refused segment metadata")
	}
	queued = q.dequeue()
	if queued != s {
		if queued != nil {
			queued.DecRef()
		}
		t.Fatal("dequeue did not return the requeued segment")
	}
	queued.DecRef()
	if !s.dataDropped {
		t.Error("dataDropped after requeue = false, want true")
	}
	if got, want := ep.receiveMemUsed(), s.segMemSize(); got != want {
		t.Errorf("receiveMemUsed after requeue = %d, want compact segment charge %d", got, want)
	}
}

func TestSegmentQueueDroppedPayloadReleasesStorage(t *testing.T) {
	s, _, wantMetadata := droppedQueuedSegment(t)
	if !s.dataDropped {
		t.Error("dataDropped = false, want true")
	}
	if got := s.payloadSize(); got != 0 {
		t.Errorf("payloadSize = %d, want 0", got)
	}
	if diff := cmp.Diff(wantMetadata, queuedSegmentMetadataOf(s)); diff != "" {
		t.Errorf("segment metadata changed after dropping payload (-want +got):\n%s", diff)
	}
	// Logical truncation alone retains the large chunk containing the headers.
	// Inspect backing capacities so this verifies actual storage retention.
	views, _ := s.pkt.AsViewList()
	capacity := 0
	for v := views.Front(); v != nil; v = v.Next() {
		capacity += v.Capacity()
	}
	const maxHeaderCapacity = 128
	if capacity > maxHeaderCapacity {
		t.Errorf("header backing capacity = %d, want <= %d", capacity, maxHeaderCapacity)
	}
	if got := cap(s.options); got > maxHeaderCapacity {
		t.Errorf("options backing capacity = %d, want <= %d", got, maxHeaderCapacity)
	}
}

func TestSegmentQueueDroppedPayloadSaveRestore(t *testing.T) {
	s, ep, wantMetadata := droppedQueuedSegment(t)
	if !s.dataDropped {
		t.Fatal("dataDropped = false before save, want true")
	}
	// Save the segment alone: its artificial owner has no stack or route.
	// Release its accounted memory before removing the ownership reference.
	ep.updateReceiveMemUsed(-s.segMemSize())
	s.ep = nil
	s.qFlags = 0
	var saved bytes.Buffer
	if _, err := state.Save(context.Background(), &saved, s); err != nil {
		t.Fatalf("state.Save: %s", err)
	}
	var restored segment
	if _, err := state.Load(context.Background(), &saved, &restored); err != nil {
		t.Fatalf("state.Load: %s", err)
	}
	defer restored.DecRef()
	if !restored.dataDropped {
		t.Error("dataDropped = false after restore, want true")
	}
	if got := restored.payloadSize(); got != 0 {
		t.Errorf("restored payloadSize = %d, want 0", got)
	}
	// The endpoint ID is intentionally not saved by segment's state tags.
	wantMetadata.ID = stack.TransportEndpointID{}
	if diff := cmp.Diff(wantMetadata, queuedSegmentMetadataOf(&restored)); diff != "" {
		t.Errorf("segment metadata changed after restore (-want +got):\n%s", diff)
	}
}
