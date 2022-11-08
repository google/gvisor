// Copyright 2018 The gVisor Authors.
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
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// queueFlags are used to indicate which queue of an endpoint a particular segment
// belongs to. This is used to track memory accounting correctly.
type queueFlags uint8

const (
	// SegOverheadSize is the size of an empty seg in memory including packet
	// buffer overhead. It is advised to use SegOverheadSize instead of segSize
	// in all cases where accounting for segment memory overhead is important.
	SegOverheadSize = segSize + stack.PacketBufferStructSize + header.IPv4MaximumHeaderSize

	recvQ queueFlags = 1 << iota
	sendQ
)

var segmentPool = sync.Pool{
	New: func() any {
		return &segment{}
	},
}

// segment represents a TCP segment. It holds the payload and parsed TCP segment
// information, and can be added to intrusive lists.
// segment is mostly immutable, the only field allowed to change is data.
//
// +stateify savable
type segment struct {
	segmentEntry
	segmentRefs

	ep     *endpoint
	qFlags queueFlags
	id     stack.TransportEndpointID `state:"manual"`

	pkt stack.PacketBufferPtr

	sequenceNumber seqnum.Value
	ackNumber      seqnum.Value
	flags          header.TCPFlags
	window         seqnum.Size
	// csum is only populated for received segments.
	csum uint16
	// csumValid is true if the csum in the received segment is valid.
	csumValid bool

	// parsedOptions stores the parsed values from the options in the segment.
	parsedOptions  header.TCPOptions
	options        []byte `state:".([]byte)"`
	hasNewSACKInfo bool
	rcvdTime       tcpip.MonotonicTime
	// xmitTime is the last transmit time of this segment.
	xmitTime  tcpip.MonotonicTime
	xmitCount uint32

	// acked indicates if the segment has already been SACKed.
	acked bool

	// dataMemSize is the memory used by pkt initially. The value is used for
	// memory accounting in the receive buffer instead of pkt.MemSize() because
	// packet contents can be modified, so relying on the computed memory size
	// to "free" reserved bytes could leak memory in the receiver.
	dataMemSize int

	// lost indicates if the segment is marked as lost by RACK.
	lost bool
}

func newIncomingSegment(id stack.TransportEndpointID, clock tcpip.Clock, pkt stack.PacketBufferPtr) (*segment, error) {
	hdr := header.TCP(pkt.TransportHeader().Slice())
	netHdr := pkt.Network()
	csum, csumValid, ok := header.TCPValid(
		hdr,
		func() uint16 { return pkt.Data().Checksum() },
		uint16(pkt.Data().Size()),
		netHdr.SourceAddress(),
		netHdr.DestinationAddress(),
		pkt.RXChecksumValidated)
	if !ok {
		return nil, fmt.Errorf("header data offset does not respect size constraints: %d < offset < %d, got offset=%d", header.TCPMinimumSize, len(hdr), hdr.DataOffset())
	}

	s := newSegment()
	s.id = id
	s.options = hdr[header.TCPMinimumSize:]
	s.parsedOptions = header.ParseTCPOptions(hdr[header.TCPMinimumSize:])
	s.sequenceNumber = seqnum.Value(hdr.SequenceNumber())
	s.ackNumber = seqnum.Value(hdr.AckNumber())
	s.flags = hdr.Flags()
	s.window = seqnum.Size(hdr.WindowSize())
	s.rcvdTime = clock.NowMonotonic()
	s.dataMemSize = pkt.MemSize()
	s.pkt = pkt.IncRef()
	s.csumValid = csumValid

	if !s.pkt.RXChecksumValidated {
		s.csum = csum
	}
	return s, nil
}

func newOutgoingSegment(id stack.TransportEndpointID, clock tcpip.Clock, buf bufferv2.Buffer) *segment {
	s := newSegment()
	s.id = id
	s.rcvdTime = clock.NowMonotonic()
	s.pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buf})
	s.dataMemSize = s.pkt.MemSize()
	return s
}

func (s *segment) clone() *segment {
	t := newSegment()
	t.id = s.id
	t.sequenceNumber = s.sequenceNumber
	t.ackNumber = s.ackNumber
	t.flags = s.flags
	t.window = s.window
	t.rcvdTime = s.rcvdTime
	t.xmitTime = s.xmitTime
	t.xmitCount = s.xmitCount
	t.ep = s.ep
	t.qFlags = s.qFlags
	t.dataMemSize = s.dataMemSize
	t.pkt = s.pkt.Clone()
	return t
}

func newSegment() *segment {
	s := segmentPool.Get().(*segment)
	*s = segment{}
	s.InitRefs()
	return s
}

// merge merges data in oth and clears oth.
func (s *segment) merge(oth *segment) {
	s.pkt.Data().Merge(oth.pkt.Data())
	s.dataMemSize = s.pkt.MemSize()
	oth.dataMemSize = oth.pkt.MemSize()
}

// setOwner sets the owning endpoint for this segment. Its required
// to be called to ensure memory accounting for receive/send buffer
// queues is done properly.
func (s *segment) setOwner(ep *endpoint, qFlags queueFlags) {
	switch qFlags {
	case recvQ:
		ep.updateReceiveMemUsed(s.segMemSize())
	case sendQ:
		// no memory account for sendQ yet.
	default:
		panic(fmt.Sprintf("unexpected queue flag %b", qFlags))
	}
	s.ep = ep
	s.qFlags = qFlags
}

func (s *segment) DecRef() {
	s.segmentRefs.DecRef(func() {
		if s.ep != nil {
			switch s.qFlags {
			case recvQ:
				s.ep.updateReceiveMemUsed(-s.segMemSize())
			case sendQ:
				// no memory accounting for sendQ yet.
			default:
				panic(fmt.Sprintf("unexpected queue flag %b set for segment", s.qFlags))
			}
		}
		s.pkt.DecRef()
		segmentPool.Put(s)
	})
}

// logicalLen is the segment length in the sequence number space. It's defined
// as the data length plus one for each of the SYN and FIN bits set.
func (s *segment) logicalLen() seqnum.Size {
	l := seqnum.Size(s.payloadSize())
	if s.flags.Contains(header.TCPFlagSyn) {
		l++
	}
	if s.flags.Contains(header.TCPFlagFin) {
		l++
	}
	return l
}

// payloadSize is the size of s.data.
func (s *segment) payloadSize() int {
	return s.pkt.Data().Size()
}

// segMemSize is the amount of memory used to hold the segment data and
// the associated metadata.
func (s *segment) segMemSize() int {
	return segSize + s.dataMemSize
}

// sackBlock returns a header.SACKBlock that represents this segment.
func (s *segment) sackBlock() header.SACKBlock {
	return header.SACKBlock{Start: s.sequenceNumber, End: s.sequenceNumber.Add(s.logicalLen())}
}

func (s *segment) TrimFront(ackLeft seqnum.Size) {
	s.pkt.Data().TrimFront(int(ackLeft))
}

func (s *segment) ReadTo(dst io.Writer, peek bool) (int, error) {
	return s.pkt.Data().ReadTo(dst, peek)
}
