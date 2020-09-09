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
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// segment represents a TCP segment. It holds the payload and parsed TCP segment
// information, and can be added to intrusive lists.
// segment is mostly immutable, the only field allowed to change is viewToDeliver.
//
// +stateify savable
type segment struct {
	segmentEntry
	refCnt int32
	id     stack.TransportEndpointID `state:"manual"`
	route  stack.Route               `state:"manual"`
	data   buffer.VectorisedView     `state:".(buffer.VectorisedView)"`
	hdr    header.TCP
	// views is used as buffer for data when its length is large
	// enough to store a VectorisedView.
	views [8]buffer.View `state:"nosave"`
	// viewToDeliver keeps track of the next View that should be
	// delivered by the Read endpoint.
	viewToDeliver  int
	sequenceNumber seqnum.Value
	ackNumber      seqnum.Value
	flags          uint8
	window         seqnum.Size
	// csum is only populated for received segments.
	csum uint16
	// csumValid is true if the csum in the received segment is valid.
	csumValid bool

	// parsedOptions stores the parsed values from the options in the segment.
	parsedOptions  header.TCPOptions
	options        []byte `state:".([]byte)"`
	hasNewSACKInfo bool
	rcvdTime       time.Time `state:".(unixTime)"`
	// xmitTime is the last transmit time of this segment.
	xmitTime  time.Time `state:".(unixTime)"`
	xmitCount uint32
}

func newSegment(r *stack.Route, id stack.TransportEndpointID, pkt *stack.PacketBuffer) *segment {
	s := &segment{
		refCnt: 1,
		id:     id,
		route:  r.Clone(),
	}
	s.data = pkt.Data.Clone(s.views[:])
	s.hdr = header.TCP(pkt.TransportHeader().View())
	s.rcvdTime = time.Now()
	return s
}

func newSegmentFromView(r *stack.Route, id stack.TransportEndpointID, v buffer.View) *segment {
	s := &segment{
		refCnt: 1,
		id:     id,
		route:  r.Clone(),
	}
	s.rcvdTime = time.Now()
	if len(v) != 0 {
		s.views[0] = v
		s.data = buffer.NewVectorisedView(len(v), s.views[:1])
	}
	return s
}

func (s *segment) clone() *segment {
	t := &segment{
		refCnt:         1,
		id:             s.id,
		sequenceNumber: s.sequenceNumber,
		ackNumber:      s.ackNumber,
		flags:          s.flags,
		window:         s.window,
		route:          s.route.Clone(),
		viewToDeliver:  s.viewToDeliver,
		rcvdTime:       s.rcvdTime,
		xmitTime:       s.xmitTime,
		xmitCount:      s.xmitCount,
	}
	t.data = s.data.Clone(t.views[:])
	return t
}

// flagIsSet checks if at least one flag in flags is set in s.flags.
func (s *segment) flagIsSet(flags uint8) bool {
	return s.flags&flags != 0
}

// flagsAreSet checks if all flags in flags are set in s.flags.
func (s *segment) flagsAreSet(flags uint8) bool {
	return s.flags&flags == flags
}

func (s *segment) decRef() {
	if atomic.AddInt32(&s.refCnt, -1) == 0 {
		s.route.Release()
	}
}

func (s *segment) incRef() {
	atomic.AddInt32(&s.refCnt, 1)
}

// logicalLen is the segment length in the sequence number space. It's defined
// as the data length plus one for each of the SYN and FIN bits set.
func (s *segment) logicalLen() seqnum.Size {
	l := seqnum.Size(s.data.Size())
	if s.flagIsSet(header.TCPFlagSyn) {
		l++
	}
	if s.flagIsSet(header.TCPFlagFin) {
		l++
	}
	return l
}

// segMemSize is the amount of memory used to hold the segment data and
// the associated metadata.
func (s *segment) segMemSize() int {
	return segSize + s.data.Size()
}

// parse populates the sequence & ack numbers, flags, and window fields of the
// segment from the TCP header stored in the data. It then updates the view to
// skip the header.
//
// Returns boolean indicating if the parsing was successful.
//
// If checksum verification is not offloaded then parse also verifies the
// TCP checksum and stores the checksum and result of checksum verification in
// the csum and csumValid fields of the segment.
func (s *segment) parse() bool {
	// h is the header followed by the payload. We check that the offset to
	// the data respects the following constraints:
	// 1. That it's at least the minimum header size; if we don't do this
	//    then part of the header would be delivered to user.
	// 2. That the header fits within the buffer; if we don't do this, we
	//    would panic when we tried to access data beyond the buffer.
	//
	// N.B. The segment has already been validated as having at least the
	//      minimum TCP size before reaching here, so it's safe to read the
	//      fields.
	offset := int(s.hdr.DataOffset())
	if offset < header.TCPMinimumSize || offset > len(s.hdr) {
		return false
	}

	s.options = []byte(s.hdr[header.TCPMinimumSize:])
	s.parsedOptions = header.ParseTCPOptions(s.options)

	// Query the link capabilities to decide if checksum validation is
	// required.
	verifyChecksum := true
	if s.route.Capabilities()&stack.CapabilityRXChecksumOffload != 0 {
		s.csumValid = true
		verifyChecksum = false
	}
	if verifyChecksum {
		s.csum = s.hdr.Checksum()
		xsum := s.route.PseudoHeaderChecksum(ProtocolNumber, uint16(s.data.Size()+len(s.hdr)))
		xsum = s.hdr.CalculateChecksum(xsum)
		xsum = header.ChecksumVV(s.data, xsum)
		s.csumValid = xsum == 0xffff
	}

	s.sequenceNumber = seqnum.Value(s.hdr.SequenceNumber())
	s.ackNumber = seqnum.Value(s.hdr.AckNumber())
	s.flags = s.hdr.Flags()
	s.window = seqnum.Size(s.hdr.WindowSize())
	return true
}

// sackBlock returns a header.SACKBlock that represents this segment.
func (s *segment) sackBlock() header.SACKBlock {
	return header.SACKBlock{s.sequenceNumber, s.sequenceNumber.Add(s.logicalLen())}
}
