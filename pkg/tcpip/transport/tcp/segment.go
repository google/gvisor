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

	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
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
	// xmitTime is the last transmit time of this segment. A zero value
	// indicates that the segment has yet to be transmitted.
	xmitTime time.Time `state:".(unixTime)"`
}

func newSegment(r *stack.Route, id stack.TransportEndpointID, vv buffer.VectorisedView) *segment {
	s := &segment{
		refCnt: 1,
		id:     id,
		route:  r.Clone(),
	}
	s.data = vv.Clone(s.views[:])
	s.rcvdTime = time.Now()
	return s
}

func newSegmentFromView(r *stack.Route, id stack.TransportEndpointID, v buffer.View) *segment {
	s := &segment{
		refCnt: 1,
		id:     id,
		route:  r.Clone(),
	}
	s.views[0] = v
	s.data = buffer.NewVectorisedView(len(v), s.views[:1])
	s.rcvdTime = time.Now()
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
	}
	t.data = s.data.Clone(t.views[:])
	return t
}

func (s *segment) flagIsSet(flag uint8) bool {
	return (s.flags & flag) != 0
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
	h := header.TCP(s.data.First())

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
	offset := int(h.DataOffset())
	if offset < header.TCPMinimumSize || offset > len(h) {
		return false
	}

	s.options = []byte(h[header.TCPMinimumSize:offset])
	s.parsedOptions = header.ParseTCPOptions(s.options)

	// Query the link capabilities to decide if checksum validation is
	// required.
	verifyChecksum := true
	if s.route.Capabilities()&stack.CapabilityRXChecksumOffload != 0 {
		s.csumValid = true
		verifyChecksum = false
		s.data.TrimFront(offset)
	}
	if verifyChecksum {
		s.csum = h.Checksum()
		xsum := s.route.PseudoHeaderChecksum(ProtocolNumber, uint16(s.data.Size()))
		xsum = h.CalculateChecksum(xsum)
		s.data.TrimFront(offset)
		xsum = header.ChecksumVV(s.data, xsum)
		s.csumValid = xsum == 0xffff
	}

	s.sequenceNumber = seqnum.Value(h.SequenceNumber())
	s.ackNumber = seqnum.Value(h.AckNumber())
	s.flags = h.Flags()
	s.window = seqnum.Size(h.WindowSize())
	return true
}

// sackBlock returns a header.SACKBlock that represents this segment.
func (s *segment) sackBlock() header.SACKBlock {
	return header.SACKBlock{s.sequenceNumber, s.sequenceNumber.Add(s.logicalLen())}
}
