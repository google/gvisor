// Copyright 2018 Google Inc.
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
	"container/heap"

	"gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum"
)

// receiver holds the state necessary to receive TCP segments and turn them
// into a stream of bytes.
type receiver struct {
	ep *endpoint

	rcvNxt seqnum.Value

	// rcvAcc is one beyond the last acceptable sequence number. That is,
	// the "largest" sequence value that the receiver has announced to the
	// its peer that it's willing to accept. This may be different than
	// rcvNxt + rcvWnd if the receive window is reduced; in that case we
	// have to reduce the window as we receive more data instead of
	// shrinking it.
	rcvAcc seqnum.Value

	rcvWndScale uint8

	closed bool

	pendingRcvdSegments segmentHeap
	pendingBufUsed      seqnum.Size
	pendingBufSize      seqnum.Size
}

func newReceiver(ep *endpoint, irs seqnum.Value, rcvWnd seqnum.Size, rcvWndScale uint8) *receiver {
	return &receiver{
		ep:             ep,
		rcvNxt:         irs + 1,
		rcvAcc:         irs.Add(rcvWnd + 1),
		rcvWndScale:    rcvWndScale,
		pendingBufSize: rcvWnd,
	}
}

// acceptable checks if the segment sequence number range is acceptable
// according to the table on page 26 of RFC 793.
func (r *receiver) acceptable(segSeq seqnum.Value, segLen seqnum.Size) bool {
	rcvWnd := r.rcvNxt.Size(r.rcvAcc)
	if rcvWnd == 0 {
		return segLen == 0 && segSeq == r.rcvNxt
	}

	return segSeq.InWindow(r.rcvNxt, rcvWnd) ||
		seqnum.Overlap(r.rcvNxt, rcvWnd, segSeq, segLen)
}

// getSendParams returns the parameters needed by the sender when building
// segments to send.
func (r *receiver) getSendParams() (rcvNxt seqnum.Value, rcvWnd seqnum.Size) {
	// Calculate the window size based on the current buffer size.
	n := r.ep.receiveBufferAvailable()
	acc := r.rcvNxt.Add(seqnum.Size(n))
	if r.rcvAcc.LessThan(acc) {
		r.rcvAcc = acc
	}

	return r.rcvNxt, r.rcvNxt.Size(r.rcvAcc) >> r.rcvWndScale
}

// nonZeroWindow is called when the receive window grows from zero to nonzero;
// in such cases we may need to send an ack to indicate to our peer that it can
// resume sending data.
func (r *receiver) nonZeroWindow() {
	if (r.rcvAcc-r.rcvNxt)>>r.rcvWndScale != 0 {
		// We never got around to announcing a zero window size, so we
		// don't need to immediately announce a nonzero one.
		return
	}

	// Immediately send an ack.
	r.ep.snd.sendAck()
}

// consumeSegment attempts to consume a segment that was received by r. The
// segment may have just been received or may have been received earlier but
// wasn't ready to be consumed then.
//
// Returns true if the segment was consumed, false if it cannot be consumed
// yet because of a missing segment.
func (r *receiver) consumeSegment(s *segment, segSeq seqnum.Value, segLen seqnum.Size) bool {
	if segLen > 0 {
		// If the segment doesn't include the seqnum we're expecting to
		// consume now, we're missing a segment. We cannot proceed until
		// we receive that segment though.
		if !r.rcvNxt.InWindow(segSeq, segLen) {
			return false
		}

		// Trim segment to eliminate already acknowledged data.
		if segSeq.LessThan(r.rcvNxt) {
			diff := segSeq.Size(r.rcvNxt)
			segLen -= diff
			segSeq.UpdateForward(diff)
			s.sequenceNumber.UpdateForward(diff)
			s.data.TrimFront(int(diff))
		}

		// Move segment to ready-to-deliver list. Wakeup any waiters.
		r.ep.readyToRead(s)

	} else if segSeq != r.rcvNxt {
		return false
	}

	// Update the segment that we're expecting to consume.
	r.rcvNxt = segSeq.Add(segLen)

	// Trim SACK Blocks to remove any SACK information that covers
	// sequence numbers that have been consumed.
	TrimSACKBlockList(&r.ep.sack, r.rcvNxt)

	if s.flagIsSet(flagFin) {
		r.rcvNxt++

		// Send ACK immediately.
		r.ep.snd.sendAck()

		// Tell any readers that no more data will come.
		r.closed = true
		r.ep.readyToRead(nil)

		// Flush out any pending segments, except the very first one if
		// it happens to be the one we're handling now because the
		// caller is using it.
		first := 0
		if len(r.pendingRcvdSegments) != 0 && r.pendingRcvdSegments[0] == s {
			first = 1
		}

		for i := first; i < len(r.pendingRcvdSegments); i++ {
			r.pendingRcvdSegments[i].decRef()
		}
		r.pendingRcvdSegments = r.pendingRcvdSegments[:first]
	}

	return true
}

// handleRcvdSegment handles TCP segments directed at the connection managed by
// r as they arrive. It is called by the protocol main loop.
func (r *receiver) handleRcvdSegment(s *segment) {
	// We don't care about receive processing anymore if the receive side
	// is closed.
	if r.closed {
		return
	}

	segLen := seqnum.Size(s.data.Size())
	segSeq := s.sequenceNumber

	// If the sequence number range is outside the acceptable range, just
	// send an ACK. This is according to RFC 793, page 37.
	if !r.acceptable(segSeq, segLen) {
		r.ep.snd.sendAck()
		return
	}

	// Defer segment processing if it can't be consumed now.
	if !r.consumeSegment(s, segSeq, segLen) {
		if segLen > 0 || s.flagIsSet(flagFin) {
			// We only store the segment if it's within our buffer
			// size limit.
			if r.pendingBufUsed < r.pendingBufSize {
				r.pendingBufUsed += s.logicalLen()
				s.incRef()
				heap.Push(&r.pendingRcvdSegments, s)
			}

			UpdateSACKBlocks(&r.ep.sack, segSeq, segSeq.Add(segLen), r.rcvNxt)

			// Immediately send an ack so that the peer knows it may
			// have to retransmit.
			r.ep.snd.sendAck()
		}
		return
	}

	// By consuming the current segment, we may have filled a gap in the
	// sequence number domain that allows pending segments to be consumed
	// now. So try to do it.
	for !r.closed && r.pendingRcvdSegments.Len() > 0 {
		s := r.pendingRcvdSegments[0]
		segLen := seqnum.Size(s.data.Size())
		segSeq := s.sequenceNumber

		// Skip segment altogether if it has already been acknowledged.
		if !segSeq.Add(segLen-1).LessThan(r.rcvNxt) &&
			!r.consumeSegment(s, segSeq, segLen) {
			break
		}

		heap.Pop(&r.pendingRcvdSegments)
		r.pendingBufUsed -= s.logicalLen()
		s.decRef()
	}
}
