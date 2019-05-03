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
	"math"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/sleep"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum"
)

const (
	// minRTO is the minimum allowed value for the retransmit timeout.
	minRTO = 200 * time.Millisecond

	// InitialCwnd is the initial congestion window.
	InitialCwnd = 10

	// nDupAckThreshold is the number of duplicate ACK's required
	// before fast-retransmit is entered.
	nDupAckThreshold = 3
)

// congestionControl is an interface that must be implemented by any supported
// congestion control algorithm.
type congestionControl interface {
	// HandleNDupAcks is invoked when sender.dupAckCount >= nDupAckThreshold
	// just before entering fast retransmit.
	HandleNDupAcks()

	// HandleRTOExpired is invoked when the retransmit timer expires.
	HandleRTOExpired()

	// Update is invoked when processing inbound acks. It's passed the
	// number of packet's that were acked by the most recent cumulative
	// acknowledgement.
	Update(packetsAcked int)

	// PostRecovery is invoked when the sender is exiting a fast retransmit/
	// recovery phase. This provides congestion control algorithms a way
	// to adjust their state when exiting recovery.
	PostRecovery()
}

// sender holds the state necessary to send TCP segments.
//
// +stateify savable
type sender struct {
	ep *endpoint

	// lastSendTime is the timestamp when the last packet was sent.
	lastSendTime time.Time `state:".(unixTime)"`

	// dupAckCount is the number of duplicated acks received. It is used for
	// fast retransmit.
	dupAckCount int

	// fr holds state related to fast recovery.
	fr fastRecovery

	// sndCwnd is the congestion window, in packets.
	sndCwnd int

	// sndSsthresh is the threshold between slow start and congestion
	// avoidance.
	sndSsthresh int

	// sndCAAckCount is the number of packets acknowledged during congestion
	// avoidance. When enough packets have been ack'd (typically cwnd
	// packets), the congestion window is incremented by one.
	sndCAAckCount int

	// outstanding is the number of outstanding packets, that is, packets
	// that have been sent but not yet acknowledged.
	outstanding int

	// sndWnd is the send window size.
	sndWnd seqnum.Size

	// sndUna is the next unacknowledged sequence number.
	sndUna seqnum.Value

	// sndNxt is the sequence number of the next segment to be sent.
	sndNxt seqnum.Value

	// sndNxtList is the sequence number of the next segment to be added to
	// the send list.
	sndNxtList seqnum.Value

	// rttMeasureSeqNum is the sequence number being used for the latest RTT
	// measurement.
	rttMeasureSeqNum seqnum.Value

	// rttMeasureTime is the time when the rttMeasureSeqNum was sent.
	rttMeasureTime time.Time `state:".(unixTime)"`

	closed      bool
	writeNext   *segment
	writeList   segmentList
	resendTimer timer       `state:"nosave"`
	resendWaker sleep.Waker `state:"nosave"`

	// rtt.srtt, rtt.rttvar, and rto are the "smoothed round-trip time",
	// "round-trip time variation" and "retransmit timeout", as defined in
	// section 2 of RFC 6298.
	rtt        rtt
	rto        time.Duration
	srttInited bool

	// maxPayloadSize is the maximum size of the payload of a given segment.
	// It is initialized on demand.
	maxPayloadSize int

	// gso is set if generic segmentation offload is enabled.
	gso bool

	// sndWndScale is the number of bits to shift left when reading the send
	// window size from a segment.
	sndWndScale uint8

	// maxSentAck is the maxium acknowledgement actually sent.
	maxSentAck seqnum.Value

	// cc is the congestion control algorithm in use for this sender.
	cc congestionControl
}

// rtt is a synchronization wrapper used to appease stateify. See the comment
// in sender, where it is used.
//
// +stateify savable
type rtt struct {
	sync.Mutex `state:"nosave"`

	srtt   time.Duration
	rttvar time.Duration
}

// fastRecovery holds information related to fast recovery from a packet loss.
//
// +stateify savable
type fastRecovery struct {
	// active whether the endpoint is in fast recovery. The following fields
	// are only meaningful when active is true.
	active bool

	// first and last represent the inclusive sequence number range being
	// recovered.
	first seqnum.Value
	last  seqnum.Value

	// maxCwnd is the maximum value the congestion window may be inflated to
	// due to duplicate acks. This exists to avoid attacks where the
	// receiver intentionally sends duplicate acks to artificially inflate
	// the sender's cwnd.
	maxCwnd int

	// highRxt is the highest sequence number which has been retransmitted
	// during the current loss recovery phase.
	// See: RFC 6675 Section 2 for details.
	highRxt seqnum.Value

	// rescueRxt is the highest sequence number which has been
	// optimistically retransmitted to prevent stalling of the ACK clock
	// when there is loss at the end of the window and no new data is
	// available for transmission.
	// See: RFC 6675 Section 2 for details.
	rescueRxt seqnum.Value
}

func newSender(ep *endpoint, iss, irs seqnum.Value, sndWnd seqnum.Size, mss uint16, sndWndScale int) *sender {
	// The sender MUST reduce the TCP data length to account for any IP or
	// TCP options that it is including in the packets that it sends.
	// See: https://tools.ietf.org/html/rfc6691#section-2
	maxPayloadSize := int(mss) - ep.maxOptionSize()

	s := &sender{
		ep:               ep,
		sndCwnd:          InitialCwnd,
		sndSsthresh:      math.MaxInt64,
		sndWnd:           sndWnd,
		sndUna:           iss + 1,
		sndNxt:           iss + 1,
		sndNxtList:       iss + 1,
		rto:              1 * time.Second,
		rttMeasureSeqNum: iss + 1,
		lastSendTime:     time.Now(),
		maxPayloadSize:   maxPayloadSize,
		maxSentAck:       irs + 1,
		fr: fastRecovery{
			// See: https://tools.ietf.org/html/rfc6582#section-3.2 Step 1.
			last:      iss,
			highRxt:   iss,
			rescueRxt: iss,
		},
		gso: ep.gso != nil,
	}

	if s.gso {
		s.ep.gso.MSS = uint16(maxPayloadSize)
	}

	s.cc = s.initCongestionControl(ep.cc)

	// A negative sndWndScale means that no scaling is in use, otherwise we
	// store the scaling value.
	if sndWndScale > 0 {
		s.sndWndScale = uint8(sndWndScale)
	}

	s.resendTimer.init(&s.resendWaker)

	s.updateMaxPayloadSize(int(ep.route.MTU()), 0)

	// Initialize SACK Scoreboard after updating max payload size as we use
	// the maxPayloadSize as the smss when determining if a segment is lost
	// etc.
	s.ep.scoreboard = NewSACKScoreboard(uint16(s.maxPayloadSize), iss)

	return s
}

func (s *sender) initCongestionControl(congestionControlName CongestionControlOption) congestionControl {
	switch congestionControlName {
	case ccCubic:
		return newCubicCC(s)
	case ccReno:
		fallthrough
	default:
		return newRenoCC(s)
	}
}

// updateMaxPayloadSize updates the maximum payload size based on the given
// MTU. If this is in response to "packet too big" control packets (indicated
// by the count argument), it also reduces the number of outstanding packets and
// attempts to retransmit the first packet above the MTU size.
func (s *sender) updateMaxPayloadSize(mtu, count int) {
	m := mtu - header.TCPMinimumSize

	m -= s.ep.maxOptionSize()

	// We don't adjust up for now.
	if m >= s.maxPayloadSize {
		return
	}

	// Make sure we can transmit at least one byte.
	if m <= 0 {
		m = 1
	}

	s.maxPayloadSize = m
	if s.gso {
		s.ep.gso.MSS = uint16(m)
	}

	if count == 0 {
		// updateMaxPayloadSize is also called when the sender is created.
		// and there is no data to send in such cases. Return immediately.
		return
	}

	// Update the scoreboard's smss to reflect the new lowered
	// maxPayloadSize.
	s.ep.scoreboard.smss = uint16(m)

	s.outstanding -= count
	if s.outstanding < 0 {
		s.outstanding = 0
	}

	// Rewind writeNext to the first segment exceeding the MTU. Do nothing
	// if it is already before such a packet.
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		if seg == s.writeNext {
			// We got to writeNext before we could find a segment
			// exceeding the MTU.
			break
		}

		if seg.data.Size() > m {
			// We found a segment exceeding the MTU. Rewind
			// writeNext and try to retransmit it.
			s.writeNext = seg
			break
		}
	}

	// Since we likely reduced the number of outstanding packets, we may be
	// ready to send some more.
	s.sendData()
}

// sendAck sends an ACK segment.
func (s *sender) sendAck() {
	s.sendSegmentFromView(buffer.VectorisedView{}, header.TCPFlagAck, s.sndNxt)
}

// updateRTO updates the retransmit timeout when a new roud-trip time is
// available. This is done in accordance with section 2 of RFC 6298.
func (s *sender) updateRTO(rtt time.Duration) {
	s.rtt.Lock()
	if !s.srttInited {
		s.rtt.rttvar = rtt / 2
		s.rtt.srtt = rtt
		s.srttInited = true
	} else {
		diff := s.rtt.srtt - rtt
		if diff < 0 {
			diff = -diff
		}
		// Use RFC6298 standard algorithm to update rttvar and srtt when
		// no timestamps are available.
		if !s.ep.sendTSOk {
			s.rtt.rttvar = (3*s.rtt.rttvar + diff) / 4
			s.rtt.srtt = (7*s.rtt.srtt + rtt) / 8
		} else {
			// When we are taking RTT measurements of every ACK then
			// we need to use a modified method as specified in
			// https://tools.ietf.org/html/rfc7323#appendix-G
			if s.outstanding == 0 {
				s.rtt.Unlock()
				return
			}
			// Netstack measures congestion window/inflight all in
			// terms of packets and not bytes. This is similar to
			// how linux also does cwnd and inflight. In practice
			// this approximation works as expected.
			expectedSamples := math.Ceil(float64(s.outstanding) / 2)

			// alpha & beta values are the original values as recommended in
			// https://tools.ietf.org/html/rfc6298#section-2.3.
			const alpha = 0.125
			const beta = 0.25

			alphaPrime := alpha / expectedSamples
			betaPrime := beta / expectedSamples
			rttVar := (1-betaPrime)*s.rtt.rttvar.Seconds() + betaPrime*diff.Seconds()
			srtt := (1-alphaPrime)*s.rtt.srtt.Seconds() + alphaPrime*rtt.Seconds()
			s.rtt.rttvar = time.Duration(rttVar * float64(time.Second))
			s.rtt.srtt = time.Duration(srtt * float64(time.Second))
		}
	}

	s.rto = s.rtt.srtt + 4*s.rtt.rttvar
	s.rtt.Unlock()
	if s.rto < minRTO {
		s.rto = minRTO
	}
}

// resendSegment resends the first unacknowledged segment.
func (s *sender) resendSegment() {
	// Don't use any segments we already sent to measure RTT as they may
	// have been affected by packets being lost.
	s.rttMeasureSeqNum = s.sndNxt

	// Resend the segment.
	if seg := s.writeList.Front(); seg != nil {
		if seg.data.Size() > s.maxPayloadSize {
			s.splitSeg(seg, s.maxPayloadSize)
		}

		// See: RFC 6675 section 5 Step 4.3
		//
		// To prevent retransmission, set both the HighRXT and RescueRXT
		// to the highest sequence number in the retransmitted segment.
		s.fr.highRxt = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size())) - 1
		s.fr.rescueRxt = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size())) - 1
		s.sendSegment(seg)
		s.ep.stack.Stats().TCP.FastRetransmit.Increment()

		// Run SetPipe() as per RFC 6675 section 5 Step 4.4
		s.SetPipe()
	}
}

// retransmitTimerExpired is called when the retransmit timer expires, and
// unacknowledged segments are assumed lost, and thus need to be resent.
// Returns true if the connection is still usable, or false if the connection
// is deemed lost.
func (s *sender) retransmitTimerExpired() bool {
	// Check if the timer actually expired or if it's a spurious wake due
	// to a previously orphaned runtime timer.
	if !s.resendTimer.checkExpiration() {
		return true
	}

	s.ep.stack.Stats().TCP.Timeouts.Increment()

	// Give up if we've waited more than a minute since the last resend.
	if s.rto >= 60*time.Second {
		return false
	}

	// Set new timeout. The timer will be restarted by the call to sendData
	// below.
	s.rto *= 2

	// See: https://tools.ietf.org/html/rfc6582#section-3.2 Step 4.
	//
	// Retransmit timeouts:
	//     After a retransmit timeout, record the highest sequence number
	//     transmitted in the variable recover, and exit the fast recovery
	//     procedure if applicable.
	s.fr.last = s.sndNxt - 1

	if s.fr.active {
		// We were attempting fast recovery but were not successful.
		// Leave the state. We don't need to update ssthresh because it
		// has already been updated when entered fast-recovery.
		s.leaveFastRecovery()
	}

	s.cc.HandleRTOExpired()

	// Mark the next segment to be sent as the first unacknowledged one and
	// start sending again. Set the number of outstanding packets to 0 so
	// that we'll be able to retransmit.
	//
	// We'll keep on transmitting (or retransmitting) as we get acks for
	// the data we transmit.
	s.outstanding = 0

	// Expunge all SACK information as per https://tools.ietf.org/html/rfc6675#section-5.1
	//
	//  In order to avoid memory deadlocks, the TCP receiver is allowed to
	//  discard data that has already been selectively acknowledged. As a
	//  result, [RFC2018] suggests that a TCP sender SHOULD expunge the SACK
	//  information gathered from a receiver upon a retransmission timeout
	//  (RTO) "since the timeout might indicate that the data receiver has
	//  reneged." Additionally, a TCP sender MUST "ignore prior SACK
	//  information in determining which data to retransmit."
	//
	// NOTE: We take the stricter interpretation and just expunge all
	// information as we lack more rigorous checks to validate if the SACK
	// information is usable after an RTO.
	s.ep.scoreboard.Reset()
	s.writeNext = s.writeList.Front()
	s.sendData()

	return true
}

// pCount returns the number of packets in the segment. Due to GSO, a segment
// can be composed of multiple packets.
func (s *sender) pCount(seg *segment) int {
	size := seg.data.Size()
	if size == 0 {
		return 1
	}

	return (size-1)/s.maxPayloadSize + 1
}

// splitSeg splits a given segment at the size specified and inserts the
// remainder as a new segment after the current one in the write list.
func (s *sender) splitSeg(seg *segment, size int) {
	if seg.data.Size() <= size {
		return
	}
	// Split this segment up.
	nSeg := seg.clone()
	nSeg.data.TrimFront(size)
	nSeg.sequenceNumber.UpdateForward(seqnum.Size(size))
	s.writeList.InsertAfter(seg, nSeg)
	seg.data.CapLength(size)
}

// NextSeg implements the RFC6675 NextSeg() operation. It returns segments that
// match rule 1, 3 and 4 of the NextSeg() operation defined in RFC6675. Rule 2
// is handled by the normal send logic.
func (s *sender) NextSeg() (nextSeg1, nextSeg3, nextSeg4 *segment) {
	var s3 *segment
	var s4 *segment
	smss := s.ep.scoreboard.SMSS()
	// Step 1.
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		if !s.isAssignedSequenceNumber(seg) {
			break
		}
		segSeq := seg.sequenceNumber
		if seg.data.Size() > int(smss) {
			s.splitSeg(seg, int(smss))
		}
		// See RFC 6675 Section 4
		//
		//     1. If there exists a smallest unSACKED sequence number
		//     'S2' that meets the following 3 criteria for determinig
		//     loss, the sequence range of one segment of up to SMSS
		//     octects starting with S2 MUST be returned.
		if !s.ep.scoreboard.IsSACKED(header.SACKBlock{segSeq, segSeq.Add(1)}) {
			// NextSeg():
			//
			//    (1.a) S2 is greater than HighRxt
			//    (1.b) S2 is less than highest octect covered by
			//    any received SACK.
			if s.fr.highRxt.LessThan(segSeq) && segSeq.LessThan(s.ep.scoreboard.maxSACKED) {
				// NextSeg():
				//     (1.c) IsLost(S2) returns true.
				if s.ep.scoreboard.IsLost(segSeq) {
					return seg, s3, s4
				}
				// NextSeg():
				//
				// (3): If the conditions for rules (1) and (2)
				// fail, but there exists an unSACKed sequence
				// number S3 that meets the criteria for
				// detecting loss given in steps 1.a and 1.b
				// above (specifically excluding (1.c)) then one
				// segment of upto SMSS octets starting with S3
				// SHOULD be returned.
				if s3 == nil {
					s3 = seg
				}
			}
			// NextSeg():
			//
			//     (4) If the conditions for (1), (2) and (3) fail,
			//     but there exists outstanding unSACKED data, we
			//     provide the opportunity for a single "rescue"
			//     retransmission per entry into loss recovery. If
			//     HighACK is greater than RescueRxt, the one
			//     segment of upto SMSS octects that MUST include
			//     the highest outstanding unSACKed sequence number
			//     SHOULD be returned.
			if s.fr.rescueRxt.LessThan(s.sndUna - 1) {
				if s4 != nil {
					if s4.sequenceNumber.LessThan(segSeq) {
						s4 = seg
					}
				} else {
					s4 = seg
				}
				s.fr.rescueRxt = s.fr.last
			}
		}
	}

	return nil, s3, s4
}

// maybeSendSegment tries to send the specified segment and either coalesces
// other segments into this one or splits the specified segment based on the
// lower of the specified limit value or the receivers window size specified by
// end.
func (s *sender) maybeSendSegment(seg *segment, limit int, end seqnum.Value) (sent bool) {
	// We abuse the flags field to determine if we have already
	// assigned a sequence number to this segment.
	if !s.isAssignedSequenceNumber(seg) {
		// Merge segments if allowed.
		if seg.data.Size() != 0 {
			available := int(seg.sequenceNumber.Size(end))
			if available > limit {
				available = limit
			}

			// nextTooBig indicates that the next segment was too
			// large to entirely fit in the current segment. It
			// would be possible to split the next segment and merge
			// the portion that fits, but unexpectedly splitting
			// segments can have user visible side-effects which can
			// break applications. For example, RFC 7766 section 8
			// says that the length and data of a DNS response
			// should be sent in the same TCP segment to avoid
			// triggering bugs in poorly written DNS
			// implementations.
			var nextTooBig bool
			for seg.Next() != nil && seg.Next().data.Size() != 0 {
				if seg.data.Size()+seg.Next().data.Size() > available {
					nextTooBig = true
					break
				}
				seg.data.Append(seg.Next().data)

				// Consume the segment that we just merged in.
				s.writeList.Remove(seg.Next())
			}
			if !nextTooBig && seg.data.Size() < available {
				// Segment is not full.
				if s.outstanding > 0 && atomic.LoadUint32(&s.ep.delay) != 0 {
					// Nagle's algorithm. From Wikipedia:
					//   Nagle's algorithm works by
					//   combining a number of small
					//   outgoing messages and sending them
					//   all at once. Specifically, as long
					//   as there is a sent packet for which
					//   the sender has received no
					//   acknowledgment, the sender should
					//   keep buffering its output until it
					//   has a full packet's worth of
					//   output, thus allowing output to be
					//   sent all at once.
					return false
				}
				if atomic.LoadUint32(&s.ep.cork) != 0 {
					// Hold back the segment until full.
					return false
				}
			}
		}

		// Assign flags. We don't do it above so that we can merge
		// additional data if Nagle holds the segment.
		seg.sequenceNumber = s.sndNxt
		seg.flags = header.TCPFlagAck | header.TCPFlagPsh
	}

	var segEnd seqnum.Value
	if seg.data.Size() == 0 {
		if s.writeList.Back() != seg {
			panic("FIN segments must be the final segment in the write list.")
		}
		seg.flags = header.TCPFlagAck | header.TCPFlagFin
		segEnd = seg.sequenceNumber.Add(1)
	} else {
		// We're sending a non-FIN segment.
		if seg.flags&header.TCPFlagFin != 0 {
			panic("Netstack queues FIN segments without data.")
		}

		if !seg.sequenceNumber.LessThan(end) {
			return false
		}

		available := int(seg.sequenceNumber.Size(end))
		if available == 0 {
			return false
		}
		if available > limit {
			available = limit
		}

		if seg.data.Size() > available {
			s.splitSeg(seg, available)
		}

		segEnd = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size()))
	}

	s.sendSegment(seg)

	// Update sndNxt if we actually sent new data (as opposed to
	// retransmitting some previously sent data).
	if s.sndNxt.LessThan(segEnd) {
		s.sndNxt = segEnd
	}

	return true
}

// handleSACKRecovery implements the loss recovery phase as described in RFC6675
// section 5, step C.
func (s *sender) handleSACKRecovery(limit int, end seqnum.Value) (dataSent bool) {
	s.SetPipe()
	for s.outstanding < s.sndCwnd {
		nextSeg, s3, s4 := s.NextSeg()
		if nextSeg == nil {
			// NextSeg():
			//
			// Step (2): "If no sequence number 'S2' per rule (1)
			// exists but there exists available unsent data and the
			// receiver's advertised window allows, the sequence
			// range of one segment of up to SMSS octets of
			// previously unsent data starting with sequence number
			// HighData+1 MUST be returned."
			for seg := s.writeNext; seg != nil; seg = seg.Next() {
				if s.isAssignedSequenceNumber(seg) && seg.sequenceNumber.LessThan(s.sndNxt) {
					continue
				}
				// Step C.3 described below is handled by
				// maybeSendSegment which increments sndNxt when
				// a segment is transmitted.
				//
				// Step C.3 "If any of the data octets sent in
				// (C.1) are above HighData, HighData must be
				// updated to reflect the transmission of
				// previously unsent data."
				if sent := s.maybeSendSegment(seg, limit, end); !sent {
					break
				}
				dataSent = true
				s.outstanding++
				s.writeNext = seg.Next()
				nextSeg = seg
				break
			}
			if nextSeg != nil {
				continue
			}
		}
		rescueRtx := false
		if nextSeg == nil && s3 != nil {
			nextSeg = s3
		}
		if nextSeg == nil && s4 != nil {
			nextSeg = s4
			rescueRtx = true
		}
		if nextSeg == nil {
			break
		}
		segEnd := nextSeg.sequenceNumber.Add(nextSeg.logicalLen())
		if !rescueRtx && nextSeg.sequenceNumber.LessThan(s.sndNxt) {
			// RFC 6675, Step C.2
			//
			// "If any of the data octets sent in (C.1) are below
			// HighData, HighRxt MUST be set to the highest sequence
			// number of the retransmitted segment unless NextSeg ()
			// rule (4) was invoked for this retransmission."
			s.fr.highRxt = segEnd - 1
		}

		// RFC 6675, Step C.4.
		//
		// "The estimate of the amount of data outstanding in the network
		// must be updated by incrementing pipe by the number of octets
		// transmitted in (C.1)."
		s.outstanding++
		dataSent = true
		s.sendSegment(nextSeg)
	}
	return dataSent
}

// sendData sends new data segments. It is called when data becomes available or
// when the send window opens up.
func (s *sender) sendData() {
	limit := s.maxPayloadSize
	if s.gso {
		limit = int(s.ep.gso.MaxSize - header.TCPHeaderMaximumSize)
	}
	end := s.sndUna.Add(s.sndWnd)

	// Reduce the congestion window to min(IW, cwnd) per RFC 5681, page 10.
	// "A TCP SHOULD set cwnd to no more than RW before beginning
	// transmission if the TCP has not sent data in the interval exceeding
	// the retrasmission timeout."
	if !s.fr.active && time.Now().Sub(s.lastSendTime) > s.rto {
		if s.sndCwnd > InitialCwnd {
			s.sndCwnd = InitialCwnd
		}
	}

	var dataSent bool

	// RFC 6675 recovery algorithm step C 1-5.
	if s.fr.active && s.ep.sackPermitted {
		dataSent = s.handleSACKRecovery(s.maxPayloadSize, end)
	} else {
		for seg := s.writeNext; seg != nil && s.outstanding < s.sndCwnd; seg = seg.Next() {
			cwndLimit := (s.sndCwnd - s.outstanding) * s.maxPayloadSize
			if cwndLimit < limit {
				limit = cwndLimit
			}
			if s.isAssignedSequenceNumber(seg) && s.ep.sackPermitted && s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
				continue
			}
			if sent := s.maybeSendSegment(seg, limit, end); !sent {
				break
			}
			dataSent = true
			s.outstanding++
			s.writeNext = seg.Next()
		}
	}

	if dataSent {
		// We sent data, so we should stop the keepalive timer to ensure
		// that no keepalives are sent while there is pending data.
		s.ep.disableKeepaliveTimer()
	}

	// Enable the timer if we have pending data and it's not enabled yet.
	if !s.resendTimer.enabled() && s.sndUna != s.sndNxt {
		s.resendTimer.enable(s.rto)
	}
	// If we have no more pending data, start the keepalive timer.
	if s.sndUna == s.sndNxt {
		s.ep.resetKeepaliveTimer(false)
	}
}

func (s *sender) enterFastRecovery() {
	s.fr.active = true
	// Save state to reflect we're now in fast recovery.
	//
	// See : https://tools.ietf.org/html/rfc5681#section-3.2 Step 3.
	// We inflate the cwnd by 3 to account for the 3 packets which triggered
	// the 3 duplicate ACKs and are now not in flight.
	s.sndCwnd = s.sndSsthresh + 3
	s.fr.first = s.sndUna
	s.fr.last = s.sndNxt - 1
	s.fr.maxCwnd = s.sndCwnd + s.outstanding
	if s.ep.sackPermitted {
		s.ep.stack.Stats().TCP.SACKRecovery.Increment()
		return
	}
	s.ep.stack.Stats().TCP.FastRecovery.Increment()
}

func (s *sender) leaveFastRecovery() {
	s.fr.active = false
	s.fr.maxCwnd = 0
	s.dupAckCount = 0

	// Deflate cwnd. It had been artificially inflated when new dups arrived.
	s.sndCwnd = s.sndSsthresh

	s.cc.PostRecovery()
}

func (s *sender) handleFastRecovery(seg *segment) (rtx bool) {
	ack := seg.ackNumber
	// We are in fast recovery mode. Ignore the ack if it's out of
	// range.
	if !ack.InRange(s.sndUna, s.sndNxt+1) {
		return false
	}

	// Leave fast recovery if it acknowledges all the data covered by
	// this fast recovery session.
	if s.fr.last.LessThan(ack) {
		s.leaveFastRecovery()
		return false
	}

	if s.ep.sackPermitted {
		// When SACK is enabled we let retransmission be governed by
		// the SACK logic.
		return false
	}

	// Don't count this as a duplicate if it is carrying data or
	// updating the window.
	if seg.logicalLen() != 0 || s.sndWnd != seg.window {
		return false
	}

	// Inflate the congestion window if we're getting duplicate acks
	// for the packet we retransmitted.
	if ack == s.fr.first {
		// We received a dup, inflate the congestion window by 1 packet
		// if we're not at the max yet. Only inflate the window if
		// regular FastRecovery is in use, RFC6675 does not require
		// inflating cwnd on duplicate ACKs.
		if s.sndCwnd < s.fr.maxCwnd {
			s.sndCwnd++
		}
		return false
	}

	// A partial ack was received. Retransmit this packet and
	// remember it so that we don't retransmit it again. We don't
	// inflate the window because we're putting the same packet back
	// onto the wire.
	//
	// N.B. The retransmit timer will be reset by the caller.
	s.fr.first = ack
	s.dupAckCount = 0
	return true
}

// isAssignedSequenceNumber relies on the fact that we only set flags once a
// sequencenumber is assigned and that is only done right before we send the
// segment. As a result any segment that has a non-zero flag has a valid
// sequence number assigned to it.
func (s *sender) isAssignedSequenceNumber(seg *segment) bool {
	return seg.flags != 0
}

// SetPipe implements the SetPipe() function described in RFC6675. Netstack
// maintains the congestion window in number of packets and not bytes, so
// SetPipe() here measures number of outstanding packets rather than actual
// outstanding bytes in the network.
func (s *sender) SetPipe() {
	// If SACK isn't permitted or it is permitted but recovery is not active
	// then ignore pipe calculations.
	if !s.ep.sackPermitted || !s.fr.active {
		return
	}
	pipe := 0
	smss := seqnum.Size(s.ep.scoreboard.SMSS())
	for s1 := s.writeList.Front(); s1 != nil && s1.data.Size() != 0 && s.isAssignedSequenceNumber(s1); s1 = s1.Next() {
		// With GSO each segment can be much larger than SMSS. So check the segment
		// in SMSS sized ranges.
		segEnd := s1.sequenceNumber.Add(seqnum.Size(s1.data.Size()))
		for startSeq := s1.sequenceNumber; startSeq.LessThan(segEnd); startSeq = startSeq.Add(smss) {
			endSeq := startSeq.Add(smss)
			if segEnd.LessThan(endSeq) {
				endSeq = segEnd
			}
			sb := header.SACKBlock{startSeq, endSeq}
			// SetPipe():
			//
			// After initializing pipe to zero, the following steps are
			// taken for each octet 'S1' in the sequence space between
			// HighACK and HighData that has not been SACKed:
			if !s1.sequenceNumber.LessThan(s.sndNxt) {
				break
			}
			if s.ep.scoreboard.IsSACKED(sb) {
				continue
			}

			// SetPipe():
			//
			//    (a) If IsLost(S1) returns false, Pipe is incremened by 1.
			//
			// NOTE: here we mark the whole segment as lost. We do not try
			// and test every byte in our write buffer as we maintain our
			// pipe in terms of oustanding packets and not bytes.
			if !s.ep.scoreboard.IsRangeLost(sb) {
				pipe++
			}
			// SetPipe():
			//    (b) If S1 <= HighRxt, Pipe is incremented by 1.
			if s1.sequenceNumber.LessThanEq(s.fr.highRxt) {
				pipe++
			}
		}
	}
	s.outstanding = pipe
}

// checkDuplicateAck is called when an ack is received. It manages the state
// related to duplicate acks and determines if a retransmit is needed according
// to the rules in RFC 6582 (NewReno).
func (s *sender) checkDuplicateAck(seg *segment) (rtx bool) {
	ack := seg.ackNumber
	if s.fr.active {
		return s.handleFastRecovery(seg)
	}

	// We're not in fast recovery yet. A segment is considered a duplicate
	// only if it doesn't carry any data and doesn't update the send window,
	// because if it does, it wasn't sent in response to an out-of-order
	// segment. If SACK is enabled then we have an additional check to see
	// if the segment carries new SACK information. If it does then it is
	// considered a duplicate ACK as per RFC6675.
	if ack != s.sndUna || seg.logicalLen() != 0 || s.sndWnd != seg.window || ack == s.sndNxt {
		if !s.ep.sackPermitted || !seg.hasNewSACKInfo {
			s.dupAckCount = 0
			return false
		}
	}

	s.dupAckCount++

	// Do not enter fast recovery until we reach nDupAckThreshold or the
	// first unacknowledged byte is considered lost as per SACK scoreboard.
	if s.dupAckCount < nDupAckThreshold || (s.ep.sackPermitted && !s.ep.scoreboard.IsLost(s.sndUna)) {
		// RFC 6675 Step 3.
		s.fr.highRxt = s.sndUna - 1
		// Do run SetPipe() to calculate the outstanding segments.
		s.SetPipe()
		return false
	}

	// See: https://tools.ietf.org/html/rfc6582#section-3.2 Step 2
	//
	// We only do the check here, the incrementing of last to the highest
	// sequence number transmitted till now is done when enterFastRecovery
	// is invoked.
	if !s.fr.last.LessThan(seg.ackNumber) {
		s.dupAckCount = 0
		return false
	}
	s.cc.HandleNDupAcks()
	s.enterFastRecovery()
	s.dupAckCount = 0
	return true
}

// handleRcvdSegment is called when a segment is received; it is responsible for
// updating the send-related state.
func (s *sender) handleRcvdSegment(seg *segment) {
	// Check if we can extract an RTT measurement from this ack.
	if !seg.parsedOptions.TS && s.rttMeasureSeqNum.LessThan(seg.ackNumber) {
		s.updateRTO(time.Now().Sub(s.rttMeasureTime))
		s.rttMeasureSeqNum = s.sndNxt
	}

	// Update Timestamp if required. See RFC7323, section-4.3.
	if s.ep.sendTSOk && seg.parsedOptions.TS {
		s.ep.updateRecentTimestamp(seg.parsedOptions.TSVal, s.maxSentAck, seg.sequenceNumber)
	}

	// Insert SACKBlock information into our scoreboard.
	if s.ep.sackPermitted {
		for _, sb := range seg.parsedOptions.SACKBlocks {
			// Only insert the SACK block if the following holds
			// true:
			//  * SACK block acks data after the ack number in the
			//    current segment.
			//  * SACK block represents a sequence
			//    between sndUna and sndNxt (i.e. data that is
			//    currently unacked and in-flight).
			//  * SACK block that has not been SACKed already.
			//
			// NOTE: This check specifically excludes DSACK blocks
			// which have start/end before sndUna and are used to
			// indicate spurious retransmissions.
			if seg.ackNumber.LessThan(sb.Start) && s.sndUna.LessThan(sb.Start) && sb.End.LessThanEq(s.sndNxt) && !s.ep.scoreboard.IsSACKED(sb) {
				s.ep.scoreboard.Insert(sb)
				seg.hasNewSACKInfo = true
			}
		}
		s.SetPipe()
	}

	// Count the duplicates and do the fast retransmit if needed.
	rtx := s.checkDuplicateAck(seg)

	// Stash away the current window size.
	s.sndWnd = seg.window

	// Ignore ack if it doesn't acknowledge any new data.
	ack := seg.ackNumber
	if (ack - 1).InRange(s.sndUna, s.sndNxt) {
		s.dupAckCount = 0

		// See : https://tools.ietf.org/html/rfc1323#section-3.3.
		// Specifically we should only update the RTO using TSEcr if the
		// following condition holds:
		//
		//    A TSecr value received in a segment is used to update the
		//    averaged RTT measurement only if the segment acknowledges
		//    some new data, i.e., only if it advances the left edge of
		//    the send window.
		if s.ep.sendTSOk && seg.parsedOptions.TSEcr != 0 {
			// TSVal/Ecr values sent by Netstack are at a millisecond
			// granularity.
			elapsed := time.Duration(s.ep.timestamp()-seg.parsedOptions.TSEcr) * time.Millisecond
			s.updateRTO(elapsed)
		}

		// When an ack is received we must rearm the timer.
		// RFC 6298 5.2
		s.resendTimer.enable(s.rto)

		// Remove all acknowledged data from the write list.
		acked := s.sndUna.Size(ack)
		s.sndUna = ack

		ackLeft := acked
		originalOutstanding := s.outstanding
		for ackLeft > 0 {
			// We use logicalLen here because we can have FIN
			// segments (which are always at the end of list) that
			// have no data, but do consume a sequence number.
			seg := s.writeList.Front()
			datalen := seg.logicalLen()

			if datalen > ackLeft {
				prevCount := s.pCount(seg)
				seg.data.TrimFront(int(ackLeft))
				seg.sequenceNumber.UpdateForward(ackLeft)
				s.outstanding -= prevCount - s.pCount(seg)
				break
			}

			if s.writeNext == seg {
				s.writeNext = seg.Next()
			}
			s.writeList.Remove(seg)

			// if SACK is enabled then Only reduce outstanding if
			// the segment was not previously SACKED as these have
			// already been accounted for in SetPipe().
			if !s.ep.sackPermitted || !s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
				s.outstanding -= s.pCount(seg)
			}
			seg.decRef()
			ackLeft -= datalen
		}

		// Update the send buffer usage and notify potential waiters.
		s.ep.updateSndBufferUsage(int(acked))

		// Clear SACK information for all acked data.
		s.ep.scoreboard.Delete(s.sndUna)

		// If we are not in fast recovery then update the congestion
		// window based on the number of acknowledged packets.
		if !s.fr.active {
			s.cc.Update(originalOutstanding - s.outstanding)
		}

		// It is possible for s.outstanding to drop below zero if we get
		// a retransmit timeout, reset outstanding to zero but later
		// get an ack that cover previously sent data.
		if s.outstanding < 0 {
			s.outstanding = 0
		}

		s.SetPipe()

		// If all outstanding data was acknowledged the disable the timer.
		// RFC 6298 Rule 5.3
		if s.sndUna == s.sndNxt {
			s.outstanding = 0
			s.resendTimer.disable()
		}
	}
	// Now that we've popped all acknowledged data from the retransmit
	// queue, retransmit if needed.
	if rtx {
		s.resendSegment()
	}

	// Send more data now that some of the pending data has been ack'd, or
	// that the window opened up, or the congestion window was inflated due
	// to a duplicate ack during fast recovery. This will also re-enable
	// the retransmit timer if needed.
	if !s.ep.sackPermitted || s.fr.active || s.dupAckCount == 0 || seg.hasNewSACKInfo {
		s.sendData()
	}
}

// sendSegment sends the specified segment.
func (s *sender) sendSegment(seg *segment) *tcpip.Error {
	if !seg.xmitTime.IsZero() {
		s.ep.stack.Stats().TCP.Retransmits.Increment()
		if s.sndCwnd < s.sndSsthresh {
			s.ep.stack.Stats().TCP.SlowStartRetransmits.Increment()
		}
	}
	seg.xmitTime = time.Now()
	return s.sendSegmentFromView(seg.data, seg.flags, seg.sequenceNumber)
}

// sendSegmentFromView sends a new segment containing the given payload, flags
// and sequence number.
func (s *sender) sendSegmentFromView(data buffer.VectorisedView, flags byte, seq seqnum.Value) *tcpip.Error {
	s.lastSendTime = time.Now()
	if seq == s.rttMeasureSeqNum {
		s.rttMeasureTime = s.lastSendTime
	}

	rcvNxt, rcvWnd := s.ep.rcv.getSendParams()

	// Remember the max sent ack.
	s.maxSentAck = rcvNxt

	// Every time a packet containing data is sent (including a
	// retransmission), if SACK is enabled then use the conservative timer
	// described in RFC6675 Section 4.0, otherwise follow the standard time
	// described in RFC6298 Section 5.2.
	if data.Size() != 0 {
		if s.ep.sackPermitted {
			s.resendTimer.enable(s.rto)
		} else {
			if !s.resendTimer.enabled() {
				s.resendTimer.enable(s.rto)
			}
		}
	}

	return s.ep.sendRaw(data, flags, seq, rcvNxt, rcvWnd)
}
