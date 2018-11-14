// Copyright 2018 Google LLC
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
}

func newSender(ep *endpoint, iss, irs seqnum.Value, sndWnd seqnum.Size, mss uint16, sndWndScale int) *sender {
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
		maxPayloadSize:   int(mss),
		maxSentAck:       irs + 1,
		fr: fastRecovery{
			// See: https://tools.ietf.org/html/rfc6582#section-3.2 Step 1.
			last: iss,
		},
	}

	s.cc = s.initCongestionControl(ep.cc)

	// A negative sndWndScale means that no scaling is in use, otherwise we
	// store the scaling value.
	if sndWndScale > 0 {
		s.sndWndScale = uint8(sndWndScale)
	}

	s.updateMaxPayloadSize(int(ep.route.MTU()), 0)

	s.resendTimer.init(&s.resendWaker)

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

	// Calculate the maximum option size.
	var maxSackBlocks [header.TCPMaxSACKBlocks]header.SACKBlock
	options := s.ep.makeOptions(maxSackBlocks[:])
	m -= len(options)
	putOptions(options)

	// We don't adjust up for now.
	if m >= s.maxPayloadSize {
		return
	}

	// Make sure we can transmit at least one byte.
	if m <= 0 {
		m = 1
	}

	s.maxPayloadSize = m

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
	s.sendSegment(buffer.VectorisedView{}, flagAck, s.sndNxt)
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
		s.sendSegment(seg.data, seg.flags, seg.sequenceNumber)
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

	// Give up if we've waited more than a minute since the last resend.
	if s.rto >= 60*time.Second {
		return false
	}

	// Set new timeout. The timer will be restarted by the call to sendData
	// below.
	s.rto *= 2

	if s.fr.active {
		// We were attempting fast recovery but were not successful.
		// Leave the state. We don't need to update ssthresh because it
		// has already been updated when entered fast-recovery.
		s.leaveFastRecovery()
	}

	// See: https://tools.ietf.org/html/rfc6582#section-3.2 Step 4.
	// We store the highest sequence number transmitted in cases where
	// we were not in fast recovery.
	s.fr.last = s.sndNxt - 1

	s.cc.HandleRTOExpired()

	// Mark the next segment to be sent as the first unacknowledged one and
	// start sending again. Set the number of outstanding packets to 0 so
	// that we'll be able to retransmit.
	//
	// We'll keep on transmitting (or retransmitting) as we get acks for
	// the data we transmit.
	s.outstanding = 0
	s.writeNext = s.writeList.Front()
	s.sendData()

	return true
}

// sendData sends new data segments. It is called when data becomes available or
// when the send window opens up.
func (s *sender) sendData() {
	limit := s.maxPayloadSize

	// Reduce the congestion window to min(IW, cwnd) per RFC 5681, page 10.
	// "A TCP SHOULD set cwnd to no more than RW before beginning
	// transmission if the TCP has not sent data in the interval exceeding
	// the retrasmission timeout."
	if !s.fr.active && time.Now().Sub(s.lastSendTime) > s.rto {
		if s.sndCwnd > InitialCwnd {
			s.sndCwnd = InitialCwnd
		}
	}

	seg := s.writeNext
	end := s.sndUna.Add(s.sndWnd)
	var dataSent bool
	for ; seg != nil && s.outstanding < s.sndCwnd; seg = seg.Next() {

		// We abuse the flags field to determine if we have already
		// assigned a sequence number to this segment.
		if seg.flags == 0 {
			// Merge segments if allowed.
			if seg.data.Size() != 0 {
				available := int(seg.sequenceNumber.Size(end))
				if available > limit {
					available = limit
				}

				// nextTooBig indicates that the next segment was too
				// large to entirely fit in the current segment. It would
				// be possible to split the next segment and merge the
				// portion that fits, but unexpectedly splitting segments
				// can have user visible side-effects which can break
				// applications. For example, RFC 7766 section 8 says
				// that the length and data of a DNS response should be
				// sent in the same TCP segment to avoid triggering bugs
				// in poorly written DNS implementations.
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
						//   Nagle's algorithm works by combining a number of
						//   small outgoing messages and sending them all at
						//   once. Specifically, as long as there is a sent
						//   packet for which the sender has received no
						//   acknowledgment, the sender should keep buffering
						//   its output until it has a full packet's worth of
						//   output, thus allowing output to be sent all at
						//   once.
						break
					}
					if atomic.LoadUint32(&s.ep.cork) != 0 {
						// Hold back the segment until full.
						break
					}
				}
			}

			// Assign flags. We don't do it above so that we can merge
			// additional data if Nagle holds the segment.
			seg.sequenceNumber = s.sndNxt
			seg.flags = flagAck | flagPsh
		}

		var segEnd seqnum.Value
		if seg.data.Size() == 0 {
			if s.writeList.Back() != seg {
				panic("FIN segments must be the final segment in the write list.")
			}
			seg.flags = flagAck | flagFin
			segEnd = seg.sequenceNumber.Add(1)
		} else {
			// We're sending a non-FIN segment.
			if seg.flags&flagFin != 0 {
				panic("Netstack queues FIN segments without data.")
			}

			if !seg.sequenceNumber.LessThan(end) {
				break
			}

			available := int(seg.sequenceNumber.Size(end))
			if available > limit {
				available = limit
			}

			if seg.data.Size() > available {
				// Split this segment up.
				nSeg := seg.clone()
				nSeg.data.TrimFront(available)
				nSeg.sequenceNumber.UpdateForward(seqnum.Size(available))
				s.writeList.InsertAfter(seg, nSeg)
				seg.data.CapLength(available)
			}

			s.outstanding++
			segEnd = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size()))
		}

		if !dataSent {
			dataSent = true
			// We are sending data, so we should stop the keepalive timer to
			// ensure that no keepalives are sent while there is pending data.
			s.ep.disableKeepaliveTimer()
		}
		s.sendSegment(seg.data, seg.flags, seg.sequenceNumber)

		// Update sndNxt if we actually sent new data (as opposed to
		// retransmitting some previously sent data).
		if s.sndNxt.LessThan(segEnd) {
			s.sndNxt = segEnd
		}
	}

	// Remember the next segment we'll write.
	s.writeNext = seg

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
	// See : https://tools.ietf.org/html/rfc5681#section-3.2 Step 3.
	// We inflat the cwnd by 3 to account for the 3 packets which triggered
	// the 3 duplicate ACKs and are now not in flight.
	s.sndCwnd = s.sndSsthresh + 3
	s.fr.first = s.sndUna
	s.fr.last = s.sndNxt - 1
	s.fr.maxCwnd = s.sndCwnd + s.outstanding
}

func (s *sender) leaveFastRecovery() {
	s.fr.active = false
	s.fr.first = 0
	s.fr.last = s.sndNxt - 1
	s.fr.maxCwnd = 0
	s.dupAckCount = 0

	// Deflate cwnd. It had been artificially inflated when new dups arrived.
	s.sndCwnd = s.sndSsthresh
	s.cc.PostRecovery()
}

// checkDuplicateAck is called when an ack is received. It manages the state
// related to duplicate acks and determines if a retransmit is needed according
// to the rules in RFC 6582 (NewReno).
func (s *sender) checkDuplicateAck(seg *segment) (rtx bool) {
	ack := seg.ackNumber
	if s.fr.active {
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

		// Don't count this as a duplicate if it is carrying data or
		// updating the window.
		if seg.logicalLen() != 0 || s.sndWnd != seg.window {
			return false
		}

		// Inflate the congestion window if we're getting duplicate acks
		// for the packet we retransmitted.
		if ack == s.fr.first {
			// We received a dup, inflate the congestion window by 1
			// packet if we're not at the max yet.
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

	// We're not in fast recovery yet. A segment is considered a duplicate
	// only if it doesn't carry any data and doesn't update the send window,
	// because if it does, it wasn't sent in response to an out-of-order
	// segment.
	if ack != s.sndUna || seg.logicalLen() != 0 || s.sndWnd != seg.window || ack == s.sndNxt {
		s.dupAckCount = 0
		return false
	}

	s.dupAckCount++
	// Do not enter fast recovery until we reach nDupAckThreshold.
	if s.dupAckCount < nDupAckThreshold {
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
	if !s.ep.sendTSOk && s.rttMeasureSeqNum.LessThan(seg.ackNumber) {
		s.updateRTO(time.Now().Sub(s.rttMeasureTime))
		s.rttMeasureSeqNum = s.sndNxt
	}

	// Update Timestamp if required. See RFC7323, section-4.3.
	s.ep.updateRecentTimestamp(seg.parsedOptions.TSVal, s.maxSentAck, seg.sequenceNumber)

	// Count the duplicates and do the fast retransmit if needed.
	rtx := s.checkDuplicateAck(seg)

	// Stash away the current window size.
	s.sndWnd = seg.window

	// Ignore ack if it doesn't acknowledge any new data.
	ack := seg.ackNumber
	if (ack - 1).InRange(s.sndUna, s.sndNxt) {
		s.dupAckCount = 0
		// When an ack is received we must reset the timer. We stop it
		// here and it will be restarted later if needed.
		s.resendTimer.disable()

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
				seg.data.TrimFront(int(ackLeft))
				break
			}

			if s.writeNext == seg {
				s.writeNext = seg.Next()
			}
			s.writeList.Remove(seg)
			s.outstanding--
			seg.decRef()
			ackLeft -= datalen
		}

		// Update the send buffer usage and notify potential waiters.
		s.ep.updateSndBufferUsage(int(acked))

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
	s.sendData()
}

// sendSegment sends a new segment containing the given payload, flags and
// sequence number.
func (s *sender) sendSegment(data buffer.VectorisedView, flags byte, seq seqnum.Value) *tcpip.Error {
	s.lastSendTime = time.Now()
	if seq == s.rttMeasureSeqNum {
		s.rttMeasureTime = s.lastSendTime
	}

	rcvNxt, rcvWnd := s.ep.rcv.getSendParams()

	// Remember the max sent ack.
	s.maxSentAck = rcvNxt

	return s.ep.sendRaw(data, flags, seq, rcvNxt, rcvWnd)
}
