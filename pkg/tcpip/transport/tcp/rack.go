// Copyright 2020 The gVisor Authors.
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
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

const (
	// wcDelayedACKTimeout is the recommended maximum delayed ACK timer
	// value as defined in the RFC. It stands for worst case delayed ACK
	// timer (WCDelAckT). When FlightSize is 1, PTO is inflated by
	// WCDelAckT time to compensate for a potential long delayed ACK timer
	// at the receiver.
	// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.5.
	wcDelayedACKTimeout = 200 * time.Millisecond

	// tcpRACKRecoveryThreshold is the number of loss recoveries for which
	// the reorder window is inflated and after that the reorder window is
	// reset to its initial value of minRTT/4.
	// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.2.
	tcpRACKRecoveryThreshold = 16
)

// RACK is a loss detection algorithm used in TCP to detect packet loss and
// reordering using transmission timestamp of the packets instead of packet or
// sequence counts. To use RACK, SACK should be enabled on the connection.

// rackControl stores the rack related fields.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-6.1
//
// +stateify savable
type rackControl struct {
	// dsackSeen indicates if the connection has seen a DSACK.
	dsackSeen bool

	// endSequence is the ending TCP sequence number of the most recent
	// acknowledged segment.
	endSequence seqnum.Value

	// exitedRecovery indicates if the connection is exiting loss recovery.
	// This flag is set if the sender is leaving the recovery after
	// receiving an ACK and is reset during updating of reorder window.
	exitedRecovery bool

	// fack is the highest selectively or cumulatively acknowledged
	// sequence.
	fack seqnum.Value

	// minRTT is the estimated minimum RTT of the connection.
	minRTT time.Duration

	// reorderSeen indicates if reordering has been detected on this
	// connection.
	reorderSeen bool

	// reoWnd is the reordering window time used for recording packet
	// transmission times. It is used to defer the moment at which RACK
	// marks a packet lost.
	reoWnd time.Duration

	// reoWndIncr is the multiplier applied to adjust reorder window.
	reoWndIncr uint8

	// reoWndPersist is the number of loss recoveries before resetting
	// reorder window.
	reoWndPersist int8

	// rtt is the RTT of the most recently delivered packet on the
	// connection (either cumulatively acknowledged or selectively
	// acknowledged) that was not marked invalid as a possible spurious
	// retransmission.
	rtt time.Duration

	// rttSeq is the SND.NXT when rtt is updated.
	rttSeq seqnum.Value

	// xmitTime is the latest transmission timestamp of the most recent
	// acknowledged segment.
	xmitTime time.Time `state:".(unixTime)"`

	// tlpRxtOut indicates whether there is an unacknowledged
	// TLP retransmission.
	tlpRxtOut bool

	// tlpHighRxt the value of sender.sndNxt at the time of sending
	// a TLP retransmission.
	tlpHighRxt seqnum.Value

	// snd is a reference to the sender.
	snd *sender
}

// init initializes RACK specific fields.
func (rc *rackControl) init(snd *sender, iss seqnum.Value) {
	rc.fack = iss
	rc.reoWndIncr = 1
	rc.snd = snd
}

// update will update the RACK related fields when an ACK has been received.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-09#section-6.2
func (rc *rackControl) update(seg *segment, ackSeg *segment) {
	rtt := time.Now().Sub(seg.xmitTime)
	tsOffset := rc.snd.ep.tsOffset

	// If the ACK is for a retransmitted packet, do not update if it is a
	// spurious inference which is determined by below checks:
	// 1. When Timestamping option is available, if the TSVal is less than
	// the transmit time of the most recent retransmitted packet.
	// 2. When RTT calculated for the packet is less than the smoothed RTT
	// for the connection.
	// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.2
	// step 2
	if seg.xmitCount > 1 {
		if ackSeg.parsedOptions.TS && ackSeg.parsedOptions.TSEcr != 0 {
			if ackSeg.parsedOptions.TSEcr < tcpTimeStamp(seg.xmitTime, tsOffset) {
				return
			}
		}
		if rtt < rc.minRTT {
			return
		}
	}

	rc.rtt = rtt

	// The sender can either track a simple global minimum of all RTT
	// measurements from the connection, or a windowed min-filtered value
	// of recent RTT measurements. This implementation keeps track of the
	// simple global minimum of all RTTs for the connection.
	if rtt < rc.minRTT || rc.minRTT == 0 {
		rc.minRTT = rtt
	}

	// Update rc.xmitTime and rc.endSequence to the transmit time and
	// ending sequence number of the packet which has been acknowledged
	// most recently.
	endSeq := seg.sequenceNumber.Add(seqnum.Size(seg.data.Size()))
	if rc.xmitTime.Before(seg.xmitTime) || (seg.xmitTime.Equal(rc.xmitTime) && rc.endSequence.LessThan(endSeq)) {
		rc.xmitTime = seg.xmitTime
		rc.endSequence = endSeq
	}
}

// detectReorder detects if packet reordering has been observed.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.2
// * Step 3: Detect data segment reordering.
//   To detect reordering, the sender looks for original data segments being
//   delivered out of order. To detect such cases, the sender tracks the
//   highest sequence selectively or cumulatively acknowledged in the RACK.fack
//   variable. The name "fack" stands for the most "Forward ACK" (this term is
//   adopted from [FACK]). If a never retransmitted segment that's below
//   RACK.fack is (selectively or cumulatively) acknowledged, it has been
//   delivered out of order. The sender sets RACK.reord to TRUE if such segment
//   is identified.
func (rc *rackControl) detectReorder(seg *segment) {
	endSeq := seg.sequenceNumber.Add(seqnum.Size(seg.data.Size()))
	if rc.fack.LessThan(endSeq) {
		rc.fack = endSeq
		return
	}

	if endSeq.LessThan(rc.fack) && seg.xmitCount == 1 {
		rc.reorderSeen = true
	}
}

func (rc *rackControl) setDSACKSeen(dsackSeen bool) {
	rc.dsackSeen = dsackSeen
}

// shouldSchedulePTO dictates whether we should schedule a PTO or not.
// See https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.5.1.
func (s *sender) shouldSchedulePTO() bool {
	// Schedule PTO only if RACK loss detection is enabled.
	return s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 &&
		// The connection supports SACK.
		s.ep.sackPermitted &&
		// The connection is not in loss recovery.
		(s.state != tcpip.RTORecovery && s.state != tcpip.SACKRecovery) &&
		// The connection has no SACKed sequences in the SACK scoreboard.
		s.ep.scoreboard.Sacked() == 0
}

// schedulePTO schedules the probe timeout as defined in
// https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.5.1.
func (s *sender) schedulePTO() {
	pto := time.Second
	s.rtt.Lock()
	if s.rtt.srttInited && s.rtt.srtt > 0 {
		pto = s.rtt.srtt * 2
		if s.outstanding == 1 {
			pto += wcDelayedACKTimeout
		}
	}
	s.rtt.Unlock()

	now := time.Now()
	if s.resendTimer.enabled() {
		if now.Add(pto).After(s.resendTimer.target) {
			pto = s.resendTimer.target.Sub(now)
		}
		s.resendTimer.disable()
	}

	s.probeTimer.enable(pto)
}

// probeTimerExpired is the same as TLP_send_probe() as defined in
// https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.5.2.
func (s *sender) probeTimerExpired() tcpip.Error {
	if !s.probeTimer.checkExpiration() {
		return nil
	}

	var dataSent bool
	if s.writeNext != nil && s.writeNext.xmitCount == 0 && s.outstanding < s.sndCwnd {
		dataSent = s.maybeSendSegment(s.writeNext, int(s.ep.scoreboard.SMSS()), s.sndUna.Add(s.sndWnd))
		if dataSent {
			s.outstanding += s.pCount(s.writeNext, s.maxPayloadSize)
			s.writeNext = s.writeNext.Next()
		}
	}

	if !dataSent && !s.rc.tlpRxtOut {
		var highestSeqXmit *segment
		for highestSeqXmit = s.writeList.Front(); highestSeqXmit != nil; highestSeqXmit = highestSeqXmit.Next() {
			if highestSeqXmit.xmitCount == 0 {
				// Nothing in writeList is transmitted, no need to send a probe.
				highestSeqXmit = nil
				break
			}
			if highestSeqXmit.Next() == nil || highestSeqXmit.Next().xmitCount == 0 {
				// Either everything in writeList has been transmitted or the next
				// sequence has not been transmitted. Either way this is the highest
				// sequence segment that was transmitted.
				break
			}
		}

		if highestSeqXmit != nil {
			dataSent = s.maybeSendSegment(highestSeqXmit, int(s.ep.scoreboard.SMSS()), s.sndUna.Add(s.sndWnd))
			if dataSent {
				s.rc.tlpRxtOut = true
				s.rc.tlpHighRxt = s.sndNxt
			}
		}
	}

	// Whether or not the probe was sent, the sender must arm the resend timer,
	// not the probe timer. This ensures that the sender does not send repeated,
	// back-to-back tail loss probes.
	s.postXmit(dataSent, false /* shouldScheduleProbe */)
	return nil
}

// detectTLPRecovery detects if recovery was accomplished by the loss probes
// and updates TLP state accordingly.
// See https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.6.3.
func (s *sender) detectTLPRecovery(ack seqnum.Value, rcvdSeg *segment) {
	if !(s.ep.sackPermitted && s.rc.tlpRxtOut) {
		return
	}

	// Step 1.
	if s.isDupAck(rcvdSeg) && ack == s.rc.tlpHighRxt {
		var sbAboveTLPHighRxt bool
		for _, sb := range rcvdSeg.parsedOptions.SACKBlocks {
			if s.rc.tlpHighRxt.LessThan(sb.End) {
				sbAboveTLPHighRxt = true
				break
			}
		}
		if !sbAboveTLPHighRxt {
			// TLP episode is complete.
			s.rc.tlpRxtOut = false
		}
	}

	if s.rc.tlpRxtOut && s.rc.tlpHighRxt.LessThanEq(ack) {
		// TLP episode is complete.
		s.rc.tlpRxtOut = false
		if !checkDSACK(rcvdSeg) {
			// Step 2. Either the original packet or the retransmission (in the
			// form of a probe) was lost. Invoke a congestion control response
			// equivalent to fast recovery.
			s.cc.HandleLossDetected()
			s.enterRecovery()
			s.leaveRecovery()
		}
	}
}

// updateRACKReorderWindow updates the reorder window.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.2
// * Step 4: Update RACK reordering window
//   To handle the prevalent small degree of reordering, RACK.reo_wnd serves as
//   an allowance for settling time before marking a packet lost. RACK starts
//   initially with a conservative window of min_RTT/4. If no reordering has
//   been observed RACK uses reo_wnd of zero during loss recovery, in order to
//   retransmit quickly, or when the number of DUPACKs exceeds the classic
//   DUPACKthreshold.
func (rc *rackControl) updateRACKReorderWindow(ackSeg *segment) {
	dsackSeen := rc.dsackSeen
	snd := rc.snd

	// React to DSACK once per round trip.
	// If SND.UNA < RACK.rtt_seq:
	//   RACK.dsack = false
	if snd.sndUna.LessThan(rc.rttSeq) {
		dsackSeen = false
	}

	// If RACK.dsack:
	//   RACK.reo_wnd_incr += 1
	//   RACK.dsack = false
	//   RACK.rtt_seq = SND.NXT
	//   RACK.reo_wnd_persist = 16
	if dsackSeen {
		rc.reoWndIncr++
		dsackSeen = false
		rc.rttSeq = snd.sndNxt
		rc.reoWndPersist = tcpRACKRecoveryThreshold
	} else if rc.exitedRecovery {
		// Else if exiting loss recovery:
		//   RACK.reo_wnd_persist -= 1
		//   If RACK.reo_wnd_persist <= 0:
		//      RACK.reo_wnd_incr = 1
		rc.reoWndPersist--
		if rc.reoWndPersist <= 0 {
			rc.reoWndIncr = 1
		}
		rc.exitedRecovery = false
	}

	// Reorder window is zero during loss recovery, or when the number of
	// DUPACKs exceeds the classic DUPACKthreshold.
	// If RACK.reord is FALSE:
	//   If in loss recovery:  (If in fast or timeout recovery)
	//      RACK.reo_wnd = 0
	//      Return
	//   Else if RACK.pkts_sacked >= RACK.dupthresh:
	//     RACK.reo_wnd = 0
	//     return
	if !rc.reorderSeen {
		if snd.state == tcpip.RTORecovery || snd.state == tcpip.SACKRecovery {
			rc.reoWnd = 0
			return
		}

		if snd.sackedOut >= nDupAckThreshold {
			rc.reoWnd = 0
			return
		}
	}

	// Calculate reorder window.
	// RACK.reo_wnd = RACK.min_RTT / 4 * RACK.reo_wnd_incr
	// RACK.reo_wnd = min(RACK.reo_wnd, SRTT)
	snd.rtt.Lock()
	srtt := snd.rtt.srtt
	snd.rtt.Unlock()
	rc.reoWnd = time.Duration((int64(rc.minRTT) / 4) * int64(rc.reoWndIncr))
	if srtt < rc.reoWnd {
		rc.reoWnd = srtt
	}
}

func (rc *rackControl) exitRecovery() {
	rc.exitedRecovery = true
}

// detectLoss marks the segment as lost if the reordering window has elapsed
// and the ACK is not received. It will also arm the reorder timer.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.2 Step 5.
func (rc *rackControl) detectLoss(rcvTime time.Time) int {
	var timeout time.Duration
	numLost := 0
	for seg := rc.snd.writeList.Front(); seg != nil && seg.xmitCount != 0; seg = seg.Next() {
		if rc.snd.ep.scoreboard.IsSACKED(seg.sackBlock()) {
			continue
		}

		if seg.lost && seg.xmitCount == 1 {
			numLost++
			continue
		}

		endSeq := seg.sequenceNumber.Add(seqnum.Size(seg.data.Size()))
		if seg.xmitTime.Before(rc.xmitTime) || (seg.xmitTime.Equal(rc.xmitTime) && rc.endSequence.LessThan(endSeq)) {
			timeRemaining := seg.xmitTime.Sub(rcvTime) + rc.rtt + rc.reoWnd
			if timeRemaining <= 0 {
				seg.lost = true
				numLost++
			} else if timeRemaining > timeout {
				timeout = timeRemaining
			}
		}
	}

	if timeout != 0 && !rc.snd.reorderTimer.enabled() {
		rc.snd.reorderTimer.enable(timeout)
	}
	return numLost
}

// reorderTimerExpired will retransmit the segments which have not been acked
// before the reorder timer expired.
func (rc *rackControl) reorderTimerExpired() tcpip.Error {
	// Check if the timer actually expired or if it's a spurious wake due
	// to a previously orphaned runtime timer.
	if !rc.snd.reorderTimer.checkExpiration() {
		return nil
	}

	numLost := rc.detectLoss(time.Now())
	if numLost == 0 {
		return nil
	}

	fastRetransmit := false
	if !rc.snd.fr.active {
		rc.snd.cc.HandleLossDetected()
		rc.snd.enterRecovery()
		fastRetransmit = true
	}

	rc.DoRecovery(nil, fastRetransmit)
	return nil
}

// DoRecovery implements lossRecovery.DoRecovery.
func (rc *rackControl) DoRecovery(_ *segment, fastRetransmit bool) {
	snd := rc.snd
	if fastRetransmit {
		snd.resendSegment()
	}

	var dataSent bool
	// Iterate the writeList and retransmit the segments which are marked
	// as lost by RACK.
	for seg := snd.writeList.Front(); seg != nil && seg.xmitCount > 0; seg = seg.Next() {
		if seg == snd.writeNext {
			break
		}

		if !seg.lost {
			continue
		}

		// Reset seg.lost as it is already SACKed.
		if snd.ep.scoreboard.IsSACKED(seg.sackBlock()) {
			seg.lost = false
			continue
		}

		// Check the congestion window after entering recovery.
		if snd.outstanding >= snd.sndCwnd {
			break
		}

		if sent := snd.maybeSendSegment(seg, int(snd.ep.scoreboard.SMSS()), snd.sndUna.Add(snd.sndWnd)); !sent {
			break
		}
		dataSent = true
		snd.outstanding += snd.pCount(seg, snd.maxPayloadSize)
	}

	snd.postXmit(dataSent, true /* shouldScheduleProbe */)
}
