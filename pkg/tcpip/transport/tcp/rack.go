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

	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// RACK is a loss detection algorithm used in TCP to detect packet loss and
// reordering using transmission timestamp of the packets instead of packet or
// sequence counts. To use RACK, SACK should be enabled on the connection.

// rackControl stores the rack related fields.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-09#section-5.2
//
// +stateify savable
type rackControl struct {
	// endSequence is the ending TCP sequence number of rackControl.seg.
	endSequence seqnum.Value

	// dsack indicates if the connection has seen a DSACK.
	dsack bool

	// fack is the highest selectively or cumulatively acknowledged
	// sequence.
	fack seqnum.Value

	// minRTT is the estimated minimum RTT of the connection.
	minRTT time.Duration

	// rtt is the RTT of the most recently delivered packet on the
	// connection (either cumulatively acknowledged or selectively
	// acknowledged) that was not marked invalid as a possible spurious
	// retransmission.
	rtt time.Duration

	// rttSeq is the SND.NXT when rtt is updated.
	rttSeq seqnum.Value

	// reord indicates if reordering has been detected on this connection.
	reord bool

	// reoWnd is the reordering window time used for recording packet
	// transmission times. It is used to defer the moment at which RACK
	// marks a packet lost.
	reoWnd time.Duration

	// reoWndIncr is the multiplier applied to adjust reorder window.
	reoWndIncr uint8

	// reoWndPersist is the number of loss recoveries before resetting
	// reorder window.
	reoWndPersist uint8

	// xmitTime is the latest transmission timestamp of rackControl.seg.
	xmitTime time.Time `state:".(unixTime)"`
}

const tcpRACKRecoveryThreshold = 16

// update will update the RACK related fields when an ACK has been received.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-09#section-6.2
func (rc *rackControl) update(seg *segment, ackSeg *segment, srtt time.Duration, offset uint32, sndNxt seqnum.Value) {
	rtt := time.Now().Sub(seg.xmitTime)

	// If the ACK is for a retransmitted packet, do not update if it is a
	// spurious inference which is determined by below checks:
	// 1. When Timestamping option is available, if the TSVal is less than the
	// transmit time of the most recent retransmitted packet.
	// 2. When RTT calculated for the packet is less than the smoothed RTT
	// for the connection.
	// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-09#section-6.2
	// step 2
	if seg.xmitCount > 1 {
		if ackSeg.parsedOptions.TS && ackSeg.parsedOptions.TSEcr != 0 {
			if ackSeg.parsedOptions.TSEcr < tcpTimeStamp(seg.xmitTime, offset) {
				return
			}
		}
		if rtt < rc.minRTT {
			return
		}
	}

	rc.rtt = rtt
	rc.rttSeq = sndNxt

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
// step 3
func (rc *rackControl) detectReorder(seg *segment) {
	endSeq := seg.sequenceNumber.Add(seqnum.Size(seg.data.Size()))
	if rc.fack.LessThan(endSeq) {
		rc.fack = endSeq
		return
	}

	if endSeq.LessThan(rc.fack) && seg.xmitCount == 1 {
		rc.reord = true
	}
}

// dsackSeen updates rack control if duplicate SACK is seen by the connection.
func (rc *rackControl) dsackSeen() {
	rc.dsack = true
}

// updateRACKReorderWindow updates the reorder window.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.2
// step 4
func (rc *rackControl) updateRACKReorderWindow(ackSeg *segment, sndUna seqnum.Value, sndNxt seqnum.Value, recoveryActive bool, srtt time.Duration) {
	if sndUna.LessThan(rc.rttSeq) {
		rc.dsack = false
	}

	if rc.dsack {
		rc.reoWndIncr++
		rc.dsack = false
		rc.rttSeq = sndNxt
		rc.reoWndPersist = tcpRACKRecoveryThreshold
	} else if recoveryActive {
		rc.reoWndPersist--
		if rc.reoWndPersist <= 0 {
			rc.reoWndIncr = 1
		}
	}

	// TODO: This checks only if the connection is in fast recovery, check
	// for timeout recovery and number of duplicate ACKs as well.
	if !rc.reord && recoveryActive {
		rc.reoWnd = 0
		return
	}

	t := int64(rc.minRTT/time.Microsecond) / 4
	t = t * int64(rc.reoWndIncr)
	rc.reoWnd = time.Duration(t) * time.Microsecond
	if srtt < rc.reoWnd {
		rc.reoWnd = srtt
	}
}
