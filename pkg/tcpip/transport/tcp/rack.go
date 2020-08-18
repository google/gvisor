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
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-6.1
//
// +stateify savable
type rackControl struct {
	// xmitTime is the latest transmission timestamp of rackControl.seg.
	xmitTime time.Time `state:".(unixTime)"`

	// endSequence is the ending TCP sequence number of rackControl.seg.
	endSequence seqnum.Value

	// fack is the highest selectively or cumulatively acknowledged
	// sequence.
	fack seqnum.Value

	// rtt is the RTT of the most recently delivered packet on the
	// connection (either cumulatively acknowledged or selectively
	// acknowledged) that was not marked invalid as a possible spurious
	// retransmission.
	rtt time.Duration
}

// Update will update the RACK related fields when an ACK has been received.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.2
func (rc *rackControl) Update(seg *segment, ackSeg *segment, srtt time.Duration, offset uint32) {
	rtt := time.Now().Sub(seg.xmitTime)

	// If the ACK is for a retransmitted packet, do not update if it is a
	// spurious inference which is determined by below checks:
	// 1. When Timestamping option is available, if the TSVal is less than the
	// transmit time of the most recent retransmitted packet.
	// 2. When RTT calculated for the packet is less than the smoothed RTT
	// for the connection.
	// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.2
	// step 2
	if seg.xmitCount > 1 {
		if ackSeg.parsedOptions.TS && ackSeg.parsedOptions.TSEcr != 0 {
			if ackSeg.parsedOptions.TSEcr < tcpTimeStamp(seg.xmitTime, offset) {
				return
			}
		}
		if rtt < srtt {
			return
		}
	}

	rc.rtt = rtt
	// Update rc.xmitTime and rc.endSequence to the transmit time and
	// ending sequence number of the packet which has been acknowledged
	// most recently.
	endSeq := seg.sequenceNumber.Add(seqnum.Size(seg.data.Size()))
	if rc.xmitTime.Before(seg.xmitTime) || (seg.xmitTime.Equal(rc.xmitTime) && rc.endSequence.LessThan(endSeq)) {
		rc.xmitTime = seg.xmitTime
		rc.endSequence = endSeq
	}
}
