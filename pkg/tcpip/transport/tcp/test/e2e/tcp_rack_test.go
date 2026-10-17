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

package tcp_rack_test

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	maxPayload       = 10
	maxTCPOptionSize = 40
	mtu              = header.TCPMinimumSize + header.IPv4MinimumSize + maxTCPOptionSize + maxPayload
)

// TestRACKUpdate tests the RACK related fields are updated when an ACK is
// received on a SACK enabled connection.
func TestRACKUpdate(t *testing.T) {
	var xmitTime tcpip.MonotonicTime
	probeDone := make(chan struct{})
	probe := func(state *tcp.TCPEndpointState) {
		// Validate that the endpoint Sender.RACKState is what we expect.
		if state.Sender.RACKState.XmitTime.Before(xmitTime) {
			t.Fatalf("RACK transmit time failed to update when an ACK is received")
		}

		gotSeq := state.Sender.RACKState.EndSequence
		wantSeq := state.Sender.SndNxt
		if !gotSeq.LessThanEq(wantSeq) || gotSeq.LessThan(wantSeq) {
			t.Fatalf("RACK sequence number failed to update, got: %v, but want: %v", gotSeq, wantSeq)
		}

		if state.Sender.RACKState.RTT == 0 {
			t.Fatalf("RACK RTT failed to update when an ACK is received, got RACKState.RTT == 0 want != 0")
		}
		close(probeDone)
	}

	c := context.NewWithProbe(t, uint32(mtu), probe)
	defer c.Cleanup()

	e2e.SetStackSACKPermitted(t, c, true)
	e2e.CreateConnectedWithSACKAndTS(c)

	data := make([]byte, maxPayload)
	for i := range data {
		data[i] = byte(i)
	}

	// Write the data.
	xmitTime = c.Stack().Clock().NowMonotonic()
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	bytesRead := 0
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, e2e.TSOptionSize)
	bytesRead += maxPayload
	c.SendAck(seqnum.Value(context.TestInitialSequenceNumber).Add(1), bytesRead)

	// Wait for the probe function to finish processing the ACK before the
	// test completes.
	<-probeDone
}

// TestRACKDetectReorder tests that RACK detects packet reordering.
func TestRACKDetectReorder(t *testing.T) {
	t.Skipf("Skipping this test as reorder detection does not consider DSACK.")

	var n int
	const ackNumToVerify = 2
	probeDone := make(chan struct{})
	probe := func(state *tcp.TCPEndpointState) {
		gotSeq := state.Sender.RACKState.FACK
		wantSeq := state.Sender.SndNxt
		// FACK should be updated to the highest ending sequence number of the
		// segment acknowledged most recently.
		if !gotSeq.LessThanEq(wantSeq) || gotSeq.LessThan(wantSeq) {
			t.Fatalf("RACK FACK failed to update, got: %v, but want: %v", gotSeq, wantSeq)
		}

		n++
		if n < ackNumToVerify {
			if state.Sender.RACKState.Reord {
				t.Fatalf("RACK reorder detected when there is no reordering")
			}
			return
		}

		if state.Sender.RACKState.Reord == false {
			t.Fatalf("RACK reorder detection failed")
		}
		close(probeDone)
	}

	c := context.NewWithProbe(t, uint32(mtu), probe)
	defer c.Cleanup()

	e2e.SetStackSACKPermitted(t, c, true)
	e2e.CreateConnectedWithSACKAndTS(c)
	data := make([]byte, ackNumToVerify*maxPayload)
	for i := range data {
		data[i] = byte(i)
	}

	// Write the data.
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	bytesRead := 0
	for i := 0; i < ackNumToVerify; i++ {
		c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, e2e.TSOptionSize)
		bytesRead += maxPayload
	}

	start := c.IRS.Add(maxPayload + 1)
	end := start.Add(maxPayload)
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendAckWithSACK(seq, 0, []header.SACKBlock{{start, end}})
	c.SendAck(seq, bytesRead)

	// Wait for the probe function to finish processing the ACK before the
	// test completes.
	<-probeDone
}

const (
	validDSACKDetected   = 1
	failedToDetectDSACK  = 2
	invalidDSACKDetected = 3
)

func dsackSeenCheckerProbe(t *testing.T, numACK int, probeDone chan int) tcp.TCPProbeFunc {
	var n int
	return func(state *tcp.TCPEndpointState) {
		// Validate that RACK detects DSACK.
		n++
		if n < numACK {
			if state.Sender.RACKState.DSACKSeen {
				probeDone <- invalidDSACKDetected
			}
			return
		}

		if !state.Sender.RACKState.DSACKSeen {
			probeDone <- failedToDetectDSACK
			return
		}
		probeDone <- validDSACKDetected
	}
}

// TestRACKTLPRecovery tests that RACK sends a tail loss probe (TLP) in the
// case of a tail loss. This simulates a situation where the TLP is able to
// insinuate the SACK holes and sender is able to retransmit the rest.
func TestRACKTLPRecovery(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	// Send 8 packets.
	numPackets := 8
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Packets [6-8] are lost. Send cumulative ACK for [1-5].
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	c.SendAck(seq, bytesRead)

	// PTO should fire and send #8 packet as a TLP.
	c.ReceiveAndCheckPacketWithOptions(data, 7*maxPayload, maxPayload, e2e.TSOptionSize)
	var info tcpip.TCPInfoOption
	if err := c.EP.GetSockOpt(&info); err != nil {
		t.Fatalf("GetSockOpt failed: %v", err)
	}

	// Send the SACK after RTT because RACK RFC states that if the ACK for a
	// retransmission arrives before the smoothed RTT then the sender should not
	// update RACK state as it could be a spurious inference.
	time.Sleep(info.RTT)

	// Okay, let the sender know we got #8 using a SACK block.
	eighthPStart := c.IRS.Add(1 + seqnum.Size(7*maxPayload))
	eighthPEnd := eighthPStart.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{eighthPStart, eighthPEnd}})

	// The sender should be entering RACK based loss-recovery and sending #6 and
	// #7 one after another.
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, e2e.TSOptionSize)
	bytesRead += maxPayload
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, e2e.TSOptionSize)
	bytesRead += 2 * maxPayload
	c.SendAck(seq, bytesRead)

	metricPollFn := func() error {
		tcpStats := c.Stack().Stats().TCP
		stats := []struct {
			stat *tcpip.StatCounter
			name string
			want uint64
		}{
			// One fast retransmit after the SACK.
			{tcpStats.FastRetransmit, "stats.TCP.FastRetransmit", 1},
			// Recovery should be SACK recovery.
			{tcpStats.SACKRecovery, "stats.TCP.SACKRecovery", 1},
			// Packets 6, 7 and 8 were retransmitted.
			{tcpStats.Retransmits, "stats.TCP.Retransmits", 3},
			// TLP recovery should have been detected.
			{tcpStats.TLPRecovery, "stats.TCP.TLPRecovery", 1},
			// No RTOs should have occurred.
			{tcpStats.Timeouts, "stats.TCP.Timeouts", 0},
		}
		for _, s := range stats {
			if got, want := s.stat.Value(), s.want; got != want {
				return fmt.Errorf("got %s.Value() = %d, want = %d", s.name, got, want)
			}
		}
		return nil
	}
	if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
		t.Error(err)
	}
}

// TestRACKTLPFallbackRTO tests that RACK sends a tail loss probe (TLP) in the
// case of a tail loss. This simulates a situation where either the TLP or its
// ACK is lost. The sender should retransmit when RTO fires.
func TestRACKTLPFallbackRTO(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	// Send 8 packets.
	numPackets := 8
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Packets [6-8] are lost. Send cumulative ACK for [1-5].
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	c.SendAck(seq, bytesRead)

	// PTO should fire and send #8 packet as a TLP.
	c.ReceiveAndCheckPacketWithOptions(data, 7*maxPayload, maxPayload, e2e.TSOptionSize)

	// Either the TLP or the ACK the receiver sent with SACK blocks was lost.

	// Confirm that RTO fires and retransmits packet #6.
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, e2e.TSOptionSize)

	metricPollFn := func() error {
		tcpStats := c.Stack().Stats().TCP
		stats := []struct {
			stat *tcpip.StatCounter
			name string
			want uint64
		}{
			// No fast retransmits happened.
			{tcpStats.FastRetransmit, "stats.TCP.FastRetransmit", 0},
			// No SACK recovery happened.
			{tcpStats.SACKRecovery, "stats.TCP.SACKRecovery", 0},
			// TLP was unsuccessful.
			{tcpStats.TLPRecovery, "stats.TCP.TLPRecovery", 0},
			// RTO should have fired.
			{tcpStats.Timeouts, "stats.TCP.Timeouts", 1},
		}
		for _, s := range stats {
			if got, want := s.stat.Value(), s.want; got != want {
				return fmt.Errorf("got %s.Value() = %d, want = %d", s.name, got, want)
			}
		}
		return nil
	}
	if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
		t.Error(err)
	}
}

// TestNoTLPRecoveryOnDSACK tests the scenario where the sender speculates a
// tail loss and sends a TLP. Everything is received and acked. The probe
// segment is DSACKed. No fast recovery should be triggered in this case.
func TestNoTLPRecoveryOnDSACK(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	// Send 8 packets.
	numPackets := 8
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Packets [1-5] are received first. [6-8] took a detour and will take a
	// while to arrive. Ack [1-5].
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	c.SendAck(seq, bytesRead)

	// The tail loss probe (#8 packet) is received.
	c.ReceiveAndCheckPacketWithOptions(data, 7*maxPayload, maxPayload, e2e.TSOptionSize)

	// Now that all 8 packets are received + duplicate 8th packet, send ack.
	bytesRead += 3 * maxPayload
	eighthPStart := c.IRS.Add(1 + seqnum.Size(7*maxPayload))
	eighthPEnd := eighthPStart.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{eighthPStart, eighthPEnd}})

	// Wait for RTO and make sure that nothing else is received.
	var info tcpip.TCPInfoOption
	if err := c.EP.GetSockOpt(&info); err != nil {
		t.Fatalf("GetSockOpt failed: %v", err)
	}
	var p *buffer.View
	if p = c.GetPacketWithTimeout(info.RTO); p != nil {
		t.Errorf("received an unexpected packet: %v", p)
		p.Release()
	}

	metricPollFn := func() error {
		tcpStats := c.Stack().Stats().TCP
		stats := []struct {
			stat *tcpip.StatCounter
			name string
			want uint64
		}{
			// Make sure no recovery was entered.
			{tcpStats.FastRetransmit, "stats.TCP.FastRetransmit", 0},
			{tcpStats.SACKRecovery, "stats.TCP.SACKRecovery", 0},
			{tcpStats.TLPRecovery, "stats.TCP.TLPRecovery", 0},
			// RTO should not have fired.
			{tcpStats.Timeouts, "stats.TCP.Timeouts", 0},
			// Only #8 was retransmitted.
			{tcpStats.Retransmits, "stats.TCP.Retransmits", 1},
		}
		for _, s := range stats {
			if got, want := s.stat.Value(), s.want; got != want {
				return fmt.Errorf("got %s.Value() = %d, want = %d", s.name, got, want)
			}
		}
		return nil
	}
	if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
		t.Error(err)
	}
}

// TestNoTLPOnSACK tests the scenario where there is not exactly a tail loss
// due to the presence of multiple SACK holes. In such a scenario, TLP should
// not be sent.
func TestNoTLPOnSACK(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	// Send 8 packets.
	numPackets := 8
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Packets [1-5] and #7 were received. #6 and #8 were dropped.
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	seventhStart := c.IRS.Add(1 + seqnum.Size(6*maxPayload))
	seventhEnd := seventhStart.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{seventhStart, seventhEnd}})

	// The sender should retransmit #6. If the sender sends a TLP, then #8 will
	// received and fail this test.
	c.ReceiveAndCheckPacketWithOptions(data, 5*maxPayload, maxPayload, e2e.TSOptionSize)

	metricPollFn := func() error {
		tcpStats := c.Stack().Stats().TCP
		stats := []struct {
			stat *tcpip.StatCounter
			name string
			want uint64
		}{
			// #6 was retransmitted due to SACK recovery.
			{tcpStats.FastRetransmit, "stats.TCP.FastRetransmit", 1},
			{tcpStats.SACKRecovery, "stats.TCP.SACKRecovery", 1},
			{tcpStats.TLPRecovery, "stats.TCP.TLPRecovery", 0},
			// RTO should not have fired.
			{tcpStats.Timeouts, "stats.TCP.Timeouts", 0},
			// Only #6 was retransmitted.
			{tcpStats.Retransmits, "stats.TCP.Retransmits", 1},
		}
		for _, s := range stats {
			if got, want := s.stat.Value(), s.want; got != want {
				return fmt.Errorf("got %s.Value() = %d, want = %d", s.name, got, want)
			}
		}
		return nil
	}
	if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
		t.Error(err)
	}
}

// TestRACKOnePacketTailLoss tests the trivial case of a tail loss of only one
// packet. The probe should itself repairs the loss instead of having to go
// into any recovery.
func TestRACKOnePacketTailLoss(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	// Send 3 packets.
	numPackets := 3
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Packets [1-2] are received. #3 is lost.
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 2 * maxPayload
	c.SendAck(seq, bytesRead)

	// PTO should fire and send #3 packet as a TLP.
	c.ReceiveAndCheckPacketWithOptions(data, 2*maxPayload, maxPayload, e2e.TSOptionSize)
	bytesRead += maxPayload
	c.SendAck(seq, bytesRead)

	metricPollFn := func() error {
		tcpStats := c.Stack().Stats().TCP
		stats := []struct {
			stat *tcpip.StatCounter
			name string
			want uint64
		}{
			// #3 was retransmitted as TLP.
			{tcpStats.FastRetransmit, "stats.TCP.FastRetransmit", 0},
			{tcpStats.SACKRecovery, "stats.TCP.SACKRecovery", 1},
			{tcpStats.TLPRecovery, "stats.TCP.TLPRecovery", 0},
			// RTO should not have fired.
			{tcpStats.Timeouts, "stats.TCP.Timeouts", 0},
			// Only #3 was retransmitted.
			{tcpStats.Retransmits, "stats.TCP.Retransmits", 1},
		}
		for _, s := range stats {
			if got, want := s.stat.Value(), s.want; got != want {
				return fmt.Errorf("got %s.Value() = %d, want = %d", s.name, got, want)
			}
		}
		return nil
	}
	if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
		t.Error(err)
	}
}

// TestRACKDetectDSACK tests that RACK detects DSACK with duplicate segments.
// See: https://tools.ietf.org/html/rfc2883#section-4.1.1.
func TestRACKDetectDSACK(t *testing.T) {
	probeDone := make(chan int)
	const ackNumToVerify = 2
	probe := dsackSeenCheckerProbe(t, ackNumToVerify, probeDone)

	c := context.NewWithProbe(t, uint32(mtu), probe)
	defer c.Cleanup()

	numPackets := 8
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Cumulative ACK for [1-5] packets and SACK #8 packet (to prevent TLP).
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	eighthPStart := c.IRS.Add(1 + seqnum.Size(7*maxPayload))
	eighthPEnd := eighthPStart.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{eighthPStart, eighthPEnd}})

	// Expect retransmission of #6 packet after RTO expires.
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, e2e.TSOptionSize)

	// Send DSACK block for #6 packet indicating both
	// initial and retransmitted packet are received and
	// packets [1-8] are received.
	start := c.IRS.Add(1 + seqnum.Size(bytesRead))
	end := start.Add(maxPayload)
	bytesRead += 3 * maxPayload
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}})

	// Wait for the probe function to finish processing the
	// ACK before the test completes.
	err := <-probeDone
	switch err {
	case failedToDetectDSACK:
		t.Fatalf("RACK DSACK detection failed")
	case invalidDSACKDetected:
		t.Fatalf("RACK DSACK detected when there is no duplicate SACK")
	}

	metricPollFn := func() error {
		tcpStats := c.Stack().Stats().TCP
		stats := []struct {
			stat *tcpip.StatCounter
			name string
			want uint64
		}{
			// Check DSACK was received for one segment.
			{tcpStats.SegmentsAckedWithDSACK, "stats.TCP.SegmentsAckedWithDSACK", 1},
		}
		for _, s := range stats {
			if got, want := s.stat.Value(), s.want; got != want {
				return fmt.Errorf("got %s.Value() = %d, want = %d", s.name, got, want)
			}
		}
		return nil
	}

	if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
		t.Error(err)
	}
}

// TestRACKDetectDSACKWithOutOfOrder tests that RACK detects DSACK with out of
// order segments.
// See: https://tools.ietf.org/html/rfc2883#section-4.1.2.
func TestRACKDetectDSACKWithOutOfOrder(t *testing.T) {
	probeDone := make(chan int)
	const ackNumToVerify = 2
	probe := dsackSeenCheckerProbe(t, ackNumToVerify, probeDone)

	c := context.NewWithProbe(t, uint32(mtu), probe)
	defer c.Cleanup()

	numPackets := 10
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Cumulative ACK for [1-5] packets and SACK for #7 packet (to prevent TLP).
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	seventhPStart := c.IRS.Add(1 + seqnum.Size(6*maxPayload))
	seventhPEnd := seventhPStart.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{seventhPStart, seventhPEnd}})

	// Expect retransmission of #6 packet.
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, e2e.TSOptionSize)

	// Send DSACK block for #6 packet indicating both
	// initial and retransmitted packet are received and
	// packets [1-7] are received.
	start := c.IRS.Add(1 + seqnum.Size(bytesRead))
	end := start.Add(maxPayload)
	bytesRead += 2 * maxPayload
	// Send DSACK block for #6 along with SACK for out of
	// order #9 packet.
	start1 := c.IRS.Add(1 + seqnum.Size(bytesRead) + maxPayload)
	end1 := start1.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}, {start1, end1}})

	// Wait for the probe function to finish processing the
	// ACK before the test completes.
	err := <-probeDone
	switch err {
	case failedToDetectDSACK:
		t.Fatalf("RACK DSACK detection failed")
	case invalidDSACKDetected:
		t.Fatalf("RACK DSACK detected when there is no duplicate SACK")
	}
}

// TestRACKDetectDSACKWithOutOfOrderDup tests that DSACK is detected on a
// duplicate of out of order packet.
// See: https://tools.ietf.org/html/rfc2883#section-4.1.3
func TestRACKDetectDSACKWithOutOfOrderDup(t *testing.T) {
	probeDone := make(chan int)
	const ackNumToVerify = 4
	probe := dsackSeenCheckerProbe(t, ackNumToVerify, probeDone)

	c := context.NewWithProbe(t, uint32(mtu), probe)
	defer c.Cleanup()

	numPackets := 10
	e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// ACK [1-5] packets.
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	c.SendAck(seq, bytesRead)

	// Send SACK indicating #6 packet is missing and received #7 packet.
	offset := seqnum.Size(bytesRead + maxPayload)
	start := c.IRS.Add(1 + offset)
	end := start.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}})

	// Send SACK with #6 packet is missing and received [7-8] packets.
	end = start.Add(2 * maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}})

	// Consider #8 packet is duplicated on the network and send DSACK.
	dsackStart := c.IRS.Add(1 + offset + maxPayload)
	dsackEnd := dsackStart.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{dsackStart, dsackEnd}, {start, end}})

	// Wait for the probe function to finish processing the ACK before the
	// test completes.
	err := <-probeDone
	switch err {
	case failedToDetectDSACK:
		t.Fatalf("RACK DSACK detection failed")
	case invalidDSACKDetected:
		t.Fatalf("RACK DSACK detected when there is no duplicate SACK")
	}
}

// TestRACKDetectDSACKSingleDup tests DSACK for a single duplicate subsegment.
// See: https://tools.ietf.org/html/rfc2883#section-4.2.1.
func TestRACKDetectDSACKSingleDup(t *testing.T) {
	probeDone := make(chan int)
	const ackNumToVerify = 4
	probe := dsackSeenCheckerProbe(t, ackNumToVerify, probeDone)

	c := context.NewWithProbe(t, uint32(mtu), probe)
	defer c.Cleanup()

	numPackets := 4
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Send ACK for #1 packet.
	bytesRead := maxPayload
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendAck(seq, bytesRead)

	// Missing [2-3] packets and received #4 packet.
	seq = seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	start := c.IRS.Add(1 + seqnum.Size(3*maxPayload))
	end := start.Add(seqnum.Size(maxPayload))
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}})

	// Expect retransmission of #2 packet.
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, e2e.TSOptionSize)

	// ACK for retransmitted #2 packet.
	bytesRead += maxPayload
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}})

	// Simulate receiving delayed subsegment of #2 packet and delayed #3 packet by
	// sending DSACK block for the subsegment.
	dsackStart := c.IRS.Add(1 + seqnum.Size(bytesRead))
	dsackEnd := dsackStart.Add(seqnum.Size(maxPayload / 2))
	c.SendAckWithSACK(seq, numPackets*maxPayload, []header.SACKBlock{{dsackStart, dsackEnd}})

	// Wait for the probe function to finish processing the ACK before the
	// test completes.
	err := <-probeDone
	switch err {
	case failedToDetectDSACK:
		t.Fatalf("RACK DSACK detection failed")
	case invalidDSACKDetected:
		t.Fatalf("RACK DSACK detected when there is no duplicate SACK")
	}

	metricPollFn := func() error {
		tcpStats := c.Stack().Stats().TCP
		stats := []struct {
			stat *tcpip.StatCounter
			name string
			want uint64
		}{
			// Check DSACK was received for a subsegment.
			{tcpStats.SegmentsAckedWithDSACK, "stats.TCP.SegmentsAckedWithDSACK", 1},
		}
		for _, s := range stats {
			if got, want := s.stat.Value(), s.want; got != want {
				return fmt.Errorf("got %s.Value() = %d, want = %d", s.name, got, want)
			}
		}
		return nil
	}

	if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
		t.Error(err)
	}
}

// TestRACKDetectDSACKDupWithCumulativeACK tests DSACK for two non-contiguous
// duplicate subsegments covered by the cumulative acknowledgement.
// See: https://tools.ietf.org/html/rfc2883#section-4.2.2.
func TestRACKDetectDSACKDupWithCumulativeACK(t *testing.T) {
	probeDone := make(chan int)
	const ackNumToVerify = 5
	probe := dsackSeenCheckerProbe(t, ackNumToVerify, probeDone)

	c := context.NewWithProbe(t, uint32(mtu), probe)
	defer c.Cleanup()

	numPackets := 6
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Send ACK for #1 packet.
	bytesRead := maxPayload
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendAck(seq, bytesRead)

	// Missing [2-5] packets and received #6 packet.
	seq = seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	start := c.IRS.Add(1 + seqnum.Size(5*maxPayload))
	end := start.Add(seqnum.Size(maxPayload))
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}})

	// Expect retransmission of #2 packet.
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, e2e.TSOptionSize)

	// Received delayed #2 packet.
	bytesRead += maxPayload
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}})

	// Received delayed #4 packet.
	start1 := c.IRS.Add(1 + seqnum.Size(3*maxPayload))
	end1 := start1.Add(seqnum.Size(maxPayload))
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start1, end1}, {start, end}})

	// Simulate receiving retransmitted subsegment for #2 packet and delayed #3
	// packet by sending DSACK block for #2 packet.
	dsackStart := c.IRS.Add(1 + seqnum.Size(maxPayload))
	dsackEnd := dsackStart.Add(seqnum.Size(maxPayload / 2))
	c.SendAckWithSACK(seq, 4*maxPayload, []header.SACKBlock{{dsackStart, dsackEnd}, {start, end}})

	// Wait for the probe function to finish processing the ACK before the
	// test completes.
	err := <-probeDone
	switch err {
	case failedToDetectDSACK:
		t.Fatalf("RACK DSACK detection failed")
	case invalidDSACKDetected:
		t.Fatalf("RACK DSACK detected when there is no duplicate SACK")
	}
}

// TestRACKDetectDSACKDup tests two non-contiguous duplicate subsegments not
// covered by the cumulative acknowledgement.
// See: https://tools.ietf.org/html/rfc2883#section-4.2.3.
func TestRACKDetectDSACKDup(t *testing.T) {
	probeDone := make(chan int)
	const ackNumToVerify = 5
	probe := dsackSeenCheckerProbe(t, ackNumToVerify, probeDone)

	c := context.NewWithProbe(t, uint32(mtu), probe)
	defer c.Cleanup()

	numPackets := 7
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Send ACK for #1 packet.
	bytesRead := maxPayload
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendAck(seq, bytesRead)

	// Missing [2-6] packets and SACK #7 packet.
	seq = seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	start := c.IRS.Add(1 + seqnum.Size(6*maxPayload))
	end := start.Add(seqnum.Size(maxPayload))
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}})

	// Received delayed #3 packet.
	start1 := c.IRS.Add(1 + seqnum.Size(2*maxPayload))
	end1 := start1.Add(seqnum.Size(maxPayload))
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start1, end1}, {start, end}})

	// Expect retransmission of #2 packet.
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, e2e.TSOptionSize)

	// Consider #2 packet has been dropped and SACK #4 packet.
	start2 := c.IRS.Add(1 + seqnum.Size(3*maxPayload))
	end2 := start2.Add(seqnum.Size(maxPayload))
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start2, end2}, {start1, end1}, {start, end}})

	// Simulate receiving retransmitted subsegment for #3 packet and delayed #5
	// packet by sending DSACK block for the subsegment.
	dsackStart := c.IRS.Add(1 + seqnum.Size(2*maxPayload))
	dsackEnd := dsackStart.Add(seqnum.Size(maxPayload / 2))
	end1 = end1.Add(seqnum.Size(2 * maxPayload))
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{dsackStart, dsackEnd}, {start1, end1}})

	// Wait for the probe function to finish processing the ACK before the
	// test completes.
	err := <-probeDone
	switch err {
	case failedToDetectDSACK:
		t.Fatalf("RACK DSACK detection failed")
	case invalidDSACKDetected:
		t.Fatalf("RACK DSACK detected when there is no duplicate SACK")
	}
}

// TestRACKWithInvalidDSACKBlock tests that DSACK is not detected when DSACK
// is not the first SACK block.
func TestRACKWithInvalidDSACKBlock(t *testing.T) {
	probeDone := make(chan struct{})
	const ackNumToVerify = 2
	var n int
	probe := func(state *tcp.TCPEndpointState) {
		// Validate that RACK does not detect DSACK when DSACK block is
		// not the first SACK block.
		n++
		t.Helper()
		if state.Sender.RACKState.DSACKSeen {
			t.Fatalf("RACK DSACK detected when there is no duplicate SACK")
		}

		if n == ackNumToVerify {
			close(probeDone)
		}
	}

	c := context.NewWithProbe(t, uint32(mtu), probe)
	defer c.Cleanup()

	numPackets := 10
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Cumulative ACK for [1-5] packets and SACK for #7 packet (to prevent TLP).
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	seventhPStart := c.IRS.Add(1 + seqnum.Size(6*maxPayload))
	seventhPEnd := seventhPStart.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{seventhPStart, seventhPEnd}})

	// Expect retransmission of #6 packet.
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, e2e.TSOptionSize)

	// Send DSACK block for #6 packet indicating both
	// initial and retransmitted packet are received and
	// packets [1-7] are received.
	start := c.IRS.Add(1 + seqnum.Size(bytesRead))
	end := start.Add(maxPayload)
	bytesRead += 2 * maxPayload

	// Send DSACK block as second block. The first block is a SACK for #9 packet.
	start1 := c.IRS.Add(1 + seqnum.Size(bytesRead) + maxPayload)
	end1 := start1.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start1, end1}, {start, end}})

	// Wait for the probe function to finish processing the
	// ACK before the test completes.
	<-probeDone
}

func reorderWindowCheckerProbe(numACK int, probeDone chan error) tcp.TCPProbeFunc {
	var n int
	return func(state *tcp.TCPEndpointState) {
		// Validate that RACK detects DSACK.
		n++
		if n < numACK {
			return
		}

		if state.Sender.RACKState.ReoWnd == 0 || state.Sender.RACKState.ReoWnd > state.Sender.RTTState.SRTT {
			probeDone <- fmt.Errorf("got RACKState.ReoWnd: %d, expected it to be greater than 0 and less than %d", state.Sender.RACKState.ReoWnd, state.Sender.RTTState.SRTT)
			return
		}

		if state.Sender.RACKState.ReoWndIncr != 1 {
			probeDone <- fmt.Errorf("got RACKState.ReoWndIncr: %v, want: 1", state.Sender.RACKState.ReoWndIncr)
			return
		}

		if state.Sender.RACKState.ReoWndPersist > 0 {
			probeDone <- fmt.Errorf("got RACKState.ReoWndPersist: %v, want: greater than 0", state.Sender.RACKState.ReoWndPersist)
			return
		}
		probeDone <- nil
	}
}

func TestRACKCheckReorderWindow(t *testing.T) {
	probeDone := make(chan error)
	const ackNumToVerify = 3
	probe := reorderWindowCheckerProbe(ackNumToVerify, probeDone)

	c := context.NewWithProbe(t, uint32(mtu), probe)
	defer c.Cleanup()

	const numPackets = 7
	e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Send ACK for #1 packet.
	bytesRead := maxPayload
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	c.SendAck(seq, bytesRead)

	// Missing [2-6] packets and SACK #7 packet.
	start := c.IRS.Add(1 + seqnum.Size(6*maxPayload))
	end := start.Add(seqnum.Size(maxPayload))
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}})

	// Received delayed packets [2-6] which indicates there is reordering
	// in the connection.
	bytesRead += 6 * maxPayload
	c.SendAck(seq, bytesRead)

	// Wait for the probe function to finish processing the ACK before the
	// test completes.
	if err := <-probeDone; err != nil {
		t.Fatalf("unexpected values for RACK variables: %v", err)
	}
}

func TestRACKWithDuplicateACK(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	const numPackets = 4
	data := e2e.SendAndReceiveWithSACK(t, c, maxPayload, numPackets, true /* enableRACK */)

	// Send three duplicate ACKs to trigger fast recovery. The first
	// segment is considered as lost and will be retransmitted after
	// receiving the duplicate ACKs.
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	start := c.IRS.Add(1 + seqnum.Size(maxPayload))
	end := start.Add(seqnum.Size(maxPayload))
	for i := 0; i < 3; i++ {
		c.SendAckWithSACK(seq, 0, []header.SACKBlock{{start, end}})
		end = end.Add(seqnum.Size(maxPayload))
	}

	// Receive the retransmitted packet.
	c.ReceiveAndCheckPacketWithOptions(data, 0, maxPayload, e2e.TSOptionSize)

	metricPollFn := func() error {
		tcpStats := c.Stack().Stats().TCP
		stats := []struct {
			stat *tcpip.StatCounter
			name string
			want uint64
		}{
			{tcpStats.FastRetransmit, "stats.TCP.FastRetransmit", 1},
			{tcpStats.SACKRecovery, "stats.TCP.SACKRecovery", 1},
			{tcpStats.FastRecovery, "stats.TCP.FastRecovery", 0},
		}
		for _, s := range stats {
			if got, want := s.stat.Value(), s.want; got != want {
				return fmt.Errorf("got %s.Value() = %d, want = %d", s.name, got, want)
			}
		}
		return nil
	}

	if err := testutil.Poll(metricPollFn, 1*time.Second); err != nil {
		t.Error(err)
	}
}

// TestRACKUpdateSackedOut checks selective ACK credit across cumulative ACKs,
// recovery, retransmission timeout, and GSO queue fragmentation.
func TestRACKUpdateSackedOut(t *testing.T) {
	data := make([]byte, 5*maxPayload)
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	newContext := func(t *testing.T, recovery tcpip.TCPRecovery, gso stack.SupportedGSO) (*context.Context, *faketime.ManualClock, func() *tcp.TCPEndpointState) {
		t.Helper()
		clock := faketime.NewManualClock()
		// Keep transmission times distinct from unset RACK timestamps.
		clock.Advance(time.Second)
		states := make(chan *tcp.TCPEndpointState, 16)
		c := context.NewWithOpts(t, context.Options{
			EnableV4: true,
			MTU:      uint32(mtu),
			Clock:    clock,
			GSO:      gso,
			Probe:    func(state *tcp.TCPEndpointState) { states <- state },
		})
		t.Cleanup(c.Cleanup)
		e2e.SetStackSACKPermitted(t, c, true)
		e2e.SetStackTCPRecovery(t, c, int(recovery))
		e2e.CreateConnectedWithSACKAndTS(c)
		n, err := c.EP.Write(bytes.NewReader(data), tcpip.WriteOptions{})
		if err != nil {
			t.Fatalf("Write: %s", err)
		}
		if got, want := n, int64(len(data)); got != want {
			t.Fatalf("Write = %d, want %d", got, want)
		}
		for offset := 0; offset < len(data); offset += maxPayload {
			c.ReceiveAndCheckPacketWithOptions(data, offset, maxPayload, e2e.TSOptionSize)
		}
		snapshot := func() *tcp.TCPEndpointState {
			c.Stack().Pause()
			c.Stack().Resume()
			return <-states
		}
		// Acknowledge packet 1 before reporting the gap at packet 2. This
		// advances past the initial recovery boundary and supplies an RTT.
		clock.Advance(100 * time.Millisecond)
		c.SendAck(seq, maxPayload)
		if got, want := snapshot().Sender.SackedOut, 0; got != want {
			t.Fatalf("SackedOut after first ACK = %d, want %d", got, want)
		}
		return c, clock, snapshot
	}
	checkCredit := func(t *testing.T, phase string, state *tcp.TCPEndpointState, expected int) {
		t.Helper()
		if got, want := state.Sender.SackedOut, expected; got != want {
			t.Errorf("SackedOut after %s = %d, want %d", phase, got, want)
		}
	}
	// Packet checkers stop on any prior test failure. Each scenario finishes
	// its packet reads before comparing the captured states.
	t.Run("two_sacks", func(t *testing.T) {
		c, _, snapshot := newContext(t, tcpip.TCPRACKLossDetection, stack.GSONotSupported)
		start := c.IRS.Add(1 + 2*maxPayload)
		c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{{Start: start, End: start.Add(maxPayload)}})
		one := snapshot()
		c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{{Start: start, End: start.Add(2 * maxPayload)}})
		two := snapshot()
		c.SendAck(seq, 3*maxPayload)
		partial := snapshot()
		c.SendAck(seq, len(data))
		complete := snapshot()

		checkCredit(t, "first SACK", one, 1)
		checkCredit(t, "second SACK", two, 2)
		checkCredit(t, "partial cumulative ACK", partial, 1)
		checkCredit(t, "full cumulative ACK", complete, 0)
		if got, want := two.Sender.FastRecovery.Active, false; got != want {
			t.Errorf("FastRecovery.Active after two SACKs = %t, want %t", got, want)
		}
		if got, want := partial.Sender.Outstanding, 2; got != want {
			t.Errorf("Outstanding after partial cumulative ACK = %d, want %d", got, want)
		}
	})
	t.Run("without_rack", func(t *testing.T) {
		c, _, snapshot := newContext(t, 0, stack.GSONotSupported)
		start := c.IRS.Add(1 + 2*maxPayload)
		c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{{Start: start, End: start.Add(maxPayload)}})
		one := snapshot()
		// Three full packets beyond the gap exceed the RFC 6675 byte
		// threshold, without needing a third duplicate ACK.
		c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{{Start: start, End: start.Add(3 * maxPayload)}})
		recovered := snapshot()
		c.ReceiveAndCheckPacketWithOptions(data, maxPayload, maxPayload, e2e.TSOptionSize)
		c.SendAck(seq, len(data))
		complete := snapshot()

		checkCredit(t, "first SACK without RACK", one, 1)
		checkCredit(t, "recovery without RACK", recovered, 3)
		checkCredit(t, "full cumulative ACK", complete, 0)
		if got, want := one.Sender.FastRecovery.Active, false; got != want {
			t.Errorf("FastRecovery.Active after first SACK = %t, want %t", got, want)
		}
		if got, want := recovered.Sender.FastRecovery.Active, true; got != want {
			t.Errorf("FastRecovery.Active after three packets are SACKed = %t, want %t", got, want)
		}
	})
	t.Run("recovery", func(t *testing.T) {
		c, _, snapshot := newContext(t, tcpip.TCPRACKLossDetection, stack.GSONotSupported)
		start := c.IRS.Add(1 + 2*maxPayload)
		var recovered *tcp.TCPEndpointState
		for count := 1; count <= 3; count++ {
			c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{{Start: start, End: start.Add(seqnum.Size(count * maxPayload))}})
			recovered = snapshot()
		}
		c.ReceiveAndCheckPacketWithOptions(data, maxPayload, maxPayload, e2e.TSOptionSize)
		c.SendAck(seq, len(data))
		complete := snapshot()

		checkCredit(t, "recovery entry", recovered, 3)
		checkCredit(t, "full cumulative ACK", complete, 0)
		if got, want := recovered.Sender.FastRecovery.Active, true; got != want {
			t.Errorf("FastRecovery.Active after three SACKs = %t, want %t", got, want)
		}
		if got, want := complete.Sender.FastRecovery.Active, false; got != want {
			t.Errorf("FastRecovery.Active after full ACK = %t, want %t", got, want)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		c, clock, snapshot := newContext(t, tcpip.TCPRACKLossDetection, stack.GSONotSupported)
		start := c.IRS.Add(1 + 2*maxPayload)
		var recovered *tcp.TCPEndpointState
		for count := 1; count <= 3; count++ {
			c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{{Start: start, End: start.Add(seqnum.Size(count * maxPayload))}})
			recovered = snapshot()
		}
		c.ReceiveAndCheckPacketWithOptions(data, maxPayload, maxPayload, e2e.TSOptionSize)
		var info tcpip.TCPInfoOption
		if err := c.EP.GetSockOpt(&info); err != nil {
			t.Fatalf("GetSockOpt(TCPInfoOption): %s", err)
		}
		clock.Advance(info.RTO)
		c.ReceiveAndCheckPacketWithOptions(data, maxPayload, maxPayload, e2e.TSOptionSize)
		c.SendAck(seq, maxPayload)
		timedOut := snapshot()
		c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{{Start: start, End: start.Add(3 * maxPayload)}})
		resacked := snapshot()
		c.SendAck(seq, len(data))
		complete := snapshot()

		checkCredit(t, "recovery entry", recovered, 3)
		checkCredit(t, "RTO", timedOut, 0)
		checkCredit(t, "SACK after RTO", resacked, 3)
		checkCredit(t, "full cumulative ACK", complete, 0)
		// The duplicate ACK used to observe the reset can start another
		// recovery. The timeout event and retransmission establish the RTO.
		if got, want := c.Stack().Stats().TCP.Timeouts.Value(), uint64(1); got != want {
			t.Errorf("RTO events = %d, want %d", got, want)
		}
	})
	t.Run("disjoint_sacks", func(t *testing.T) {
		c, _, snapshot := newContext(t, tcpip.TCPRACKLossDetection, stack.GSONotSupported)
		third, fifth := c.IRS.Add(1+2*maxPayload), c.IRS.Add(1+4*maxPayload)
		// The highest/newest block comes first; both ranges need credit.
		c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{
			{Start: fifth, End: fifth.Add(maxPayload)},
			{Start: third, End: third.Add(maxPayload)},
		})
		sacked := snapshot()
		c.SendAck(seq, 3*maxPayload)
		partial := snapshot()
		c.SendAck(seq, len(data))
		complete := snapshot()

		checkCredit(t, "disjoint SACKs", sacked, 2)
		checkCredit(t, "partial cumulative ACK", partial, 1)
		checkCredit(t, "full cumulative ACK", complete, 0)
		if got, want := partial.Sender.Outstanding, 2; got != want {
			t.Errorf("Outstanding after partial cumulative ACK = %d, want %d", got, want)
		}
	})
	t.Run("overlapping_sacks_across_acks", func(t *testing.T) {
		c, _, snapshot := newContext(t, tcpip.TCPRACKLossDetection, stack.GVisorGSOSupported)
		start := c.IRS.Add(1 + 2*maxPayload)
		// Each ACK reports only part of packet 3. Together they cover the
		// whole packet, so the retained merged range earns one credit.
		c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{{Start: start, End: start.Add(6)}})
		first := snapshot()
		c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{{Start: start.Add(4), End: start.Add(maxPayload)}})
		merged := snapshot()
		c.SendAck(seq, len(data))
		complete := snapshot()

		checkCredit(t, "partial packet SACK", first, 0)
		checkCredit(t, "merged partial SACKs", merged, 1)
		checkCredit(t, "full cumulative ACK", complete, 0)
	})
	t.Run("overlapping_sacks_one_ack", func(t *testing.T) {
		c, _, snapshot := newContext(t, tcpip.TCPRACKLossDetection, stack.GVisorGSOSupported)
		start := c.IRS.Add(1 + 2*maxPayload)
		c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{
			{Start: start, End: start.Add(6)},
			{Start: start.Add(4), End: start.Add(maxPayload)},
		})
		merged := snapshot()
		c.SendAck(seq, len(data))
		complete := snapshot()

		checkCredit(t, "merged SACKs in one ACK", merged, 1)
		checkCredit(t, "full cumulative ACK", complete, 0)
	})
	t.Run("overlapping_sacks_with_cumulative_ack", func(t *testing.T) {
		c, _, snapshot := newContext(t, tcpip.TCPRACKLossDetection, stack.GVisorGSOSupported)
		start := c.IRS.Add(1 + 2*maxPayload)
		c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{{Start: start, End: start.Add(6)}})
		first := snapshot()
		// Merge the rest of packet 3 while cumulatively acknowledging its
		// first half. The remaining half keeps one current-MSS credit.
		c.SendAckWithSACK(seq, 2*maxPayload+5, []header.SACKBlock{{Start: start.Add(6), End: start.Add(maxPayload)}})
		trimmed := snapshot()
		c.SendAck(seq, len(data))
		complete := snapshot()

		checkCredit(t, "partial packet SACK", first, 0)
		checkCredit(t, "merged range after simultaneous cumulative ACK", trimmed, 1)
		checkCredit(t, "full cumulative ACK", complete, 0)
	})
	t.Run("gso_partial_ack", func(t *testing.T) {
		c, _, snapshot := newContext(t, tcpip.TCPRACKLossDetection, stack.GVisorGSOSupported)
		start := c.IRS.Add(1 + 2*maxPayload)
		// Software GSO sends ordinary packets from an aggregate write-list
		// entry. One SACK covers two packets within it. The cumulative
		// ACK then cuts the credited entry in half.
		c.SendAckWithSACK(seq, maxPayload, []header.SACKBlock{{Start: start, End: start.Add(2 * maxPayload)}})
		sacked := snapshot()
		c.SendAck(seq, 3*maxPayload)
		partial := snapshot()
		c.SendAck(seq, len(data))
		complete := snapshot()

		checkCredit(t, "GSO SACK", sacked, 2)
		checkCredit(t, "partial GSO cumulative ACK", partial, 1)
		checkCredit(t, "full cumulative ACK", complete, 0)
		if got, want := partial.Sender.Outstanding, 2; got != want {
			t.Errorf("Outstanding after partial GSO cumulative ACK = %d, want %d", got, want)
		}
	})
}

// TestRACKWithWindowFull tests that RACK honors the receive window size.
func TestRACKWithWindowFull(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	e2e.SetStackSACKPermitted(t, c, true)
	e2e.CreateConnectedWithSACKAndTS(c)

	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	const numPkts = 10
	data := make([]byte, numPkts*maxPayload)
	for i := range data {
		data[i] = byte(i)
	}

	// Write the data.
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}

	bytesRead := 0
	for i := 0; i < numPkts; i++ {
		c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, e2e.TSOptionSize)
		bytesRead += maxPayload
	}

	// Expect retransmission of last packet due to TLP.
	c.ReceiveAndCheckPacketWithOptions(data, (numPkts-1)*maxPayload, maxPayload, e2e.TSOptionSize)

	// SACK for first and last packet.
	start := c.IRS.Add(seqnum.Size(maxPayload))
	end := start.Add(seqnum.Size(maxPayload))
	dsackStart := c.IRS.Add(seqnum.Size(1 + (numPkts-1)*maxPayload))
	dsackEnd := dsackStart.Add(seqnum.Size(maxPayload))
	c.SendAckWithSACK(seq, 2*maxPayload, []header.SACKBlock{{dsackStart, dsackEnd}, {start, end}})

	var info tcpip.TCPInfoOption
	if err := c.EP.GetSockOpt(&info); err != nil {
		t.Fatalf("GetSockOpt failed: %v", err)
	}
	// Wait for RTT to trigger recovery.
	time.Sleep(info.RTT)

	// Expect retransmission of #2 packet.
	c.ReceiveAndCheckPacketWithOptions(data, 2*maxPayload, maxPayload, e2e.TSOptionSize)

	// Send ACK for #2 packet.
	c.SendAck(seq, 3*maxPayload)

	// Expect retransmission of #3 packet.
	c.ReceiveAndCheckPacketWithOptions(data, 3*maxPayload, maxPayload, e2e.TSOptionSize)

	// Send ACK with zero window size.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  seq,
		AckNum:  c.IRS.Add(1 + 4*maxPayload),
		RcvWnd:  0,
	})

	// No packet should be received as the receive window size is zero.
	c.CheckNoPacket("unexpected packet received after userTimeout has expired")
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	// Allow TCP async work to complete to avoid false reports of leaks.
	// TODO(gvisor.dev/issue/5940): Use fake clock in tests.
	time.Sleep(1 * time.Second)
	refs.DoLeakCheck()
	os.Exit(code)
}
