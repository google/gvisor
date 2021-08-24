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

package tcp_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	maxPayload       = 10
	tsOptionSize     = 12
	maxTCPOptionSize = 40
	mtu              = header.TCPMinimumSize + header.IPv4MinimumSize + maxTCPOptionSize + maxPayload
)

func setStackTCPRecovery(t *testing.T, c *context.Context, recovery int) {
	t.Helper()
	opt := tcpip.TCPRecovery(recovery)
	if err := c.Stack().SetTransportProtocolOption(header.TCPProtocolNumber, &opt); err != nil {
		t.Fatalf("c.s.SetTransportProtocolOption(%d, &%v(%v)): %s", header.TCPProtocolNumber, opt, opt, err)
	}
}

// TestRACKUpdate tests the RACK related fields are updated when an ACK is
// received on a SACK enabled connection.
func TestRACKUpdate(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	var xmitTime tcpip.MonotonicTime
	probeDone := make(chan struct{})
	c.Stack().AddTCPProbe(func(state stack.TCPEndpointState) {
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
	})
	setStackSACKPermitted(t, c, true)
	createConnectedWithSACKAndTS(c)

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
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
	bytesRead += maxPayload
	c.SendAck(seqnum.Value(context.TestInitialSequenceNumber).Add(1), bytesRead)

	// Wait for the probe function to finish processing the ACK before the
	// test completes.
	<-probeDone
}

// TestRACKDetectReorder tests that RACK detects packet reordering.
func TestRACKDetectReorder(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	t.Skipf("Skipping this test as reorder detection does not consider DSACK.")

	var n int
	const ackNumToVerify = 2
	probeDone := make(chan struct{})
	c.Stack().AddTCPProbe(func(state stack.TCPEndpointState) {
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
	})
	setStackSACKPermitted(t, c, true)
	createConnectedWithSACKAndTS(c)
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
		c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
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

func sendAndReceiveWithSACK(t *testing.T, c *context.Context, numPackets int, enableRACK bool) []byte {
	setStackSACKPermitted(t, c, true)
	if !enableRACK {
		setStackTCPRecovery(t, c, 0)
	}
	// The delay should be below initial RTO (1s) otherwise retransimission
	// will start. Choose a relatively large value so that estimated RTT
	// keeps high even after a few rounds of undelayed RTT samples.
	c.CreateConnectedWithOptions(header.TCPSynOptions{SACKPermitted: c.SACKEnabled(), TS: true}, 800*time.Millisecond /* delay */)

	data := make([]byte, numPackets*maxPayload)
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
	for i := 0; i < numPackets; i++ {
		c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
		bytesRead += maxPayload
	}

	return data
}

const (
	validDSACKDetected   = 1
	failedToDetectDSACK  = 2
	invalidDSACKDetected = 3
)

func addDSACKSeenCheckerProbe(t *testing.T, c *context.Context, numACK int, probeDone chan int) {
	var n int
	c.Stack().AddTCPProbe(func(state stack.TCPEndpointState) {
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
	})
}

// TestRACKTLPRecovery tests that RACK sends a tail loss probe (TLP) in the
// case of a tail loss. This simulates a situation where the TLP is able to
// insinuate the SACK holes and sender is able to retransmit the rest.
func TestRACKTLPRecovery(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	// Send 8 packets.
	numPackets := 8
	data := sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

	// Packets [6-8] are lost. Send cumulative ACK for [1-5].
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	c.SendAck(seq, bytesRead)

	// PTO should fire and send #8 packet as a TLP.
	c.ReceiveAndCheckPacketWithOptions(data, 7*maxPayload, maxPayload, tsOptionSize)
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
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
	bytesRead += maxPayload
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
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
	data := sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

	// Packets [6-8] are lost. Send cumulative ACK for [1-5].
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	c.SendAck(seq, bytesRead)

	// PTO should fire and send #8 packet as a TLP.
	c.ReceiveAndCheckPacketWithOptions(data, 7*maxPayload, maxPayload, tsOptionSize)

	// Either the TLP or the ACK the receiver sent with SACK blocks was lost.

	// Confirm that RTO fires and retransmits packet #6.
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)

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
	data := sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

	// Packets [1-5] are received first. [6-8] took a detour and will take a
	// while to arrive. Ack [1-5].
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	c.SendAck(seq, bytesRead)

	// The tail loss probe (#8 packet) is received.
	c.ReceiveAndCheckPacketWithOptions(data, 7*maxPayload, maxPayload, tsOptionSize)

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
	if p := c.GetPacketWithTimeout(info.RTO); p != nil {
		t.Errorf("received an unexpected packet: %v", p)
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
	data := sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

	// Packets [1-5] and #7 were received. #6 and #8 were dropped.
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	seventhStart := c.IRS.Add(1 + seqnum.Size(6*maxPayload))
	seventhEnd := seventhStart.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{seventhStart, seventhEnd}})

	// The sender should retransmit #6. If the sender sends a TLP, then #8 will
	// received and fail this test.
	c.ReceiveAndCheckPacketWithOptions(data, 5*maxPayload, maxPayload, tsOptionSize)

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
	data := sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

	// Packets [1-2] are received. #3 is lost.
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 2 * maxPayload
	c.SendAck(seq, bytesRead)

	// PTO should fire and send #3 packet as a TLP.
	c.ReceiveAndCheckPacketWithOptions(data, 2*maxPayload, maxPayload, tsOptionSize)
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
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	probeDone := make(chan int)
	const ackNumToVerify = 2
	addDSACKSeenCheckerProbe(t, c, ackNumToVerify, probeDone)

	numPackets := 8
	data := sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

	// Cumulative ACK for [1-5] packets and SACK #8 packet (to prevent TLP).
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	eighthPStart := c.IRS.Add(1 + seqnum.Size(7*maxPayload))
	eighthPEnd := eighthPStart.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{eighthPStart, eighthPEnd}})

	// Expect retransmission of #6 packet after RTO expires.
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)

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
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	probeDone := make(chan int)
	const ackNumToVerify = 2
	addDSACKSeenCheckerProbe(t, c, ackNumToVerify, probeDone)

	numPackets := 10
	data := sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

	// Cumulative ACK for [1-5] packets and SACK for #7 packet (to prevent TLP).
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	seventhPStart := c.IRS.Add(1 + seqnum.Size(6*maxPayload))
	seventhPEnd := seventhPStart.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{seventhPStart, seventhPEnd}})

	// Expect retransmission of #6 packet.
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)

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
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	probeDone := make(chan int)
	const ackNumToVerify = 4
	addDSACKSeenCheckerProbe(t, c, ackNumToVerify, probeDone)

	numPackets := 10
	sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

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
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	probeDone := make(chan int)
	const ackNumToVerify = 4
	addDSACKSeenCheckerProbe(t, c, ackNumToVerify, probeDone)

	numPackets := 4
	data := sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

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
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)

	// ACK for retransmitted #2 packet.
	bytesRead += maxPayload
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}})

	// Simulate receving delayed subsegment of #2 packet and delayed #3 packet by
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
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	probeDone := make(chan int)
	const ackNumToVerify = 5
	addDSACKSeenCheckerProbe(t, c, ackNumToVerify, probeDone)

	numPackets := 6
	data := sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

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
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)

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
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	probeDone := make(chan int)
	const ackNumToVerify = 5
	addDSACKSeenCheckerProbe(t, c, ackNumToVerify, probeDone)

	numPackets := 7
	data := sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

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
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)

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
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	probeDone := make(chan struct{})
	const ackNumToVerify = 2
	var n int
	c.Stack().AddTCPProbe(func(state stack.TCPEndpointState) {
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
	})

	numPackets := 10
	data := sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

	// Cumulative ACK for [1-5] packets and SACK for #7 packet (to prevent TLP).
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	bytesRead := 5 * maxPayload
	seventhPStart := c.IRS.Add(1 + seqnum.Size(6*maxPayload))
	seventhPEnd := seventhPStart.Add(maxPayload)
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{seventhPStart, seventhPEnd}})

	// Expect retransmission of #6 packet.
	c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)

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

func addReorderWindowCheckerProbe(c *context.Context, numACK int, probeDone chan error) {
	var n int
	c.Stack().AddTCPProbe(func(state stack.TCPEndpointState) {
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
	})
}

func TestRACKCheckReorderWindow(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	probeDone := make(chan error)
	const ackNumToVerify = 3
	addReorderWindowCheckerProbe(c, ackNumToVerify, probeDone)

	const numPackets = 7
	sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

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
	data := sendAndReceiveWithSACK(t, c, numPackets, true /* enableRACK */)

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
	c.ReceiveAndCheckPacketWithOptions(data, 0, maxPayload, tsOptionSize)

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

// TestRACKUpdateSackedOut tests the sacked out field is updated when a SACK
// is received.
func TestRACKUpdateSackedOut(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	probeDone := make(chan struct{})
	ackNum := 0
	c.Stack().AddTCPProbe(func(state stack.TCPEndpointState) {
		// Validate that the endpoint Sender.SackedOut is what we expect.
		if state.Sender.SackedOut != 2 && ackNum == 0 {
			t.Fatalf("SackedOut got updated to wrong value got: %v want: 2", state.Sender.SackedOut)
		}

		if state.Sender.SackedOut != 0 && ackNum == 1 {
			t.Fatalf("SackedOut got updated to wrong value got: %v want: 0", state.Sender.SackedOut)
		}
		if ackNum > 0 {
			close(probeDone)
		}
		ackNum++
	})

	sendAndReceiveWithSACK(t, c, 8, true /* enableRACK */)

	// ACK for [3-5] packets.
	seq := seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	start := c.IRS.Add(seqnum.Size(1 + 3*maxPayload))
	bytesRead := 2 * maxPayload
	end := start.Add(seqnum.Size(bytesRead))
	c.SendAckWithSACK(seq, bytesRead, []header.SACKBlock{{start, end}})

	bytesRead += 3 * maxPayload
	c.SendAck(seq, bytesRead)

	// Wait for the probe function to finish processing the ACK before the
	// test completes.
	<-probeDone
}

// TestRACKWithWindowFull tests that RACK honors the receive window size.
func TestRACKWithWindowFull(t *testing.T) {
	c := context.New(t, uint32(mtu))
	defer c.Cleanup()

	setStackSACKPermitted(t, c, true)
	createConnectedWithSACKAndTS(c)

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
		c.ReceiveAndCheckPacketWithOptions(data, bytesRead, maxPayload, tsOptionSize)
		bytesRead += maxPayload
		if i == 0 {
			// Send ACK for the first packet to establish RTT.
			c.SendAck(seq, maxPayload)
		}
	}

	// SACK for #10 packet.
	start := c.IRS.Add(seqnum.Size(1 + (numPkts-1)*maxPayload))
	end := start.Add(seqnum.Size(maxPayload))
	c.SendAckWithSACK(seq, 2*maxPayload, []header.SACKBlock{{start, end}})

	var info tcpip.TCPInfoOption
	if err := c.EP.GetSockOpt(&info); err != nil {
		t.Fatalf("GetSockOpt failed: %v", err)
	}
	// Wait for RTT to trigger recovery.
	time.Sleep(info.RTT)

	// Expect retransmission of #2 packet.
	c.ReceiveAndCheckPacketWithOptions(data, 2*maxPayload, maxPayload, tsOptionSize)

	// Send ACK for #2 packet.
	c.SendAck(seq, 3*maxPayload)

	// Expect retransmission of #3 packet.
	c.ReceiveAndCheckPacketWithOptions(data, 3*maxPayload, maxPayload, tsOptionSize)

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
