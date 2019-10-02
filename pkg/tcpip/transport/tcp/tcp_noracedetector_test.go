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
//
// These tests are flaky when run under the go race detector due to some
// iterations taking long enough that the retransmit timer can kick in causing
// the congestion window measurements to fail due to extra packets etc.
//
// +build !race

package tcp_test

import (
	"fmt"
	"math"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
)

func TestFastRecovery(t *testing.T) {
	maxPayload := 32
	c := context.New(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.Cleanup()

	c.CreateConnected(789, 30000, -1 /* epRcvBuf */)

	const iterations = 7
	data := buffer.NewView(2 * maxPayload * (tcp.InitialCwnd << (iterations + 1)))
	for i := range data {
		data[i] = byte(i)
	}

	// Write all the data in one shot. Packets will only be written at the
	// MTU size though.
	if _, _, err := c.EP.Write(tcpip.SlicePayload(data), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Do slow start for a few iterations.
	expected := tcp.InitialCwnd
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		expected = tcp.InitialCwnd << uint(i)
		if i > 0 {
			// Acknowledge all the data received so far if not on
			// first iteration.
			c.SendAck(790, bytesRead)
		}

		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.ReceiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.CheckNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)
	}

	// Send 3 duplicate acks. This should force an immediate retransmit of
	// the pending packet and put the sender into fast recovery.
	rtxOffset := bytesRead - maxPayload*expected
	for i := 0; i < 3; i++ {
		c.SendAck(790, rtxOffset)
	}

	// Receive the retransmitted packet.
	c.ReceiveAndCheckPacket(data, rtxOffset, maxPayload)

	if got, want := c.Stack().Stats().TCP.FastRetransmit.Value(), uint64(1); got != want {
		t.Errorf("got stats.TCP.FastRetransmit.Value = %v, want = %v", got, want)
	}

	if got, want := c.Stack().Stats().TCP.Retransmits.Value(), uint64(1); got != want {
		t.Errorf("got stats.TCP.Retransmit.Value = %v, want = %v", got, want)
	}

	if got, want := c.Stack().Stats().TCP.FastRecovery.Value(), uint64(1); got != want {
		t.Errorf("got stats.TCP.FastRecovery.Value = %v, want = %v", got, want)
	}

	// Now send 7 mode duplicate acks. Each of these should cause a window
	// inflation by 1 and cause the sender to send an extra packet.
	for i := 0; i < 7; i++ {
		c.SendAck(790, rtxOffset)
	}

	recover := bytesRead

	// Ensure no new packets arrive.
	c.CheckNoPacketTimeout("More packets received than expected during recovery after dupacks for this cwnd.",
		50*time.Millisecond)

	// Acknowledge half of the pending data.
	rtxOffset = bytesRead - expected*maxPayload/2
	c.SendAck(790, rtxOffset)

	// Receive the retransmit due to partial ack.
	c.ReceiveAndCheckPacket(data, rtxOffset, maxPayload)

	if got, want := c.Stack().Stats().TCP.FastRetransmit.Value(), uint64(2); got != want {
		t.Errorf("got stats.TCP.FastRetransmit.Value = %v, want = %v", got, want)
	}

	if got, want := c.Stack().Stats().TCP.Retransmits.Value(), uint64(2); got != want {
		t.Errorf("got stats.TCP.Retransmit.Value = %v, want = %v", got, want)
	}

	// Receive the 10 extra packets that should have been released due to
	// the congestion window inflation in recovery.
	for i := 0; i < 10; i++ {
		c.ReceiveAndCheckPacket(data, bytesRead, maxPayload)
		bytesRead += maxPayload
	}

	// A partial ACK during recovery should reduce congestion window by the
	// number acked. Since we had "expected" packets outstanding before sending
	// partial ack and we acked expected/2 , the cwnd and outstanding should
	// be expected/2 + 10 (7 dupAcks + 3 for the original 3 dupacks that triggered
	// fast recovery). Which means the sender should not send any more packets
	// till we ack this one.
	c.CheckNoPacketTimeout("More packets received than expected during recovery after partial ack for this cwnd.",
		50*time.Millisecond)

	// Acknowledge all pending data to recover point.
	c.SendAck(790, recover)

	// At this point, the cwnd should reset to expected/2 and there are 10
	// packets outstanding.
	//
	// NOTE: Technically netstack is incorrect in that we adjust the cwnd on
	// the same segment that takes us out of recovery. But because of that
	// the actual cwnd at exit of recovery will be expected/2 + 1 as we
	// acked a cwnd worth of packets which will increase the cwnd further by
	// 1 in congestion avoidance.
	//
	// Now in the first iteration since there are 10 packets outstanding.
	// We would expect to get expected/2 +1 - 10 packets. But subsequent
	// iterations will send us expected/2 + 1 + 1 (per iteration).
	expected = expected/2 + 1 - 10
	for i := 0; i < iterations; i++ {
		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.ReceiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.CheckNoPacketTimeout(fmt.Sprintf("More packets received(after deflation) than expected %d for this cwnd.", expected), 50*time.Millisecond)

		// Acknowledge all the data received so far.
		c.SendAck(790, bytesRead)

		// In cogestion avoidance, the packets trains increase by 1 in
		// each iteration.
		if i == 0 {
			// After the first iteration we expect to get the full
			// congestion window worth of packets in every
			// iteration.
			expected += 10
		}
		expected++
	}
}

func TestExponentialIncreaseDuringSlowStart(t *testing.T) {
	maxPayload := 32
	c := context.New(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.Cleanup()

	c.CreateConnected(789, 30000, -1 /* epRcvBuf */)

	const iterations = 7
	data := buffer.NewView(maxPayload * (tcp.InitialCwnd << (iterations + 1)))
	for i := range data {
		data[i] = byte(i)
	}

	// Write all the data in one shot. Packets will only be written at the
	// MTU size though.
	if _, _, err := c.EP.Write(tcpip.SlicePayload(data), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	expected := tcp.InitialCwnd
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.ReceiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.CheckNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)

		// Acknowledge all the data received so far.
		c.SendAck(790, bytesRead)

		// Double the number of expected packets for the next iteration.
		expected *= 2
	}
}

func TestCongestionAvoidance(t *testing.T) {
	maxPayload := 32
	c := context.New(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.Cleanup()

	c.CreateConnected(789, 30000, -1 /* epRcvBuf */)

	const iterations = 7
	data := buffer.NewView(2 * maxPayload * (tcp.InitialCwnd << (iterations + 1)))
	for i := range data {
		data[i] = byte(i)
	}

	// Write all the data in one shot. Packets will only be written at the
	// MTU size though.
	if _, _, err := c.EP.Write(tcpip.SlicePayload(data), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Do slow start for a few iterations.
	expected := tcp.InitialCwnd
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		expected = tcp.InitialCwnd << uint(i)
		if i > 0 {
			// Acknowledge all the data received so far if not on
			// first iteration.
			c.SendAck(790, bytesRead)
		}

		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.ReceiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.CheckNoPacketTimeout("More packets received than expected for this cwnd (slow start phase).", 50*time.Millisecond)
	}

	// Don't acknowledge the first packet of the last packet train. Let's
	// wait for them to time out, which will trigger a restart of slow
	// start, and initialization of ssthresh to cwnd/2.
	rtxOffset := bytesRead - maxPayload*expected
	c.ReceiveAndCheckPacket(data, rtxOffset, maxPayload)

	// Acknowledge all the data received so far.
	c.SendAck(790, bytesRead)

	// This part is tricky: when the timeout happened, we had "expected"
	// packets pending, cwnd reset to 1, and ssthresh set to expected/2.
	// By acknowledging "expected" packets, the slow-start part will
	// increase cwnd to expected/2 (which "consumes" expected/2-1 of the
	// acknowledgements), then the congestion avoidance part will consume
	// an extra expected/2 acks to take cwnd to expected/2 + 1. One ack
	// remains in the "ack count" (which will cause cwnd to be incremented
	// once it reaches cwnd acks).
	//
	// So we're straight into congestion avoidance with cwnd set to
	// expected/2 + 1.
	//
	// Check that packets trains of cwnd packets are sent, and that cwnd is
	// incremented by 1 after we acknowledge each packet.
	expected = expected/2 + 1
	for i := 0; i < iterations; i++ {
		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.ReceiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.CheckNoPacketTimeout("More packets received than expected for this cwnd (congestion avoidance phase).", 50*time.Millisecond)

		// Acknowledge all the data received so far.
		c.SendAck(790, bytesRead)

		// In cogestion avoidance, the packets trains increase by 1 in
		// each iteration.
		expected++
	}
}

// cubicCwnd returns an estimate of a cubic window given the
// originalCwnd, wMax, last congestion event time and sRTT.
func cubicCwnd(origCwnd int, wMax int, congEventTime time.Time, sRTT time.Duration) int {
	cwnd := float64(origCwnd)
	// We wait 50ms between each iteration so sRTT as computed by cubic
	// should be close to 50ms.
	elapsed := (time.Since(congEventTime) + sRTT).Seconds()
	k := math.Cbrt(float64(wMax) * 0.3 / 0.7)
	wtRTT := 0.4*math.Pow(elapsed-k, 3) + float64(wMax)
	cwnd += (wtRTT - cwnd) / cwnd
	return int(cwnd)
}

func TestCubicCongestionAvoidance(t *testing.T) {
	maxPayload := 32
	c := context.New(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.Cleanup()

	enableCUBIC(t, c)

	c.CreateConnected(789, 30000, -1 /* epRcvBuf */)

	const iterations = 7
	data := buffer.NewView(2 * maxPayload * (tcp.InitialCwnd << (iterations + 1)))

	for i := range data {
		data[i] = byte(i)
	}

	// Write all the data in one shot. Packets will only be written at the
	// MTU size though.
	if _, _, err := c.EP.Write(tcpip.SlicePayload(data), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Do slow start for a few iterations.
	expected := tcp.InitialCwnd
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		expected = tcp.InitialCwnd << uint(i)
		if i > 0 {
			// Acknowledge all the data received so far if not on
			// first iteration.
			c.SendAck(790, bytesRead)
		}

		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.ReceiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.CheckNoPacketTimeout("More packets received than expected for this cwnd (during slow-start phase).", 50*time.Millisecond)
	}

	// Don't acknowledge the first packet of the last packet train. Let's
	// wait for them to time out, which will trigger a restart of slow
	// start, and initialization of ssthresh to cwnd * 0.7.
	rtxOffset := bytesRead - maxPayload*expected
	c.ReceiveAndCheckPacket(data, rtxOffset, maxPayload)

	// Acknowledge all pending data.
	c.SendAck(790, bytesRead)

	// Store away the time we sent the ACK and assuming a 200ms RTO
	// we estimate that the sender will have an RTO 200ms from now
	// and go back into slow start.
	packetDropTime := time.Now().Add(200 * time.Millisecond)

	// This part is tricky: when the timeout happened, we had "expected"
	// packets pending, cwnd reset to 1, and ssthresh set to expected * 0.7.
	// By acknowledging "expected" packets, the slow-start part will
	// increase cwnd to expected/2 essentially putting the connection
	// straight into congestion avoidance.
	wMax := expected
	// Lower expected as per cubic spec after a congestion event.
	expected = int(float64(expected) * 0.7)
	cwnd := expected
	for i := 0; i < iterations; i++ {
		// Cubic grows window independent of ACKs. Cubic Window growth
		// is a function of time elapsed since last congestion event.
		// As a result the congestion window does not grow
		// deterministically in response to ACKs.
		//
		// We need to roughly estimate what the cwnd of the sender is
		// based on when we sent the dupacks.
		cwnd := cubicCwnd(cwnd, wMax, packetDropTime, 50*time.Millisecond)

		packetsExpected := cwnd
		for j := 0; j < packetsExpected; j++ {
			c.ReceiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}
		t.Logf("expected packets received, next trying to receive any extra packets that may come")

		// If our estimate was correct there should be no more pending packets.
		// We attempt to read a packet a few times with a short sleep in between
		// to ensure that we don't see the sender send any unexpected packets.
		unexpectedPackets := 0
		for {
			gotPacket := c.ReceiveNonBlockingAndCheckPacket(data, bytesRead, maxPayload)
			if !gotPacket {
				break
			}
			bytesRead += maxPayload
			unexpectedPackets++
			time.Sleep(1 * time.Millisecond)
		}
		if unexpectedPackets != 0 {
			t.Fatalf("received %d unexpected packets for iteration %d", unexpectedPackets, i)
		}
		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.CheckNoPacketTimeout("More packets received than expected for this cwnd(congestion avoidance)", 5*time.Millisecond)

		// Acknowledge all the data received so far.
		c.SendAck(790, bytesRead)
	}
}

func TestRetransmit(t *testing.T) {
	maxPayload := 32
	c := context.New(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.Cleanup()

	c.CreateConnected(789, 30000, -1 /* epRcvBuf */)

	const iterations = 7
	data := buffer.NewView(maxPayload * (tcp.InitialCwnd << (iterations + 1)))
	for i := range data {
		data[i] = byte(i)
	}

	// Write all the data in two shots. Packets will only be written at the
	// MTU size though.
	half := data[:len(data)/2]
	if _, _, err := c.EP.Write(tcpip.SlicePayload(half), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	half = data[len(data)/2:]
	if _, _, err := c.EP.Write(tcpip.SlicePayload(half), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Do slow start for a few iterations.
	expected := tcp.InitialCwnd
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		expected = tcp.InitialCwnd << uint(i)
		if i > 0 {
			// Acknowledge all the data received so far if not on
			// first iteration.
			c.SendAck(790, bytesRead)
		}

		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.ReceiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.CheckNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)
	}

	// Wait for a timeout and retransmit.
	rtxOffset := bytesRead - maxPayload*expected
	c.ReceiveAndCheckPacket(data, rtxOffset, maxPayload)

	if got, want := c.Stack().Stats().TCP.Timeouts.Value(), uint64(1); got != want {
		t.Errorf("got stats.TCP.Timeouts.Value = %v, want = %v", got, want)
	}

	if got, want := c.Stack().Stats().TCP.Retransmits.Value(), uint64(1); got != want {
		t.Errorf("got stats.TCP.Retransmits.Value = %v, want = %v", got, want)
	}

	if got, want := c.Stack().Stats().TCP.SlowStartRetransmits.Value(), uint64(1); got != want {
		t.Errorf("got stats.TCP.SlowStartRetransmits.Value = %v, want = %v", got, want)
	}

	// Acknowledge half of the pending data.
	rtxOffset = bytesRead - expected*maxPayload/2
	c.SendAck(790, rtxOffset)

	// Receive the remaining data, making sure that acknowledged data is not
	// retransmitted.
	for offset := rtxOffset; offset < len(data); offset += maxPayload {
		c.ReceiveAndCheckPacket(data, offset, maxPayload)
		c.SendAck(790, offset+maxPayload)
	}

	c.CheckNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)
}
