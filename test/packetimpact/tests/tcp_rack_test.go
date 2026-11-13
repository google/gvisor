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
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

const (
	// simulatedRTT is the time delay between packets sent and acked to
	// increase the RTT.
	simulatedRTT = 30 * time.Millisecond

	// numPktsForRTT is the number of packets sent and acked to establish
	// RTT.
	numPktsForRTT = 10
)

func createSACKConnection(t *testing.T) (testbench.DUT, testbench.TCPIPv4, int32, int) {
	t.Helper()
	dut := testbench.NewDUT(t)
	listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	t.Cleanup(func() { dut.Close(t, listenFd) })
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	t.Cleanup(func() { conn.Close(t) })

	// Enable SACK.
	opts := make([]byte, 40)
	optsOff := 0
	optsOff += header.EncodeNOP(opts[optsOff:])
	optsOff += header.EncodeNOP(opts[optsOff:])
	optsOff += header.EncodeSACKPermittedOption(opts[optsOff:])

	conn.ConnectWithOptions(t, opts[:optsOff])
	acceptFd, _ := dut.Accept(t, listenFd)
	t.Cleanup(func() { dut.Close(t, acceptFd) })

	// Each write must occupy one full segment: the recovery assertions count
	// packets and construct SACK ranges from their payloads. TCP options can
	// reduce the usable payload below the negotiated MSS.
	payloadSize := int(dut.GetSockOptTCPInfo(t, acceptFd).SndMss)
	if payloadSize <= 0 {
		t.Fatalf("TCP_INFO send MSS = %d, want positive", payloadSize)
	}
	return dut, conn, acceptFd, payloadSize
}

func getRTTAndRTO(t *testing.T, dut testbench.DUT, acceptFd int32) (rtt, rto time.Duration) {
	info := dut.GetSockOptTCPInfo(t, acceptFd)
	return time.Duration(info.RTT) * time.Microsecond, time.Duration(info.RTO) * time.Microsecond
}

func sendAndReceive(t *testing.T, dut testbench.DUT, conn testbench.TCPIPv4, numPkts int, acceptFd int32, payloadSize int, sendACK bool) time.Time {
	t.Helper()
	seqNum1 := *conn.RemoteSeqNum(t)
	payload := make([]byte, payloadSize)
	var lastSent time.Time
	for i, sn := 0, seqNum1; i < numPkts; i++ {
		lastSent = time.Now()
		if got, want := dut.Send(t, acceptFd, payload, 0), int32(len(payload)); got != want {
			t.Fatalf("Send #%d = %d, want %d", i+1, got, want)
		}
		if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(uint32(sn))}, &testbench.Payload{Bytes: payload}, time.Second); err != nil {
			t.Fatalf("ExpectData #%d: %s", i+1, err)
		}
		sn.UpdateForward(seqnum.Size(payloadSize))

		if sendACK {
			time.Sleep(simulatedRTT)
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(sn))})
		}
	}
	return lastSent
}

// TestRTOAfterPartialACK compares two losses with the same eight-segment flight.
// Only the second connection advances the cumulative ACK between timeouts.
func TestRTOAfterPartialACK(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ackHalf bool
	}{{"no_ack", false}, {"half_segment", true}} {
		t.Run(tc.name, func(t *testing.T) {
			dut, conn, fd, mss := createSACKConnection(t)
			dut.SetSockOpt(t, fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, []byte("reno"))
			sendAndReceive(t, dut, conn, 1, fd, mss, true)
			first := *conn.RemoteSeqNum(t)
			sendAndReceive(t, dut, conn, 8, fd, mss, false)

			// A tail-loss probe can retransmit the last segment. The first RTO
			// retransmits the head of the flight and enters the Loss state.
			_, rto := getRTTAndRTO(t, dut, fd)
			if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(uint32(first))}, &testbench.Payload{Bytes: make([]byte, mss)}, 2*rto+time.Second); err != nil {
				t.Fatalf("first retransmission at %d: %v", first, err)
			}
			before := dut.GetSockOptTCPInfo(t, fd)
			if got, want := before.CaState, uint8(linux.TCP_CA_Loss); got != want {
				t.Fatalf("congestion state after first retransmission = %d, want loss (%d)", got, want)
			}
			if before.SndSsthresh <= 2 {
				t.Fatalf("first timeout threshold = %d, need >2 to distinguish another reduction", before.SndSsthresh)
			}
			next := first
			if tc.ackHalf {
				next = first.Add(seqnum.Size(mss / 2))
				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(next))})
			}
			// A partial ACK may cause an immediate retransmission. Observe
			// packets at the remaining sequence until the next timeout has
			// reduced the threshold, or the measured RTO budget expires.
			deadline := time.Now().Add(3*time.Microsecond*time.Duration(before.RTO) + time.Second)
			for {
				if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(uint32(next))}, &testbench.Payload{}, time.Until(deadline)); err != nil {
					after := dut.GetSockOptTCPInfo(t, fd)
					t.Fatalf("retransmission at %d; initial threshold=%d, current=%d, cwnd=%d, RTO=%d us: %v", next, before.SndSsthresh, after.SndSsthresh, after.SndCwnd, after.RTO, err)
				}
				after := dut.GetSockOptTCPInfo(t, fd)
				if !tc.ackHalf {
					if got, want := after.SndSsthresh, before.SndSsthresh; got != want {
						t.Errorf("threshold after repeated timeout = %d, want %d", got, want)
					}
					return
				}
				if after.SndSsthresh < before.SndSsthresh {
					return
				}
			}
		})
	}
}

// TestRTOInterruptsCubicRecovery checks that timing out the same outstanding
// flight does not undo CUBIC's choice of threshold on entry to fast recovery.
func TestRTOInterruptsCubicRecovery(t *testing.T) {
	dut, conn, fd, mss := createSACKConnection(t)
	dut.SetSockOpt(t, fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, []byte("cubic"))
	sendAndReceive(t, dut, conn, numPktsForRTT, fd, mss, true)
	first := *conn.RemoteSeqNum(t)
	const flight = 8
	sendAndReceive(t, dut, conn, flight, fd, mss, false)

	// Report the tail of the flight in reverse order. Leave the head missing
	// throughout recovery, so SND.UNA never reaches the recovery boundary.
	end := first.Add(seqnum.Size(flight * mss))
	time.Sleep(simulatedRTT)
	for i := flight - 1; i > 0; i-- {
		block := header.SACKBlock{Start: first.Add(seqnum.Size(i * mss)), End: end}
		var opts [40]byte
		n := header.EncodeNOP(opts[:])
		n += header.EncodeNOP(opts[n:])
		n += header.EncodeSACKBlocks([]header.SACKBlock{block}, opts[n:])
		conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(first)), Options: opts[:n]})
	}

	head := &testbench.TCP{SeqNum: testbench.Uint32(uint32(first))}
	data := &testbench.Payload{Bytes: make([]byte, mss)}
	if _, err := conn.ExpectData(t, head, data, time.Second); err != nil {
		t.Fatalf("fast retransmission of the head: %v", err)
	}
	before := dut.GetSockOptTCPInfo(t, fd)
	t.Logf("fast recovery state=%d threshold=%d cwnd=%d", before.CaState, before.SndSsthresh, before.SndCwnd)
	if before.CaState != linux.TCP_CA_Recovery || before.SndSsthresh <= 2 || before.RTO == 0 {
		t.Fatalf("cannot distinguish another threshold reduction in state %d with ssthresh %d and RTO %d", before.CaState, before.SndSsthresh, before.RTO)
	}

	// Withhold the ACK for the repair. A further retransmission can be
	// compared only after TCP_INFO confirms the transition to Loss.
	deadline := time.Now().Add(3*time.Duration(before.RTO)*time.Microsecond + time.Second)
	for {
		if _, err := conn.ExpectData(t, head, data, time.Until(deadline)); err != nil {
			t.Fatalf("timeout retransmission of the head: %v", err)
		}
		after := dut.GetSockOptTCPInfo(t, fd)
		if after.CaState != linux.TCP_CA_Loss {
			continue
		}
		t.Logf("timeout loss state=%d threshold=%d cwnd=%d", after.CaState, after.SndSsthresh, after.SndCwnd)
		if got, want := after.SndSsthresh, before.SndSsthresh; got != want {
			t.Errorf("ssthresh when a timeout interrupts fast recovery = %d, want %d", got, want)
		}
		return
	}
}

// TestRACKTLPAllPacketsLost tests TLP when an entire flight of data is lost.
func TestRACKTLPAllPacketsLost(t *testing.T) {
	dut, conn, acceptFd, payloadSize := createSACKConnection(t)
	payload := &testbench.Payload{Bytes: make([]byte, payloadSize)}
	seqNum1 := *conn.RemoteSeqNum(t)

	// Send ACK for data packets to establish RTT.
	sendAndReceive(t, dut, conn, numPktsForRTT, acceptFd, payloadSize, true /* sendACK */)
	seqNum1.UpdateForward(seqnum.Size(numPktsForRTT * payloadSize))

	// We are not sending ACK for these packets.
	const numPkts = 5
	lastSent := sendAndReceive(t, dut, conn, numPkts, acceptFd, payloadSize, false /* sendACK */)

	// Probe Timeout (PTO) should be two times RTT. Check that the last
	// packet is retransmitted after probe timeout.
	rtt, _ := getRTTAndRTO(t, dut, acceptFd)
	pto := rtt * 2
	// We expect the 5th packet (the last unacknowledged packet) to be
	// retransmitted.
	tlpProbe := testbench.Uint32(uint32(seqNum1) + uint32((numPkts-1)*payloadSize))
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: tlpProbe}, payload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s %v %v", err, rtt, pto)
	}
	diff := time.Now().Sub(lastSent)
	if diff < pto {
		t.Fatalf("expected payload was received before the probe timeout, got: %v, want: %v", diff, pto)
	}
}

// TestRACKTLPLost tests TLP when there are tail losses.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.4
func TestRACKTLPLost(t *testing.T) {
	dut, conn, acceptFd, payloadSize := createSACKConnection(t)
	payload := &testbench.Payload{Bytes: make([]byte, payloadSize)}
	seqNum1 := *conn.RemoteSeqNum(t)

	// Send ACK for data packets to establish RTT.
	sendAndReceive(t, dut, conn, numPktsForRTT, acceptFd, payloadSize, true /* sendACK */)
	seqNum1.UpdateForward(seqnum.Size(numPktsForRTT * payloadSize))

	// We are not sending ACK for these packets.
	const numPkts = 10
	lastSent := sendAndReceive(t, dut, conn, numPkts, acceptFd, payloadSize, false /* sendACK */)

	// Cumulative ACK for #[1-6] packets.
	ackNum := seqNum1.Add(seqnum.Size(6 * payloadSize))
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(ackNum))})

	// Probe Timeout (PTO) should be two times RTT. Check that the last
	// packet is retransmitted after probe timeout.
	rtt, _ := getRTTAndRTO(t, dut, acceptFd)
	pto := rtt * 2
	// We expect the 10th packet (the last unacknowledged packet) to be
	// retransmitted.
	tlpProbe := testbench.Uint32(uint32(seqNum1) + uint32((numPkts-1)*payloadSize))
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: tlpProbe}, payload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
	diff := time.Now().Sub(lastSent)
	if diff < pto {
		t.Fatalf("expected payload was received before the probe timeout, got: %v, want: %v", diff, pto)
	}
}

// TestRACKWithSACK tests that RACK marks the packets as lost after receiving
// the ACK for retransmitted packets.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-8.1
func TestRACKWithSACK(t *testing.T) {
	dut, conn, acceptFd, payloadSize := createSACKConnection(t)
	payload := &testbench.Payload{Bytes: make([]byte, payloadSize)}
	seqNum1 := *conn.RemoteSeqNum(t)

	// Send ACK for data packets to establish RTT.
	sendAndReceive(t, dut, conn, numPktsForRTT, acceptFd, payloadSize, true /* sendACK */)
	seqNum1.UpdateForward(seqnum.Size(numPktsForRTT * payloadSize))

	// We are not sending ACK for these packets.
	const numPkts = 3
	sendAndReceive(t, dut, conn, numPkts, acceptFd, payloadSize, false /* sendACK */)

	time.Sleep(simulatedRTT)
	// SACK for #2 packet.
	sackBlock := make([]byte, 40)
	start := seqNum1.Add(seqnum.Size(payloadSize))
	end := start.Add(seqnum.Size(payloadSize))
	sbOff := 0
	sbOff += header.EncodeNOP(sackBlock[sbOff:])
	sbOff += header.EncodeNOP(sackBlock[sbOff:])
	sbOff += header.EncodeSACKBlocks([]header.SACKBlock{{
		start, end,
	}}, sackBlock[sbOff:])
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(seqNum1)), Options: sackBlock[:sbOff]})

	rtt, _ := getRTTAndRTO(t, dut, acceptFd)
	timeout := 2 * rtt
	// RACK marks #1 packet as lost after RTT+reorderWindow(RTT/4) and
	// retransmits it.
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(uint32(seqNum1))}, payload, timeout); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}

	// RACK ignores retransmission samples shorter than its minimum RTT
	// (RFC 8985, section 6.2). Wait longer than the warmup ACKs to leave margin
	// for scheduling jitter in that comparison.
	time.Sleep(2 * simulatedRTT)
	// ACK for #1 packet.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(end))})

	// RACK considers transmission times of the packets to mark them lost.
	// As the 3rd packet was sent before the retransmitted 1st packet, RACK
	// marks it as lost and retransmits it..
	expectedSeqNum := testbench.Uint32(uint32(seqNum1) + uint32((numPkts-1)*payloadSize))
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: expectedSeqNum}, payload, timeout); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
}

// TestRACKWithoutReorder tests that without reordering RACK will retransmit the
// lost packets after reorder timer expires.
func TestRACKWithoutReorder(t *testing.T) {
	dut, conn, acceptFd, payloadSize := createSACKConnection(t)
	payload := &testbench.Payload{Bytes: make([]byte, payloadSize)}
	seqNum1 := *conn.RemoteSeqNum(t)

	// Send ACK for data packets to establish RTT.
	sendAndReceive(t, dut, conn, numPktsForRTT, acceptFd, payloadSize, true /* sendACK */)
	seqNum1.UpdateForward(seqnum.Size(numPktsForRTT * payloadSize))

	// We are not sending ACK for these packets.
	const numPkts = 4
	sendAndReceive(t, dut, conn, numPkts, acceptFd, payloadSize, false /* sendACK */)

	// SACK for [3,4] packets.
	sackBlock := make([]byte, 40)
	start := seqNum1.Add(seqnum.Size(2 * payloadSize))
	end := start.Add(seqnum.Size(2 * payloadSize))
	sbOff := 0
	sbOff += header.EncodeNOP(sackBlock[sbOff:])
	sbOff += header.EncodeNOP(sackBlock[sbOff:])
	sbOff += header.EncodeSACKBlocks([]header.SACKBlock{{
		start, end,
	}}, sackBlock[sbOff:])
	time.Sleep(simulatedRTT)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(seqNum1)), Options: sackBlock[:sbOff]})

	// RACK marks #1 and #2 packets as lost and retransmits both after
	// RTT + reorderWindow. The reorderWindow initially will be a small
	// fraction of RTT.
	rtt, _ := getRTTAndRTO(t, dut, acceptFd)
	timeout := 2 * rtt
	for i, sn := 0, seqNum1; i < 2; i++ {
		if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(uint32(sn))}, payload, timeout); err != nil {
			t.Fatalf("expected payload was not received: %s", err)
		}
		sn.UpdateForward(seqnum.Size(payloadSize))
	}
}

// TestRACKWithReorder tests that RACK will retransmit segments when there is
// reordering in the connection and reorder timer expires.
func TestRACKWithReorder(t *testing.T) {
	dut, conn, acceptFd, payloadSize := createSACKConnection(t)
	payload := &testbench.Payload{Bytes: make([]byte, payloadSize)}
	seqNum1 := *conn.RemoteSeqNum(t)

	// Send ACK for data packets to establish RTT.
	sendAndReceive(t, dut, conn, numPktsForRTT, acceptFd, payloadSize, true /* sendACK */)
	seqNum1.UpdateForward(seqnum.Size(numPktsForRTT * payloadSize))

	// Netstack's Reno halves the outstanding flight on loss. Send eight
	// segments so recovery leaves room for the second flight of four. Its three
	// SACKed segments exercise RACK's reordering window past the dup-ACK threshold.
	const firstFlightPackets = 8
	const secondFlightPackets = 4
	sendAndReceive(t, dut, conn, firstFlightPackets, acceptFd, payloadSize, false /* sendACK */)

	time.Sleep(simulatedRTT)
	// SACK in reverse order for the connection to detect reorder.
	var start seqnum.Value
	var end seqnum.Value
	for i := 0; i < firstFlightPackets-1; i++ {
		sackBlock := make([]byte, 40)
		sbOff := 0
		start = seqNum1.Add(seqnum.Size((firstFlightPackets - i - 1) * payloadSize))
		end = start.Add(seqnum.Size((i + 1) * payloadSize))
		sbOff += header.EncodeNOP(sackBlock[sbOff:])
		sbOff += header.EncodeNOP(sackBlock[sbOff:])
		sbOff += header.EncodeSACKBlocks([]header.SACKBlock{{
			start, end,
		}}, sackBlock[sbOff:])
		conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(seqNum1)), Options: sackBlock[:sbOff]})
	}

	// A DSACK reports duplicate bytes actually received. Wait for the first
	// segment to be retransmitted before reporting exactly that segment.
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(uint32(seqNum1))}, payload, time.Second); err != nil {
		t.Fatalf("first-round retransmission was not received: %s", err)
	}
	// Require recovery before the DSACK, so the Open poll below cannot succeed
	// on stale pre-ACK state. Loss would indicate a retransmission timeout.
	beforeDSACK := dut.GetSockOptTCPInfo(t, acceptFd)
	if got, want := beforeDSACK.CaState, uint8(linux.TCP_CA_Recovery); got != want {
		t.Fatalf("congestion state after retransmission = %d, want %d (recovery)", got, want)
	}
	dsackBlock := make([]byte, 40)
	dbOff := 0
	start = seqNum1
	end = start.Add(seqnum.Size(payloadSize))
	dbOff += header.EncodeNOP(dsackBlock[dbOff:])
	dbOff += header.EncodeNOP(dsackBlock[dbOff:])
	dbOff += header.EncodeSACKBlocks([]header.SACKBlock{{
		start, end,
	}}, dsackBlock[dbOff:])
	conn.Send(t, testbench.TCP{
		Flags:   testbench.TCPFlags(header.TCPFlagAck),
		AckNum:  testbench.Uint32(uint32(seqNum1.Add(seqnum.Size(firstFlightPackets * payloadSize)))),
		Options: dsackBlock[:dbOff],
	})

	// Wait for the DSACK to finish recovery before sending the next flight.
	deadline := time.Now().Add(time.Second)
	for {
		info := dut.GetSockOptTCPInfo(t, acceptFd)
		if info.CaState == linux.TCP_CA_Open {
			if got, want := info.SndCwnd, uint32(secondFlightPackets); got < want {
				t.Fatalf("congestion window = %d, want at least %d segments", got, want)
			}
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("DSACK did not complete recovery within one second")
		}
		time.Sleep(time.Millisecond)
	}

	seqNum1.UpdateForward(seqnum.Size(firstFlightPackets * payloadSize))
	// ExpectData tracks the end of the last matched segment, including old
	// retransmissions. Restore the cumulative receive position before expecting
	// new data, so queued first-flight retransmissions cannot match this flight.
	*conn.RemoteSeqNum(t) = seqNum1
	sendTime := time.Now()
	sendAndReceive(t, dut, conn, secondFlightPackets, acceptFd, payloadSize, false /* sendACK */)

	time.Sleep(simulatedRTT)
	// Send SACK for [2-4] packets.
	sackBlock := make([]byte, 40)
	sbOff := 0
	start = seqNum1.Add(seqnum.Size(payloadSize))
	end = start.Add(seqnum.Size((secondFlightPackets - 1) * payloadSize))
	sbOff += header.EncodeNOP(sackBlock[sbOff:])
	sbOff += header.EncodeNOP(sackBlock[sbOff:])
	sbOff += header.EncodeSACKBlocks([]header.SACKBlock{{
		start, end,
	}}, sackBlock[sbOff:])
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(seqNum1)), Options: sackBlock[:sbOff]})

	// Expect the retransmission of #1 packet after RTT+ReorderWindow.
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(uint32(seqNum1))}, payload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
	rtt, _ := getRTTAndRTO(t, dut, acceptFd)
	diff := time.Now().Sub(sendTime)
	if diff < rtt {
		t.Fatalf("expected payload was received too soon, within RTT")
	}
}

// TestRACKWithLostRetransmission tests that RACK will not enter RTO when a
// retransmitted segment is lost and enters fast recovery.
func TestRACKWithLostRetransmission(t *testing.T) {
	dut, conn, acceptFd, payloadSize := createSACKConnection(t)
	payload := &testbench.Payload{Bytes: make([]byte, payloadSize)}
	seqNum1 := *conn.RemoteSeqNum(t)

	// Send ACK for data packets to establish RTT.
	sendAndReceive(t, dut, conn, numPktsForRTT, acceptFd, payloadSize, true /* sendACK */)
	seqNum1.UpdateForward(seqnum.Size(numPktsForRTT * payloadSize))

	// We are not sending ACK for these packets.
	const numPkts = 5
	sendAndReceive(t, dut, conn, numPkts, acceptFd, payloadSize, false /* sendACK */)

	// SACK for [2-5] packets.
	sackBlock := make([]byte, 40)
	start := seqNum1.Add(seqnum.Size(payloadSize))
	end := start.Add(seqnum.Size(4 * payloadSize))
	sbOff := 0
	sbOff += header.EncodeNOP(sackBlock[sbOff:])
	sbOff += header.EncodeNOP(sackBlock[sbOff:])
	sbOff += header.EncodeSACKBlocks([]header.SACKBlock{{
		start, end,
	}}, sackBlock[sbOff:])
	time.Sleep(simulatedRTT)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(seqNum1)), Options: sackBlock[:sbOff]})

	// RACK marks #1 packet as lost and retransmits it after
	// RTT + reorderWindow. The reorderWindow is bounded between a small
	// fraction of RTT and 1 RTT.
	rtt, _ := getRTTAndRTO(t, dut, acceptFd)
	timeout := 2 * rtt
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(uint32(seqNum1))}, payload, timeout); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}

	// Send #6 packet.
	if got, want := dut.Send(t, acceptFd, payload.Bytes, 0), int32(len(payload.Bytes)); got != want {
		t.Fatalf("Send #6 = %d, want %d", got, want)
	}
	seqNum6 := seqNum1.Add(seqnum.Size(5 * payloadSize))
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(uint32(seqNum6))}, payload, time.Second); err != nil {
		t.Fatalf("ExpectData #6: %s", err)
	}

	// SACK for [2-6] packets.
	sackBlock1 := make([]byte, 40)
	start = seqNum1.Add(seqnum.Size(payloadSize))
	end = start.Add(seqnum.Size(5 * payloadSize))
	sbOff1 := 0
	sbOff1 += header.EncodeNOP(sackBlock1[sbOff1:])
	sbOff1 += header.EncodeNOP(sackBlock1[sbOff1:])
	sbOff1 += header.EncodeSACKBlocks([]header.SACKBlock{{
		start, end,
	}}, sackBlock1[sbOff1:])
	time.Sleep(simulatedRTT)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(seqNum1)), Options: sackBlock1[:sbOff1]})

	// Expect re-retransmission of #1 packet without entering an RTO.
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(uint32(seqNum1))}, payload, timeout); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}

	// Check the congestion control state.
	info := dut.GetSockOptTCPInfo(t, acceptFd)
	if info.CaState != linux.TCP_CA_Recovery {
		t.Fatalf("expected connection to be in fast recovery, want: %v got: %v", linux.TCP_CA_Recovery, info.CaState)
	}
}
