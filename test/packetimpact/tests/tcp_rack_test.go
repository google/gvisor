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
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

const (
	// payloadSize is the size used to send packets.
	payloadSize = header.TCPDefaultMSS

	// simulatedRTT is the time delay between packets sent and acked to
	// increase the RTT.
	simulatedRTT = 30 * time.Millisecond

	// numPktsForRTT is the number of packets sent and acked to establish
	// RTT.
	numPktsForRTT = 10
)

func createSACKConnection(t *testing.T) (testbench.DUT, testbench.TCPIPv4, int32, int32) {
	dut := testbench.NewDUT(t)
	listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})

	// Enable SACK.
	opts := make([]byte, 40)
	optsOff := 0
	optsOff += header.EncodeNOP(opts[optsOff:])
	optsOff += header.EncodeNOP(opts[optsOff:])
	optsOff += header.EncodeSACKPermittedOption(opts[optsOff:])

	conn.ConnectWithOptions(t, opts[:optsOff])
	acceptFd, _ := dut.Accept(t, listenFd)
	return dut, conn, acceptFd, listenFd
}

func closeSACKConnection(t *testing.T, dut testbench.DUT, conn testbench.TCPIPv4, acceptFd, listenFd int32) {
	dut.Close(t, acceptFd)
	dut.Close(t, listenFd)
	conn.Close(t)
}

func getRTTAndRTO(t *testing.T, dut testbench.DUT, acceptFd int32) (rtt, rto time.Duration) {
	info := linux.TCPInfo{}
	ret := dut.GetSockOpt(t, acceptFd, unix.SOL_TCP, unix.TCP_INFO, int32(linux.SizeOfTCPInfo))
	binary.Unmarshal(ret, usermem.ByteOrder, &info)
	return time.Duration(info.RTT) * time.Microsecond, time.Duration(info.RTO) * time.Microsecond
}

func sendAndReceive(t *testing.T, dut testbench.DUT, conn testbench.TCPIPv4, numPkts int, acceptFd int32, sendACK bool) time.Time {
	seqNum1 := *conn.RemoteSeqNum(t)
	payload := make([]byte, payloadSize)
	var lastSent time.Time
	for i, sn := 0, seqNum1; i < numPkts; i++ {
		lastSent = time.Now()
		dut.Send(t, acceptFd, payload, 0)
		gotOne, err := conn.Expect(t, testbench.TCP{SeqNum: testbench.Uint32(uint32(sn))}, time.Second)
		if err != nil {
			t.Fatalf("Expect #%d: %s", i+1, err)
			continue
		}
		if gotOne == nil {
			t.Fatalf("#%d: expected a packet within a second but got none", i+1)
		}
		sn.UpdateForward(seqnum.Size(payloadSize))

		if sendACK {
			time.Sleep(simulatedRTT)
			conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(sn))})
		}
	}
	return lastSent
}

// TestRACKTLPAllPacketsLost tests TLP when an entire flight of data is lost.
func TestRACKTLPAllPacketsLost(t *testing.T) {
	dut, conn, acceptFd, listenFd := createSACKConnection(t)
	seqNum1 := *conn.RemoteSeqNum(t)

	// Send ACK for data packets to establish RTT.
	sendAndReceive(t, dut, conn, numPktsForRTT, acceptFd, true /* sendACK */)
	seqNum1.UpdateForward(seqnum.Size(numPktsForRTT * payloadSize))

	// We are not sending ACK for these packets.
	const numPkts = 5
	lastSent := sendAndReceive(t, dut, conn, numPkts, acceptFd, false /* sendACK */)

	// Probe Timeout (PTO) should be two times RTT. Check that the last
	// packet is retransmitted after probe timeout.
	rtt, _ := getRTTAndRTO(t, dut, acceptFd)
	pto := rtt * 2
	// We expect the 5th packet (the last unacknowledged packet) to be
	// retransmitted.
	tlpProbe := testbench.Uint32(uint32(seqNum1) + uint32((numPkts-1)*payloadSize))
	if _, err := conn.Expect(t, testbench.TCP{SeqNum: tlpProbe}, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s %v %v", err, rtt, pto)
	}
	diff := time.Now().Sub(lastSent)
	if diff < pto {
		t.Fatalf("expected payload was received before the probe timeout, got: %v, want: %v", diff, pto)
	}
	closeSACKConnection(t, dut, conn, acceptFd, listenFd)
}

// TestRACKTLPLost tests TLP when there are tail losses.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.4
func TestRACKTLPLost(t *testing.T) {
	dut, conn, acceptFd, listenFd := createSACKConnection(t)
	seqNum1 := *conn.RemoteSeqNum(t)

	// Send ACK for data packets to establish RTT.
	sendAndReceive(t, dut, conn, numPktsForRTT, acceptFd, true /* sendACK */)
	seqNum1.UpdateForward(seqnum.Size(numPktsForRTT * payloadSize))

	// We are not sending ACK for these packets.
	const numPkts = 10
	lastSent := sendAndReceive(t, dut, conn, numPkts, acceptFd, false /* sendACK */)

	// Cumulative ACK for #[1-5] packets.
	ackNum := seqNum1.Add(seqnum.Size(6 * payloadSize))
	conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(ackNum))})

	// Probe Timeout (PTO) should be two times RTT. Check that the last
	// packet is retransmitted after probe timeout.
	rtt, _ := getRTTAndRTO(t, dut, acceptFd)
	pto := rtt * 2
	// We expect the 10th packet (the last unacknowledged packet) to be
	// retransmitted.
	tlpProbe := testbench.Uint32(uint32(seqNum1) + uint32((numPkts-1)*payloadSize))
	if _, err := conn.Expect(t, testbench.TCP{SeqNum: tlpProbe}, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
	diff := time.Now().Sub(lastSent)
	if diff < pto {
		t.Fatalf("expected payload was received before the probe timeout, got: %v, want: %v", diff, pto)
	}
	closeSACKConnection(t, dut, conn, acceptFd, listenFd)
}

// TestRACKTLPWithSACK tests TLP by acknowledging out of order packets.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-8.1
func TestRACKTLPWithSACK(t *testing.T) {
	dut, conn, acceptFd, listenFd := createSACKConnection(t)
	seqNum1 := *conn.RemoteSeqNum(t)

	// Send ACK for data packets to establish RTT.
	sendAndReceive(t, dut, conn, numPktsForRTT, acceptFd, true /* sendACK */)
	seqNum1.UpdateForward(seqnum.Size(numPktsForRTT * payloadSize))

	// We are not sending ACK for these packets.
	const numPkts = 3
	lastSent := sendAndReceive(t, dut, conn, numPkts, acceptFd, false /* sendACK */)

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
	conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(seqNum1)), Options: sackBlock[:sbOff]})

	// RACK marks #1 packet as lost and retransmits it.
	if _, err := conn.Expect(t, testbench.TCP{SeqNum: testbench.Uint32(uint32(seqNum1))}, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}

	// ACK for #1 packet.
	conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(end))})

	// Probe Timeout (PTO) should be two times RTT. TLP will trigger for #3
	// packet. RACK adds an additional timeout of 200ms if the number of
	// outstanding packets is equal to 1.
	rtt, rto := getRTTAndRTO(t, dut, acceptFd)
	pto := rtt*2 + (200 * time.Millisecond)
	if rto < pto {
		pto = rto
	}
	// We expect the 3rd packet (the last unacknowledged packet) to be
	// retransmitted.
	tlpProbe := testbench.Uint32(uint32(seqNum1) + uint32((numPkts-1)*payloadSize))
	if _, err := conn.Expect(t, testbench.TCP{SeqNum: tlpProbe}, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
	diff := time.Now().Sub(lastSent)
	if diff < pto {
		t.Fatalf("expected payload was received before the probe timeout, got: %v, want: %v", diff, pto)
	}
	closeSACKConnection(t, dut, conn, acceptFd, listenFd)
}
