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

package tcp_unacc_seq_ack_test

import (
	"flag"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func TestEstablishedUnaccSeqAck(t *testing.T) {
	for _, tt := range []struct {
		description    string
		makeTestingTCP func(t *testing.T, conn *testbench.TCPIPv4, seqNumOffset, windowSize seqnum.Size) testbench.TCP
		seqNumOffset   seqnum.Size
		expectAck      bool
		restoreSeq     bool
	}{
		{description: "OTWSeq", makeTestingTCP: testbench.GenerateOTWSeqSegment, seqNumOffset: 0, expectAck: true, restoreSeq: true},
		{description: "OTWSeq", makeTestingTCP: testbench.GenerateOTWSeqSegment, seqNumOffset: 1, expectAck: true, restoreSeq: true},
		{description: "OTWSeq", makeTestingTCP: testbench.GenerateOTWSeqSegment, seqNumOffset: 2, expectAck: true, restoreSeq: true},
		{description: "UnaccAck", makeTestingTCP: testbench.GenerateUnaccACKSegment, seqNumOffset: 0, expectAck: true, restoreSeq: false},
		{description: "UnaccAck", makeTestingTCP: testbench.GenerateUnaccACKSegment, seqNumOffset: 1, expectAck: false, restoreSeq: true},
		{description: "UnaccAck", makeTestingTCP: testbench.GenerateUnaccACKSegment, seqNumOffset: 2, expectAck: false, restoreSeq: true},
	} {
		t.Run(fmt.Sprintf("%s:offset=%d", tt.description, tt.seqNumOffset), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1 /*backlog*/)
			defer dut.Close(t, listenFD)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)

			conn.Connect(t)
			dut.Accept(t, listenFD)

			sampleData := []byte("Sample Data")
			samplePayload := &testbench.Payload{Bytes: sampleData}

			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh)}, samplePayload)
			gotTCP, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
			if err != nil {
				t.Fatalf("expected ack %s", err)
			}
			windowSize := seqnum.Size(*gotTCP.WindowSize)

			origSeq := *conn.LocalSeqNum(t)
			// Send a segment with OTW Seq / unacc ACK.
			conn.Send(t, tt.makeTestingTCP(t, &conn, tt.seqNumOffset, windowSize), samplePayload)
			if tt.restoreSeq {
				// Restore the local sequence number to ensure that the incoming
				// ACK matches the TCP layer state.
				*conn.LocalSeqNum(t) = origSeq
			}
			gotAck, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
			if tt.expectAck && err != nil {
				t.Fatalf("expected an ack but got none: %s", err)
			}
			if err == nil && !tt.expectAck && gotAck != nil {
				t.Fatalf("expected no ack but got one: %s", gotAck)
			}
		})
	}
}

func TestPassiveCloseUnaccSeqAck(t *testing.T) {
	for _, tt := range []struct {
		description    string
		makeTestingTCP func(t *testing.T, conn *testbench.TCPIPv4, seqNumOffset, windowSize seqnum.Size) testbench.TCP
		seqNumOffset   seqnum.Size
		expectAck      bool
	}{
		{description: "OTWSeq", makeTestingTCP: testbench.GenerateOTWSeqSegment, seqNumOffset: 0, expectAck: false},
		{description: "OTWSeq", makeTestingTCP: testbench.GenerateOTWSeqSegment, seqNumOffset: 1, expectAck: true},
		{description: "OTWSeq", makeTestingTCP: testbench.GenerateOTWSeqSegment, seqNumOffset: 2, expectAck: true},
		{description: "UnaccAck", makeTestingTCP: testbench.GenerateUnaccACKSegment, seqNumOffset: 0, expectAck: false},
		{description: "UnaccAck", makeTestingTCP: testbench.GenerateUnaccACKSegment, seqNumOffset: 1, expectAck: true},
		{description: "UnaccAck", makeTestingTCP: testbench.GenerateUnaccACKSegment, seqNumOffset: 2, expectAck: true},
	} {
		t.Run(fmt.Sprintf("%s:offset=%d", tt.description, tt.seqNumOffset), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1 /*backlog*/)
			defer dut.Close(t, listenFD)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)

			conn.Connect(t)
			acceptFD, _ := dut.Accept(t, listenFD)

			// Send a FIN to DUT to intiate the passive close.
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagFin)})
			gotTCP, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
			if err != nil {
				t.Fatalf("expected an ACK for our fin and DUT should enter CLOSE_WAIT: %s", err)
			}
			windowSize := seqnum.Size(*gotTCP.WindowSize)

			sampleData := []byte("Sample Data")
			samplePayload := &testbench.Payload{Bytes: sampleData}

			// Send a segment with OTW Seq / unacc ACK.
			conn.Send(t, tt.makeTestingTCP(t, &conn, tt.seqNumOffset, windowSize), samplePayload)
			gotAck, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
			if tt.expectAck && err != nil {
				t.Errorf("expected an ack but got none: %s", err)
			}
			if err == nil && !tt.expectAck && gotAck != nil {
				t.Errorf("expected no ack but got one: %s", gotAck)
			}

			// Now let's verify DUT is indeed in CLOSE_WAIT
			dut.Close(t, acceptFD)
			if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagFin)}, time.Second); err != nil {
				t.Fatalf("expected DUT to send a FIN: %s", err)
			}
			// Ack the FIN from DUT
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
			// Send some extra data to DUT
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, samplePayload)
			if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)}, time.Second); err != nil {
				t.Fatalf("expected DUT to send an RST: %s", err)
			}
		})
	}
}

func TestActiveCloseUnaccpSeqAck(t *testing.T) {
	for _, tt := range []struct {
		description    string
		makeTestingTCP func(t *testing.T, conn *testbench.TCPIPv4, seqNumOffset, windowSize seqnum.Size) testbench.TCP
		seqNumOffset   seqnum.Size
		restoreSeq     bool
	}{
		{description: "OTWSeq", makeTestingTCP: testbench.GenerateOTWSeqSegment, seqNumOffset: 0, restoreSeq: true},
		{description: "OTWSeq", makeTestingTCP: testbench.GenerateOTWSeqSegment, seqNumOffset: 1, restoreSeq: true},
		{description: "OTWSeq", makeTestingTCP: testbench.GenerateOTWSeqSegment, seqNumOffset: 2, restoreSeq: true},
		{description: "UnaccAck", makeTestingTCP: testbench.GenerateUnaccACKSegment, seqNumOffset: 0, restoreSeq: false},
		{description: "UnaccAck", makeTestingTCP: testbench.GenerateUnaccACKSegment, seqNumOffset: 1, restoreSeq: true},
		{description: "UnaccAck", makeTestingTCP: testbench.GenerateUnaccACKSegment, seqNumOffset: 2, restoreSeq: true},
	} {
		t.Run(fmt.Sprintf("%s:offset=%d", tt.description, tt.seqNumOffset), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1 /*backlog*/)
			defer dut.Close(t, listenFD)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)

			conn.Connect(t)
			acceptFD, _ := dut.Accept(t, listenFD)

			// Trigger active close.
			dut.Shutdown(t, acceptFD, unix.SHUT_WR)

			// Get to FIN_WAIT2
			gotTCP, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second)
			if err != nil {
				t.Fatalf("expected a FIN: %s", err)
			}
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})

			sendUnaccSeqAck := func(state string) {
				t.Helper()
				sampleData := []byte("Sample Data")
				samplePayload := &testbench.Payload{Bytes: sampleData}

				origSeq := *conn.LocalSeqNum(t)
				// Send a segment with OTW Seq / unacc ACK.
				conn.Send(t, tt.makeTestingTCP(t, &conn, tt.seqNumOffset, seqnum.Size(*gotTCP.WindowSize)), samplePayload)
				if tt.restoreSeq {
					// Restore the local sequence number to ensure that the
					// incoming ACK matches the TCP layer state.
					*conn.LocalSeqNum(t) = origSeq
				}
				if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second); err != nil {
					t.Errorf("expected an ack in %s state, but got none: %s", state, err)
				}
			}

			sendUnaccSeqAck("FIN_WAIT2")

			// Send a FIN to DUT to get to TIME_WAIT
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)})
			if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second); err != nil {
				t.Fatalf("expected an ACK for our fin and DUT should enter TIME_WAIT: %s", err)
			}

			sendUnaccSeqAck("TIME_WAIT")
		})
	}
}
