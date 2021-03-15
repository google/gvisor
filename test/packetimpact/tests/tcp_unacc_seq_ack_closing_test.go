// Copyright 2021 The gVisor Authors.
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

package tcp_unacc_seq_ack_closing_test

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

func TestSimultaneousCloseUnaccSeqAck(t *testing.T) {
	for _, tt := range []struct {
		description    string
		makeTestingTCP func(t *testing.T, conn *testbench.TCPIPv4, seqNumOffset, windowSize seqnum.Size) testbench.TCP
		seqNumOffset   seqnum.Size
		expectAck      bool
	}{
		{description: "OTWSeq", makeTestingTCP: testbench.GenerateOTWSeqSegment, seqNumOffset: 0, expectAck: true},
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

			// Trigger active close.
			dut.Shutdown(t, acceptFD, unix.SHUT_WR)

			gotTCP, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second)
			if err != nil {
				t.Fatalf("expected a FIN: %s", err)
			}
			// Do not ack the FIN from DUT so that we get to CLOSING.
			seqNumForTheirFIN := testbench.Uint32(uint32(*conn.RemoteSeqNum(t)) - 1)
			conn.Send(t, testbench.TCP{AckNum: seqNumForTheirFIN, Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)})

			if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second); err != nil {
				t.Errorf("expected an ACK to our FIN, but got none: %s", err)
			}

			sampleData := []byte("Sample Data")
			samplePayload := &testbench.Payload{Bytes: sampleData}

			origSeq := uint32(*conn.LocalSeqNum(t))
			// Send a segment with OTW Seq / unacc ACK.
			tcp := tt.makeTestingTCP(t, &conn, tt.seqNumOffset, seqnum.Size(*gotTCP.WindowSize))
			if tt.description == "OTWSeq" {
				// If we generate an OTW Seq segment, make sure we don't acknowledge their FIN so that
				// we stay in CLOSING.
				tcp.AckNum = seqNumForTheirFIN
			}
			conn.Send(t, tcp, samplePayload)

			got, err := conn.Expect(t, testbench.TCP{AckNum: testbench.Uint32(origSeq), Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
			if tt.expectAck && err != nil {
				t.Errorf("expected an ack in CLOSING state, but got none: %s", err)
			}
			if !tt.expectAck && got != nil {
				t.Errorf("expected no ack in CLOSING state, but got one: %s", got)
			}
		})
	}
}
