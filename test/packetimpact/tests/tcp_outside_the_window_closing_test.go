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

package tcp_outside_the_window_closing_test

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

// TestAckOTWSeqInClosing tests that the DUT should send an ACK with
// the right ACK number when receiving a packet with OTW Seq number
// in CLOSING state. https://tools.ietf.org/html/rfc793#page-69
func TestAckOTWSeqInClosing(t *testing.T) {
	for seqNumOffset := seqnum.Size(0); seqNumOffset < 3; seqNumOffset++ {
		for _, tt := range []struct {
			description string
			flags       header.TCPFlags
			payloads    testbench.Layers
		}{
			{"SYN", header.TCPFlagSyn, nil},
			{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil},
			{"ACK", header.TCPFlagAck, nil},
			{"FINACK", header.TCPFlagFin | header.TCPFlagAck, nil},
			{"Data", header.TCPFlagAck, []testbench.Layer{&testbench.Payload{Bytes: []byte("abc123")}}},
		} {
			t.Run(fmt.Sprintf("%s%d", tt.description, seqNumOffset), func(t *testing.T) {
				dut := testbench.NewDUT(t)
				listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
				defer dut.Close(t, listenFD)
				conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
				defer conn.Close(t)
				conn.Connect(t)
				acceptFD, _ := dut.Accept(t, listenFD)
				defer dut.Close(t, acceptFD)

				dut.Shutdown(t, acceptFD, unix.SHUT_WR)

				if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second); err != nil {
					t.Fatalf("expected FINACK from DUT, but got none: %s", err)
				}

				// Do not ack the FIN from DUT so that the TCP state on DUT is CLOSING instead of CLOSED.
				seqNumForTheirFIN := testbench.Uint32(uint32(*conn.RemoteSeqNum(t)) - 1)
				conn.Send(t, testbench.TCP{AckNum: seqNumForTheirFIN, Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)})

				if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second); err != nil {
					t.Errorf("expected an ACK to our FIN, but got none: %s", err)
				}

				windowSize := seqnum.Size(*conn.SynAck(t).WindowSize) + seqNumOffset
				conn.SendFrameStateless(t, conn.CreateFrame(t, testbench.Layers{&testbench.TCP{
					SeqNum: testbench.Uint32(uint32(conn.LocalSeqNum(t).Add(windowSize))),
					AckNum: seqNumForTheirFIN,
					Flags:  testbench.TCPFlags(tt.flags),
				}}, tt.payloads...))

				if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second); err != nil {
					t.Errorf("expected an ACK but got none: %s", err)
				}
			})
		}
	}
}
