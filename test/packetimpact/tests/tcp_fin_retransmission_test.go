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

package tcp_fin_retransmission_test

import (
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

// TestTCPClosingFinRetransmission tests that TCP implementation should retransmit
// FIN segment in CLOSING state.
func TestTCPClosingFinRetransmission(t *testing.T) {
	for _, tt := range []struct {
		description string
		flags       header.TCPFlags
	}{
		{"CLOSING", header.TCPFlagAck | header.TCPFlagFin},
		{"FIN_WAIT_1", header.TCPFlagAck},
	} {
		t.Run(tt.description, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(t, listenFD)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)
			conn.Connect(t)
			acceptFD, _ := dut.Accept(t, listenFD)
			defer dut.Close(t, acceptFD)

			// Give a chance for the dut to estimate RTO with RTT from the DATA-ACK.
			// TODO(gvisor.dev/issue/2685) Estimate RTO during handshake, after which
			// we can skip the next block of code.
			sampleData := []byte("Sample Data")
			if got, want := dut.Send(t, acceptFD, sampleData, 0), len(sampleData); int(got) != want {
				t.Fatalf("got dut.Send(t, %d, %s, 0) = %d, want %d", acceptFD, sampleData, got, want)
			}
			if _, err := conn.ExpectData(t, &testbench.TCP{}, &testbench.Payload{Bytes: sampleData}, time.Second); err != nil {
				t.Fatalf("expected payload was not received: %s", err)
			}
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})

			dut.Shutdown(t, acceptFD, unix.SHUT_WR)

			if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second); err != nil {
				t.Fatalf("expected FINACK from DUT, but got none: %s", err)
			}

			// Do not ack the FIN from DUT so that we can test for retransmission.
			seqNumForTheirFIN := testbench.Uint32(uint32(*conn.RemoteSeqNum(t)) - 1)
			conn.Send(t, testbench.TCP{AckNum: seqNumForTheirFIN, Flags: testbench.TCPFlags(tt.flags)})

			if tt.flags&header.TCPFlagFin != 0 {
				if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second); err != nil {
					t.Errorf("expected an ACK to our FIN, but got none: %s", err)
				}
			}

			if _, err := conn.Expect(t, testbench.TCP{
				SeqNum: seqNumForTheirFIN,
				Flags:  testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck),
			}, time.Second); err != nil {
				t.Errorf("expected retransmission of FIN from the DUT: %s", err)
			}
		})
	}
}
