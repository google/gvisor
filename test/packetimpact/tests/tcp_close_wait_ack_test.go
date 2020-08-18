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

package tcp_close_wait_ack_test

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
	testbench.RegisterFlags(flag.CommandLine)
}

func TestCloseWaitAck(t *testing.T) {
	for _, tt := range []struct {
		description    string
		makeTestingTCP func(t *testing.T, conn *testbench.TCPIPv4, seqNumOffset, windowSize seqnum.Size) testbench.TCP
		seqNumOffset   seqnum.Size
		expectAck      bool
	}{
		{"OTW", generateOTWSeqSegment, 0, false},
		{"OTW", generateOTWSeqSegment, 1, true},
		{"OTW", generateOTWSeqSegment, 2, true},
		{"ACK", generateUnaccACKSegment, 0, false},
		{"ACK", generateUnaccACKSegment, 1, true},
		{"ACK", generateUnaccACKSegment, 2, true},
	} {
		t.Run(fmt.Sprintf("%s%d", tt.description, tt.seqNumOffset), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			defer dut.TearDown()
			listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(t, listenFd)
			conn := testbench.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)

			conn.Connect(t)
			acceptFd, _ := dut.Accept(t, listenFd)

			// Send a FIN to DUT to intiate the active close
			conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck | header.TCPFlagFin)})
			gotTCP, err := conn.Expect(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, time.Second)
			if err != nil {
				t.Fatalf("expected an ACK for our fin and DUT should enter CLOSE_WAIT: %s", err)
			}
			windowSize := seqnum.Size(*gotTCP.WindowSize)

			// Send a segment with OTW Seq / unacc ACK and expect an ACK back
			conn.Send(t, tt.makeTestingTCP(t, &conn, tt.seqNumOffset, windowSize), &testbench.Payload{Bytes: []byte("Sample Data")})
			gotAck, err := conn.Expect(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, time.Second)
			if tt.expectAck && err != nil {
				t.Fatalf("expected an ack but got none: %s", err)
			}
			if !tt.expectAck && gotAck != nil {
				t.Fatalf("expected no ack but got one: %s", gotAck)
			}

			// Now let's verify DUT is indeed in CLOSE_WAIT
			dut.Close(t, acceptFd)
			if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck | header.TCPFlagFin)}, time.Second); err != nil {
				t.Fatalf("expected DUT to send a FIN: %s", err)
			}
			// Ack the FIN from DUT
			conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)})
			// Send some extra data to DUT
			conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, &testbench.Payload{Bytes: []byte("Sample Data")})
			if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagRst)}, time.Second); err != nil {
				t.Fatalf("expected DUT to send an RST: %s", err)
			}
		})
	}
}

// generateOTWSeqSegment generates an segment with
// seqnum = RCV.NXT + RCV.WND + seqNumOffset, the generated segment is only
// acceptable when seqNumOffset is 0, otherwise an ACK is expected from the
// receiver.
func generateOTWSeqSegment(t *testing.T, conn *testbench.TCPIPv4, seqNumOffset seqnum.Size, windowSize seqnum.Size) testbench.TCP {
	lastAcceptable := conn.LocalSeqNum(t).Add(windowSize)
	otwSeq := uint32(lastAcceptable.Add(seqNumOffset))
	return testbench.TCP{SeqNum: testbench.Uint32(otwSeq), Flags: testbench.Uint8(header.TCPFlagAck)}
}

// generateUnaccACKSegment generates an segment with
// acknum = SND.NXT + seqNumOffset, the generated segment is only acceptable
// when seqNumOffset is 0, otherwise an ACK is expected from the receiver.
func generateUnaccACKSegment(t *testing.T, conn *testbench.TCPIPv4, seqNumOffset seqnum.Size, windowSize seqnum.Size) testbench.TCP {
	lastAcceptable := conn.RemoteSeqNum(t)
	unaccAck := uint32(lastAcceptable.Add(seqNumOffset))
	return testbench.TCP{AckNum: testbench.Uint32(unaccAck), Flags: testbench.Uint8(header.TCPFlagAck)}
}
