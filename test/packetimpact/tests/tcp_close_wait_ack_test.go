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
		makeTestingTCP func(conn *testbench.TCPIPv4, seqNumOffset seqnum.Size, windowSize seqnum.Size) testbench.TCP
		seqNumOffset   seqnum.Size
		expectAck      bool
	}{
		{"OTW", GenerateOTWSeqSegment, 0, false},
		{"OTW", GenerateOTWSeqSegment, 1, true},
		{"OTW", GenerateOTWSeqSegment, 2, true},
		{"ACK", GenerateUnaccACKSegment, 0, false},
		{"ACK", GenerateUnaccACKSegment, 1, true},
		{"ACK", GenerateUnaccACKSegment, 2, true},
	} {
		t.Run(fmt.Sprintf("%s%d", tt.description, tt.seqNumOffset), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			defer dut.TearDown()
			listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(listenFd)
			conn := testbench.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close()

			conn.Connect()
			acceptFd, _ := dut.Accept(listenFd)

			// Send a FIN to DUT to intiate the active close
			conn.Send(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck | header.TCPFlagFin)})
			gotTCP, err := conn.Expect(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, time.Second)
			if err != nil {
				t.Fatalf("expected an ACK for our fin and DUT should enter CLOSE_WAIT: %s", err)
			}
			windowSize := seqnum.Size(*gotTCP.WindowSize)

			// Send a segment with OTW Seq / unacc ACK and expect an ACK back
			conn.Send(tt.makeTestingTCP(&conn, tt.seqNumOffset, windowSize), &testbench.Payload{Bytes: []byte("Sample Data")})
			gotAck, err := conn.Expect(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, time.Second)
			if tt.expectAck && err != nil {
				t.Fatalf("expected an ack but got none: %s", err)
			}
			if !tt.expectAck && gotAck != nil {
				t.Fatalf("expected no ack but got one: %s", gotAck)
			}

			// Now let's verify DUT is indeed in CLOSE_WAIT
			dut.Close(acceptFd)
			if _, err := conn.Expect(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck | header.TCPFlagFin)}, time.Second); err != nil {
				t.Fatalf("expected DUT to send a FIN: %s", err)
			}
			// Ack the FIN from DUT
			conn.Send(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)})
			// Send some extra data to DUT
			conn.Send(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, &testbench.Payload{Bytes: []byte("Sample Data")})
			if _, err := conn.Expect(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagRst)}, time.Second); err != nil {
				t.Fatalf("expected DUT to send an RST: %s", err)
			}
		})
	}
}

// This generates an segment with seqnum = RCV.NXT + RCV.WND + seqNumOffset, the
// generated segment is only acceptable when seqNumOffset is 0, otherwise an ACK
// is expected from the receiver.
func GenerateOTWSeqSegment(conn *testbench.TCPIPv4, seqNumOffset seqnum.Size, windowSize seqnum.Size) testbench.TCP {
	lastAcceptable := conn.LocalSeqNum().Add(windowSize)
	otwSeq := uint32(lastAcceptable.Add(seqNumOffset))
	return testbench.TCP{SeqNum: testbench.Uint32(otwSeq), Flags: testbench.Uint8(header.TCPFlagAck)}
}

// This generates an segment with acknum = SND.NXT + seqNumOffset, the generated
// segment is only acceptable when seqNumOffset is 0, otherwise an ACK is
// expected from the receiver.
func GenerateUnaccACKSegment(conn *testbench.TCPIPv4, seqNumOffset seqnum.Size, windowSize seqnum.Size) testbench.TCP {
	lastAcceptable := conn.RemoteSeqNum()
	unaccAck := uint32(lastAcceptable.Add(seqNumOffset))
	return testbench.TCP{AckNum: testbench.Uint32(unaccAck), Flags: testbench.Uint8(header.TCPFlagAck)}
}
