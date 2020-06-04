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

package tcp_outside_the_window_test

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

// TestTCPOutsideTheWindows tests the behavior of the DUT when packets arrive
// that are inside or outside the TCP window. Packets that are outside the
// window should force an extra ACK, as described in RFC793 page 69:
// https://tools.ietf.org/html/rfc793#page-69
func TestTCPOutsideTheWindow(t *testing.T) {
	for _, tt := range []struct {
		description  string
		tcpFlags     uint8
		payload      []testbench.Layer
		seqNumOffset seqnum.Size
		expectACK    bool
	}{
		{"SYN", header.TCPFlagSyn, nil, 0, true},
		{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil, 0, true},
		{"ACK", header.TCPFlagAck, nil, 0, false},
		{"FIN", header.TCPFlagFin, nil, 0, false},
		{"Data", header.TCPFlagAck, []testbench.Layer{&testbench.Payload{Bytes: []byte("abc123")}}, 0, true},

		{"SYN", header.TCPFlagSyn, nil, 1, true},
		{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil, 1, true},
		{"ACK", header.TCPFlagAck, nil, 1, true},
		{"FIN", header.TCPFlagFin, nil, 1, false},
		{"Data", header.TCPFlagAck, []testbench.Layer{&testbench.Payload{Bytes: []byte("abc123")}}, 1, true},

		{"SYN", header.TCPFlagSyn, nil, 2, true},
		{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil, 2, true},
		{"ACK", header.TCPFlagAck, nil, 2, true},
		{"FIN", header.TCPFlagFin, nil, 2, false},
		{"Data", header.TCPFlagAck, []testbench.Layer{&testbench.Payload{Bytes: []byte("abc123")}}, 2, true},
	} {
		t.Run(fmt.Sprintf("%s%d", tt.description, tt.seqNumOffset), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			defer dut.TearDown()
			listenFD, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(listenFD)
			conn := testbench.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close()
			conn.Connect()
			acceptFD, _ := dut.Accept(listenFD)
			defer dut.Close(acceptFD)

			windowSize := seqnum.Size(*conn.SynAck().WindowSize) + tt.seqNumOffset
			conn.Drain()
			// Ignore whatever incrementing that this out-of-order packet might cause
			// to the AckNum.
			localSeqNum := testbench.Uint32(uint32(*conn.LocalSeqNum()))
			conn.Send(testbench.TCP{
				Flags:  testbench.Uint8(tt.tcpFlags),
				SeqNum: testbench.Uint32(uint32(conn.LocalSeqNum().Add(windowSize))),
			}, tt.payload...)
			timeout := 3 * time.Second
			gotACK, err := conn.Expect(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck), AckNum: localSeqNum}, timeout)
			if tt.expectACK && err != nil {
				t.Fatalf("expected an ACK packet within %s but got none: %s", timeout, err)
			}
			if !tt.expectACK && gotACK != nil {
				t.Fatalf("expected no ACK packet within %s but got one: %s", timeout, gotACK)
			}
		})
	}
}
