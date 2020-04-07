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
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func TestTCPOutsideTheWindow(t *testing.T) {
	for _, tt := range []struct {
		description  string
		tcpFlags     uint8
		payload      []tb.Layer
		seqNumOffset seqnum.Size
		expectAck    bool
	}{
		{"SYN", header.TCPFlagSyn, nil, 0, true},
		{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil, 0, true},
		{"ACK", header.TCPFlagAck, nil, 0, false},
		{"FIN", header.TCPFlagFin, nil, 0, false},
		{"Data", header.TCPFlagAck, []tb.Layer{&tb.Payload{Bytes: []byte("abc123")}}, 0, true},

		{"SYN", header.TCPFlagSyn, nil, 1, true},
		{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil, 1, true},
		{"ACK", header.TCPFlagAck, nil, 1, true},
		{"FIN", header.TCPFlagFin, nil, 1, false},
		{"Data", header.TCPFlagAck, []tb.Layer{&tb.Payload{Bytes: []byte("abc123")}}, 1, true},

		{"SYN", header.TCPFlagSyn, nil, 2, true},
		{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil, 2, true},
		{"ACK", header.TCPFlagAck, nil, 2, true},
		{"FIN", header.TCPFlagFin, nil, 2, false},
		{"Data", header.TCPFlagAck, []tb.Layer{&tb.Payload{Bytes: []byte("abc123")}}, 2, true},
	} {
		t.Run(fmt.Sprintf("%s%d", tt.description, tt.seqNumOffset), func(t *testing.T) {
			dut := tb.NewDUT(t)
			defer dut.TearDown()
			listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(listenFd)
			conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
			defer conn.Close()
			conn.Handshake()
			acceptFd, _ := dut.Accept(listenFd)
			defer dut.Close(acceptFd)

			windowSize := seqnum.Size(*conn.SynAck.WindowSize) + tt.seqNumOffset
			conn.Send(tb.TCP{
				Flags:  tb.Uint8(tt.tcpFlags),
				SeqNum: tb.Uint32(uint32(conn.LocalSeqNum.Add(windowSize))),
			}, tt.payload...)
			timeout := 3 * time.Second
			gotAck := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)}, timeout)
			if tt.expectAck && gotAck == nil {
				t.Fatalf("expected an ACK packet within %s but got none", timeout)
			}
			if !tt.expectAck && gotAck != nil {
				t.Fatalf("expected no ACK packet within %s but got one", timeout)
			}
		})
	}
}
