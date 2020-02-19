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

package fin_wait2_timeout_test

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func TestFinWait2Timeout(t *testing.T) {
	for _, tt := range []struct {
		description string
		linger2     bool
	}{
		{"WithLinger2", true},
		{"WithoutLinger2", false},
	} {
		t.Run(tt.description, func(t *testing.T) {
			dut := tb.NewDUT(t)
			listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(listenFd)
			conn := tb.NewTCPIPv4(t, dut, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
			defer conn.Close()
			conn.Handshake()

			acceptFd, _ := dut.Accept(listenFd)
			if tt.linger2 {
				tv := unix.Timeval{Sec: 1, Usec: 0}
				dut.SetSockOptTimeval(int(acceptFd), unix.SOL_TCP, unix.TCP_LINGER2, &tv)
			}
			dut.Close(acceptFd)

			if gotOne := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagFin | header.TCPFlagAck)}, time.Second); gotOne == nil {
				t.Fatal("expected a FIN-ACK within 1 second but got none")
			}
			conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})

			time.Sleep(5 * time.Second)
			conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})
			if tt.linger2 {
				if gotOne := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagRst)}, time.Second); gotOne == nil {
					t.Fatal("expected a RST packet within a second but got none")
				}
			} else {
				if gotOne := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagRst)}, 10*time.Second); gotOne != nil {
					t.Fatal("expected no RST packets within ten seconds but got one")
				}
			}
		})
	}
}
