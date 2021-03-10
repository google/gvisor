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

func TestFinWait2Timeout(t *testing.T) {
	for _, tt := range []struct {
		description string
		linger2     bool
	}{
		{"WithLinger2", true},
		{"WithoutLinger2", false},
	} {
		t.Run(tt.description, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(t, listenFd)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)
			conn.Connect(t)

			acceptFd, _ := dut.Accept(t, listenFd)
			if tt.linger2 {
				tv := unix.Timeval{Sec: 1, Usec: 0}
				dut.SetSockOptTimeval(t, acceptFd, unix.SOL_TCP, unix.TCP_LINGER2, &tv)
			}
			dut.Close(t, acceptFd)

			if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second); err != nil {
				t.Fatalf("expected a FIN-ACK within 1 second but got none: %s", err)
			}
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})

			time.Sleep(5 * time.Second)
			conn.Drain(t)

			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
			if tt.linger2 {
				if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)}, time.Second); err != nil {
					t.Fatalf("expected a RST packet within a second but got none: %s", err)
				}
			} else {
				if got, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)}, 10*time.Second); got != nil || err == nil {
					t.Fatalf("expected no RST packets within ten seconds but got one: %s", got)
				}
			}
		})
	}
}
