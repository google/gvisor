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

package fin_wait2_reset_test

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func TestFinWait2_RST(t *testing.T) {
	dut := tb.NewDUT(t)
	listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFd)
	conn := tb.NewTCPIPv4(t, dut, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
	defer conn.Close()
	conn.Handshake()

	acceptFd, _ := dut.Accept(listenFd)
	tv := unix.Timeval{Sec: 1, Usec: 0}
	dut.SetSockOptTimeval(int(acceptFd), unix.SOL_TCP, unix.TCP_LINGER2, &tv)
	// Initiate Termination of Connection from DUT - Triggers FIN-ACK towards Test Bench.
	dut.Close(acceptFd)

	// Expecting FIN-ACK from DUT.
	if gotOne := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagFin | header.TCPFlagAck)}, time.Second); gotOne == nil {
		t.Fatal("expected a FIN-ACK within 1 second but got none")
	}

	// Send ACK to DUT.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})

	// Send RST-ACK to DUT - This should initiate connection Termination at DUT
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck | header.TCPFlagRst)})
	time.Sleep(3 * time.Second)

	println("\nSent RST-ACK to DUT\nCheck the status of the connection by sending SYN to DUT\n")

	// Send SYN to DUT for checking connection status.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn)})

	// Expecting SYN-ACK from DUT to confirm previous connection has been closed.
	if gotOne := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second); gotOne == nil {
		t.Fatal("expected a Syn-Ack packet but got Ack")
	} else {
		println("\nReceived SYN-ACK from DUT - confirms previous connection closure\n")
	}
}
