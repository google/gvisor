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

package syn_with_same_ip_test

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
	"testing"
	"time"
)

const ipv4LayerIndex int = 1

func TestSynWithSameLocalRemoteIP(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFd)
	conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
	defer conn.Close()

	frame := conn.CreateFrame(tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn)})
        frame[ipv4LayerIndex].(*tb.IPv4).SrcAddr = frame[ipv4LayerIndex].(*tb.IPv4).DstAddr
        conn.SendFrame(frame)

	// Expecting No SYN-ACK from DUT.
	if gotOne := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn | header.TCPFlagAck)}, 3*time.Second); gotOne != nil {
		t.Fatal("expecting no SYN-ACK packet but got one")
	} else {
		println("\nNo response arrived from DUT\n" +
			"Verifying that DUT is in the LISTEN state\n" +
			"Sending a TCP packet (SYN) without any option to DUT interface\n")

		conn = tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})

		// Send SYN to DUT.
		conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn)})

		// Expecting SYN-ACK from DUT
		if gotOne := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn | header.TCPFlagAck)}, 3*time.Second); gotOne == nil {
			t.Fatal("received a SYN-ACK packet")
		}
	}
}
