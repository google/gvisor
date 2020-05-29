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

package tcp_synsent_reset_test

import (
	"flag"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	tb.RegisterFlags(flag.CommandLine)
}

// dutSynSentState sets up the dut connection in SYN-SENT state.
func dutSynSentState(t *testing.T) (*tb.DUT, *tb.TCPIPv4, uint16, uint16) {
	dut := tb.NewDUT(t)

	clientFD, clientPort := dut.CreateBoundSocket(unix.SOCK_STREAM|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP, net.ParseIP(tb.RemoteIPv4))
	port := uint16(9001)
	conn := tb.NewTCPIPv4(t, tb.TCP{SrcPort: &port, DstPort: &clientPort}, tb.TCP{SrcPort: &clientPort, DstPort: &port})

	sa := unix.SockaddrInet4{Port: int(port)}
	copy(sa.Addr[:], net.IP(net.ParseIP(tb.LocalIPv4)).To4())
	// Bring the dut to SYN-SENT state with a non-blocking connect.
	dut.Connect(clientFD, &sa)
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn)}, nil, time.Second); err != nil {
		t.Fatalf("expected SYN\n")
	}

	return &dut, &conn, port, clientPort
}

// TestTCPSynSentReset tests RFC793, p67: SYN-SENT to CLOSED transition.
func TestTCPSynSentReset(t *testing.T) {
	dut, conn, _, _ := dutSynSentState(t)
	defer conn.Close()
	defer dut.TearDown()
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagRst | header.TCPFlagAck)})
	// Expect the connection to have closed.
	// TODO(gvisor.dev/issue/478): Check for TCP_INFO on the dut side.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagRst)}, nil, time.Second); err != nil {
		t.Fatalf("expected a TCP RST")
	}
}

// TestTCPSynSentRcvdReset tests RFC793, p70, SYN-SENT to SYN-RCVD to CLOSED
// transitions.
func TestTCPSynSentRcvdReset(t *testing.T) {
	dut, c, remotePort, clientPort := dutSynSentState(t)
	defer dut.TearDown()
	defer c.Close()

	conn := tb.NewTCPIPv4(t, tb.TCP{SrcPort: &remotePort, DstPort: &clientPort}, tb.TCP{SrcPort: &clientPort, DstPort: &remotePort})
	defer conn.Close()
	// Initiate new SYN connection with the same port pair
	// (simultaneous open case), expect the dut connection to move to
	// SYN-RCVD state
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn)})
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn | header.TCPFlagAck)}, nil, time.Second); err != nil {
		t.Fatalf("expected SYN-ACK %s\n", err)
	}
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagRst)})
	// Expect the connection to have transitioned SYN-RCVD to CLOSED.
	// TODO(gvisor.dev/issue/478): Check for TCP_INFO on the dut side.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagRst)}, nil, time.Second); err != nil {
		t.Fatalf("expected a TCP RST")
	}
}
