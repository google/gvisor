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
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

// dutSynSentState sets up the dut connection in SYN-SENT state.
func dutSynSentState(t *testing.T) (*testbench.DUT, *testbench.TCPIPv4, int32, uint16, uint16) {
	t.Helper()

	dut := testbench.NewDUT(t)

	clientFD, clientPort := dut.CreateBoundSocket(t, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP, dut.Net.RemoteIPv4)
	port := uint16(9001)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{SrcPort: &port, DstPort: &clientPort}, testbench.TCP{SrcPort: &clientPort, DstPort: &port})

	sa := unix.SockaddrInet4{Port: int(port)}
	copy(sa.Addr[:], dut.Net.LocalIPv4)
	// Bring the dut to SYN-SENT state with a non-blocking connect.
	dut.Connect(t, clientFD, &sa)
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)}, nil, time.Second); err != nil {
		t.Fatalf("expected SYN\n")
	}

	return &dut, &conn, clientFD, port, clientPort
}

// TestTCPSynSentReset tests RFC793, p67: SYN-SENT to CLOSED transition.
func TestTCPSynSentReset(t *testing.T) {
	dut, conn, fd, _, _ := dutSynSentState(t)
	defer conn.Close(t)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst | header.TCPFlagAck)})
	// Expect the connection to have closed.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)}, nil, time.Second); err != nil {
		t.Fatalf("expected a TCP RST")
	}
	info := dut.GetSockOptTCPInfo(t, fd)
	if got, want := uint32(info.State), linux.TCP_CLOSE; got != want {
		t.Fatalf("got %d want %d", got, want)
	}
}

// TestTCPSynSentRcvdReset tests RFC793, p70, SYN-SENT to SYN-RCVD to CLOSED
// transitions.
func TestTCPSynSentRcvdReset(t *testing.T) {
	dut, c, fd, remotePort, clientPort := dutSynSentState(t)
	defer c.Close(t)

	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{SrcPort: &remotePort, DstPort: &clientPort}, testbench.TCP{SrcPort: &clientPort, DstPort: &remotePort})
	defer conn.Close(t)
	// Initiate new SYN connection with the same port pair
	// (simultaneous open case), expect the dut connection to move to
	// SYN-RCVD state
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, nil, time.Second); err != nil {
		t.Fatalf("expected SYN-ACK %s\n", err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)})
	// Expect the connection to have transitioned SYN-RCVD to CLOSED.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)}, nil, time.Second); err != nil {
		t.Fatalf("expected a TCP RST")
	}
	info := dut.GetSockOptTCPInfo(t, fd)
	if got, want := uint32(info.State), linux.TCP_CLOSE; got != want {
		t.Fatalf("got %d want %d", got, want)
	}
}
