// Copyright 2021 The gVisor Authors.
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

package tcp_listen_backlog_test

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

// TestTCPListenBacklog tests for a listening endpoint behavior:
// (1) reply to more SYNs than what is configured as listen backlog
// (2) ignore ACKs (that complete a handshake) when the accept queue is full
// (3) ignore incoming SYNs when the accept queue is full
func TestTCPListenBacklog(t *testing.T) {
	dut := testbench.NewDUT(t)

	// Listening endpoint accepts one more connection than the listen backlog.
	listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 0 /*backlog*/)

	var establishedConn testbench.TCPIPv4
	var incompleteConn testbench.TCPIPv4

	// Test if the DUT listener replies to more SYNs than listen backlog+1
	for i, conn := range []*testbench.TCPIPv4{&establishedConn, &incompleteConn} {
		*conn = dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
		// Expect dut connection to have transitioned to SYN-RCVD state.
		conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})
		if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, nil, time.Second); err != nil {
			t.Fatalf("expected SYN-ACK for %d connection, %s", i, err)
		}
	}
	defer establishedConn.Close(t)
	defer incompleteConn.Close(t)

	// Send the ACK to complete handshake.
	establishedConn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})

	// Poll for the established connection ready for accept.
	dut.PollOne(t, listenFd, unix.POLLIN, time.Second)

	// Send the ACK to complete handshake, expect this to be dropped by the
	// listener as the accept queue would be full because of the previous
	// handshake.
	incompleteConn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
	// Let the test wait for sometime so that the ACK is indeed dropped by
	// the listener. Without such a wait, the DUT accept can race with
	// ACK handling (dropping) causing the test to be flaky.
	time.Sleep(100 * time.Millisecond)

	// Drain the accept queue to enable poll for subsequent connections on the
	// listener.
	fd, _ := dut.Accept(t, listenFd)
	dut.Close(t, fd)

	// The ACK for the incomplete connection should be ignored by the
	// listening endpoint and the poll on listener should now time out.
	if pfds := dut.Poll(t, []unix.PollFd{{Fd: listenFd, Events: unix.POLLIN}}, time.Second); len(pfds) != 0 {
		t.Fatalf("got dut.Poll(...) = %#v", pfds)
	}

	// Re-send the ACK to complete handshake and re-fill the accept-queue.
	incompleteConn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
	dut.PollOne(t, listenFd, unix.POLLIN, time.Second)

	// Now initiate a new connection when the accept queue is full.
	connectingConn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer connectingConn.Close(t)
	// Expect dut connection to drop the SYN and let the client stay in SYN_SENT state.
	connectingConn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})
	if got, err := connectingConn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, nil, time.Second); err == nil {
		t.Fatalf("expected no SYN-ACK, but got %s", got)
	}
}
