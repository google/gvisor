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

package tcp_timewait_reset_test

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

// TestTimeWaitReset tests handling of RST when in TIME_WAIT state.
func TestTimeWaitReset(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1 /*backlog*/)
	defer dut.Close(t, listenFD)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	conn.Connect(t)
	acceptFD, _ := dut.Accept(t, listenFD)

	// Trigger active close.
	dut.Close(t, acceptFD)

	_, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second)
	if err != nil {
		t.Fatalf("expected a FIN: %s", err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
	// Send a FIN, DUT should transition to TIME_WAIT from FIN_WAIT2.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)})
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second); err != nil {
		t.Fatalf("expected an ACK for our FIN: %s", err)
	}

	// Send a RST, the DUT should transition to CLOSED from TIME_WAIT.
	// This is the default Linux behavior, it can be changed to ignore RSTs via
	// sysctl net.ipv4.tcp_rfc1337.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)})

	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
	// The DUT should reply with RST to our ACK as the state should have
	// transitioned to CLOSED.
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)}, time.Second); err != nil {
		t.Fatalf("expected a RST: %s", err)
	}
}
