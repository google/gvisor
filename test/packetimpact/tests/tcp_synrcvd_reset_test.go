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

package tcp_syn_reset_test

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

// TestTCPSynRcvdReset tests transition from SYN-RCVD to CLOSED.
func TestTCPSynRcvdReset(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFD)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	// Expect dut connection to have transitioned to SYN-RCVD state.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, nil, time.Second); err != nil {
		t.Fatalf("expected SYN-ACK %s", err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)})

	// Expect the connection to have transitioned SYN-RCVD to CLOSED.
	//
	// Retransmit the ACK a few times to give time for the DUT to transition to
	// CLOSED. We cannot use TCP_INFO to lookup the state as this is a passive
	// DUT connection.
	for i := 0; i < 5; i++ {
		conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
		if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)}, nil, time.Second); err != nil {
			t.Logf("retransmit%d ACK as we did not get the expected RST, %s", i, err)
			continue
		}
		return
	}
	t.Fatal("did not receive a TCP RST")
}
