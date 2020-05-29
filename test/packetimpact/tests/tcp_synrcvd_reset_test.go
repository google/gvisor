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
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	tb.RegisterFlags(flag.CommandLine)
}

// TestTCPSynRcvdReset tests transition from SYN-RCVD to CLOSED.
func TestTCPSynRcvdReset(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	listenFD, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFD)
	conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
	defer conn.Close()

	// Expect dut connection to have transitioned to SYN-RCVD state.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn)})
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn | header.TCPFlagAck)}, nil, time.Second); err != nil {
		t.Fatalf("expected SYN-ACK %s", err)
	}
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagRst)})
	// Expect the connection to have transitioned SYN-RCVD to CLOSED.
	// TODO(gvisor.dev/issue/478): Check for TCP_INFO on the dut side.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagRst)}, nil, time.Second); err != nil {
		t.Fatalf("expected a TCP RST %s", err)
	}
}
