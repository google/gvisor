// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package tcp_acceptable_ack_syn_rcvd_test

import (
	"flag"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func TestAcceptableAckInSynRcvd(t *testing.T) {
	for _, tt := range []struct {
		offset    uint32
		expectRst bool
	}{
		{offset: 0, expectRst: true},
		// The ACK holds the next expected SEQ so valid segments must hold an ACK
		// that is 1 larger than the last SEQ value.
		{offset: 1, expectRst: false},
		{offset: 2, expectRst: true},
	} {
		t.Run(fmt.Sprintf("offset=%d, expectRst=%t", tt.offset, tt.expectRst), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFd, listenerPort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(t, listenFd)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &listenerPort}, testbench.TCP{SrcPort: &listenerPort})
			defer conn.Close(t)

			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})

			synAck, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second)
			if err != nil {
				t.Fatalf("didn't get synack during handshake: %s", err)
			}

			// Calculate the ACK number.
			ackNum := *synAck.SeqNum + tt.offset
			conn.Send(t, testbench.TCP{AckNum: &ackNum, Flags: testbench.TCPFlags(header.TCPFlagAck)})

			if tt.expectRst {
				if _, err := conn.Expect(t, testbench.TCP{SeqNum: &ackNum, Flags: testbench.TCPFlags(header.TCPFlagRst)}, time.Second); err != nil {
					t.Fatalf("failed to receive rst for an unacceptable ack: %s", err)
				}
			} else {
				acceptFd, _ := dut.Accept(t, listenFd)
				dut.Close(t, acceptFd)
			}
		})
	}
}
