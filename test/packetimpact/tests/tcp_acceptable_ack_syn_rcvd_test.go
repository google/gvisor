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

func TestRepeatedSynInSynRcvd(t *testing.T) {
	dut := testbench.NewDUT(t)
	listener, port := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listener)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &port}, testbench.TCP{SrcPort: &port})
	defer conn.Close(t)

	syn := conn.CreateFrame(t, testbench.Layers{&testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)}})
	// Both replies must precede the initial one-second retransmission timeout.
	deadline := time.Now().Add(500 * time.Millisecond)
	conn.SendFrame(t, syn)
	flags := testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)
	first, err := conn.Expect(t, testbench.TCP{Flags: flags}, time.Until(deadline))
	if err != nil {
		t.Fatalf("initial SYN-ACK: %s", err)
	}

	conn.SendFrameStateless(t, syn)
	if _, err := conn.Expect(t, testbench.TCP{Flags: flags, SeqNum: first.SeqNum, AckNum: first.AckNum}, time.Until(deadline)); err != nil {
		t.Fatalf("SYN-ACK after repeated SYN: %s", err)
	}
	// An immediate third SYN should be rate limited.
	conn.SendFrameStateless(t, syn)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
	child, _ := dut.Accept(t, listener)
	defer dut.Close(t, child)
	if got, want := dut.GetSockOptTCPInfo(t, child).TotalRetrans, uint32(1); got != want {
		t.Errorf("accepted socket total retransmissions = %d, want %d", got, want)
	}
}
