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

package tcp_syncookie_test

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

// TestSynCookie test if the DUT listener is replying back using syn cookies.
// The test does not complete the handshake by not sending the ACK to SYNACK.
// When syncookies are not used, this forces the listener to retransmit SYNACK.
// And when syncookies are being used, there is no such retransmit.
func TestTCPSynCookie(t *testing.T) {
	dut := testbench.NewDUT(t)

	// Listening endpoint accepts one more connection than the listen backlog.
	_, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1 /*backlog*/)

	var withoutSynCookieConn testbench.TCPIPv4
	var withSynCookieConn testbench.TCPIPv4

	// Test if the DUT listener replies to more SYNs than listen backlog+1
	for _, conn := range []*testbench.TCPIPv4{&withoutSynCookieConn, &withSynCookieConn} {
		*conn = dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	}
	defer withoutSynCookieConn.Close(t)
	defer withSynCookieConn.Close(t)

	checkSynAck := func(t *testing.T, conn *testbench.TCPIPv4, expectRetransmit bool) {
		// Expect dut connection to have transitioned to SYN-RCVD state.
		conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})
		if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, nil, time.Second); err != nil {
			t.Fatalf("expected SYN-ACK, but got %s", err)
		}

		// If the DUT listener is using syn cookies, it will not retransmit SYNACK
		got, err := conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(uint32(*conn.RemoteSeqNum(t) - 1)), Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, nil, 2*time.Second)
		if expectRetransmit && err != nil {
			t.Fatalf("expected retransmitted SYN-ACK, but got %s", err)
		}
		if !expectRetransmit && err == nil {
			t.Fatalf("expected no retransmitted SYN-ACK, but got %s", got)
		}
	}

	t.Run("without syncookies", func(t *testing.T) { checkSynAck(t, &withoutSynCookieConn, true /*expectRetransmit*/) })
	t.Run("with syncookies", func(t *testing.T) { checkSynAck(t, &withSynCookieConn, false /*expectRetransmit*/) })
}
