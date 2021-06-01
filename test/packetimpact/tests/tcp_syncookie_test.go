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
	"fmt"
	"math"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

// TestTCPSynCookie tests for ACK handling for connections in SYNRCVD state
// connections with and without syncookies. It verifies if the passive open
// connection is indeed using syncookies before proceeding.
func TestTCPSynCookie(t *testing.T) {
	dut := testbench.NewDUT(t)
	for _, tt := range []struct {
		accept bool
		flags  header.TCPFlags
	}{
		{accept: true, flags: header.TCPFlagAck},
		{accept: true, flags: header.TCPFlagAck | header.TCPFlagPsh},
		{accept: false, flags: header.TCPFlagAck | header.TCPFlagSyn},
		{accept: true, flags: header.TCPFlagAck | header.TCPFlagFin},
		{accept: false, flags: header.TCPFlagAck | header.TCPFlagRst},
		{accept: false, flags: header.TCPFlagRst},
	} {
		t.Run(fmt.Sprintf("flags=%s", tt.flags), func(t *testing.T) {
			// Make a copy before parallelizing the test and refer to that
			// within the test. Otherwise, the test reference could be pointing
			// to an incorrect variant based on how it is scheduled.
			test := tt

			t.Parallel()

			// Listening endpoint accepts one more connection than the listen
			// backlog. Listener starts using syncookies when it sees a new SYN
			// and has backlog size of connections in SYNRCVD state. Keep the
			// listen backlog 1, so that the test can define 2 connections
			// without and with using syncookies.
			listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1 /*backlog*/)
			defer dut.Close(t, listenFD)

			var withoutSynCookieConn testbench.TCPIPv4
			var withSynCookieConn testbench.TCPIPv4

			for _, conn := range []*testbench.TCPIPv4{&withoutSynCookieConn, &withSynCookieConn} {
				*conn = dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			}
			defer withoutSynCookieConn.Close(t)
			defer withSynCookieConn.Close(t)

			// Setup the 2 connections in SYNRCVD state and verify if one of the
			// connection is indeed using syncookies by checking for absence of
			// SYNACK retransmits.
			for _, c := range []struct {
				desc             string
				conn             *testbench.TCPIPv4
				expectRetransmit bool
			}{
				{desc: "without syncookies", conn: &withoutSynCookieConn, expectRetransmit: true},
				{desc: "with syncookies", conn: &withSynCookieConn, expectRetransmit: false},
			} {
				t.Run(c.desc, func(t *testing.T) {
					// Expect dut connection to have transitioned to SYNRCVD state.
					c.conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})
					if _, err := c.conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, nil, time.Second); err != nil {
						t.Fatalf("expected SYNACK, but got %s", err)
					}

					// If the DUT listener is using syn cookies, it will not retransmit SYNACK.
					got, err := c.conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(uint32(*c.conn.RemoteSeqNum(t) - 1)), Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, nil, 2*time.Second)
					if c.expectRetransmit && err != nil {
						t.Fatalf("expected retransmitted SYNACK, but got %s", err)
					}
					if !c.expectRetransmit && err == nil {
						t.Fatalf("expected no retransmitted SYNACK, but got %s", got)
					}
				})
			}

			// Check whether ACKs with the given flags completes the handshake.
			for _, c := range []struct {
				desc string
				conn *testbench.TCPIPv4
			}{
				{desc: "with syncookies", conn: &withSynCookieConn},
				{desc: "without syncookies", conn: &withoutSynCookieConn},
			} {
				t.Run(c.desc, func(t *testing.T) {
					pfds := dut.Poll(t, []unix.PollFd{{Fd: listenFD, Events: math.MaxInt16}}, 0 /*timeout*/)
					if got, want := len(pfds), 0; got != want {
						t.Fatalf("dut.Poll(...) = %d, want = %d", got, want)
					}

					c.conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(test.flags)})
					pfds = dut.Poll(t, []unix.PollFd{{Fd: listenFD, Events: unix.POLLIN}}, time.Second)
					want := 0
					if test.accept {
						want = 1
					}
					if got := len(pfds); got != want {
						t.Fatalf("got dut.Poll(...) = %d, want = %d", got, want)
					}
					// Accept the connection to enable poll on any subsequent connection.
					if test.accept {
						fd, _ := dut.Accept(t, listenFD)
						dut.Close(t, fd)
					}
				})
			}
		})
	}
}
