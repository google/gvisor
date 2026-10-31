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

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

// TestTCPSynCookie checks which final handshake flags a listener accepts
// for a saved SYN and for a SYN cookie.
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

			listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1 /* backlog */)
			defer dut.Close(t, listenFD)

			// Offer SACK without timestamps. Like gVisor, Linux omits SACK
			// from a cookie SYN-ACK when the peer hasn't offered timestamps:
			// https://github.com/torvalds/linux/blob/adc218676/net/ipv4/tcp_input.c#L7232-L7239
			var options [4]byte
			n := header.EncodeSACKPermittedOption(options[:])
			header.AddTCPOptionPadding(options[:], n)
			synACK := testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}
			sendSYN := func() (*testbench.TCPIPv4, bool) {
				t.Helper()
				conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
				t.Cleanup(func() { conn.Close(t) })
				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn), Options: options[:]})
				reply, err := conn.Expect(t, synACK, time.Second)
				if err != nil {
					t.Fatalf("waiting for SYN-ACK: %v", err)
				}
				return &conn, header.ParseSynOptions(reply.Options, true /* isAck */).SACKPermitted
			}

			withoutSynCookieConn, sack := sendSYN()
			if !sack {
				t.Fatal("first SYN-ACK did not negotiate SACK on an empty queue")
			}
			// Keep each SYN outstanding. Linux and gVisor can save different
			// numbers of half-open connections for the same listen backlog.
			var withSynCookieConn *testbench.TCPIPv4
			for range 16 {
				conn, sack := sendSYN()
				if !sack {
					withSynCookieConn = conn
					break
				}
			}
			if withSynCookieConn == nil {
				t.Fatal("listener never switched to SYN cookies")
			}

			for _, c := range []struct {
				desc             string
				conn             *testbench.TCPIPv4
				expectRetransmit bool
			}{
				{desc: "without syncookies", conn: withoutSynCookieConn, expectRetransmit: true},
				{desc: "with syncookies", conn: withSynCookieConn, expectRetransmit: false},
			} {
				t.Run(c.desc, func(t *testing.T) {
					retransmit := synACK
					retransmit.SeqNum = testbench.Uint32(uint32(*c.conn.RemoteSeqNum(t) - 1))
					got, err := c.conn.Expect(t, retransmit, 2*time.Second)
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
				{desc: "with syncookies", conn: withSynCookieConn},
				{desc: "without syncookies", conn: withoutSynCookieConn},
			} {
				t.Run(c.desc, func(t *testing.T) {
					pfds := dut.Poll(t, []unix.PollFd{{Fd: listenFD, Events: math.MaxInt16}}, 0 /*timeout*/)
					if got, want := len(pfds), 0; got != want {
						t.Fatalf("dut.Poll(...) = %d, want = %d", got, want)
					}

					sampleData := []byte("Sample Data")
					samplePayload := &testbench.Payload{Bytes: sampleData}

					c.conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(test.flags)}, samplePayload)
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
						if test.flags.Contains(header.TCPFlagFin) {
							dut.PollOne(t, fd, unix.POLLIN|unix.POLLRDHUP, time.Second)
						}
						got := dut.Recv(t, fd, int32(len(sampleData)), 0)
						if diff := cmp.Diff(got, sampleData); diff != "" {
							t.Fatalf("dut.Recv: data mismatch (-want +got):\n%s", diff)
						}
						dut.Close(t, fd)
					}
				})
			}
		})
	}
}
