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

// sendSACKSYN offers SACK, optionally with timestamps, and returns the options
// the listener sent in its SYN-ACK. Keep the connection open until test cleanup.
func sendSACKSYN(t *testing.T, dut *testbench.DUT, port uint16, timestamps bool) (*testbench.TCPIPv4, header.TCPSynOptions) {
	t.Helper()
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &port}, testbench.TCP{SrcPort: &port})
	t.Cleanup(func() { conn.Close(t) })
	var options [header.TCPOptionsMaximumSize]byte
	n := header.EncodeSACKPermittedOption(options[:])
	if timestamps {
		n += header.EncodeTSOption(1, 0, options[n:])
	}
	n += header.AddTCPOptionPadding(options[:], n)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn), Options: options[:n]})
	reply, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second)
	if err != nil {
		t.Fatalf("waiting for SYN-ACK: %v", err)
	}
	return &conn, header.ParseSynOptions(reply.Options, true /* isAck */)
}

// fillSYNQueue returns a connection whose SYN was saved and one that received
// a SYN cookie. Linux and gVisor can save different numbers of half-open
// connections for the same listen backlog. Both omit SACK from the cookie
// SYN-ACK when the peer hasn't offered timestamps:
// https://github.com/torvalds/linux/blob/adc218676/net/ipv4/tcp_input.c#L7232-L7239
func fillSYNQueue(t *testing.T, dut *testbench.DUT, port uint16) (*testbench.TCPIPv4, *testbench.TCPIPv4) {
	t.Helper()
	saved, opts := sendSACKSYN(t, dut, port, false)
	if !opts.SACKPermitted {
		t.Fatal("first SYN-ACK did not negotiate SACK on an empty queue")
	}
	for range 16 {
		conn, opts := sendSACKSYN(t, dut, port, false)
		if !opts.SACKPermitted {
			return saved, conn
		}
	}
	t.Fatal("listener never switched to SYN cookies")
	return nil, nil
}

func TestSynCookieSACK(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFD, port := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1 /* backlog */)
	t.Cleanup(func() { dut.Close(t, listenFD) })
	fillSYNQueue(t, &dut, port)
	conn, opts := sendSACKSYN(t, &dut, port, true)
	if !opts.TS || opts.TSEcr != 1 || !opts.SACKPermitted {
		t.Fatalf("cookie SYN-ACK options = %+v, want echoed TSVal 1 and SACK", opts)
	}

	var ts [12]byte
	n := header.EncodeTSOption(2, opts.TSVal, ts[:])
	header.AddTCPOptionPadding(ts[:], n)
	ack := testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), Options: ts[:]}
	conn.Send(t, ack)
	dut.PollOne(t, listenFD, unix.POLLIN, time.Second)
	fd, _ := dut.Accept(t, listenFD)
	t.Cleanup(func() { dut.Close(t, fd) })

	// A SACK block for the byte beyond the hole proves that the accepted
	// socket recovered the option from the handshake.
	hole := *conn.LocalSeqNum(t)
	ack.SeqNum = testbench.Uint32(uint32(hole + 1))
	conn.Send(t, ack, &testbench.Payload{Bytes: []byte{1}})
	reply, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(hole))}, time.Second)
	if err != nil {
		t.Fatalf("waiting for ACK of out-of-order data: %v", err)
	}
	got := header.ParseTCPOptions(reply.Options).SACKBlocks
	want := []header.SACKBlock{{Start: hole + 1, End: hole + 2}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SACK blocks (-want +got):\n%s", diff)
	}
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

			withoutSynCookieConn, withSynCookieConn := fillSYNQueue(t, &dut, remotePort)
			synACK := testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}
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
