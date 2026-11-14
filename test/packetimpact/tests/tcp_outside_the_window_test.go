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

package tcp_outside_the_window_test

import (
	"flag"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func TestWindowWithUnreadFIN(t *testing.T) {
	for _, tc := range []struct {
		name       string
		payload    []testbench.Layer
		firstFlags int32
		firstRead  string
		lastRead   string
	}{
		{name: "FINOnly", firstFlags: unix.MSG_PEEK},
		{name: "DataAndFIN", payload: []testbench.Layer{&testbench.Payload{Bytes: []byte("ab")}}, firstRead: "a", lastRead: "b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFD, port := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(t, listenFD)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &port}, testbench.TCP{SrcPort: &port})
			defer conn.Close(t)
			conn.Connect(t)
			fd, _ := dut.Accept(t, listenFD)
			defer dut.Close(t, fd)

			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, tc.payload...)
			ack := testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(*conn.LocalSeqNum(t)))}
			reply, err := conn.Expect(t, ack, time.Second)
			if err != nil {
				t.Fatalf("waiting for FIN ACK: %v", err)
			}
			checkState := func() {
				t.Helper()
				if got, want := uint32(dut.GetSockOptTCPInfo(t, fd).State), uint32(linux.TCP_CLOSE_WAIT); got != want {
					t.Fatalf("TCP state = %d, want CLOSE_WAIT (%d)", got, want)
				}
			}
			checkState()
			read := func(flags int32, want string) {
				t.Helper()
				if got := string(dut.Recv(t, fd, 1, unix.MSG_DONTWAIT|flags)); got != want {
					t.Fatalf("recv(flags=%d) = %q, want %q", flags, got, want)
				}
				// A window update caused by the read is not an answer to the next probe.
				deadline := time.Now().Add(100 * time.Millisecond)
				for time.Now().Before(deadline) {
					update, err := conn.Expect(t, ack, time.Until(deadline))
					if err != nil {
						break
					}
					reply = update
				}
			}
			probe := func(inside seqnum.Size, wantACK bool) {
				t.Helper()
				window := seqnum.Size(*reply.WindowSize)
				if window <= inside {
					t.Fatalf("receive window %d is too small for probe", window)
				}
				// A stateless injection leaves the peer's next sequence number at EOF.
				seq := conn.LocalSeqNum(t).Add(window - inside)
				conn.SendFrameStateless(t, conn.CreateFrame(t, testbench.Layers{
					&testbench.TCP{Flags: ack.Flags, SeqNum: testbench.Uint32(uint32(seq))},
				}, &testbench.Payload{Bytes: []byte("xy")}))
				if wantACK {
					got, err := conn.Expect(t, ack, time.Second)
					if err != nil {
						t.Fatalf("waiting for ACK while receive queue is unread: %v", err)
					}
					reply = got
					return
				}
				// Catch a reply even if it carries the wrong acknowledgment number.
				frames, _ := conn.ListenForFrame(t, testbench.Layers{nil, nil, &ack}, time.Second)
				for _, frame := range frames {
					for _, layer := range frame {
						if tcp, ok := layer.(*testbench.TCP); ok && *tcp.SrcPort == port && *tcp.DstPort == *reply.DstPort && *tcp.Flags&header.TCPFlagAck != 0 {
							t.Errorf("unexpected ACK after draining receive queue: %s", tcp)
						}
					}
				}
			}

			probe(0, true)
			read(tc.firstFlags, tc.firstRead) // Peek at EOF or leave one byte unread.
			probe(1, true)
			read(0, tc.lastRead) // Consume EOF or the final byte accompanying FIN.
			probe(0, false)
			checkState()
		})
	}
}

// TestTCPOutsideTheWindows tests the behavior of the DUT when packets arrive
// that are inside or outside the TCP window. Packets that are outside the
// window should force an extra ACK, as described in RFC793 page 69:
// https://tools.ietf.org/html/rfc793#page-69
func TestTCPOutsideTheWindow(t *testing.T) {
	for _, tt := range []struct {
		description  string
		tcpFlags     header.TCPFlags
		payload      []testbench.Layer
		seqNumOffset seqnum.Size
		expectACK    bool
	}{
		{"SYN", header.TCPFlagSyn, nil, 0, true},
		{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil, 0, true},
		{"ACK", header.TCPFlagAck, nil, 0, false},
		{"FIN", header.TCPFlagFin, nil, 0, false},
		{"Data", header.TCPFlagAck, []testbench.Layer{&testbench.Payload{Bytes: []byte("abc123")}}, 0, true},

		{"SYN", header.TCPFlagSyn, nil, 1, true},
		{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil, 1, true},
		{"ACK", header.TCPFlagAck, nil, 1, true},
		{"FIN", header.TCPFlagFin, nil, 1, false},
		{"Data", header.TCPFlagAck, []testbench.Layer{&testbench.Payload{Bytes: []byte("abc123")}}, 1, true},

		{"SYN", header.TCPFlagSyn, nil, 2, true},
		{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil, 2, true},
		{"ACK", header.TCPFlagAck, nil, 2, true},
		{"FIN", header.TCPFlagFin, nil, 2, false},
		{"Data", header.TCPFlagAck, []testbench.Layer{&testbench.Payload{Bytes: []byte("abc123")}}, 2, true},
	} {
		t.Run(fmt.Sprintf("%s%d", tt.description, tt.seqNumOffset), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(t, listenFD)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)
			conn.Connect(t)
			acceptFD, _ := dut.Accept(t, listenFD)
			defer dut.Close(t, acceptFD)

			windowSize := seqnum.Size(*conn.SynAck(t).WindowSize) + tt.seqNumOffset
			conn.Drain(t)
			// Ignore whatever incrementing that this out-of-order packet might cause
			// to the AckNum.
			localSeqNum := testbench.Uint32(uint32(*conn.LocalSeqNum(t)))
			conn.Send(t, testbench.TCP{
				Flags:  testbench.TCPFlags(tt.tcpFlags),
				SeqNum: testbench.Uint32(uint32(conn.LocalSeqNum(t).Add(windowSize))),
			}, tt.payload...)
			timeout := time.Second
			gotACK, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: localSeqNum}, timeout)
			if tt.expectACK && err != nil {
				t.Fatalf("expected an ACK packet within %s but got none: %s", timeout, err)
			}
			// Data packets w/o SYN bits are always acked by Linux. Netstack ACK's data packets
			// always right now. So only send a second segment and test for no ACK for packets
			// with no data.
			if tt.expectACK && tt.payload == nil {
				// Sending another out-of-window segment immediately should not trigger
				// an ACK if less than 500ms(default rate limit for out-of-window ACKs)
				// has passed since the last ACK was sent.
				t.Logf("sending another segment")
				conn.Send(t, testbench.TCP{
					Flags:  testbench.TCPFlags(tt.tcpFlags),
					SeqNum: testbench.Uint32(uint32(conn.LocalSeqNum(t).Add(windowSize))),
				}, tt.payload...)
				timeout := 3 * time.Second
				gotACK, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: localSeqNum}, timeout)
				if err == nil {
					t.Fatalf("expected no ACK packet but got one: %s", gotACK)
				}
			}
			if !tt.expectACK && gotACK != nil {
				t.Fatalf("expected no ACK packet within %s but got one: %s", timeout, gotACK)
			}
		})
	}
}

// TestAckOTWSeqInClosing tests that the DUT should send an ACK with
// the right ACK number when receiving a packet with OTW Seq number
// in CLOSING state. https://tools.ietf.org/html/rfc793#page-69
func TestAckOTWSeqInClosing(t *testing.T) {
	for _, tt := range []struct {
		description  string
		flags        header.TCPFlags
		payloads     testbench.Layers
		seqNumOffset seqnum.Size
		expectACK    bool
	}{
		{"SYN", header.TCPFlagSyn, nil, 0, true},
		{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil, 0, true},
		{"ACK", header.TCPFlagAck, nil, 0, false},
		{"FINACK", header.TCPFlagFin | header.TCPFlagAck, nil, 0, false},
		{"Data", header.TCPFlagAck, []testbench.Layer{&testbench.Payload{Bytes: []byte("Sample Data")}}, 0, false},

		{"SYN", header.TCPFlagSyn, nil, 1, true},
		{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil, 1, true},
		{"ACK", header.TCPFlagAck, nil, 1, true},
		{"FINACK", header.TCPFlagFin | header.TCPFlagAck, nil, 1, true},
		{"Data", header.TCPFlagAck, []testbench.Layer{&testbench.Payload{Bytes: []byte("Sample Data")}}, 1, true},

		{"SYN", header.TCPFlagSyn, nil, 2, true},
		{"SYNACK", header.TCPFlagSyn | header.TCPFlagAck, nil, 2, true},
		{"ACK", header.TCPFlagAck, nil, 2, true},
		{"FINACK", header.TCPFlagFin | header.TCPFlagAck, nil, 2, true},
		{"Data", header.TCPFlagAck, []testbench.Layer{&testbench.Payload{Bytes: []byte("Sample Data")}}, 2, true},
	} {
		t.Run(fmt.Sprintf("%s%d", tt.description, tt.seqNumOffset), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(t, listenFD)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)
			conn.Connect(t)
			acceptFD, _ := dut.Accept(t, listenFD)
			defer dut.Close(t, acceptFD)

			dut.Shutdown(t, acceptFD, unix.SHUT_WR)

			if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second); err != nil {
				t.Fatalf("expected FINACK from DUT, but got none: %s", err)
			}

			// Do not ack the FIN from DUT so that the TCP state on DUT is CLOSING instead of CLOSED.
			seqNumForTheirFIN := testbench.Uint32(uint32(*conn.RemoteSeqNum(t)) - 1)
			conn.Send(t, testbench.TCP{AckNum: seqNumForTheirFIN, Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)})

			gotTCP, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
			if err != nil {
				t.Fatalf("expected an ACK to our FIN, but got none: %s", err)
			}

			// Consume the queued FIN so the probe tests closing-state handling
			// with an empty receive queue, rather than receive-queue validation.
			dut.ExpectEOF(t, acceptFD, linux.TCP_CLOSING)

			windowSize := seqnum.Size(*gotTCP.WindowSize) + tt.seqNumOffset
			conn.SendFrameStateless(t, conn.CreateFrame(t, testbench.Layers{&testbench.TCP{
				SeqNum: testbench.Uint32(uint32(conn.LocalSeqNum(t).Add(windowSize))),
				AckNum: seqNumForTheirFIN,
				Flags:  testbench.TCPFlags(tt.flags),
			}}, tt.payloads...))

			gotACK, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
			if tt.expectACK && err != nil {
				t.Errorf("expected an ACK but got none: %s", err)
			}
			if !tt.expectACK && gotACK != nil {
				t.Errorf("expected no ACK but got one: %s", gotACK)
			}
		})
	}
}
