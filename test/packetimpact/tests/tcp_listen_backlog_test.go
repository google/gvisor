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

package tcp_listen_backlog_test

import (
	"bytes"
	"flag"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

// TestTCPListenBacklog tests for a listening endpoint behavior:
// (1) reply to more SYNs than what is configured as listen backlog
// (2) ignore ACKs (that complete a handshake) when the accept queue is full
// (3) ignore incoming SYNs when the accept queue is full
func TestTCPListenBacklog(t *testing.T) {
	dut := testbench.NewDUT(t)

	// This is the number of pending connections before SYN cookies are used.
	const backlog = 10

	listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP, backlog)
	defer dut.Close(t, listenFd)

	// Fill the SYN queue with connections in SYN-RCVD. We will use these to test
	// that ACKs received while the accept queue is full are ignored.
	var synQueueConns [backlog]testbench.TCPIPv4
	defer func() {
		for i := range synQueueConns {
			synQueueConns[i].Close(t)
		}
	}()
	{
		var wg sync.WaitGroup
		for i := range synQueueConns {
			conn := &synQueueConns[i]
			*conn = dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{})

			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})
				if got, err := conn.Expect(t, testbench.TCP{}, time.Second); err != nil {
					t.Errorf("%d: expected TCP frame: %s", i, err)
				} else if got, want := *got.Flags, header.TCPFlagSyn|header.TCPFlagAck; got != want {
					t.Errorf("%d: got %s, want %s", i, got, want)
				}
			}(i)
		}
		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
	}

	const payloadLen = 1
	payload := testbench.Payload{Bytes: testbench.GenerateRandomPayload(t, payloadLen)}

	// Fill the accept queue with connections established using SYN cookies.
	var synCookieConns [backlog + 1]testbench.TCPIPv4
	defer func() {
		for i := range synCookieConns {
			synCookieConns[i].Close(t)
		}
	}()
	{
		var wg sync.WaitGroup
		for i := range synCookieConns {
			conn := &synCookieConns[i]
			*conn = dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{})

			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})
				if got, err := conn.Expect(t, testbench.TCP{}, time.Second); err != nil {
					t.Errorf("%d: expected TCP frame: %s", i, err)
				} else if got, want := *got.Flags, header.TCPFlagSyn|header.TCPFlagAck; got != want {
					t.Errorf("%d: got %s, want %s", i, got, want)
				}
				// Send a payload so we can observe the dut ACK.
				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, &payload)
				if got, err := conn.Expect(t, testbench.TCP{}, time.Second); err != nil {
					t.Errorf("%d: expected TCP frame: %s", i, err)
				} else if got, want := *got.Flags, header.TCPFlagAck; got != want {
					t.Errorf("%d: got %s, want %s", i, got, want)
				}
			}(i)
		}
		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
	}

	// Send ACKs to complete the handshakes. These are expected to be dropped
	// because the accept queue is full.
	{
		var wg sync.WaitGroup
		for i := range synQueueConns {
			conn := &synQueueConns[i]
			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
				// Wait for the SYN-ACK to be retransmitted to confirm the ACK was
				// dropped.
				seqNum := uint32(*conn.RemoteSeqNum(t) - 1)
				if got, err := conn.Expect(t, testbench.TCP{SeqNum: &seqNum}, time.Second); err != nil {
					t.Errorf("%d: expected TCP frame: %s", i, err)
				} else if got, want := *got.Flags, header.TCPFlagSyn|header.TCPFlagAck; got != want {
					t.Errorf("%d: got %s, want %s", i, got, want)
				}
			}(i)
		}

		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
	}

	func() {
		// Now initiate a new connection when the accept queue is full.
		connectingConn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{})
		defer connectingConn.Close(t)
		// Expect dut connection to drop the SYN.
		connectingConn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})
		if got, err := connectingConn.Expect(t, testbench.TCP{}, time.Second); err == nil {
			t.Fatalf("expected no TCP frame, got %s", got)
		}
	}()

	// Drain the accept queue.
	{
		var wg sync.WaitGroup
		for i := range synCookieConns {
			conn := &synCookieConns[i]

			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				fd, _ := dut.Accept(t, listenFd)
				b := dut.Recv(t, fd, payloadLen+1, 0)
				dut.Close(t, fd)
				if !bytes.Equal(b, payload.Bytes) {
					t.Errorf("connection %d: got dut.Recv = %x, want = %x", i, b, payload.Bytes)
				}

				if got, err := conn.Expect(t, testbench.TCP{}, time.Second); err != nil {
					t.Errorf("%d: expected TCP frame: %s", i, err)
				} else if got, want := *got.Flags, header.TCPFlagFin|header.TCPFlagAck; got != want {
					t.Errorf("%d: got %s, want %s", i, got, want)
				}

				// Prevent retransmission.
				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
			}(i)
		}
		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
	}

	// Complete the partial connections to move them from the SYN queue to the
	// accept queue. We will use these to test that connections in the accept
	// queue are closed on listener shutdown.
	{
		var wg sync.WaitGroup
		for i := range synQueueConns {
			conn := &synQueueConns[i]
			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				tcp := testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}

				// Exercise connections with and without pending data.
				if i%2 == 0 {
					// Send ACK with no payload; wait for absence of SYN-ACK retransmit.
					conn.Send(t, tcp)
					if got, err := conn.Expect(t, testbench.TCP{}, time.Second); err == nil {
						t.Errorf("%d: expected no TCP frame, got %s", i, got)
					}
				} else {
					// Send ACK with payload; wait for ACK.
					conn.Send(t, tcp, &payload)
					if got, err := conn.Expect(t, testbench.TCP{}, time.Second); err != nil {
						t.Errorf("%d: expected TCP frame: %s", i, err)
					} else if got, want := *got.Flags, header.TCPFlagAck; got != want {
						t.Errorf("%d: got %s, want %s", i, got, want)
					}
				}
			}(i)
		}

		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
	}

	// The accept queue now has N-1 connections in it. The next incoming SYN will
	// enter the SYN queue, and the one following will use SYN cookies. We test
	// both.
	var connectingConns [2]testbench.TCPIPv4
	defer func() {
		for i := range connectingConns {
			connectingConns[i].Close(t)
		}
	}()
	{
		var wg sync.WaitGroup
		for i := range connectingConns {
			conn := &connectingConns[i]
			*conn = dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{})

			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})
				if got, err := conn.Expect(t, testbench.TCP{}, time.Second); err != nil {
					t.Errorf("%d: expected TCP frame: %s", i, err)
				} else if got, want := *got.Flags, header.TCPFlagSyn|header.TCPFlagAck; got != want {
					t.Errorf("%d: got %s, want %s", i, got, want)
				}
			}(i)
		}
		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
	}

	dut.Shutdown(t, listenFd, unix.SHUT_RD)

	var wg sync.WaitGroup

	// Shutdown causes Connections in the accept queue to be closed.
	for i := range synQueueConns {
		conn := &synQueueConns[i]
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			if got, err := conn.Expect(t, testbench.TCP{}, time.Second); err != nil {
				t.Errorf("%d: expected TCP frame: %s", i, err)
			} else if got, want := *got.Flags, header.TCPFlagRst|header.TCPFlagAck; got != want {
				t.Errorf("%d: got %s, want %s", i, got, want)
			}
		}(i)
	}

	for i := range connectingConns {
		conn := &connectingConns[i]

		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			if got, err := conn.Expect(t, testbench.TCP{}, time.Second); err == nil {
				t.Errorf("%d: expected no TCP frame, got %s", i, got)
			}
		}(i)
	}

	wg.Wait()
}
