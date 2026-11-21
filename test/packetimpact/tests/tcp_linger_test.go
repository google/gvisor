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

package tcp_linger_test

import (
	"context"
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func createSocket(t *testing.T, dut testbench.DUT) (int32, int32, testbench.TCPIPv4) {
	listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	conn.Connect(t)
	acceptFD, _ := dut.Accept(t, listenFD)
	return acceptFD, listenFD, conn
}

func closeAll(t *testing.T, dut testbench.DUT, listenFD int32, conn testbench.TCPIPv4) {
	conn.Close(t)
	dut.Close(t, listenFD)
}

// lingerDuration is the timeout value used with SO_LINGER socket option.
const lingerDuration = 3 * time.Second

// TestTCPLingerZeroTimeout tests when SO_LINGER is set with zero timeout. DUT
// should send RST-ACK when socket is closed.
func TestTCPLingerZeroTimeout(t *testing.T) {
	// Create a socket, listen, TCP connect, and accept.
	dut := testbench.NewDUT(t)
	acceptFD, listenFD, conn := createSocket(t, dut)
	defer closeAll(t, dut, listenFD, conn)

	dut.SetSockLingerOption(t, acceptFD, 0, true)
	dut.Close(t, acceptFD)

	// If the linger timeout is set to zero, the DUT should send a RST.
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst | header.TCPFlagAck)}, time.Second); err != nil {
		t.Errorf("expected RST-ACK packet within a second but got none: %s", err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
}

// TestTCPLingerOff tests when SO_LINGER is not set. DUT should send FIN-ACK
// when socket is closed.
func TestTCPLingerOff(t *testing.T) {
	// Create a socket, listen, TCP connect, and accept.
	dut := testbench.NewDUT(t)
	acceptFD, listenFD, conn := createSocket(t, dut)
	defer closeAll(t, dut, listenFD, conn)

	dut.Close(t, acceptFD)

	// If SO_LINGER is not set, DUT should send a FIN-ACK.
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second); err != nil {
		t.Errorf("expected FIN-ACK packet within a second but got none: %s", err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
}

// TestTCPLingerNonZeroTimeout tests when SO_LINGER is set with non-zero timeout.
// DUT should close the socket after timeout.
func TestTCPLingerNonZeroTimeout(t *testing.T) {
	for _, tt := range []struct {
		description string
		lingerOn    bool
	}{
		{"WithNonZeroLinger", true},
		{"WithoutLinger", false},
	} {
		t.Run(tt.description, func(t *testing.T) {
			// Create a socket, listen, TCP connect, and accept.
			dut := testbench.NewDUT(t)
			acceptFD, listenFD, conn := createSocket(t, dut)
			defer closeAll(t, dut, listenFD, conn)

			dut.SetSockLingerOption(t, acceptFD, lingerDuration, tt.lingerOn)

			start := time.Now()
			dut.CloseWithErrno(context.Background(), t, acceptFD)
			elapsed := time.Since(start)

			expectedMaximum := time.Second
			if tt.lingerOn {
				expectedMaximum += lingerDuration
				if elapsed < lingerDuration {
					t.Errorf("expected close to take at least %s, but took %s", lingerDuration, elapsed)
				}
			}
			if elapsed >= expectedMaximum {
				t.Errorf("expected close to take at most %s, but took %s", expectedMaximum, elapsed)
			}

			if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second); err != nil {
				t.Errorf("expected FIN-ACK packet within a second but got none: %s", err)
			}
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
		})
	}
}

// TestTCPLingerSendNonZeroTimeout tests when SO_LINGER is set with non-zero
// timeout and send a packet. DUT should close the socket after timeout.
func TestTCPLingerSendNonZeroTimeout(t *testing.T) {
	for _, tt := range []struct {
		description string
		lingerOn    bool
	}{
		{"WithSendNonZeroLinger", true},
		{"WithoutLinger", false},
	} {
		t.Run(tt.description, func(t *testing.T) {
			// Create a socket, listen, TCP connect, and accept.
			dut := testbench.NewDUT(t)
			acceptFD, listenFD, conn := createSocket(t, dut)
			defer closeAll(t, dut, listenFD, conn)

			dut.SetSockLingerOption(t, acceptFD, lingerDuration, tt.lingerOn)

			// Send data.
			sampleData := []byte("Sample Data")
			dut.Send(t, acceptFD, sampleData, 0)

			start := time.Now()
			dut.CloseWithErrno(context.Background(), t, acceptFD)
			elapsed := time.Since(start)

			expectedMaximum := time.Second
			if tt.lingerOn {
				expectedMaximum += lingerDuration
				if elapsed < lingerDuration {
					t.Errorf("expected close to take at least %s, but took %s", lingerDuration, elapsed)
				}
			}
			if elapsed >= expectedMaximum {
				t.Errorf("expected close to take at most %s, but took %s", expectedMaximum, elapsed)
			}

			samplePayload := &testbench.Payload{Bytes: sampleData}
			if _, err := conn.ExpectData(t, &testbench.TCP{}, samplePayload, time.Second); err != nil {
				t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
			}

			if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second); err != nil {
				t.Errorf("expected FIN-ACK packet within a second but got none: %s", err)
			}
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
		})
	}
}

// TestTCPLingerShutdownZeroTimeout tests SO_LINGER with shutdown() and zero
// timeout. DUT should send RST-ACK when socket is closed.
func TestTCPLingerShutdownZeroTimeout(t *testing.T) {
	// Create a socket, listen, TCP connect, and accept.
	dut := testbench.NewDUT(t)
	acceptFD, listenFD, conn := createSocket(t, dut)
	defer closeAll(t, dut, listenFD, conn)

	dut.SetSockLingerOption(t, acceptFD, 0, true)
	dut.Shutdown(t, acceptFD, unix.SHUT_RDWR)
	dut.Close(t, acceptFD)

	// Shutdown will send FIN-ACK with read/write option.
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second); err != nil {
		t.Errorf("expected FIN-ACK packet within a second but got none: %s", err)
	}

	// If the linger timeout is set to zero, the DUT should send a RST.
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst | header.TCPFlagAck)}, time.Second); err != nil {
		t.Errorf("expected RST-ACK packet within a second but got none: %s", err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
}

// TestTCPLingerShutdownSendNonZeroTimeout tests SO_LINGER with shutdown() and
// non-zero timeout. DUT should close the socket after timeout.
func TestTCPLingerShutdownSendNonZeroTimeout(t *testing.T) {
	for _, tt := range []struct {
		description string
		lingerOn    bool
	}{
		{"shutdownRDWR", true},
		{"shutdownRDWR", false},
	} {
		t.Run(tt.description, func(t *testing.T) {
			// Create a socket, listen, TCP connect, and accept.
			dut := testbench.NewDUT(t)
			acceptFD, listenFD, conn := createSocket(t, dut)
			defer closeAll(t, dut, listenFD, conn)

			dut.SetSockLingerOption(t, acceptFD, lingerDuration, tt.lingerOn)

			// Send data.
			sampleData := []byte("Sample Data")
			dut.Send(t, acceptFD, sampleData, 0)

			dut.Shutdown(t, acceptFD, unix.SHUT_RDWR)

			start := time.Now()
			dut.CloseWithErrno(context.Background(), t, acceptFD)
			elapsed := time.Since(start)

			expectedMaximum := time.Second
			if tt.lingerOn {
				expectedMaximum += lingerDuration
				if elapsed < lingerDuration {
					t.Errorf("expected close to take at least %s, but took %s", lingerDuration, elapsed)
				}
			}
			if elapsed >= expectedMaximum {
				t.Errorf("expected close to take at most %s, but took %s", expectedMaximum, elapsed)
			}

			samplePayload := &testbench.Payload{Bytes: sampleData}
			if _, err := conn.ExpectData(t, &testbench.TCP{}, samplePayload, time.Second); err != nil {
				t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
			}

			if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second); err != nil {
				t.Errorf("expected FIN-ACK packet within a second but got none: %s", err)
			}
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
		})
	}
}

func TestTCPLingerNonEstablished(t *testing.T) {
	dut := testbench.NewDUT(t)
	newFD := dut.Socket(t, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	dut.SetSockLingerOption(t, newFD, lingerDuration, true)

	// As the socket is in the initial state, Close() should not linger
	// and return immediately.
	start := time.Now()
	dut.CloseWithErrno(context.Background(), t, newFD)
	elapsed := time.Since(start)

	expectedMaximum := time.Second
	if elapsed >= time.Second {
		t.Errorf("expected close to take at most %s, but took %s", expectedMaximum, elapsed)
	}
}

// stateLingerDuration is the SO_LINGER timeout in TestTCPLingerStates.
const stateLingerDuration = 10 * time.Second

// maxCloseDuration is how long close may take in TestTCPLingerStates after the
// peer acknowledges the DUT's FIN, or after close starts if close does not
// wait. It is much longer than such a close takes and much shorter than
// stateLingerDuration, so that a close that waits for the linger timeout fails
// clearly.
const maxCloseDuration = stateLingerDuration / 2

// blockCheckDelay is how long TestTCPLingerStates waits before it checks that
// close is blocked. It also gives the close RPC time to reach the DUT before
// the test acknowledges the DUT's FIN.
const blockCheckDelay = 500 * time.Millisecond

// expectFIN expects a FIN from the DUT.
func expectFIN(t *testing.T, conn *testbench.TCPIPv4) {
	t.Helper()

	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)}, time.Second); err != nil {
		t.Fatalf("expected FIN-ACK packet within a second but got none: %s", err)
	}
}

// shutdownWrite shuts down the DUT's socket fd for writing and expects the FIN
// that the DUT sends.
func shutdownWrite(t *testing.T, dut testbench.DUT, fd int32, conn *testbench.TCPIPv4) {
	t.Helper()

	dut.Shutdown(t, fd, unix.SHUT_WR)
	expectFIN(t, conn)
}

// sendFIN sends a FIN to the DUT and expects the DUT to acknowledge it. The FIN
// acknowledges ackNum, or all that the DUT sent if ackNum is nil.
func sendFIN(t *testing.T, conn *testbench.TCPIPv4, ackNum *uint32) {
	t.Helper()

	conn.Send(t, testbench.TCP{AckNum: ackNum, Flags: testbench.TCPFlags(header.TCPFlagFin | header.TCPFlagAck)})
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second); err != nil {
		t.Fatalf("expected ACK packet for our FIN within a second but got none: %s", err)
	}
}

// waitForTCPState waits until the TCP state of the DUT's socket fd is want.
func waitForTCPState(t *testing.T, dut testbench.DUT, fd int32, want uint32) {
	t.Helper()

	// The DUT can change its state after it sends the segment that the test
	// expects, or without sending a segment, so poll.
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := uint32(dut.GetSockOptTCPInfo(t, fd).State)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("got TCP state %d, want %d", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTCPLingerStates tests close with a nonzero SO_LINGER timeout in each TCP
// state from ESTABLISHED to TIME-WAIT. As in Linux's sk_stream_wait_close,
// close waits only while the DUT's FIN is not acknowledged, that is in
// FIN-WAIT-1, CLOSING and LAST-ACK. It returns as soon as the peer acknowledges
// the FIN, even if the peer keeps its side of the connection open.
func TestTCPLingerStates(t *testing.T) {
	for _, tt := range []struct {
		description string
		// setUp, if not nil, moves the DUT's established socket fd to the
		// state under test.
		setUp func(t *testing.T, dut testbench.DUT, fd int32, conn *testbench.TCPIPv4)
		// state, if not zero, is the TCP state of the socket when the test
		// closes it.
		state uint32
		// sendsFIN is true if close sends the DUT's FIN.
		sendsFIN bool
		// waits is true if close waits until the peer acknowledges the FIN.
		waits bool
	}{
		{
			description: "ESTABLISHED",
			state:       linux.TCP_ESTABLISHED,
			sendsFIN:    true,
			waits:       true,
		},
		{
			description: "FIN_WAIT_1",
			setUp:       shutdownWrite,
			state:       linux.TCP_FIN_WAIT1,
			waits:       true,
		},
		{
			description: "FIN_WAIT_2",
			setUp: func(t *testing.T, dut testbench.DUT, fd int32, conn *testbench.TCPIPv4) {
				shutdownWrite(t, dut, fd, conn)
				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
			},
			state: linux.TCP_FIN_WAIT2,
		},
		{
			description: "CLOSE_WAIT",
			setUp: func(t *testing.T, _ testbench.DUT, _ int32, conn *testbench.TCPIPv4) {
				sendFIN(t, conn, nil)
			},
			state:    linux.TCP_CLOSE_WAIT,
			sendsFIN: true,
			waits:    true,
		},
		{
			description: "CLOSING",
			setUp: func(t *testing.T, dut testbench.DUT, fd int32, conn *testbench.TCPIPv4) {
				shutdownWrite(t, dut, fd, conn)
				// Send a FIN that does not acknowledge the DUT's FIN,
				// as in a simultaneous close.
				finSeqNum := uint32(*conn.RemoteSeqNum(t)) - 1
				sendFIN(t, conn, &finSeqNum)
			},
			state: linux.TCP_CLOSING,
			waits: true,
		},
		{
			description: "LAST_ACK",
			setUp: func(t *testing.T, dut testbench.DUT, fd int32, conn *testbench.TCPIPv4) {
				sendFIN(t, conn, nil)
				shutdownWrite(t, dut, fd, conn)
			},
			state: linux.TCP_LAST_ACK,
			waits: true,
		},
		{
			description: "TIME_WAIT",
			setUp: func(t *testing.T, dut testbench.DUT, fd int32, conn *testbench.TCPIPv4) {
				shutdownWrite(t, dut, fd, conn)
				sendFIN(t, conn, nil)
			},
			// The test does not check the state: on Linux, a TIME-WAIT
			// socket takes over the connection, and the socket that the
			// test closes reports CLOSE.
		},
	} {
		t.Run(tt.description, func(t *testing.T) {
			// Create a socket, listen, TCP connect, and accept.
			dut := testbench.NewDUT(t)
			acceptFD, listenFD, conn := createSocket(t, dut)
			defer closeAll(t, dut, listenFD, conn)

			dut.SetSockLingerOption(t, acceptFD, stateLingerDuration, true)
			if tt.setUp != nil {
				tt.setUp(t, dut, acceptFD, &conn)
			}
			if tt.state != 0 {
				waitForTCPState(t, dut, acceptFD, tt.state)
			}

			start, since := time.Now(), "it started"
			closed := make(chan struct{})
			go func() {
				defer close(closed)
				if ret, err := dut.CloseWithErrno(context.Background(), t, acceptFD); ret != 0 {
					t.Errorf("failed to close: %s", err)
				}
			}()
			// Do not end the test before close returns.
			defer func() { <-closed }()

			if tt.sendsFIN {
				expectFIN(t, &conn)
			}
			if tt.waits {
				select {
				case <-closed:
					t.Fatalf("close returned after %s, before the FIN was acknowledged", time.Since(start))
				case <-time.After(blockCheckDelay):
				}
				// Acknowledge the DUT's FIN. In ESTABLISHED and
				// FIN-WAIT-1, the test does not send a FIN, so the
				// peer keeps its side of the connection open.
				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
				start, since = time.Now(), "the FIN was acknowledged"
			}
			<-closed
			if elapsed := time.Since(start); elapsed > maxCloseDuration {
				t.Errorf("close returned %s after %s, want at most %s", elapsed, since, maxCloseDuration)
			}
		})
	}
}
