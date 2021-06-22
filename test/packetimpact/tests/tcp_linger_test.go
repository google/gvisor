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
