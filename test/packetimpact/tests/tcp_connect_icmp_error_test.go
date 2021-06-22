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

package tcp_connect_icmp_error_test

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

func sendICMPError(t *testing.T, conn *testbench.TCPIPv4, tcp *testbench.TCP) {
	t.Helper()

	icmpPayload := testbench.Layers{tcp.Prev(), tcp}
	bytes, err := icmpPayload.ToBytes()
	if err != nil {
		t.Fatalf("got icmpPayload.ToBytes() = (_, %s), want = (_, nil)", err)
	}

	layers := conn.CreateFrame(t, nil)
	layers[len(layers)-1] = &testbench.ICMPv4{
		Type:    testbench.ICMPv4Type(header.ICMPv4DstUnreachable),
		Code:    testbench.ICMPv4Code(header.ICMPv4HostUnreachable),
		Payload: bytes,
	}
	conn.SendFrameStateless(t, layers)
}

// TestTCPConnectICMPError tests for the handshake to fail and the socket state
// cleaned up on receiving an ICMP error.
func TestTCPConnectICMPError(t *testing.T) {
	dut := testbench.NewDUT(t)

	clientFD, clientPort := dut.CreateBoundSocket(t, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP, dut.Net.RemoteIPv4)
	port := uint16(9001)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{SrcPort: &port, DstPort: &clientPort}, testbench.TCP{SrcPort: &clientPort, DstPort: &port})
	defer conn.Close(t)
	sa := unix.SockaddrInet4{Port: int(port)}
	copy(sa.Addr[:], dut.Net.LocalIPv4)
	// Bring the dut to SYN-SENT state with a non-blocking connect.
	dut.Connect(t, clientFD, &sa)
	tcp, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)}, time.Second)
	if err != nil {
		t.Fatalf("expected SYN, %s", err)
	}

	// Continuously try to read the ICMP error in an attempt to trigger a race
	// condition.
	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)

		close(start)
		for {
			select {
			case <-done:
				return
			default:
			}
			const want = unix.EHOSTUNREACH
			switch got := unix.Errno(dut.GetSockOptInt(t, clientFD, unix.SOL_SOCKET, unix.SO_ERROR)); got {
			case unix.Errno(0):
				continue
			case want:
				return
			default:
				t.Fatalf("got SO_ERROR = %s, want %s", got, want)
			}

		}
	}()

	<-start
	sendICMPError(t, &conn, tcp)

	dut.PollOne(t, clientFD, unix.POLLHUP, time.Second)
	<-done

	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
	// The DUT should reply with RST to our ACK as the state should have
	// transitioned to CLOSED because of handshake error.
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)}, time.Second); err != nil {
		t.Fatalf("expected RST, %s", err)
	}
}
