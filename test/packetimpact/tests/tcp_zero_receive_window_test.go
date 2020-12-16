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

package tcp_zero_receive_window_test

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

// TestZeroReceiveWindow tests if the DUT sends a zero receive window eventually.
func TestZeroReceiveWindow(t *testing.T) {
	for _, payloadLen := range []int{64, 512, 1024} {
		t.Run(fmt.Sprintf("TestZeroReceiveWindow_with_%dbytes_payload", payloadLen), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(t, listenFd)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)

			conn.Connect(t)
			acceptFd, _ := dut.Accept(t, listenFd)
			defer dut.Close(t, acceptFd)

			dut.SetSockOptInt(t, acceptFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

			samplePayload := &testbench.Payload{Bytes: testbench.GenerateRandomPayload(t, payloadLen)}
			// Expect the DUT to eventually advertise zero receive window.
			// The test would timeout otherwise.
			for readOnce := false; ; {
				conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck | header.TCPFlagPsh)}, samplePayload)
				gotTCP, err := conn.Expect(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, time.Second)
				if err != nil {
					t.Fatalf("expected packet was not received: %s", err)
				}
				// Read once to trigger the subsequent window update from the
				// DUT to grow the right edge of the receive window from what
				// was advertised in the SYN-ACK. This ensures that we test
				// for the full default buffer size (1MB on gVisor at the time
				// of writing this comment), thus testing for cases when the
				// scaled receive window size ends up > 65535 (0xffff).
				if !readOnce {
					if got := dut.Recv(t, acceptFd, int32(payloadLen), 0); len(got) != payloadLen {
						t.Fatalf("got dut.Recv(t, %d, %d, 0) = %d, want %d", acceptFd, payloadLen, len(got), payloadLen)
					}
					readOnce = true
				}
				windowSize := *gotTCP.WindowSize
				t.Logf("got window size = %d", windowSize)
				if windowSize == 0 {
					break
				}
			}
		})
	}
}

// TestNonZeroReceiveWindow tests for the DUT to never send a zero receive
// window when the data is being read from the socket buffer.
func TestNonZeroReceiveWindow(t *testing.T) {
	for _, payloadLen := range []int{64, 512, 1024} {
		t.Run(fmt.Sprintf("TestZeroReceiveWindow_with_%dbytes_payload", payloadLen), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(t, listenFd)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)

			conn.Connect(t)
			acceptFd, _ := dut.Accept(t, listenFd)
			defer dut.Close(t, acceptFd)

			dut.SetSockOptInt(t, acceptFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

			samplePayload := &testbench.Payload{Bytes: testbench.GenerateRandomPayload(t, payloadLen)}
			var rcvWindow uint16
			initRcv := false
			// This loop keeps a running rcvWindow value from the initial ACK for the data
			// we sent. Once we have received ACKs with non-zero receive windows, we break
			// the loop.
			for {
				conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck | header.TCPFlagPsh)}, samplePayload)
				gotTCP, err := conn.Expect(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, time.Second)
				if err != nil {
					t.Fatalf("expected packet was not received: %s", err)
				}
				if got := dut.Recv(t, acceptFd, int32(payloadLen), 0); len(got) != payloadLen {
					t.Fatalf("got dut.Recv(t, %d, %d, 0) = %d, want %d", acceptFd, payloadLen, len(got), payloadLen)
				}
				if *gotTCP.WindowSize == 0 {
					t.Fatalf("expected non-zero receive window.")
				}
				if !initRcv {
					rcvWindow = uint16(*gotTCP.WindowSize)
					initRcv = true
				}
				if rcvWindow <= uint16(payloadLen) {
					break
				}
				rcvWindow -= uint16(payloadLen)
			}
		})
	}
}
