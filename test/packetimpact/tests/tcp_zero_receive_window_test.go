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
	"math"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

// TestZeroReceiveWindow tests if the DUT sends a zero receive window eventually.
func TestZeroReceiveWindow(t *testing.T) {
	// minPayloadLen is the smallest size we can use for a payload in this test.
	// Any smaller than this and the receive buffer will fill up before the
	// receive window can shrink to zero.

	// To solve for minPayloadLen: minPayloadLen(DefaultReceiveBufferSize) =
	// 	maxWndSize(minPayloadLen + segOverheadSize)
	maxWndSize := math.MaxUint16
	minPayloadLen := int(math.Ceil(float64(maxWndSize*tcp.SegOverheadSize) / float64(tcp.DefaultReceiveBufferSize-maxWndSize)))
	for _, payloadLen := range []int{minPayloadLen, 512, 1024} {
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

			fillRecvBuffer(t, &conn, &dut, acceptFd, payloadLen)
		})
	}
}

func fillRecvBuffer(t *testing.T, conn *testbench.TCPIPv4, dut *testbench.DUT, acceptFd int32, payloadLen int) {
	// Expect the DUT to eventually advertise zero receive window.
	// The test would timeout otherwise.
	for readOnce := false; ; {
		samplePayload := &testbench.Payload{Bytes: testbench.GenerateRandomPayload(t, payloadLen)}
		conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh)}, samplePayload)
		gotTCP, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
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
		if payloadLen > int(windowSize) {
			payloadLen = int(windowSize)
		}
	}
}

func TestZeroToNonZeroWindowUpdate(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFd)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})
	synAck, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second)
	if err != nil {
		t.Fatalf("didn't get synack during handshake: %s", err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})

	acceptFd, _ := dut.Accept(t, listenFd)
	defer dut.Close(t, acceptFd)

	dut.SetSockOptInt(t, acceptFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

	mss := header.ParseSynOptions(synAck.Options, true).MSS
	fillRecvBuffer(t, &conn, &dut, acceptFd, int(mss))

	// Read < mss worth of data from the receive buffer and expect the DUT to
	// not send a non-zero window update.
	payloadLen := mss - 1
	if got := dut.Recv(t, acceptFd, int32(payloadLen), 0); len(got) != int(payloadLen) {
		t.Fatalf("got dut.Recv(t, %d, %d, 0) = %d, want %d", acceptFd, payloadLen, len(got), payloadLen)
	}
	// Send a zero-window-probe to force an ACK from the receiver with any
	// window updates.
	conn.Send(t, testbench.TCP{SeqNum: testbench.Uint32(uint32(*conn.LocalSeqNum(t) - 1)), Flags: testbench.TCPFlags(header.TCPFlagAck)})
	gotTCP, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
	if err != nil {
		t.Fatalf("expected packet was not received: %s", err)
	}
	if windowSize := *gotTCP.WindowSize; windowSize != 0 {
		t.Fatalf("got non zero window = %d", windowSize)
	}

	// Now, ensure that the DUT eventually sends non-zero window update.
	seqNum := testbench.Uint32(uint32(*conn.LocalSeqNum(t) - 1))
	ackNum := testbench.Uint32(uint32(*conn.LocalSeqNum(t)))
	recvCheckWindowUpdate := func(readLen int) uint16 {
		if got := dut.Recv(t, acceptFd, int32(readLen), 0); len(got) != readLen {
			t.Fatalf("got dut.Recv(t, %d, %d, 0) = %d, want %d", acceptFd, readLen, len(got), readLen)
		}
		conn.Send(t, testbench.TCP{SeqNum: seqNum, Flags: testbench.TCPFlags(header.TCPFlagPsh | header.TCPFlagAck)}, &testbench.Payload{Bytes: make([]byte, 1)})
		gotTCP, err := conn.Expect(t, testbench.TCP{AckNum: ackNum, Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
		if err != nil {
			t.Fatalf("expected packet was not received: %s", err)
		}
		return *gotTCP.WindowSize
	}

	if !dut.Uname.IsLinux() {
		if win := recvCheckWindowUpdate(1); win == 0 {
			t.Fatal("expected non-zero window update")
		}
	} else {
		// Linux stack takes additional socket reads to send out window update,
		// its a function of sysctl_tcp_rmem among other things.
		// https://github.com/torvalds/linux/blob/7acac4b3196/net/ipv4/tcp_input.c#L687
		for {
			if win := recvCheckWindowUpdate(int(payloadLen)); win != 0 {
				break
			}
		}
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
				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh)}, samplePayload)
				gotTCP, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
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
