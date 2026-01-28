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

package tcp_rcv_buf_space_test

import (
	"context"
	"flag"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

// TestReduceRecvBuf tests that a packet within window is still dropped
// if the available buffer space drops below the size of the incoming
// segment.
func TestReduceRecvBuf(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFd)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	conn.Connect(t)
	acceptFd, _ := dut.Accept(t, listenFd)
	defer dut.Close(t, acceptFd)

	// Set a small receive buffer for the test.
	const rcvBufSz = 4096
	dut.SetSockOptInt(t, acceptFd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvBufSz)

	// Retrieve the actual buffer.
	bufSz := dut.GetSockOptInt(t, acceptFd, unix.SOL_SOCKET, unix.SO_RCVBUF)

	// Generate a payload of 1 more than the actual buffer size used by the
	// DUT.
	sampleData := testbench.GenerateRandomPayload(t, int(bufSz)+1)
	// Send and receive sample data to the dut.
	const pktSize = 1400
	for payload := sampleData; len(payload) != 0; {
		payloadBytes := pktSize
		if l := len(payload); l < payloadBytes {
			payloadBytes = l
		}

		conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, []testbench.Layer{&testbench.Payload{Bytes: payload[:payloadBytes]}}...)
		payload = payload[payloadBytes:]
	}

	// First read should read < len(sampleData).
	// Follow up with non-blocking reads to drain the receive buffer in case
	// of partial reads.
	var totalRead int
	ret, _, err := dut.RecvWithErrno(context.Background(), t, acceptFd, int32(len(sampleData)), 0)
	if ret == -1 {
		t.Fatalf("dut.RecvWithErrno(ctx, t, %d, %d, 0) = %d,_, %s", acceptFd, int32(len(sampleData)), ret, err)
	}
	if ret == 0 {
		t.Fatalf("dut.RecvWithErrno(ctx, t, %d, %d, 0) returned 0 bytes", acceptFd, int32(len(sampleData)))
	}
	totalRead += int(ret)

	for totalRead < len(sampleData) {
		ret, _, err := dut.RecvWithErrno(context.Background(), t, acceptFd, int32(len(sampleData)-totalRead), unix.MSG_DONTWAIT)
		if ret == -1 {
			if err == unix.EAGAIN {
				break
			}
			t.Fatalf("dut.RecvWithErrno(ctx, t, %d, %d, unix.MSG_DONTWAIT) failed: %s", acceptFd, int32(len(sampleData)-totalRead), err)
		}
		if ret == 0 {
			t.Fatalf("dut.RecvWithErrno(ctx, t, %d, %d, unix.MSG_DONTWAIT) returned 0 bytes", acceptFd, int32(len(sampleData)-totalRead))
		}
		totalRead += int(ret)
	}

	if totalRead == len(sampleData) {
		t.Fatalf("Read total of %d bytes, same as sampleData length %d, expected less data to be received", totalRead, len(sampleData))
	}

	// Next read should return EAGAIN as the last segment should have been
	// dropped due to it exceeding the receive buffer space available in the
	// socket.
	if ret, got, err := dut.RecvWithErrno(context.Background(), t, acceptFd, int32(len(sampleData)), unix.MSG_DONTWAIT); got != nil || ret != -1 || err != unix.EAGAIN {
		t.Fatalf("expected no packets but got: %s", got)
	}
}
