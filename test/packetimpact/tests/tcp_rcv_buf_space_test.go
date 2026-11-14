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
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

// TestReduceRecvBuf verifies that a reduced receive buffer can drop in-window
// data before the application drains it.
func TestReduceRecvBuf(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFd)
	// Keep the DUT's response queued until all the data segments are sent.
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort, WindowSize: testbench.Uint16(0)}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	conn.Connect(t)
	firstSeq := uint32(*conn.LocalSeqNum(t))
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
	// Capture the DUT's actual cumulative ACKs. TCPIPv4.Expect would match
	// only an ACK for every byte offered.
	wire := dut.Net.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
	defer wire.Close(t)
	const marker = "ok"
	if n := dut.Send(t, acceptFd, []byte(marker), 0); int(n) != len(marker) {
		t.Fatalf("queued %d response bytes, want %d", n, len(marker))
	}

	const pktSize = 1400
	for payload := sampleData; len(payload) != 0; {
		payloadBytes := pktSize
		if l := len(payload); l < payloadBytes {
			payloadBytes = l
		}

		conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, []testbench.Layer{&testbench.Payload{Bytes: payload[:payloadBytes]}}...)
		payload = payload[payloadBytes:]
	}

	// Reading before the DUT processes the tail of the burst would make
	// buffer space available for data that it would otherwise drop.
	acknowledged := acknowledgedBurstBytes(t, &wire, &conn, firstSeq, marker)

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

	if uint32(totalRead) != acknowledged {
		t.Fatalf("read %d bytes, but DUT acknowledged %d", totalRead, acknowledged)
	}
	if totalRead == len(sampleData) {
		t.Fatalf("Read total of %d bytes, same as sampleData length %d, expected less data to be received", totalRead, len(sampleData))
	}

	// The accepted prefix has been drained.
	if ret, got, err := dut.RecvWithErrno(context.Background(), t, acceptFd, int32(len(sampleData)), unix.MSG_DONTWAIT); got != nil || ret != -1 || err != unix.EAGAIN {
		t.Fatalf("expected no packets but got: %s", got)
	}
}

// acknowledgedBurstBytes opens the reverse-direction window after the burst.
// The segment containing the last response byte carries an ACK from the DUT
// after it processed the window update. A one-byte zero-window probe cannot
// carry that byte.
func acknowledgedBurstBytes(t *testing.T, wire *testbench.IPv4Conn, conn *testbench.TCPIPv4, base uint32, marker string) uint32 {
	t.Helper()
	synAck := conn.SynAck(t)
	want := testbench.Layers{nil, nil, &testbench.TCP{SrcPort: synAck.SrcPort, DstPort: synAck.DstPort}}
	lastByte := uint32(*conn.RemoteSeqNum(t)) + uint32(len(marker)-1)
	var frontier uint32
	deadline := time.Now().Add(3 * time.Second)
	for {
		frame, err := wire.ExpectFrame(t, want, time.Until(deadline))
		if err != nil {
			t.Fatalf("DUT did not send its response after acknowledging %d burst bytes: %v", frontier, err)
		}
		tcp := frame[2].(*testbench.TCP)
		if *tcp.Flags&header.TCPFlagAck == 0 {
			continue
		}
		frontier = *tcp.AckNum - base
		if len(frame) > 3 {
			data := frame[3].(*testbench.Payload).Bytes
			if i := lastByte - *tcp.SeqNum; i < uint32(len(data)) && data[i] == marker[len(marker)-1] {
				if frontier == 0 {
					t.Fatal("DUT response acknowledged none of the burst")
				}
				return frontier
			}
		}
		// A stale sequence number may be outside the DUT's receive window.
		// Use its latest ACK so the update can be accepted even at zero window.
		conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), SeqNum: tcp.AckNum, WindowSize: testbench.Uint16(4096)})
	}
}
