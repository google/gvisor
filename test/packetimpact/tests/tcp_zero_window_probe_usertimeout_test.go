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

package tcp_zero_window_probe_usertimeout_test

import (
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

// TestZeroWindowProbeUserTimeout sanity tests user timeout when we are
// retransmitting zero window probes.
func TestZeroWindowProbeUserTimeout(t *testing.T) {
	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFd)
	conn := testbench.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close()

	conn.Connect()
	acceptFd, _ := dut.Accept(listenFd)
	defer dut.Close(acceptFd)

	dut.SetSockOptInt(acceptFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

	sampleData := []byte("Sample Data")
	samplePayload := &testbench.Payload{Bytes: sampleData}

	// Send and receive sample data to the dut.
	dut.Send(acceptFd, sampleData, 0)
	if _, err := conn.ExpectData(&testbench.TCP{}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
	conn.Send(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck | header.TCPFlagPsh)}, samplePayload)
	if _, err := conn.ExpectData(&testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, nil, time.Second); err != nil {
		t.Fatalf("expected packet was not received: %s", err)
	}

	// Test 1: Check for receive of a zero window probe, record the duration for
	//         probe to be sent.
	//
	// Advertize zero window to the dut.
	conn.Send(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck), WindowSize: testbench.Uint16(0)})

	// Expected sequence number of the zero window probe.
	probeSeq := testbench.Uint32(uint32(*conn.RemoteSeqNum() - 1))
	start := time.Now()
	// Ask the dut to send out data.
	dut.Send(acceptFd, sampleData, 0)
	// Expect zero-window probe from the dut.
	if _, err := conn.ExpectData(&testbench.TCP{SeqNum: probeSeq}, nil, time.Second); err != nil {
		t.Fatalf("expected a packet with sequence number %d: %s", probeSeq, err)
	}
	// Record the duration for first probe, the dut sends the zero window probe after
	// a retransmission time interval.
	startProbeDuration := time.Now().Sub(start)

	// Test 2: Check if the dut times out the connection by honoring usertimeout
	//         when the dut is sending zero-window probes.
	//
	// Reduce the retransmit timeout.
	dut.SetSockOptInt(acceptFd, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int32(startProbeDuration.Milliseconds()))
	// Advertize zero window again.
	conn.Send(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck), WindowSize: testbench.Uint16(0)})
	// Ask the dut to send out data that would trigger zero window probe retransmissions.
	dut.Send(acceptFd, sampleData, 0)

	// Wait for the connection to timeout after multiple zero-window probe retransmissions.
	time.Sleep(8 * startProbeDuration)

	// Expect the connection to have timed out and closed which would cause the dut
	// to reply with a RST to the ACK we send.
	conn.Send(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)})
	if _, err := conn.ExpectData(&testbench.TCP{Flags: testbench.Uint8(header.TCPFlagRst)}, nil, time.Second); err != nil {
		t.Fatalf("expected a TCP RST")
	}
}
