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

package tcp_handshake_window_size_test

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

// TestTCPHandshakeWindowSize tests if the stack is honoring the window size
// communicated during handshake.
func TestTCPHandshakeWindowSize(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFD)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	// Start handshake with zero window size.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn), WindowSize: testbench.Uint16(uint16(0))})
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, nil, time.Second); err != nil {
		t.Fatalf("expected SYN-ACK: %s", err)
	}
	// Update the advertised window size to a non-zero value with the ACK that
	// completes the handshake.
	//
	// Set the window size with MSB set and expect the dut to treat it as
	// an unsigned value.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), WindowSize: testbench.Uint16(uint16(1 << 15))})

	acceptFd, _ := dut.Accept(t, listenFD)
	defer dut.Close(t, acceptFd)

	sampleData := []byte("Sample Data")
	samplePayload := &testbench.Payload{Bytes: sampleData}

	// Since we advertised a zero window followed by a non-zero window,
	// expect the dut to honor the recently advertised non-zero window
	// and actually send out the data instead of probing for zero window.
	dut.Send(t, acceptFd, sampleData, 0)
	if _, err := conn.ExpectNextData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh)}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
}
