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

package tcp_cork_mss_test

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

// TestTCPCorkMSS tests for segment coalesce and split as per MSS.
func TestTCPCorkMSS(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFD)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	const mss = uint32(header.TCPDefaultMSS)
	options := make([]byte, header.TCPOptionMSSLength)
	header.EncodeMSSOption(mss, options)
	conn.ConnectWithOptions(t, options)

	acceptFD, _ := dut.Accept(t, listenFD)
	defer dut.Close(t, acceptFD)

	dut.SetSockOptInt(t, acceptFD, unix.IPPROTO_TCP, unix.TCP_CORK, 1)

	// Let the dut application send 2 small segments to be held up and coalesced
	// until the application sends a larger segment to fill up to > MSS.
	sampleData := []byte("Sample Data")
	dut.Send(t, acceptFD, sampleData, 0)
	dut.Send(t, acceptFD, sampleData, 0)

	expectedData := sampleData
	expectedData = append(expectedData, sampleData...)
	largeData := make([]byte, mss+1)
	expectedData = append(expectedData, largeData...)
	dut.Send(t, acceptFD, largeData, 0)

	// Expect the segments to be coalesced and sent and capped to MSS.
	expectedPayload := testbench.Payload{Bytes: expectedData[:mss]}
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, &expectedPayload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
	// Expect the coalesced segment to be split and transmitted.
	expectedPayload = testbench.Payload{Bytes: expectedData[mss:]}
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh)}, &expectedPayload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}

	// Check for segments to *not* be held up because of TCP_CORK when
	// the current send window is less than MSS.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), WindowSize: testbench.Uint16(uint16(2 * len(sampleData)))})
	dut.Send(t, acceptFD, sampleData, 0)
	dut.Send(t, acceptFD, sampleData, 0)
	expectedPayload = testbench.Payload{Bytes: append(sampleData, sampleData...)}
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh)}, &expectedPayload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
}

// TestTCPMsgMore checks that MSG_MORE combines a header with its final body.
func TestTCPMsgMore(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFD)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)
	conn.Connect(t)
	acceptFD, _ := dut.Accept(t, listenFD)
	defer dut.Close(t, acceptFD)
	dut.SetSockOptInt(t, acceptFD, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

	dut.Send(t, acceptFD, []byte("header"), unix.MSG_MORE)
	dut.Send(t, acceptFD, []byte("body"), 0)
	expectedPayload := testbench.Payload{Bytes: []byte("headerbody")}
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh)}, &expectedPayload, time.Second); err != nil {
		t.Fatalf("expected combined header and body: %s", err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
}

func TestTCPMsgMoreACKRelease(t *testing.T) {
	for _, window := range []uint16{30000, 0} {
		t.Run(fmt.Sprintf("window=%d", window), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(t, listenFD)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)
			conn.Connect(t)
			acceptFD, _ := dut.Accept(t, listenFD)
			defer dut.Close(t, acceptFD)
			dut.SetSockOptInt(t, acceptFD, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

			dut.Send(t, acceptFD, []byte("x"), 0)
			if _, err := conn.ExpectData(t, &testbench.TCP{}, &testbench.Payload{Bytes: []byte("x")}, time.Second); err != nil {
				t.Fatalf("initial payload: %s", err)
			}
			if window == 0 {
				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), WindowSize: testbench.Uint16(window)})
			}
			dut.Send(t, acceptFD, []byte("header"), unix.MSG_MORE)
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), WindowSize: testbench.Uint16(30000)})

			// Require ACK/window processing to release the data before the
			// 200 ms cork timer can expire.
			if _, err := conn.ExpectData(t, &testbench.TCP{}, &testbench.Payload{Bytes: []byte("header")}, 100*time.Millisecond); err != nil {
				t.Fatalf("ACK/window update did not release MSG_MORE data: %s", err)
			}
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
		})
	}
}
