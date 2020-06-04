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

package tcp_splitseg_mss_test

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

// TestTCPSplitSegMSS lets the dut try to send segments larger than MSS.
// It tests if the transmitted segments are capped at MSS and are split.
func TestTCPSplitSegMSS(t *testing.T) {
	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	listenFD, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFD)
	conn := testbench.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close()

	const mss = uint32(header.TCPDefaultMSS)
	options := make([]byte, header.TCPOptionMSSLength)
	header.EncodeMSSOption(mss, options)
	conn.ConnectWithOptions(options)

	acceptFD, _ := dut.Accept(listenFD)
	defer dut.Close(acceptFD)

	// Let the dut send a segment larger than MSS.
	largeData := make([]byte, mss+1)
	for i := 0; i < 2; i++ {
		dut.Send(acceptFD, largeData, 0)
		if i == 0 {
			// On Linux, the initial segment goes out beyond MSS and the segment
			// split occurs on retransmission. Call ExpectData to wait to
			// receive the split segment.
			if _, err := conn.ExpectData(&testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, &testbench.Payload{Bytes: largeData[:mss]}, time.Second); err != nil {
				t.Fatalf("expected payload was not received: %s", err)
			}
		} else {
			if _, err := conn.ExpectNextData(&testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, &testbench.Payload{Bytes: largeData[:mss]}, time.Second); err != nil {
				t.Fatalf("expected payload was not received: %s", err)
			}
		}
		conn.Send(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)})
		if _, err := conn.ExpectNextData(&testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck | header.TCPFlagPsh)}, &testbench.Payload{Bytes: largeData[mss:]}, time.Second); err != nil {
			t.Fatalf("expected payload was not received: %s", err)
		}
		conn.Send(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)})
	}
}
