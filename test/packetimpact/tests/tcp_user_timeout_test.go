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

package tcp_user_timeout_test

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

func sendPayload(t *testing.T, conn *testbench.TCPIPv4, dut *testbench.DUT, fd int32) {
	sampleData := make([]byte, 100)
	for i := range sampleData {
		sampleData[i] = uint8(i)
	}
	conn.Drain(t)
	dut.Send(t, fd, sampleData, 0)
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh)}, &testbench.Payload{Bytes: sampleData}, time.Second); err != nil {
		t.Fatalf("expected data but got none: %w", err)
	}
}

func sendFIN(t *testing.T, conn *testbench.TCPIPv4, dut *testbench.DUT, fd int32) {
	dut.Close(t, fd)
}

func TestTCPUserTimeout(t *testing.T) {
	for _, tt := range []struct {
		description string
		userTimeout time.Duration
		sendDelay   time.Duration
	}{
		{"NoUserTimeout", 0, 3 * time.Second},
		{"ACKBeforeUserTimeout", 5 * time.Second, 4 * time.Second},
		{"ACKAfterUserTimeout", 5 * time.Second, 7 * time.Second},
	} {
		for _, ttf := range []struct {
			description string
			f           func(_ *testing.T, _ *testbench.TCPIPv4, _ *testbench.DUT, fd int32)
		}{
			{"AfterPayload", sendPayload},
			{"AfterFIN", sendFIN},
		} {
			t.Run(tt.description+ttf.description, func(t *testing.T) {
				// Create a socket, listen, TCP handshake, and accept.
				dut := testbench.NewDUT(t)
				listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
				defer dut.Close(t, listenFD)
				conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
				defer conn.Close(t)
				conn.Connect(t)
				acceptFD, _ := dut.Accept(t, listenFD)

				if tt.userTimeout != 0 {
					dut.SetSockOptInt(t, acceptFD, unix.SOL_TCP, unix.TCP_USER_TIMEOUT, int32(tt.userTimeout.Milliseconds()))
				}

				ttf.f(t, &conn, &dut, acceptFD)

				time.Sleep(tt.sendDelay)
				conn.Drain(t)
				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})

				// If TCP_USER_TIMEOUT was set and the above delay was longer than the
				// TCP_USER_TIMEOUT then the DUT should send a RST in response to the
				// testbench's packet.
				expectRST := tt.userTimeout != 0 && tt.sendDelay > tt.userTimeout
				expectTimeout := 5 * time.Second
				got, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)}, expectTimeout)
				if expectRST && err != nil {
					t.Errorf("expected RST packet within %s but got none: %s", expectTimeout, err)
				}
				if !expectRST && got != nil {
					t.Errorf("expected no RST packet within %s but got one: %s", expectTimeout, got)
				}
			})
		}
	}
}
