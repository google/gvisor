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

package udp_send_recv_dgram_test

import (
	"flag"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

func TestUDPRecv(t *testing.T) {
	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	boundFD, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
	defer dut.Close(boundFD)
	conn := testbench.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
	defer conn.Close()

	testCases := []struct {
		name    string
		payload []byte
	}{
		{"emptypayload", nil},
		{"small payload", []byte("hello world")},
		{"1kPayload", testbench.GenerateRandomPayload(t, 1<<10)},
		// Even though UDP allows larger dgrams we don't test it here as
		// they need to be fragmented and written out as individual
		// frames.
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conn.Send(testbench.UDP{}, &testbench.Payload{Bytes: tc.payload})
			if got, want := string(dut.Recv(boundFD, int32(len(tc.payload)), 0)), string(tc.payload); got != want {
				t.Fatalf("received payload does not match sent payload got: %s, want: %s", got, want)
			}
		})
	}
}

func TestUDPSend(t *testing.T) {
	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	boundFD, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
	defer dut.Close(boundFD)
	conn := testbench.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
	defer conn.Close()

	testCases := []struct {
		name    string
		payload []byte
	}{
		{"emptypayload", nil},
		{"small payload", []byte("hello world")},
		{"1kPayload", testbench.GenerateRandomPayload(t, 1<<10)},
		// Even though UDP allows larger dgrams we don't test it here as
		// they need to be fragmented and written out as individual
		// frames.
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conn.Drain()
			if got, want := int(dut.SendTo(boundFD, tc.payload, 0, conn.LocalAddr())), len(tc.payload); got != want {
				t.Fatalf("short write got: %d, want: %d", got, want)
			}
			if _, err := conn.ExpectData(testbench.UDP{SrcPort: &remotePort}, testbench.Payload{Bytes: tc.payload}, 1*time.Second); err != nil {
				t.Fatal(err)
			}
		})
	}
}
