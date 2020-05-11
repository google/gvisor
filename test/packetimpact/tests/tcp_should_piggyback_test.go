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

package tcp_should_piggyback_test

import (
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	tb.RegisterFlags(flag.CommandLine)
}

func TestPiggyback(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFd)
	conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort, WindowSize: tb.Uint16(12)}, tb.TCP{SrcPort: &remotePort})
	defer conn.Close()

	conn.Handshake()
	acceptFd, _ := dut.Accept(listenFd)
	defer dut.Close(acceptFd)

	dut.SetSockOptInt(acceptFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

	sampleData := []byte("Sample Data")

	dut.Send(acceptFd, sampleData, 0)
	expectedTCP := tb.TCP{Flags: tb.Uint8(header.TCPFlagAck | header.TCPFlagPsh)}
	expectedPayload := tb.Payload{Bytes: sampleData}
	if _, err := conn.ExpectData(&expectedTCP, &expectedPayload, time.Second); err != nil {
		t.Fatalf("Expected %v but didn't get one: %s", tb.Layers{&expectedTCP, &expectedPayload}, err)
	}

	// Cause DUT to send us more data as soon as we ACK their first data segment because we have
	// a small window.
	dut.Send(acceptFd, sampleData, 0)

	// DUT should ACK our segment by piggybacking ACK to their outstanding data segment instead of
	// sending a separate ACK packet.
	conn.Send(expectedTCP, &expectedPayload)
	if _, err := conn.ExpectData(&expectedTCP, &expectedPayload, time.Second); err != nil {
		t.Fatalf("Expected %v but didn't get one: %s", tb.Layers{&expectedTCP, &expectedPayload}, err)
	}
}
