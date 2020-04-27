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

package tcp_window_shrink_test

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func TestWindowShrink(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFd)
	conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
	defer conn.Close()

	conn.Handshake()
	acceptFd, _ := dut.Accept(listenFd)
	defer dut.Close(acceptFd)

	dut.SetSockOptInt(acceptFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

	sampleData := []byte("Sample Data")
	samplePayload := &tb.Payload{Bytes: sampleData}

	dut.Send(acceptFd, sampleData, 0)
	if _, err := conn.ExpectData(&tb.TCP{}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
	}
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})

	dut.Send(acceptFd, sampleData, 0)
	dut.Send(acceptFd, sampleData, 0)
	if _, err := conn.ExpectData(&tb.TCP{}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
	}
	if _, err := conn.ExpectData(&tb.TCP{}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
	}
	// We close our receiving window here
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), WindowSize: tb.Uint16(0)})

	dut.Send(acceptFd, []byte("Sample Data"), 0)
	// Note: There is another kind of zero-window probing which Windows uses (by sending one
	// new byte at `RemoteSeqNum`), if netstack wants to go that way, we may want to change
	// the following lines.
	expectedRemoteSeqNum := *conn.RemoteSeqNum() - 1
	if _, err := conn.ExpectData(&tb.TCP{SeqNum: tb.Uint32(uint32(expectedRemoteSeqNum))}, nil, time.Second); err != nil {
		t.Fatalf("expected a packet with sequence number %v: %s", expectedRemoteSeqNum, err)
	}
}
