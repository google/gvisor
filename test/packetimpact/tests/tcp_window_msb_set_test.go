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

package tcp_window_msb_set_test

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
	"testing"
	"time"
)

func TestWindowMsb(t *testing.T) {
	dut := tb.NewDUT(t)
	listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFd)

	conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
	defer conn.Close()

	//Send SYN to DUT.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn)})

	//Expecting SYN-ACK from DUT.
	synAck, _ := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second)
	if synAck == nil {
		t.Fatal("Didn't get SYN-ACK packet")
	}

	//Send ACK to DUT with window size set as msb.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), WindowSize: tb.Uint16(0x8000)})

	//Send a data packet from DUT.
	acceptFd, _ := dut.Accept(listenFd)
	defer dut.Close(acceptFd)
	buf := []byte("Hi I am DUT sending Data")
	bufPayload := &tb.Payload{Bytes: buf}
	dut.Send(acceptFd, buf, 0)
	conn.ExpectData(&tb.TCP{}, bufPayload, time.Second)
}
