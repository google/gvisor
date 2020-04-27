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

package tcp_retransmission_test

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
	"testing"
	"time"
)

func TestTcpRetransmission(t *testing.T) {
	dut := tb.NewDUT(t)
	listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFd)

	conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
	defer conn.Close()
	conn.Handshake()

	acceptFd, _ := dut.Accept(listenFd)
	defer dut.Close(acceptFd)

	//DUT send data segment.
	buf := []byte("Hi I am DUT sending Data")
	bufPayload := &tb.Payload{Bytes: buf}
	dut.Send(acceptFd, buf, 0)
	layers, _ := conn.ExpectData(&tb.TCP{}, bufPayload, time.Second)
	id1 := *layers[1].(*tb.IPv4).ID

	//Send data segment to DUT.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)}, []tb.Layer{&tb.Payload{Bytes: []byte("hellooooooooooo")}}...)

	//DUT Retransmit data segment with ACK.
	dut.Send(acceptFd, buf, 16)
	layers, _ = conn.ExpectData(&tb.TCP{}, bufPayload, time.Second)
	id2 := *layers[1].(*tb.IPv4).ID

	//Send ACK+RST to close the connection.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagRst | header.TCPFlagAck)})

	//Check the IP Identification field.
	if id1 != id2 {
		t.Fatal("ID for packet and retransmitted packet are different")
	}
}
