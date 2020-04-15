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

package udp_recv_multicast_test

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func TestUDPRecvMulticast(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	boundFD, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
	defer dut.Close(boundFD)
	conn := tb.NewUDPIPv4(t, tb.UDP{DstPort: &remotePort}, tb.UDP{SrcPort: &remotePort})
	defer conn.Close()
	frame := conn.CreateFrame(&tb.UDP{}, &tb.Payload{Bytes: []byte("hello world")})
	frame[1].(*tb.IPv4).DstAddr = tb.Address(tcpip.Address(net.ParseIP("224.0.0.1").To4()))
	conn.SendFrame(frame)
	dut.Recv(boundFD, 100, 0)
}
