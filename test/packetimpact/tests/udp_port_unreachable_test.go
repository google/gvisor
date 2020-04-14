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

package udp_port_unreachable

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
        "gvisor.dev/gvisor/pkg/tcpip/header"
        tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func TestUDP_DstUnreachable(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	boundFD, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
	defer dut.Close(boundFD)
	conn := tb.NewUDPIPv4(t, tb.UDP{DstPort: &remotePort}, tb.UDP{SrcPort: &remotePort})
	defer conn.Close()

	//send UDP frame with remortPort as destination port
	frame := conn.CreateFrame(tb.UDP{DstPort: &remotePort}, &tb.Payload{Bytes: []byte("hello world")})
	conn.SendFrame(frame)
	dut.Recv(boundFD, 100, 0)

	//Use unused port as destination port.
	demoport := uint16(20001)
	frame = conn.CreateFrame(tb.UDP{DstPort: &demoport}, &tb.Payload{Bytes: []byte("hello world")})
	conn.SendFrame(frame)

	//check for ICMP destination unreacable message.
        icmpPacket := conn.ExpectICMPv4(time.Second)
        if icmpPacket == nil {
                t.Fatal("expected a ICMP Destination Unreachable within 1 second but got none")
        } else  if icmp := header.ICMPv4(icmpPacket); icmp.Type() != header.ICMPv4DstUnreachable {
                t.Fatal("expected a ICMP type 3 - Destination Unreachable, got different")
	}

	//send UDP frame with remortport as destination port.
	frame = conn.CreateFrame(tb.UDP{DstPort: &remotePort}, &tb.Payload{Bytes: []byte("hello world")})
	conn.SendFrame(frame)
	dut.Recv(boundFD, 100, 0)
}
