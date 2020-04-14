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

package udp_dut

import (
	"golang.org/x/sys/unix"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
	"net"
	"testing"
	"time"
	"fmt"
)

const (
	IP_OPT_TIME_STAMP = 68
)
func TestUDP_timestamp(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	boundFD, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
	/*socket option enabled for ip option timestamp
	here 68 is ip timestamp option value*/
	dut.SetSockOpt(boundFD, unix.IPPROTO_IP, unix.IP_OPTIONS, []byte{IP_OPT_TIME_STAMP, 4, 5, 0})

	conn := tb.NewUDPIPv4(t, tb.UDP{DstPort: &remotePort}, tb.UDP{SrcPort: &remotePort})

	/*getting sockaddr information*/
	newSockAddr, _ := unix.Getsockname(conn.PortPickerFD)
	defer conn.Close()

	/*Send UDP packet from dut to testbench with IP option TIMESTAMP set*/
	dut.SendTo(boundFD, []byte("Hello"), int32(len("Hello")), newSockAddr)

	/*check for IPv4 IP_OPTION TIMESTAMP
	ExpectIPv4 returns pointer to options(ipheader+minlenght(20)) field*/
        ipOptions := conn.ExpectIPv4(time.Second)
        if ipOptions == nil {
                t.Fatal("expected received packet contains IP Option is set to <IP_OPT_TIME_STAMP> but got none")
        }

	/*checking for first byte is TIMESTAMP option value (68) */
	if ipOptions[0] == IP_OPT_TIME_STAMP {
		fmt.Println("Received packet with IP option <IP_OPT_TIME_STAMP> set")
        } else {
                t.Fatal("expected IP Option is set to <IP_OPT_TIME_STAMP> but no IP option")
	}
}
