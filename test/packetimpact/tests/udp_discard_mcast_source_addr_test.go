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

package udp_discard_mcast_source_addr_test

import (
	"context"
	"flag"
	"fmt"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

var oneSecond = unix.Timeval{Sec: 1, Usec: 0}

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

func TestDiscardsUDPPacketsWithMcastSourceAddressV4(t *testing.T) {
	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	remoteFD, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP(testbench.RemoteIPv4))
	defer dut.Close(remoteFD)
	dut.SetSockOptTimeval(remoteFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &oneSecond)
	conn := testbench.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
	defer conn.Close()

	for _, mcastAddr := range []net.IP{
		net.IPv4allsys,
		net.IPv4allrouter,
		net.IPv4(224, 0, 1, 42),
		net.IPv4(232, 1, 2, 3),
	} {
		t.Run(fmt.Sprintf("srcaddr=%s", mcastAddr), func(t *testing.T) {
			conn.SendIP(
				testbench.IPv4{SrcAddr: testbench.Address(tcpip.Address(mcastAddr.To4()))},
				testbench.UDP{},
			)

			ret, payload, errno := dut.RecvWithErrno(context.Background(), remoteFD, 100, 0)
			if errno != syscall.EAGAIN || errno != syscall.EWOULDBLOCK {
				t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, payload, errno)
			}
		})
	}
}

func TestDiscardsUDPPacketsWithMcastSourceAddressV6(t *testing.T) {
	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	remoteFD, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP(testbench.RemoteIPv6))
	defer dut.Close(remoteFD)
	dut.SetSockOptTimeval(remoteFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &oneSecond)
	conn := testbench.NewUDPIPv6(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
	defer conn.Close()

	for _, mcastAddr := range []net.IP{
		net.IPv6interfacelocalallnodes,
		net.IPv6linklocalallnodes,
		net.IPv6linklocalallrouters,
		net.ParseIP("fe01::42"),
		net.ParseIP("fe02::4242"),
	} {
		t.Run(fmt.Sprintf("srcaddr=%s", mcastAddr), func(t *testing.T) {
			conn.SendIPv6(
				testbench.IPv6{SrcAddr: testbench.Address(tcpip.Address(mcastAddr.To16()))},
				testbench.UDP{},
			)
			ret, payload, errno := dut.RecvWithErrno(context.Background(), remoteFD, 100, 0)
			if errno != syscall.EAGAIN || errno != syscall.EWOULDBLOCK {
				t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, payload, errno)
			}
		})
	}
}
