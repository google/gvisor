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

package udp_recv_mcast_bcast_test

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

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

func TestUDPRecvMcastBcast(t *testing.T) {
	subnetBcastAddr := broadcastAddr(net.ParseIP(testbench.RemoteIPv4), net.CIDRMask(testbench.IPv4PrefixLength, 32))

	for _, v := range []struct {
		bound, to net.IP
	}{
		{bound: net.IPv4(0, 0, 0, 0), to: subnetBcastAddr},
		{bound: net.IPv4(0, 0, 0, 0), to: net.IPv4bcast},
		{bound: net.IPv4(0, 0, 0, 0), to: net.IPv4allsys},

		{bound: subnetBcastAddr, to: subnetBcastAddr},
		{bound: subnetBcastAddr, to: net.IPv4bcast},

		{bound: net.IPv4bcast, to: net.IPv4bcast},
		{bound: net.IPv4allsys, to: net.IPv4allsys},
	} {
		t.Run(fmt.Sprintf("bound=%s,to=%s", v.bound, v.to), func(t *testing.T) {
			dut := testbench.NewDUT(t)
			defer dut.TearDown()
			boundFD, remotePort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, v.bound)
			defer dut.Close(t, boundFD)
			conn := testbench.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
			defer conn.Close(t)

			payload := testbench.GenerateRandomPayload(t, 1<<10)
			conn.SendIP(
				t,
				testbench.IPv4{DstAddr: testbench.Address(tcpip.Address(v.to.To4()))},
				testbench.UDP{},
				&testbench.Payload{Bytes: payload},
			)
			if got, want := string(dut.Recv(t, boundFD, int32(len(payload)), 0)), string(payload); got != want {
				t.Errorf("received payload does not match sent payload got: %s, want: %s", got, want)
			}
		})
	}
}

func TestUDPDoesntRecvMcastBcastOnUnicastAddr(t *testing.T) {
	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	boundFD, remotePort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP(testbench.RemoteIPv4))
	dut.SetSockOptTimeval(t, boundFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1, Usec: 0})
	defer dut.Close(t, boundFD)
	conn := testbench.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
	defer conn.Close(t)

	for _, to := range []net.IP{
		broadcastAddr(net.ParseIP(testbench.RemoteIPv4), net.CIDRMask(testbench.IPv4PrefixLength, 32)),
		net.IPv4(255, 255, 255, 255),
		net.IPv4(224, 0, 0, 1),
	} {
		t.Run(fmt.Sprint("to=%s", to), func(t *testing.T) {
			payload := testbench.GenerateRandomPayload(t, 1<<10)
			conn.SendIP(
				t,
				testbench.IPv4{DstAddr: testbench.Address(tcpip.Address(to.To4()))},
				testbench.UDP{},
				&testbench.Payload{Bytes: payload},
			)
			ret, payload, errno := dut.RecvWithErrno(context.Background(), t, boundFD, 100, 0)
			if errno != syscall.EAGAIN || errno != syscall.EWOULDBLOCK {
				t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, payload, errno)
			}
		})
	}
}

func broadcastAddr(ip net.IP, mask net.IPMask) net.IP {
	ip4 := ip.To4()
	for i := range ip4 {
		ip4[i] |= ^mask[i]
	}
	return ip4
}
