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

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func TestUDPRecvMcastBcast(t *testing.T) {
	dut := testbench.NewDUT(t)
	subnetBcastAddr := broadcastAddr(dut.Net.RemoteIPv4, net.CIDRMask(dut.Net.IPv4PrefixLength, 32))
	for _, v := range []struct {
		bound, to net.IP
	}{
		{bound: net.IPv4zero, to: subnetBcastAddr},
		{bound: net.IPv4zero, to: net.IPv4bcast},
		{bound: net.IPv4zero, to: net.IPv4allsys},

		{bound: subnetBcastAddr, to: subnetBcastAddr},

		// FIXME(gvisor.dev/issue/4896):  Previously by the time subnetBcastAddr is
		// created, IPv4PrefixLength is still 0 because genPseudoFlags is not called
		// yet, it was only called in NewDUT, so the test didn't do what the author
		// original intended to and becomes failing because we process all flags at
		// the very beginning.
		//
		// {bound: subnetBcastAddr, to: net.IPv4bcast},

		{bound: net.IPv4bcast, to: net.IPv4bcast},
		{bound: net.IPv4allsys, to: net.IPv4allsys},
	} {
		t.Run(fmt.Sprintf("bound=%s,to=%s", v.bound, v.to), func(t *testing.T) {
			boundFD, remotePort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, v.bound)
			defer dut.Close(t, boundFD)
			conn := dut.Net.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
			defer conn.Close(t)

			payload := testbench.GenerateRandomPayload(t, 1<<10 /* 1 KiB */)
			conn.SendIP(
				t,
				testbench.IPv4{DstAddr: testbench.Address(tcpip.Address(v.to.To4()))},
				testbench.UDP{},
				&testbench.Payload{Bytes: payload},
			)
			got, want := dut.Recv(t, boundFD, int32(len(payload)+1), 0), payload
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestUDPDoesntRecvMcastBcastOnUnicastAddr(t *testing.T) {
	dut := testbench.NewDUT(t)
	boundFD, remotePort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, dut.Net.RemoteIPv4)
	dut.SetSockOptTimeval(t, boundFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1, Usec: 0})
	defer dut.Close(t, boundFD)
	conn := dut.Net.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
	defer conn.Close(t)

	for _, to := range []net.IP{
		broadcastAddr(dut.Net.RemoteIPv4, net.CIDRMask(dut.Net.IPv4PrefixLength, 32)),
		net.IPv4(255, 255, 255, 255),
		net.IPv4(224, 0, 0, 1),
	} {
		t.Run(fmt.Sprint("to=%s", to), func(t *testing.T) {
			payload := testbench.GenerateRandomPayload(t, 1<<10 /* 1 KiB */)
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
	result := make(net.IP, net.IPv4len)
	ip4 := ip.To4()
	for i := range ip4 {
		result[i] = ip4[i] | ^mask[i]
	}
	return result
}
