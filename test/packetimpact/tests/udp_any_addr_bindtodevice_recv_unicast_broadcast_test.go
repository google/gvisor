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

package udp_any_addr_bindtodevice_recv_unicast_broadcast_test

import (
	"flag"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

func TestAnyAddrBindtodeviceRecvUnicastBroadcastUDP(t *testing.T) {
	// Bind socket to INADDR_ANY with SO_BINDTODEVICE set.
	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	sockFD := dut.Socket(t, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	defer dut.Close(t, sockFD)
	dut.SetSockOpt(t, sockFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(testbench.Device))
	sa := unix.SockaddrInet4{}
	copy(sa.Addr[:], net.IPv4zero.To4())
	dut.Bind(t, sockFD, &sa)

	name := dut.GetSockName(t, sockFD)
	p := name.(*unix.SockaddrInet4).Port
	port := uint16(p)
	conn := testbench.NewUDPIPv4(t, testbench.UDP{DstPort: &port}, testbench.UDP{SrcPort: &port})
	defer conn.Close(t)

	// Socket receives unicast message.
	payload := testbench.GenerateRandomPayload(t, 1<<10 /* 1 KiB */)
	conn.SendIP(
		t,
		testbench.IPv4{DstAddr: testbench.Address(tcpip.Address(net.ParseIP(testbench.RemoteIPv4).To4()))},
		testbench.UDP{},
		&testbench.Payload{Bytes: payload},
	)
	got, want := dut.Recv(t, sockFD, int32(len(payload)+1), 0), payload
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
	}

	// Socket receives broadcast message.
	conn.SendIP(
		t,
		testbench.IPv4{DstAddr: testbench.Address(tcpip.Address(net.IPv4bcast.To4()))},
		testbench.UDP{},
		&testbench.Payload{Bytes: payload},
	)
	got, want = dut.Recv(t, sockFD, int32(len(payload)+1), 0), payload
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
	}
}
