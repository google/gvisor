// Copyright 2021 The gVisor Authors.
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

package generic_dgram_socket_send_recv_test

import (
	"flag"
	"fmt"
	"net"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

const (
	// Even though sockets allow larger datagrams we don't test it here as they
	// need to be fragmented and written out as individual frames.

	maxICMPv4PayloadSize = header.IPv4MinimumMTU - header.EthernetMinimumSize - header.IPv4MinimumSize - header.ICMPv4MinimumSize
	maxICMPv6PayloadSize = header.IPv6MinimumMTU - header.EthernetMinimumSize - header.IPv6MinimumSize - header.ICMPv6MinimumSize
	maxUDPv4PayloadSize  = header.IPv4MinimumMTU - header.EthernetMinimumSize - header.IPv4MinimumSize - header.UDPMinimumSize
	maxUDPv6PayloadSize  = header.IPv6MinimumMTU - header.EthernetMinimumSize - header.IPv6MinimumSize - header.UDPMinimumSize
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func expectedEthLayer(t *testing.T, dut testbench.DUT, socketFD int32, sendTo net.IP) testbench.Layer {
	t.Helper()
	dst := func() tcpip.LinkAddress {
		if isBroadcast(dut, sendTo) {
			dut.SetSockOptInt(t, socketFD, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)

			// When sending to broadcast (subnet or limited), the expected ethernet
			// address is also broadcast.
			return header.EthernetBroadcastAddress
		}
		if sendTo.IsMulticast() {
			if sendTo4 := sendTo.To4(); sendTo4 != nil {
				return header.EthernetAddressFromMulticastIPv4Address(tcpip.AddrFrom4Slice(sendTo4))
			}
			return header.EthernetAddressFromMulticastIPv6Address(tcpip.AddrFrom16Slice(sendTo.To16()))
		}
		return ""
	}()
	var ether testbench.Ether
	if len(dst) != 0 {
		ether.DstAddr = &dst
	}
	return &ether
}

type protocolTest interface {
	Send(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool)
	Receive(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool)
}

func runAllCombinations(t *testing.T, proto protocolTest) {
	dut := testbench.NewDUT(t)
	subnetBroadcast := dut.Net.SubnetBroadcast()
	// Test every combination of bound/unbound, broadcast/multicast/unicast
	// bound/destination address, and bound/not-bound to device.
	for _, bindTo := range []net.IP{
		nil, // Do not bind.
		net.IPv4zero,
		net.IPv4bcast,
		net.IPv4allsys,
		net.IPv6zero,
		subnetBroadcast,
		dut.Net.RemoteIPv4,
		dut.Net.RemoteIPv6,
	} {
		t.Run(fmt.Sprintf("bindTo=%s", bindTo), func(t *testing.T) {
			t.Parallel()
			for _, sendTo := range []net.IP{
				net.IPv4bcast,
				net.IPv4allsys,
				subnetBroadcast,
				dut.Net.LocalIPv4,
				dut.Net.LocalIPv6,
				dut.Net.RemoteIPv4,
				dut.Net.RemoteIPv6,
			} {
				t.Run(fmt.Sprintf("sendTo=%s", sendTo), func(t *testing.T) {
					for _, bindToDevice := range []bool{true, false} {
						t.Run(fmt.Sprintf("bindToDevice=%t", bindToDevice), func(t *testing.T) {
							t.Run("Send", func(t *testing.T) {
								proto.Send(t, dut, bindTo, sendTo, bindToDevice)
							})
							t.Run("Receive", func(t *testing.T) {
								proto.Receive(t, dut, bindTo, sendTo, bindToDevice)
							})
						})
					}
				})
			}
		})
	}
}

func isBroadcast(dut testbench.DUT, ip net.IP) bool {
	return ip.Equal(net.IPv4bcast) || ip.Equal(dut.Net.SubnetBroadcast())
}

func isBroadcastOrMulticast(dut testbench.DUT, ip net.IP) bool {
	return isBroadcast(dut, ip) || ip.IsMulticast()
}

func sameIPVersion(a, b net.IP) bool {
	return (a.To4() == nil) == (b.To4() == nil)
}

func isRemoteAddr(dut testbench.DUT, ip net.IP) bool {
	return ip.Equal(dut.Net.RemoteIPv4) || ip.Equal(dut.Net.RemoteIPv6)
}

func isInTestSubnetV4(dut testbench.DUT, ip net.IP) bool {
	network := net.IPNet{
		IP:   dut.Net.LocalIPv4,
		Mask: net.CIDRMask(dut.Net.IPv4PrefixLength, net.IPv4len*8),
	}
	return network.Contains(ip)
}
