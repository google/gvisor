// Copyright 2022 The gVisor Authors.
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

package raw_test

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/testing/context"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	testTOS = 0x80
	testTTL = 65
)

func TestReceiveControlMessage(t *testing.T) {
	var payload = [...]byte{0, 1, 2, 3, 4, 5}

	for _, flow := range []context.TestFlow{context.UnicastV4, context.UnicastV6, context.UnicastV6Only, context.MulticastV4, context.MulticastV6, context.MulticastV6Only, context.Broadcast} {
		t.Run(flow.String(), func(t *testing.T) {
			for _, test := range []struct {
				name             string
				optionProtocol   tcpip.NetworkProtocolNumber
				getReceiveOption func(tcpip.Endpoint) bool
				setReceiveOption func(tcpip.Endpoint, bool)
				presenceChecker  checker.ControlMessagesChecker
				absenceChecker   checker.ControlMessagesChecker
			}{
				{
					name:             "TOS",
					optionProtocol:   header.IPv4ProtocolNumber,
					getReceiveOption: func(ep tcpip.Endpoint) bool { return ep.SocketOptions().GetReceiveTOS() },
					setReceiveOption: func(ep tcpip.Endpoint, value bool) { ep.SocketOptions().SetReceiveTOS(value) },
					presenceChecker:  checker.ReceiveTOS(testTOS),
					absenceChecker:   checker.NoTOSReceived(),
				},
				{
					name:             "TClass",
					optionProtocol:   header.IPv6ProtocolNumber,
					getReceiveOption: func(ep tcpip.Endpoint) bool { return ep.SocketOptions().GetReceiveTClass() },
					setReceiveOption: func(ep tcpip.Endpoint, value bool) { ep.SocketOptions().SetReceiveTClass(value) },
					presenceChecker:  checker.ReceiveTClass(testTOS),
					absenceChecker:   checker.NoTClassReceived(),
				},
				{
					name:             "TTL",
					optionProtocol:   header.IPv4ProtocolNumber,
					getReceiveOption: func(ep tcpip.Endpoint) bool { return ep.SocketOptions().GetReceiveTTL() },
					setReceiveOption: func(ep tcpip.Endpoint, value bool) { ep.SocketOptions().SetReceiveTTL(value) },
					presenceChecker:  checker.ReceiveTTL(testTTL),
					absenceChecker:   checker.NoTTLReceived(),
				},
				{
					name:             "HopLimit",
					optionProtocol:   header.IPv6ProtocolNumber,
					getReceiveOption: func(ep tcpip.Endpoint) bool { return ep.SocketOptions().GetReceiveHopLimit() },
					setReceiveOption: func(ep tcpip.Endpoint, value bool) { ep.SocketOptions().SetReceiveHopLimit(value) },
					presenceChecker:  checker.ReceiveHopLimit(testTTL),
					absenceChecker:   checker.NoHopLimitReceived(),
				},
				{
					name:             "IPPacketInfo",
					optionProtocol:   header.IPv4ProtocolNumber,
					getReceiveOption: func(ep tcpip.Endpoint) bool { return ep.SocketOptions().GetReceivePacketInfo() },
					setReceiveOption: func(ep tcpip.Endpoint, value bool) { ep.SocketOptions().SetReceivePacketInfo(value) },
					presenceChecker: func() checker.ControlMessagesChecker {
						h := flow.MakeHeader4Tuple(context.Incoming)
						return checker.ReceiveIPPacketInfo(tcpip.IPPacketInfo{
							NIC: context.NICID,
							// TODO(https://gvisor.dev/issue/3556): Expect the NIC's address
							// instead of the header destination address for the LocalAddr
							// field.
							LocalAddr:       h.Dst.Addr,
							DestinationAddr: h.Dst.Addr,
						})
					}(),
					absenceChecker: checker.NoIPPacketInfoReceived(),
				},
				{
					name:             "IPv6PacketInfo",
					optionProtocol:   header.IPv6ProtocolNumber,
					getReceiveOption: func(ep tcpip.Endpoint) bool { return ep.SocketOptions().GetIPv6ReceivePacketInfo() },
					setReceiveOption: func(ep tcpip.Endpoint, value bool) { ep.SocketOptions().SetIPv6ReceivePacketInfo(value) },
					presenceChecker: func() checker.ControlMessagesChecker {
						h := flow.MakeHeader4Tuple(context.Incoming)
						return checker.ReceiveIPv6PacketInfo(tcpip.IPv6PacketInfo{
							NIC:  context.NICID,
							Addr: h.Dst.Addr,
						})
					}(),
					absenceChecker: checker.NoIPv6PacketInfoReceived(),
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					c := context.New(t, []stack.TransportProtocolFactory{udp.NewProtocol})
					defer c.Cleanup()

					c.CreateRawEndpointForFlow(flow, header.UDPProtocolNumber)
					if err := c.EP.Bind(tcpip.FullAddress{Port: context.StackPort}); err != nil {
						c.T.Fatalf("Bind failed: %s", err)
					}
					if flow.IsMulticast() {
						netProto := flow.NetProto()
						addr := flow.GetMulticastAddr()
						if err := c.Stack.JoinGroup(netProto, context.NICID, addr); err != nil {
							c.T.Fatalf("JoinGroup(%d, %d, %s): %s", netProto, context.NICID, addr, err)
						}
					}

					buf := context.BuildUDPPacket(payload[:], flow, context.Incoming, testTOS, testTTL, false)
					expectedReadData := buf
					if flow.IsV6() {
						// Raw IPv6 endpoints do not return the network header.
						expectedReadData = expectedReadData[header.IPv6MinimumSize:]
					}

					if test.getReceiveOption(c.EP) {
						t.Fatal("got getReceiveOption() = true, want = false")
					}

					test.setReceiveOption(c.EP, true)
					if !test.getReceiveOption(c.EP) {
						t.Fatal("got getReceiveOption() = false, want = true")
					}

					c.InjectPacket(flow.NetProto(), buf)
					if flow.NetProto() == test.optionProtocol {
						c.ReadFromEndpointExpectSuccess(expectedReadData, flow, test.presenceChecker)
					} else {
						c.ReadFromEndpointExpectSuccess(expectedReadData, flow, test.absenceChecker)
					}
				})
			}
		})
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
