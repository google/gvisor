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

package network_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport"
	"gvisor.dev/gvisor/pkg/tcpip/transport/internal/network"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestEndpointStateTransitions(t *testing.T) {
	const (
		nicID = 1
	)

	var (
		ipv4NICAddr    = testutil.MustParse4("1.2.3.4")
		ipv6NICAddr    = testutil.MustParse6("a::1")
		ipv4RemoteAddr = testutil.MustParse4("6.7.8.9")
		ipv6RemoteAddr = testutil.MustParse6("b::1")
	)

	data := buffer.View([]byte{1, 2, 4, 5})
	v4Checker := func(t *testing.T, b buffer.View) {
		checker.IPv4(t, b,
			checker.SrcAddr(ipv4NICAddr),
			checker.DstAddr(ipv4RemoteAddr),
			checker.IPPayload(data),
		)
	}

	v6Checker := func(t *testing.T, b buffer.View) {
		checker.IPv6(t, b,
			checker.SrcAddr(ipv6NICAddr),
			checker.DstAddr(ipv6RemoteAddr),
			checker.IPPayload(data),
		)
	}

	tests := []struct {
		name                    string
		netProto                tcpip.NetworkProtocolNumber
		expectedMaxHeaderLength uint16
		expectedNetProto        tcpip.NetworkProtocolNumber
		expectedLocalAddr       tcpip.Address
		bindAddr                tcpip.Address
		expectedBoundAddr       tcpip.Address
		remoteAddr              tcpip.Address
		expectedRemoteAddr      tcpip.Address
		checker                 func(*testing.T, buffer.View)
	}{
		{
			name:                    "IPv4",
			netProto:                ipv4.ProtocolNumber,
			expectedMaxHeaderLength: header.IPv4MaximumHeaderSize,
			expectedNetProto:        ipv4.ProtocolNumber,
			expectedLocalAddr:       ipv4NICAddr,
			bindAddr:                header.IPv4AllSystems,
			expectedBoundAddr:       header.IPv4AllSystems,
			remoteAddr:              ipv4RemoteAddr,
			expectedRemoteAddr:      ipv4RemoteAddr,
			checker:                 v4Checker,
		},
		{
			name:                    "IPv6",
			netProto:                ipv6.ProtocolNumber,
			expectedMaxHeaderLength: header.IPv6FixedHeaderSize,
			expectedNetProto:        ipv6.ProtocolNumber,
			expectedLocalAddr:       ipv6NICAddr,
			bindAddr:                header.IPv6AllNodesMulticastAddress,
			expectedBoundAddr:       header.IPv6AllNodesMulticastAddress,
			remoteAddr:              ipv6RemoteAddr,
			expectedRemoteAddr:      ipv6RemoteAddr,
			checker:                 v6Checker,
		},
		{
			name:                    "IPv4-mapped-IPv6",
			netProto:                ipv6.ProtocolNumber,
			expectedMaxHeaderLength: header.IPv4MaximumHeaderSize,
			expectedNetProto:        ipv4.ProtocolNumber,
			expectedLocalAddr:       ipv4NICAddr,
			bindAddr:                testutil.MustParse6("::ffff:e000:0001"),
			expectedBoundAddr:       header.IPv4AllSystems,
			remoteAddr:              testutil.MustParse6("::ffff:0607:0809"),
			expectedRemoteAddr:      ipv4RemoteAddr,
			checker:                 v4Checker,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
				Clock:              &faketime.NullClock{},
			})
			e := channel.New(1, header.IPv6MinimumMTU, "")
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
			}

			if err := s.AddAddress(nicID, ipv4.ProtocolNumber, ipv4NICAddr); err != nil {
				t.Fatalf("s.AddAddress(%d, %d, %s): %s", nicID, ipv4.ProtocolNumber, ipv4NICAddr, err)
			}
			if err := s.AddAddress(nicID, ipv6.ProtocolNumber, ipv6NICAddr); err != nil {
				t.Fatalf("s.AddAddress(%d, %d, %s): %s", nicID, ipv6.ProtocolNumber, ipv6NICAddr, err)
			}

			s.SetRouteTable([]tcpip.Route{
				{Destination: ipv4RemoteAddr.WithPrefix().Subnet(), NIC: nicID},
				{Destination: ipv6RemoteAddr.WithPrefix().Subnet(), NIC: nicID},
			})

			var ops tcpip.SocketOptions
			var ep network.Endpoint
			ep.Init(s, test.netProto, udp.ProtocolNumber, &ops)
			if state := ep.State(); state != transport.DatagramEndpointStateInitial {
				t.Fatalf("got ep.State() = %s, want = %s", state, transport.DatagramEndpointStateInitial)
			}

			bindAddr := tcpip.FullAddress{Addr: test.bindAddr}
			if err := ep.Bind(bindAddr); err != nil {
				t.Fatalf("ep.Bind(%#v): %s", bindAddr, err)
			}
			if state := ep.State(); state != transport.DatagramEndpointStateBound {
				t.Fatalf("got ep.State() = %s, want = %s", state, transport.DatagramEndpointStateBound)
			}
			if diff := cmp.Diff(ep.GetLocalAddress(), tcpip.FullAddress{Addr: test.expectedBoundAddr}); diff != "" {
				t.Errorf("ep.GetLocalAddress() mismatch (-want +got):\n%s", diff)
			}
			if addr, connected := ep.GetRemoteAddress(); connected {
				t.Errorf("got ep.GetRemoteAddress() = (true, %#v), want = (false, _)", addr)
			}

			connectAddr := tcpip.FullAddress{Addr: test.remoteAddr}
			if err := ep.Connect(connectAddr); err != nil {
				t.Fatalf("ep.Connect(%#v): %s", connectAddr, err)
			}
			if state := ep.State(); state != transport.DatagramEndpointStateConnected {
				t.Fatalf("got ep.State() = %s, want = %s", state, transport.DatagramEndpointStateConnected)
			}
			if diff := cmp.Diff(ep.GetLocalAddress(), tcpip.FullAddress{Addr: test.expectedLocalAddr}); diff != "" {
				t.Errorf("ep.GetLocalAddress() mismatch (-want +got):\n%s", diff)
			}
			if addr, connected := ep.GetRemoteAddress(); !connected {
				t.Errorf("got ep.GetRemoteAddress() = (false, _), want = (true, %#v)", connectAddr)
			} else if diff := cmp.Diff(addr, tcpip.FullAddress{Addr: test.expectedRemoteAddr}); diff != "" {
				t.Errorf("remote address mismatch (-want +got):\n%s", diff)
			}

			ctx, err := ep.AcquireContextForWrite(tcpip.WriteOptions{})
			if err != nil {
				t.Fatalf("ep.AcquireContexForWrite({}): %s", err)
			}
			defer ctx.Release()
			info := ctx.PacketInfo()
			if diff := cmp.Diff(network.WritePacketInfo{
				NetProto:                    test.expectedNetProto,
				LocalAddress:                test.expectedLocalAddr,
				RemoteAddress:               test.expectedRemoteAddr,
				MaxHeaderLength:             test.expectedMaxHeaderLength,
				RequiresTXTransportChecksum: true,
			}, info); diff != "" {
				t.Errorf("write packet info mismatch (-want +got):\n%s", diff)
			}
			if err := ctx.WritePacket(stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: int(info.MaxHeaderLength),
				Data:               data.ToVectorisedView(),
			}), false /* headerIncluded */); err != nil {
				t.Fatalf("ctx.WritePacket(_, false): %s", err)
			}
			if pkt, ok := e.Read(); !ok {
				t.Fatalf("expected packet to be read from link endpoint")
			} else {
				test.checker(t, stack.PayloadSince(pkt.Pkt.NetworkHeader()))
			}

			ep.Close()
			if state := ep.State(); state != transport.DatagramEndpointStateClosed {
				t.Fatalf("got ep.State() = %s, want = %s", state, transport.DatagramEndpointStateClosed)
			}
		})
	}
}
