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

package integration_test

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	linkAddr1 = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x06")
	linkAddr2 = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x07")
	linkAddr3 = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x08")
	linkAddr4 = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x09")
)

var (
	ipv4Addr1 = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.1").To4()),
			PrefixLen: 24,
		},
	}
	ipv4Addr2 = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.2").To4()),
			PrefixLen: 8,
		},
	}
	ipv4Addr3 = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.3").To4()),
			PrefixLen: 8,
		},
	}
	ipv6Addr1 = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::1").To16()),
			PrefixLen: 64,
		},
	}
	ipv6Addr2 = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::2").To16()),
			PrefixLen: 64,
		},
	}
	ipv6Addr3 = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::3").To16()),
			PrefixLen: 64,
		},
	}
)

func setupStack(t *testing.T, stackOpts stack.Options, host1NICID, host2NICID tcpip.NICID) (*stack.Stack, *stack.Stack) {
	host1Stack := stack.New(stackOpts)
	host2Stack := stack.New(stackOpts)

	host1NIC, host2NIC := pipe.New(linkAddr1, linkAddr2)

	if err := host1Stack.CreateNIC(host1NICID, newEthernetEndpoint(host1NIC)); err != nil {
		t.Fatalf("host1Stack.CreateNIC(%d, _): %s", host1NICID, err)
	}
	if err := host2Stack.CreateNIC(host2NICID, newEthernetEndpoint(host2NIC)); err != nil {
		t.Fatalf("host2Stack.CreateNIC(%d, _): %s", host2NICID, err)
	}

	if err := host1Stack.AddProtocolAddress(host1NICID, ipv4Addr1); err != nil {
		t.Fatalf("host1Stack.AddProtocolAddress(%d, %#v): %s", host1NICID, ipv4Addr1, err)
	}
	if err := host2Stack.AddProtocolAddress(host2NICID, ipv4Addr2); err != nil {
		t.Fatalf("host2Stack.AddProtocolAddress(%d, %#v): %s", host2NICID, ipv4Addr2, err)
	}
	if err := host1Stack.AddProtocolAddress(host1NICID, ipv6Addr1); err != nil {
		t.Fatalf("host1Stack.AddProtocolAddress(%d, %#v): %s", host1NICID, ipv6Addr1, err)
	}
	if err := host2Stack.AddProtocolAddress(host2NICID, ipv6Addr2); err != nil {
		t.Fatalf("host2Stack.AddProtocolAddress(%d, %#v): %s", host2NICID, ipv6Addr2, err)
	}

	host1Stack.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Addr1.AddressWithPrefix.Subnet(),
			NIC:         host1NICID,
		},
		{
			Destination: ipv6Addr1.AddressWithPrefix.Subnet(),
			NIC:         host1NICID,
		},
	})
	host2Stack.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Addr2.AddressWithPrefix.Subnet(),
			NIC:         host2NICID,
		},
		{
			Destination: ipv6Addr2.AddressWithPrefix.Subnet(),
			NIC:         host2NICID,
		},
	})

	return host1Stack, host2Stack
}

// TestPing tests that two hosts can ping eachother when link resolution is
// enabled.
func TestPing(t *testing.T) {
	const (
		host1NICID = 1
		host2NICID = 4

		// icmpDataOffset is the offset to the data in both ICMPv4 and ICMPv6 echo
		// request/reply packets.
		icmpDataOffset = 8
	)

	tests := []struct {
		name       string
		transProto tcpip.TransportProtocolNumber
		netProto   tcpip.NetworkProtocolNumber
		remoteAddr tcpip.Address
		icmpBuf    func(*testing.T) []byte
	}{
		{
			name:       "IPv4 Ping",
			transProto: icmp.ProtocolNumber4,
			netProto:   ipv4.ProtocolNumber,
			remoteAddr: ipv4Addr2.AddressWithPrefix.Address,
			icmpBuf: func(t *testing.T) []byte {
				data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
				hdr := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize+len(data)))
				hdr.SetType(header.ICMPv4Echo)
				if n := copy(hdr.Payload(), data[:]); n != len(data) {
					t.Fatalf("copied %d bytes but expected to copy %d bytes", n, len(data))
				}
				return hdr
			},
		},
		{
			name:       "IPv6 Ping",
			transProto: icmp.ProtocolNumber6,
			netProto:   ipv6.ProtocolNumber,
			remoteAddr: ipv6Addr2.AddressWithPrefix.Address,
			icmpBuf: func(t *testing.T) []byte {
				data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
				hdr := header.ICMPv6(make([]byte, header.ICMPv6MinimumSize+len(data)))
				hdr.SetType(header.ICMPv6EchoRequest)
				if n := copy(hdr.Payload(), data[:]); n != len(data) {
					t.Fatalf("copied %d bytes but expected to copy %d bytes", n, len(data))
				}
				return hdr
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stackOpts := stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4, icmp.NewProtocol6},
			}

			host1Stack, _ := setupStack(t, stackOpts, host1NICID, host2NICID)

			var wq waiter.Queue
			we, waiterCH := waiter.NewChannelEntry(nil)
			wq.EventRegister(&we, waiter.EventIn)
			ep, err := host1Stack.NewEndpoint(test.transProto, test.netProto, &wq)
			if err != nil {
				t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", test.transProto, test.netProto, err)
			}
			defer ep.Close()

			icmpBuf := test.icmpBuf(t)
			var r bytes.Reader
			r.Reset(icmpBuf)
			wOpts := tcpip.WriteOptions{To: &tcpip.FullAddress{Addr: test.remoteAddr}}
			if n, err := ep.Write(&r, wOpts); err != nil {
				t.Fatalf("ep.Write(_, _): %s", err)
			} else if want := int64(len(icmpBuf)); n != want {
				t.Fatalf("got ep.Write(_, _) = (%d, _), want = (%d, _)", n, want)
			}

			// Wait for the endpoint to be readable.
			<-waiterCH

			var buf bytes.Buffer
			opts := tcpip.ReadOptions{NeedRemoteAddr: true}
			res, err := ep.Read(&buf, opts)
			if err != nil {
				t.Fatalf("ep.Read(_, %d, %#v): %s", len(icmpBuf), opts, err)
			}
			if diff := cmp.Diff(tcpip.ReadResult{
				Count:      buf.Len(),
				Total:      buf.Len(),
				RemoteAddr: tcpip.FullAddress{Addr: test.remoteAddr},
			}, res, checker.IgnoreCmpPath(
				"ControlMessages",
				"RemoteAddr.NIC",
				"RemoteAddr.Port",
			)); diff != "" {
				t.Errorf("ep.Read: unexpected result (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(buf.Bytes()[icmpDataOffset:], icmpBuf[icmpDataOffset:]); diff != "" {
				t.Errorf("received data mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

type transportError struct {
	origin tcpip.SockErrOrigin
	typ    uint8
	code   uint8
	info   uint32
	kind   stack.TransportErrorKind
}

func TestTCPLinkResolutionFailure(t *testing.T) {
	const (
		host1NICID = 1
		host2NICID = 4
	)

	tests := []struct {
		name             string
		netProto         tcpip.NetworkProtocolNumber
		remoteAddr       tcpip.Address
		expectedWriteErr tcpip.Error
		sockError        tcpip.SockError
		transErr         transportError
	}{
		{
			name:             "IPv4 with resolvable remote",
			netProto:         ipv4.ProtocolNumber,
			remoteAddr:       ipv4Addr2.AddressWithPrefix.Address,
			expectedWriteErr: nil,
		},
		{
			name:             "IPv6 with resolvable remote",
			netProto:         ipv6.ProtocolNumber,
			remoteAddr:       ipv6Addr2.AddressWithPrefix.Address,
			expectedWriteErr: nil,
		},
		{
			name:             "IPv4 without resolvable remote",
			netProto:         ipv4.ProtocolNumber,
			remoteAddr:       ipv4Addr3.AddressWithPrefix.Address,
			expectedWriteErr: &tcpip.ErrNoRoute{},
			sockError: tcpip.SockError{
				Err: &tcpip.ErrNoRoute{},
				Dst: tcpip.FullAddress{
					NIC:  host1NICID,
					Addr: ipv4Addr3.AddressWithPrefix.Address,
					Port: 1234,
				},
				Offender: tcpip.FullAddress{
					NIC:  host1NICID,
					Addr: ipv4Addr1.AddressWithPrefix.Address,
				},
				NetProto: ipv4.ProtocolNumber,
			},
			transErr: transportError{
				origin: tcpip.SockExtErrorOriginICMP,
				typ:    uint8(header.ICMPv4DstUnreachable),
				code:   uint8(header.ICMPv4HostUnreachable),
				kind:   stack.DestinationHostUnreachableTransportError,
			},
		},
		{
			name:             "IPv6 without resolvable remote",
			netProto:         ipv6.ProtocolNumber,
			remoteAddr:       ipv6Addr3.AddressWithPrefix.Address,
			expectedWriteErr: &tcpip.ErrNoRoute{},
			sockError: tcpip.SockError{
				Err: &tcpip.ErrNoRoute{},
				Dst: tcpip.FullAddress{
					NIC:  host1NICID,
					Addr: ipv6Addr3.AddressWithPrefix.Address,
					Port: 1234,
				},
				Offender: tcpip.FullAddress{
					NIC:  host1NICID,
					Addr: ipv6Addr1.AddressWithPrefix.Address,
				},
				NetProto: ipv6.ProtocolNumber,
			},
			transErr: transportError{
				origin: tcpip.SockExtErrorOriginICMP6,
				typ:    uint8(header.ICMPv6DstUnreachable),
				code:   uint8(header.ICMPv6AddressUnreachable),
				kind:   stack.DestinationHostUnreachableTransportError,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stackOpts := stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
			}

			host1Stack, host2Stack := setupStack(t, stackOpts, host1NICID, host2NICID)

			var listenerWQ waiter.Queue
			listenerEP, err := host2Stack.NewEndpoint(tcp.ProtocolNumber, test.netProto, &listenerWQ)
			if err != nil {
				t.Fatalf("host2Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, test.netProto, err)
			}
			defer listenerEP.Close()

			listenerAddr := tcpip.FullAddress{Port: 1234}
			if err := listenerEP.Bind(listenerAddr); err != nil {
				t.Fatalf("listenerEP.Bind(%#v): %s", listenerAddr, err)
			}

			if err := listenerEP.Listen(1); err != nil {
				t.Fatalf("listenerEP.Listen(1): %s", err)
			}

			var clientWQ waiter.Queue
			we, ch := waiter.NewChannelEntry(nil)
			clientWQ.EventRegister(&we, waiter.EventOut|waiter.EventErr)
			clientEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, test.netProto, &clientWQ)
			if err != nil {
				t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, test.netProto, err)
			}
			defer clientEP.Close()

			sockOpts := clientEP.SocketOptions()
			sockOpts.SetRecvError(true)

			remoteAddr := listenerAddr
			remoteAddr.Addr = test.remoteAddr
			{
				err := clientEP.Connect(remoteAddr)
				if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
					t.Fatalf("got clientEP.Connect(%#v) = %s, want = %s", remoteAddr, err, &tcpip.ErrConnectStarted{})
				}
			}

			// Wait for an error due to link resolution failing, or the endpoint to be
			// writable.
			<-ch
			{
				var r bytes.Reader
				r.Reset([]byte{0})
				var wOpts tcpip.WriteOptions
				_, err := clientEP.Write(&r, wOpts)
				if diff := cmp.Diff(test.expectedWriteErr, err); diff != "" {
					t.Errorf("unexpected error from clientEP.Write(_, %#v), (-want, +got):\n%s", wOpts, diff)
				}
			}

			if test.expectedWriteErr == nil {
				return
			}

			sockErr := sockOpts.DequeueErr()
			if sockErr == nil {
				t.Fatalf("got sockOpts.DequeueErr() = nil, want = non-nil")
			}

			sockErrCmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(tcpip.SockError{}),
				cmp.Comparer(func(a, b tcpip.Error) bool {
					// tcpip.Error holds an unexported field but the errors netstack uses
					// are pre defined so we can simply compare pointers.
					return a == b
				}),
				checker.IgnoreCmpPath(
					// Ignore the payload since we do not know the TCP seq/ack numbers.
					"Payload",
					// Ignore the cause since we will compare its properties separately
					// since the concrete type of the cause is unknown.
					"Cause",
				),
			}

			if addr, err := clientEP.GetLocalAddress(); err != nil {
				t.Fatalf("clientEP.GetLocalAddress(): %s", err)
			} else {
				test.sockError.Offender.Port = addr.Port
			}
			if diff := cmp.Diff(&test.sockError, sockErr, sockErrCmpOpts...); diff != "" {
				t.Errorf("socket error mismatch (-want +got):\n%s", diff)
			}

			transErr, ok := sockErr.Cause.(stack.TransportError)
			if !ok {
				t.Fatalf("socket error cause is not a transport error; cause = %#v", sockErr.Cause)
			}
			if diff := cmp.Diff(
				test.transErr,
				transportError{
					origin: transErr.Origin(),
					typ:    transErr.Type(),
					code:   transErr.Code(),
					info:   transErr.Info(),
					kind:   transErr.Kind(),
				},
				cmp.AllowUnexported(transportError{}),
			); diff != "" {
				t.Errorf("socket error mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetLinkAddress(t *testing.T) {
	const (
		host1NICID = 1
		host2NICID = 4
	)

	tests := []struct {
		name       string
		netProto   tcpip.NetworkProtocolNumber
		remoteAddr tcpip.Address
		expectedOk bool
	}{
		{
			name:       "IPv4 resolvable",
			netProto:   ipv4.ProtocolNumber,
			remoteAddr: ipv4Addr2.AddressWithPrefix.Address,
			expectedOk: true,
		},
		{
			name:       "IPv6 resolvable",
			netProto:   ipv6.ProtocolNumber,
			remoteAddr: ipv6Addr2.AddressWithPrefix.Address,
			expectedOk: true,
		},
		{
			name:       "IPv4 not resolvable",
			netProto:   ipv4.ProtocolNumber,
			remoteAddr: ipv4Addr3.AddressWithPrefix.Address,
			expectedOk: false,
		},
		{
			name:       "IPv6 not resolvable",
			netProto:   ipv6.ProtocolNumber,
			remoteAddr: ipv6Addr3.AddressWithPrefix.Address,
			expectedOk: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stackOpts := stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
			}

			host1Stack, _ := setupStack(t, stackOpts, host1NICID, host2NICID)

			ch := make(chan stack.LinkResolutionResult, 1)
			err := host1Stack.GetLinkAddress(host1NICID, test.remoteAddr, "", test.netProto, func(r stack.LinkResolutionResult) {
				ch <- r
			})
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				t.Fatalf("got host1Stack.GetLinkAddress(%d, %s, '', %d, _) = %s, want = %s", host1NICID, test.remoteAddr, test.netProto, err, &tcpip.ErrWouldBlock{})
			}
			wantRes := stack.LinkResolutionResult{Success: test.expectedOk}
			if test.expectedOk {
				wantRes.LinkAddress = linkAddr2
			}
			if diff := cmp.Diff(wantRes, <-ch); diff != "" {
				t.Fatalf("link resolution result mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRouteResolvedFields(t *testing.T) {
	const (
		host1NICID = 1
		host2NICID = 4
	)

	tests := []struct {
		name                  string
		netProto              tcpip.NetworkProtocolNumber
		localAddr             tcpip.Address
		remoteAddr            tcpip.Address
		immediatelyResolvable bool
		expectedSuccess       bool
		expectedLinkAddr      tcpip.LinkAddress
	}{
		{
			name:                  "IPv4 immediately resolvable",
			netProto:              ipv4.ProtocolNumber,
			localAddr:             ipv4Addr1.AddressWithPrefix.Address,
			remoteAddr:            header.IPv4AllSystems,
			immediatelyResolvable: true,
			expectedSuccess:       true,
			expectedLinkAddr:      header.EthernetAddressFromMulticastIPv4Address(header.IPv4AllSystems),
		},
		{
			name:                  "IPv6 immediately resolvable",
			netProto:              ipv6.ProtocolNumber,
			localAddr:             ipv6Addr1.AddressWithPrefix.Address,
			remoteAddr:            header.IPv6AllNodesMulticastAddress,
			immediatelyResolvable: true,
			expectedSuccess:       true,
			expectedLinkAddr:      header.EthernetAddressFromMulticastIPv6Address(header.IPv6AllNodesMulticastAddress),
		},
		{
			name:                  "IPv4 resolvable",
			netProto:              ipv4.ProtocolNumber,
			localAddr:             ipv4Addr1.AddressWithPrefix.Address,
			remoteAddr:            ipv4Addr2.AddressWithPrefix.Address,
			immediatelyResolvable: false,
			expectedSuccess:       true,
			expectedLinkAddr:      linkAddr2,
		},
		{
			name:                  "IPv6 resolvable",
			netProto:              ipv6.ProtocolNumber,
			localAddr:             ipv6Addr1.AddressWithPrefix.Address,
			remoteAddr:            ipv6Addr2.AddressWithPrefix.Address,
			immediatelyResolvable: false,
			expectedSuccess:       true,
			expectedLinkAddr:      linkAddr2,
		},
		{
			name:                  "IPv4 not resolvable",
			netProto:              ipv4.ProtocolNumber,
			localAddr:             ipv4Addr1.AddressWithPrefix.Address,
			remoteAddr:            ipv4Addr3.AddressWithPrefix.Address,
			immediatelyResolvable: false,
			expectedSuccess:       false,
		},
		{
			name:                  "IPv6 not resolvable",
			netProto:              ipv6.ProtocolNumber,
			localAddr:             ipv6Addr1.AddressWithPrefix.Address,
			remoteAddr:            ipv6Addr3.AddressWithPrefix.Address,
			immediatelyResolvable: false,
			expectedSuccess:       false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stackOpts := stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
			}

			host1Stack, _ := setupStack(t, stackOpts, host1NICID, host2NICID)
			r, err := host1Stack.FindRoute(host1NICID, "", test.remoteAddr, test.netProto, false /* multicastLoop */)
			if err != nil {
				t.Fatalf("host1Stack.FindRoute(%d, '', %s, %d, false): %s", host1NICID, test.remoteAddr, test.netProto, err)
			}
			defer r.Release()

			var wantRouteInfo stack.RouteInfo
			wantRouteInfo.LocalLinkAddress = linkAddr1
			wantRouteInfo.LocalAddress = test.localAddr
			wantRouteInfo.RemoteAddress = test.remoteAddr
			wantRouteInfo.NetProto = test.netProto
			wantRouteInfo.Loop = stack.PacketOut
			wantRouteInfo.RemoteLinkAddress = test.expectedLinkAddr

			ch := make(chan stack.ResolvedFieldsResult, 1)

			if !test.immediatelyResolvable {
				wantUnresolvedRouteInfo := wantRouteInfo
				wantUnresolvedRouteInfo.RemoteLinkAddress = ""

				err := r.ResolvedFields(func(r stack.ResolvedFieldsResult) {
					ch <- r
				})
				if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
					t.Errorf("got r.ResolvedFields(_) = %s, want = %s", err, &tcpip.ErrWouldBlock{})
				}
				if diff := cmp.Diff(stack.ResolvedFieldsResult{RouteInfo: wantRouteInfo, Success: test.expectedSuccess}, <-ch, cmp.AllowUnexported(stack.RouteInfo{})); diff != "" {
					t.Errorf("route resolve result mismatch (-want +got):\n%s", diff)
				}

				if !test.expectedSuccess {
					return
				}

				// At this point the neighbor table should be populated so the route
				// should be immediately resolvable.
			}

			if err := r.ResolvedFields(func(r stack.ResolvedFieldsResult) {
				ch <- r
			}); err != nil {
				t.Errorf("r.ResolvedFields(_): %s", err)
			}
			select {
			case routeResolveRes := <-ch:
				if diff := cmp.Diff(stack.ResolvedFieldsResult{RouteInfo: wantRouteInfo, Success: true}, routeResolveRes, cmp.AllowUnexported(stack.RouteInfo{})); diff != "" {
					t.Errorf("route resolve result from resolved route mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("expected route to be immediately resolvable")
			}
		})
	}
}

func TestWritePacketsLinkResolution(t *testing.T) {
	const (
		host1NICID = 1
		host2NICID = 4
	)

	tests := []struct {
		name             string
		netProto         tcpip.NetworkProtocolNumber
		remoteAddr       tcpip.Address
		expectedWriteErr tcpip.Error
	}{
		{
			name:             "IPv4",
			netProto:         ipv4.ProtocolNumber,
			remoteAddr:       ipv4Addr2.AddressWithPrefix.Address,
			expectedWriteErr: nil,
		},
		{
			name:             "IPv6",
			netProto:         ipv6.ProtocolNumber,
			remoteAddr:       ipv6Addr2.AddressWithPrefix.Address,
			expectedWriteErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stackOpts := stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			}

			host1Stack, host2Stack := setupStack(t, stackOpts, host1NICID, host2NICID)

			var serverWQ waiter.Queue
			serverWE, serverCH := waiter.NewChannelEntry(nil)
			serverWQ.EventRegister(&serverWE, waiter.EventIn)
			serverEP, err := host2Stack.NewEndpoint(udp.ProtocolNumber, test.netProto, &serverWQ)
			if err != nil {
				t.Fatalf("host2Stack.NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, test.netProto, err)
			}
			defer serverEP.Close()

			serverAddr := tcpip.FullAddress{Port: 1234}
			if err := serverEP.Bind(serverAddr); err != nil {
				t.Fatalf("serverEP.Bind(%#v): %s", serverAddr, err)
			}

			r, err := host1Stack.FindRoute(host1NICID, "", test.remoteAddr, test.netProto, false /* multicastLoop */)
			if err != nil {
				t.Fatalf("host1Stack.FindRoute(%d, '', %s, %d, false): %s", host1NICID, test.remoteAddr, test.netProto, err)
			}
			defer r.Release()

			data := []byte{1, 2}
			var pkts stack.PacketBufferList
			for _, d := range data {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: header.UDPMinimumSize + int(r.MaxHeaderLength()),
					Data:               buffer.View([]byte{d}).ToVectorisedView(),
				})
				pkt.TransportProtocolNumber = udp.ProtocolNumber
				length := uint16(pkt.Size())
				udpHdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
				udpHdr.Encode(&header.UDPFields{
					SrcPort: 5555,
					DstPort: serverAddr.Port,
					Length:  length,
				})
				xsum := r.PseudoHeaderChecksum(udp.ProtocolNumber, length)
				for _, v := range pkt.Data.Views() {
					xsum = header.Checksum(v, xsum)
				}
				udpHdr.SetChecksum(^udpHdr.CalculateChecksum(xsum))

				pkts.PushBack(pkt)
			}

			params := stack.NetworkHeaderParams{
				Protocol: udp.ProtocolNumber,
				TTL:      64,
				TOS:      stack.DefaultTOS,
			}

			if n, err := r.WritePackets(nil /* gso */, pkts, params); err != nil {
				t.Fatalf("r.WritePackets(nil, %#v, _): %s", params, err)
			} else if want := pkts.Len(); want != n {
				t.Fatalf("got r.WritePackets(nil, %#v, _) = %d, want = %d", n, params, want)
			}

			var writer bytes.Buffer
			count := 0
			for {
				var rOpts tcpip.ReadOptions
				res, err := serverEP.Read(&writer, rOpts)
				if err != nil {
					if _, ok := err.(*tcpip.ErrWouldBlock); ok {
						// Should not have anymore bytes to read after we read the sent
						// number of bytes.
						if count == len(data) {
							break
						}

						<-serverCH
						continue
					}

					t.Fatalf("serverEP.Read(_, %#v): %s", rOpts, err)
				}
				count += res.Count
			}

			if got, want := host2Stack.Stats().UDP.PacketsReceived.Value(), uint64(len(data)); got != want {
				t.Errorf("got host2Stack.Stats().UDP.PacketsReceived.Value() = %d, want = %d", got, want)
			}
			if diff := cmp.Diff(data, writer.Bytes()); diff != "" {
				t.Errorf("read bytes mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

type eventType int

const (
	entryAdded eventType = iota
	entryChanged
	entryRemoved
)

func (t eventType) String() string {
	switch t {
	case entryAdded:
		return "add"
	case entryChanged:
		return "change"
	case entryRemoved:
		return "remove"
	default:
		return fmt.Sprintf("unknown (%d)", t)
	}
}

type eventInfo struct {
	eventType eventType
	nicID     tcpip.NICID
	entry     stack.NeighborEntry
}

func (e eventInfo) String() string {
	return fmt.Sprintf("%s event for NIC #%d, %#v", e.eventType, e.nicID, e.entry)
}

var _ stack.NUDDispatcher = (*nudDispatcher)(nil)

type nudDispatcher struct {
	c chan eventInfo
}

func (d *nudDispatcher) OnNeighborAdded(nicID tcpip.NICID, entry stack.NeighborEntry) {
	e := eventInfo{
		eventType: entryAdded,
		nicID:     nicID,
		entry:     entry,
	}
	d.c <- e
}

func (d *nudDispatcher) OnNeighborChanged(nicID tcpip.NICID, entry stack.NeighborEntry) {
	e := eventInfo{
		eventType: entryChanged,
		nicID:     nicID,
		entry:     entry,
	}
	d.c <- e
}

func (d *nudDispatcher) OnNeighborRemoved(nicID tcpip.NICID, entry stack.NeighborEntry) {
	e := eventInfo{
		eventType: entryRemoved,
		nicID:     nicID,
		entry:     entry,
	}
	d.c <- e
}

func (d *nudDispatcher) waitForEvent(want eventInfo) error {
	if diff := cmp.Diff(want, <-d.c, cmp.AllowUnexported(eventInfo{}), cmpopts.IgnoreFields(stack.NeighborEntry{}, "UpdatedAtNanos")); diff != "" {
		return fmt.Errorf("got invalid event (-want +got):\n%s", diff)
	}
	return nil
}

// TestTCPConfirmNeighborReachability tests that TCP informs layers beneath it
// that the neighbor used for a route is reachable.
func TestTCPConfirmNeighborReachability(t *testing.T) {
	tests := []struct {
		name            string
		netProto        tcpip.NetworkProtocolNumber
		remoteAddr      tcpip.Address
		neighborAddr    tcpip.Address
		getEndpoints    func(*testing.T, *stack.Stack, *stack.Stack, *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{})
		isHost1Listener bool
	}{
		{
			name:         "IPv4 active connection through neighbor",
			netProto:     ipv4.ProtocolNumber,
			remoteAddr:   host2IPv4Addr.AddressWithPrefix.Address,
			neighborAddr: routerNIC1IPv4Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, _, host2Stack *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := host2Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host2Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.EventOut)
				clientEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &clientWQ)
				if err != nil {
					listenerEP.Close()
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				return listenerEP, clientEP, clientCH
			},
		},
		{
			name:         "IPv6 active connection through neighbor",
			netProto:     ipv6.ProtocolNumber,
			remoteAddr:   host2IPv6Addr.AddressWithPrefix.Address,
			neighborAddr: routerNIC1IPv6Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, _, host2Stack *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := host2Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host2Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.EventOut)
				clientEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &clientWQ)
				if err != nil {
					listenerEP.Close()
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				return listenerEP, clientEP, clientCH
			},
		},
		{
			name:         "IPv4 active connection to neighbor",
			netProto:     ipv4.ProtocolNumber,
			remoteAddr:   routerNIC1IPv4Addr.AddressWithPrefix.Address,
			neighborAddr: routerNIC1IPv4Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, routerStack, _ *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := routerStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("routerStack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.EventOut)
				clientEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &clientWQ)
				if err != nil {
					listenerEP.Close()
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				return listenerEP, clientEP, clientCH
			},
		},
		{
			name:         "IPv6 active connection to neighbor",
			netProto:     ipv6.ProtocolNumber,
			remoteAddr:   routerNIC1IPv6Addr.AddressWithPrefix.Address,
			neighborAddr: routerNIC1IPv6Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, routerStack, _ *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := routerStack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("routerStack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.EventOut)
				clientEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &clientWQ)
				if err != nil {
					listenerEP.Close()
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				return listenerEP, clientEP, clientCH
			},
		},
		{
			name:         "IPv4 passive connection to neighbor",
			netProto:     ipv4.ProtocolNumber,
			remoteAddr:   host1IPv4Addr.AddressWithPrefix.Address,
			neighborAddr: routerNIC1IPv4Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, routerStack, _ *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.EventOut)
				clientEP, err := routerStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &clientWQ)
				if err != nil {
					listenerEP.Close()
					t.Fatalf("routerStack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				return listenerEP, clientEP, clientCH
			},
			isHost1Listener: true,
		},
		{
			name:         "IPv6 passive connection to neighbor",
			netProto:     ipv6.ProtocolNumber,
			remoteAddr:   host1IPv6Addr.AddressWithPrefix.Address,
			neighborAddr: routerNIC1IPv6Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, routerStack, _ *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.EventOut)
				clientEP, err := routerStack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &clientWQ)
				if err != nil {
					listenerEP.Close()
					t.Fatalf("routerStack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				return listenerEP, clientEP, clientCH
			},
			isHost1Listener: true,
		},
		{
			name:         "IPv4 passive connection through neighbor",
			netProto:     ipv4.ProtocolNumber,
			remoteAddr:   host1IPv4Addr.AddressWithPrefix.Address,
			neighborAddr: routerNIC1IPv4Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, _, host2Stack *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.EventOut)
				clientEP, err := host2Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &clientWQ)
				if err != nil {
					listenerEP.Close()
					t.Fatalf("host2Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				return listenerEP, clientEP, clientCH
			},
			isHost1Listener: true,
		},
		{
			name:         "IPv6 passive connection through neighbor",
			netProto:     ipv6.ProtocolNumber,
			remoteAddr:   host1IPv6Addr.AddressWithPrefix.Address,
			neighborAddr: routerNIC1IPv6Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, _, host2Stack *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.EventOut)
				clientEP, err := host2Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &clientWQ)
				if err != nil {
					listenerEP.Close()
					t.Fatalf("host2Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				return listenerEP, clientEP, clientCH
			},
			isHost1Listener: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			nudDisp := nudDispatcher{
				c: make(chan eventInfo, 3),
			}
			stackOpts := stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
				Clock:              clock,
			}
			host1StackOpts := stackOpts
			host1StackOpts.NUDDisp = &nudDisp

			host1Stack := stack.New(host1StackOpts)
			routerStack := stack.New(stackOpts)
			host2Stack := stack.New(stackOpts)
			setupRoutedStacks(t, host1Stack, routerStack, host2Stack)

			// Add a reachable dynamic entry to our neighbor table for the remote.
			{
				ch := make(chan stack.LinkResolutionResult, 1)
				err := host1Stack.GetLinkAddress(host1NICID, test.neighborAddr, "", test.netProto, func(r stack.LinkResolutionResult) {
					ch <- r
				})
				if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
					t.Fatalf("got host1Stack.GetLinkAddress(%d, %s, '', %d, _) = %s, want = %s", host1NICID, test.neighborAddr, test.netProto, err, &tcpip.ErrWouldBlock{})
				}
				if diff := cmp.Diff(stack.LinkResolutionResult{LinkAddress: linkAddr2, Success: true}, <-ch); diff != "" {
					t.Fatalf("link resolution mismatch (-want +got):\n%s", diff)
				}
			}
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryAdded,
				nicID:     host1NICID,
				entry:     stack.NeighborEntry{State: stack.Incomplete, Addr: test.neighborAddr},
			}); err != nil {
				t.Fatalf("error waiting for initial NUD event: %s", err)
			}
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryChanged,
				nicID:     host1NICID,
				entry:     stack.NeighborEntry{State: stack.Reachable, Addr: test.neighborAddr, LinkAddr: linkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for reachable NUD event: %s", err)
			}

			// Wait for the remote's neighbor entry to be stale before creating a
			// TCP connection from host1 to some remote.
			nudConfigs, err := host1Stack.NUDConfigurations(host1NICID, test.netProto)
			if err != nil {
				t.Fatalf("host1Stack.NUDConfigurations(%d, %d): %s", host1NICID, test.netProto, err)
			}
			// The maximum reachable time for a neighbor is some maximum random factor
			// applied to the base reachable time.
			//
			// See NUDConfigurations.BaseReachableTime for more information.
			maxReachableTime := time.Duration(float32(nudConfigs.BaseReachableTime) * nudConfigs.MaxRandomFactor)
			clock.Advance(maxReachableTime)
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryChanged,
				nicID:     host1NICID,
				entry:     stack.NeighborEntry{State: stack.Stale, Addr: test.neighborAddr, LinkAddr: linkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for stale NUD event: %s", err)
			}

			listenerEP, clientEP, clientCH := test.getEndpoints(t, host1Stack, routerStack, host2Stack)
			defer listenerEP.Close()
			defer clientEP.Close()
			listenerAddr := tcpip.FullAddress{Addr: test.remoteAddr, Port: 1234}
			if err := listenerEP.Bind(listenerAddr); err != nil {
				t.Fatalf("listenerEP.Bind(%#v): %s", listenerAddr, err)
			}
			if err := listenerEP.Listen(1); err != nil {
				t.Fatalf("listenerEP.Listen(1): %s", err)
			}
			{
				err := clientEP.Connect(listenerAddr)
				if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
					t.Fatalf("got clientEP.Connect(%#v) = %s, want = %s", listenerAddr, err, &tcpip.ErrConnectStarted{})
				}
			}

			// Wait for the TCP handshake to complete then make sure the neighbor is
			// reachable without entering the probe state as TCP should provide NUD
			// with confirmation that the neighbor is reachable (indicated by a
			// successful 3-way handshake).
			<-clientCH
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryChanged,
				nicID:     host1NICID,
				entry:     stack.NeighborEntry{State: stack.Delay, Addr: test.neighborAddr, LinkAddr: linkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for delay NUD event: %s", err)
			}
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryChanged,
				nicID:     host1NICID,
				entry:     stack.NeighborEntry{State: stack.Reachable, Addr: test.neighborAddr, LinkAddr: linkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for reachable NUD event: %s", err)
			}

			// Wait for the neighbor to be stale again then send data to the remote.
			//
			// On successful transmission, the neighbor should become reachable
			// without probing the neighbor as a TCP ACK would be received which is an
			// indication of the neighbor being reachable.
			clock.Advance(maxReachableTime)
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryChanged,
				nicID:     host1NICID,
				entry:     stack.NeighborEntry{State: stack.Stale, Addr: test.neighborAddr, LinkAddr: linkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for stale NUD event: %s", err)
			}
			var r bytes.Reader
			r.Reset([]byte{0})
			var wOpts tcpip.WriteOptions
			if _, err := clientEP.Write(&r, wOpts); err != nil {
				t.Errorf("clientEP.Write(_, %#v): %s", wOpts, err)
			}
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryChanged,
				nicID:     host1NICID,
				entry:     stack.NeighborEntry{State: stack.Delay, Addr: test.neighborAddr, LinkAddr: linkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for delay NUD event: %s", err)
			}
			if test.isHost1Listener {
				// If host1 is not the client, host1 does not send any data so TCP
				// has no way to know it is making forward progress. Because of this,
				// TCP should not mark the route reachable and NUD should go through the
				// probe state.
				clock.Advance(nudConfigs.DelayFirstProbeTime)
				if err := nudDisp.waitForEvent(eventInfo{
					eventType: entryChanged,
					nicID:     host1NICID,
					entry:     stack.NeighborEntry{State: stack.Probe, Addr: test.neighborAddr, LinkAddr: linkAddr2},
				}); err != nil {
					t.Fatalf("error waiting for probe NUD event: %s", err)
				}
			}
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryChanged,
				nicID:     host1NICID,
				entry:     stack.NeighborEntry{State: stack.Reachable, Addr: test.neighborAddr, LinkAddr: linkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for reachable NUD event: %s", err)
			}
		})
	}
}

func TestDAD(t *testing.T) {
	const (
		host1NICID = 1
		host2NICID = 4
	)

	dadConfigs := stack.DADConfigurations{
		DupAddrDetectTransmits: 1,
		RetransmitTimer:        time.Second,
	}

	tests := []struct {
		name             string
		netProto         tcpip.NetworkProtocolNumber
		dadNetProto      tcpip.NetworkProtocolNumber
		remoteAddr       tcpip.Address
		expectedResolved bool
	}{
		{
			name:             "IPv4 own address",
			netProto:         ipv4.ProtocolNumber,
			dadNetProto:      arp.ProtocolNumber,
			remoteAddr:       ipv4Addr1.AddressWithPrefix.Address,
			expectedResolved: true,
		},
		{
			name:             "IPv6 own address",
			netProto:         ipv6.ProtocolNumber,
			dadNetProto:      ipv6.ProtocolNumber,
			remoteAddr:       ipv6Addr1.AddressWithPrefix.Address,
			expectedResolved: true,
		},
		{
			name:             "IPv4 duplicate address",
			netProto:         ipv4.ProtocolNumber,
			dadNetProto:      arp.ProtocolNumber,
			remoteAddr:       ipv4Addr2.AddressWithPrefix.Address,
			expectedResolved: false,
		},
		{
			name:             "IPv6 duplicate address",
			netProto:         ipv6.ProtocolNumber,
			dadNetProto:      ipv6.ProtocolNumber,
			remoteAddr:       ipv6Addr2.AddressWithPrefix.Address,
			expectedResolved: false,
		},
		{
			name:             "IPv4 no duplicate address",
			netProto:         ipv4.ProtocolNumber,
			dadNetProto:      arp.ProtocolNumber,
			remoteAddr:       ipv4Addr3.AddressWithPrefix.Address,
			expectedResolved: true,
		},
		{
			name:             "IPv6 no duplicate address",
			netProto:         ipv6.ProtocolNumber,
			dadNetProto:      ipv6.ProtocolNumber,
			remoteAddr:       ipv6Addr3.AddressWithPrefix.Address,
			expectedResolved: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			stackOpts := stack.Options{
				Clock: clock,
				NetworkProtocols: []stack.NetworkProtocolFactory{
					arp.NewProtocol,
					ipv4.NewProtocol,
					ipv6.NewProtocol,
				},
			}

			host1Stack, _ := setupStack(t, stackOpts, host1NICID, host2NICID)

			// DAD should be disabled by default.
			if res, err := host1Stack.CheckDuplicateAddress(host1NICID, test.netProto, test.remoteAddr, func(r stack.DADResult) {
				t.Errorf("unexpectedly called DAD completion handler when DAD was supposed to be disabled")
			}); err != nil {
				t.Fatalf("host1Stack.CheckDuplicateAddress(%d, %d, %s, _): %s", host1NICID, test.netProto, test.remoteAddr, err)
			} else if res != stack.DADDisabled {
				t.Errorf("got host1Stack.CheckDuplicateAddress(%d, %d, %s, _) = %d, want = %d", host1NICID, test.netProto, test.remoteAddr, res, stack.DADDisabled)
			}

			// Enable DAD then attempt to check if an address is duplicated.
			netEP, err := host1Stack.GetNetworkEndpoint(host1NICID, test.dadNetProto)
			if err != nil {
				t.Fatalf("host1Stack.GetNetworkEndpoint(%d, %d): %s", host1NICID, test.dadNetProto, err)
			}
			dad, ok := netEP.(stack.DuplicateAddressDetector)
			if !ok {
				t.Fatalf("expected %T to implement stack.DuplicateAddressDetector", netEP)
			}
			dad.SetDADConfigurations(dadConfigs)
			ch := make(chan stack.DADResult, 3)
			if res, err := host1Stack.CheckDuplicateAddress(host1NICID, test.netProto, test.remoteAddr, func(r stack.DADResult) {
				ch <- r
			}); err != nil {
				t.Fatalf("host1Stack.CheckDuplicateAddress(%d, %d, %s, _): %s", host1NICID, test.netProto, test.remoteAddr, err)
			} else if res != stack.DADStarting {
				t.Errorf("got host1Stack.CheckDuplicateAddress(%d, %d, %s, _) = %d, want = %d", host1NICID, test.netProto, test.remoteAddr, res, stack.DADStarting)
			}

			expectResults := 1
			if test.expectedResolved {
				const delta = time.Nanosecond
				clock.Advance(time.Duration(dadConfigs.DupAddrDetectTransmits)*dadConfigs.RetransmitTimer - delta)
				select {
				case r := <-ch:
					t.Fatalf("unexpectedly got DAD result before the DAD timeout; r = %#v", r)
				default:
				}

				// If we expect the resolve to succeed try requesting DAD again on the
				// same address. The handler for the new request should be called once
				// the original DAD request completes.
				expectResults = 2
				if res, err := host1Stack.CheckDuplicateAddress(host1NICID, test.netProto, test.remoteAddr, func(r stack.DADResult) {
					ch <- r
				}); err != nil {
					t.Fatalf("host1Stack.CheckDuplicateAddress(%d, %d, %s, _): %s", host1NICID, test.netProto, test.remoteAddr, err)
				} else if res != stack.DADAlreadyRunning {
					t.Errorf("got host1Stack.CheckDuplicateAddress(%d, %d, %s, _) = %d, want = %d", host1NICID, test.netProto, test.remoteAddr, res, stack.DADAlreadyRunning)
				}

				clock.Advance(delta)
			}

			for i := 0; i < expectResults; i++ {
				if diff := cmp.Diff(stack.DADResult{Resolved: test.expectedResolved}, <-ch); diff != "" {
					t.Errorf("(i=%d) DAD result mismatch (-want +got):\n%s", i, diff)
				}
			}

			// Should have no more results.
			select {
			case r := <-ch:
				t.Errorf("unexpectedly got an extra DAD result; r = %#v", r)
			default:
			}
		})
	}
}
