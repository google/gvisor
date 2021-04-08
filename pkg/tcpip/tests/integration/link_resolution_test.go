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

package link_resolution_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/tests/utils"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func setupStack(t *testing.T, stackOpts stack.Options, host1NICID, host2NICID tcpip.NICID) (*stack.Stack, *stack.Stack) {
	host1Stack := stack.New(stackOpts)
	host2Stack := stack.New(stackOpts)

	host1NIC, host2NIC := pipe.New(utils.LinkAddr1, utils.LinkAddr2)

	if err := host1Stack.CreateNIC(host1NICID, utils.NewEthernetEndpoint(host1NIC)); err != nil {
		t.Fatalf("host1Stack.CreateNIC(%d, _): %s", host1NICID, err)
	}
	if err := host2Stack.CreateNIC(host2NICID, utils.NewEthernetEndpoint(host2NIC)); err != nil {
		t.Fatalf("host2Stack.CreateNIC(%d, _): %s", host2NICID, err)
	}

	if err := host1Stack.AddProtocolAddress(host1NICID, utils.Ipv4Addr1); err != nil {
		t.Fatalf("host1Stack.AddProtocolAddress(%d, %#v): %s", host1NICID, utils.Ipv4Addr1, err)
	}
	if err := host2Stack.AddProtocolAddress(host2NICID, utils.Ipv4Addr2); err != nil {
		t.Fatalf("host2Stack.AddProtocolAddress(%d, %#v): %s", host2NICID, utils.Ipv4Addr2, err)
	}
	if err := host1Stack.AddProtocolAddress(host1NICID, utils.Ipv6Addr1); err != nil {
		t.Fatalf("host1Stack.AddProtocolAddress(%d, %#v): %s", host1NICID, utils.Ipv6Addr1, err)
	}
	if err := host2Stack.AddProtocolAddress(host2NICID, utils.Ipv6Addr2); err != nil {
		t.Fatalf("host2Stack.AddProtocolAddress(%d, %#v): %s", host2NICID, utils.Ipv6Addr2, err)
	}

	host1Stack.SetRouteTable([]tcpip.Route{
		{
			Destination: utils.Ipv4Addr1.AddressWithPrefix.Subnet(),
			NIC:         host1NICID,
		},
		{
			Destination: utils.Ipv6Addr1.AddressWithPrefix.Subnet(),
			NIC:         host1NICID,
		},
	})
	host2Stack.SetRouteTable([]tcpip.Route{
		{
			Destination: utils.Ipv4Addr2.AddressWithPrefix.Subnet(),
			NIC:         host2NICID,
		},
		{
			Destination: utils.Ipv6Addr2.AddressWithPrefix.Subnet(),
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
			remoteAddr: utils.Ipv4Addr2.AddressWithPrefix.Address,
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
			remoteAddr: utils.Ipv6Addr2.AddressWithPrefix.Address,
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
			wq.EventRegister(&we, waiter.ReadableEvents)
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
			remoteAddr:       utils.Ipv4Addr2.AddressWithPrefix.Address,
			expectedWriteErr: nil,
		},
		{
			name:             "IPv6 with resolvable remote",
			netProto:         ipv6.ProtocolNumber,
			remoteAddr:       utils.Ipv6Addr2.AddressWithPrefix.Address,
			expectedWriteErr: nil,
		},
		{
			name:             "IPv4 without resolvable remote",
			netProto:         ipv4.ProtocolNumber,
			remoteAddr:       utils.Ipv4Addr3.AddressWithPrefix.Address,
			expectedWriteErr: &tcpip.ErrNoRoute{},
			sockError: tcpip.SockError{
				Err: &tcpip.ErrNoRoute{},
				Dst: tcpip.FullAddress{
					NIC:  host1NICID,
					Addr: utils.Ipv4Addr3.AddressWithPrefix.Address,
					Port: 1234,
				},
				Offender: tcpip.FullAddress{
					NIC:  host1NICID,
					Addr: utils.Ipv4Addr1.AddressWithPrefix.Address,
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
			remoteAddr:       utils.Ipv6Addr3.AddressWithPrefix.Address,
			expectedWriteErr: &tcpip.ErrNoRoute{},
			sockError: tcpip.SockError{
				Err: &tcpip.ErrNoRoute{},
				Dst: tcpip.FullAddress{
					NIC:  host1NICID,
					Addr: utils.Ipv6Addr3.AddressWithPrefix.Address,
					Port: 1234,
				},
				Offender: tcpip.FullAddress{
					NIC:  host1NICID,
					Addr: utils.Ipv6Addr1.AddressWithPrefix.Address,
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
			clientWQ.EventRegister(&we, waiter.WritableEvents|waiter.EventErr)
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
		name                  string
		netProto              tcpip.NetworkProtocolNumber
		remoteAddr, localAddr tcpip.Address
		expectedErr           tcpip.Error
	}{
		{
			name:        "IPv4 resolvable",
			netProto:    ipv4.ProtocolNumber,
			remoteAddr:  utils.Ipv4Addr2.AddressWithPrefix.Address,
			expectedErr: nil,
		},
		{
			name:        "IPv6 resolvable",
			netProto:    ipv6.ProtocolNumber,
			remoteAddr:  utils.Ipv6Addr2.AddressWithPrefix.Address,
			expectedErr: nil,
		},
		{
			name:        "IPv4 not resolvable",
			netProto:    ipv4.ProtocolNumber,
			remoteAddr:  utils.Ipv4Addr3.AddressWithPrefix.Address,
			expectedErr: &tcpip.ErrTimeout{},
		},
		{
			name:        "IPv6 not resolvable",
			netProto:    ipv6.ProtocolNumber,
			remoteAddr:  utils.Ipv6Addr3.AddressWithPrefix.Address,
			expectedErr: &tcpip.ErrTimeout{},
		},
		{
			name:        "IPv4 bad local address",
			netProto:    ipv4.ProtocolNumber,
			remoteAddr:  utils.Ipv4Addr2.AddressWithPrefix.Address,
			localAddr:   utils.Ipv4Addr2.AddressWithPrefix.Address,
			expectedErr: &tcpip.ErrBadLocalAddress{},
		},
		{
			name:        "IPv6 bad local address",
			netProto:    ipv6.ProtocolNumber,
			remoteAddr:  utils.Ipv6Addr2.AddressWithPrefix.Address,
			localAddr:   utils.Ipv6Addr2.AddressWithPrefix.Address,
			expectedErr: &tcpip.ErrBadLocalAddress{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stackOpts := stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
			}

			host1Stack, _ := setupStack(t, stackOpts, host1NICID, host2NICID)

			ch := make(chan stack.LinkResolutionResult, 1)
			err := host1Stack.GetLinkAddress(host1NICID, test.remoteAddr, test.localAddr, test.netProto, func(r stack.LinkResolutionResult) {
				ch <- r
			})
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				t.Fatalf("got host1Stack.GetLinkAddress(%d, %s, '', %d, _) = %s, want = %s", host1NICID, test.remoteAddr, test.netProto, err, &tcpip.ErrWouldBlock{})
			}
			wantRes := stack.LinkResolutionResult{Err: test.expectedErr}
			if test.expectedErr == nil {
				wantRes.LinkAddress = utils.LinkAddr2
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
		expectedErr           tcpip.Error
		expectedLinkAddr      tcpip.LinkAddress
	}{
		{
			name:                  "IPv4 immediately resolvable",
			netProto:              ipv4.ProtocolNumber,
			localAddr:             utils.Ipv4Addr1.AddressWithPrefix.Address,
			remoteAddr:            header.IPv4AllSystems,
			immediatelyResolvable: true,
			expectedErr:           nil,
			expectedLinkAddr:      header.EthernetAddressFromMulticastIPv4Address(header.IPv4AllSystems),
		},
		{
			name:                  "IPv6 immediately resolvable",
			netProto:              ipv6.ProtocolNumber,
			localAddr:             utils.Ipv6Addr1.AddressWithPrefix.Address,
			remoteAddr:            header.IPv6AllNodesMulticastAddress,
			immediatelyResolvable: true,
			expectedErr:           nil,
			expectedLinkAddr:      header.EthernetAddressFromMulticastIPv6Address(header.IPv6AllNodesMulticastAddress),
		},
		{
			name:                  "IPv4 resolvable",
			netProto:              ipv4.ProtocolNumber,
			localAddr:             utils.Ipv4Addr1.AddressWithPrefix.Address,
			remoteAddr:            utils.Ipv4Addr2.AddressWithPrefix.Address,
			immediatelyResolvable: false,
			expectedErr:           nil,
			expectedLinkAddr:      utils.LinkAddr2,
		},
		{
			name:                  "IPv6 resolvable",
			netProto:              ipv6.ProtocolNumber,
			localAddr:             utils.Ipv6Addr1.AddressWithPrefix.Address,
			remoteAddr:            utils.Ipv6Addr2.AddressWithPrefix.Address,
			immediatelyResolvable: false,
			expectedErr:           nil,
			expectedLinkAddr:      utils.LinkAddr2,
		},
		{
			name:                  "IPv4 not resolvable",
			netProto:              ipv4.ProtocolNumber,
			localAddr:             utils.Ipv4Addr1.AddressWithPrefix.Address,
			remoteAddr:            utils.Ipv4Addr3.AddressWithPrefix.Address,
			immediatelyResolvable: false,
			expectedErr:           &tcpip.ErrTimeout{},
		},
		{
			name:                  "IPv6 not resolvable",
			netProto:              ipv6.ProtocolNumber,
			localAddr:             utils.Ipv6Addr1.AddressWithPrefix.Address,
			remoteAddr:            utils.Ipv6Addr3.AddressWithPrefix.Address,
			immediatelyResolvable: false,
			expectedErr:           &tcpip.ErrTimeout{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stackOpts := stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
			}

			host1Stack, _ := setupStack(t, stackOpts, host1NICID, host2NICID)
			r, err := host1Stack.FindRoute(host1NICID, test.localAddr, test.remoteAddr, test.netProto, false /* multicastLoop */)
			if err != nil {
				t.Fatalf("host1Stack.FindRoute(%d, %s, %s, %d, false): %s", host1NICID, test.localAddr, test.remoteAddr, test.netProto, err)
			}
			defer r.Release()

			var wantRouteInfo stack.RouteInfo
			wantRouteInfo.LocalLinkAddress = utils.LinkAddr1
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
				if diff := cmp.Diff(stack.ResolvedFieldsResult{RouteInfo: wantRouteInfo, Err: test.expectedErr}, <-ch, cmp.AllowUnexported(stack.RouteInfo{})); diff != "" {
					t.Errorf("route resolve result mismatch (-want +got):\n%s", diff)
				}

				if test.expectedErr != nil {
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
				if diff := cmp.Diff(stack.ResolvedFieldsResult{RouteInfo: wantRouteInfo, Err: nil}, routeResolveRes, cmp.AllowUnexported(stack.RouteInfo{})); diff != "" {
					t.Errorf("route resolve result from resolved route mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("expected route to be immediately resolvable")
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
			remoteAddr:   utils.Host2IPv4Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, _, host2Stack *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := host2Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host2Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.WritableEvents)
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
			remoteAddr:   utils.Host2IPv6Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, _, host2Stack *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := host2Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host2Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.WritableEvents)
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
			remoteAddr:   utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, routerStack, _ *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := routerStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("routerStack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.WritableEvents)
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
			remoteAddr:   utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, routerStack, _ *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := routerStack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("routerStack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.WritableEvents)
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
			remoteAddr:   utils.Host1IPv4Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, routerStack, _ *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.WritableEvents)
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
			remoteAddr:   utils.Host1IPv6Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, routerStack, _ *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.WritableEvents)
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
			remoteAddr:   utils.Host1IPv4Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, _, host2Stack *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.WritableEvents)
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
			remoteAddr:   utils.Host1IPv6Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, _, host2Stack *stack.Stack) (tcpip.Endpoint, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(nil)
				clientWQ.EventRegister(&clientWE, waiter.WritableEvents)
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
			utils.SetupRoutedStacks(t, host1Stack, routerStack, host2Stack)

			// Add a reachable dynamic entry to our neighbor table for the remote.
			{
				ch := make(chan stack.LinkResolutionResult, 1)
				err := host1Stack.GetLinkAddress(utils.Host1NICID, test.neighborAddr, "", test.netProto, func(r stack.LinkResolutionResult) {
					ch <- r
				})
				if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
					t.Fatalf("got host1Stack.GetLinkAddress(%d, %s, '', %d, _) = %s, want = %s", utils.Host1NICID, test.neighborAddr, test.netProto, err, &tcpip.ErrWouldBlock{})
				}
				if diff := cmp.Diff(stack.LinkResolutionResult{LinkAddress: utils.LinkAddr2, Err: nil}, <-ch); diff != "" {
					t.Fatalf("link resolution mismatch (-want +got):\n%s", diff)
				}
			}
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryAdded,
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Incomplete, Addr: test.neighborAddr},
			}); err != nil {
				t.Fatalf("error waiting for initial NUD event: %s", err)
			}
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryChanged,
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Reachable, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for reachable NUD event: %s", err)
			}

			// Wait for the remote's neighbor entry to be stale before creating a
			// TCP connection from host1 to some remote.
			nudConfigs, err := host1Stack.NUDConfigurations(utils.Host1NICID, test.netProto)
			if err != nil {
				t.Fatalf("host1Stack.NUDConfigurations(%d, %d): %s", utils.Host1NICID, test.netProto, err)
			}
			// The maximum reachable time for a neighbor is some maximum random factor
			// applied to the base reachable time.
			//
			// See NUDConfigurations.BaseReachableTime for more information.
			maxReachableTime := time.Duration(float32(nudConfigs.BaseReachableTime) * nudConfigs.MaxRandomFactor)
			clock.Advance(maxReachableTime)
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryChanged,
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Stale, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
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
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Delay, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for delay NUD event: %s", err)
			}
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryChanged,
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Reachable, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
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
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Stale, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
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
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Delay, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
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
					nicID:     utils.Host1NICID,
					entry:     stack.NeighborEntry{State: stack.Probe, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
				}); err != nil {
					t.Fatalf("error waiting for probe NUD event: %s", err)
				}
			}
			if err := nudDisp.waitForEvent(eventInfo{
				eventType: entryChanged,
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Reachable, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for reachable NUD event: %s", err)
			}
		})
	}
}

func TestDAD(t *testing.T) {
	dadConfigs := stack.DADConfigurations{
		DupAddrDetectTransmits: 1,
		RetransmitTimer:        time.Second,
	}

	tests := []struct {
		name           string
		netProto       tcpip.NetworkProtocolNumber
		dadNetProto    tcpip.NetworkProtocolNumber
		remoteAddr     tcpip.Address
		expectedResult stack.DADResult
	}{
		{
			name:           "IPv4 own address",
			netProto:       ipv4.ProtocolNumber,
			dadNetProto:    arp.ProtocolNumber,
			remoteAddr:     utils.Ipv4Addr1.AddressWithPrefix.Address,
			expectedResult: &stack.DADSucceeded{},
		},
		{
			name:           "IPv6 own address",
			netProto:       ipv6.ProtocolNumber,
			dadNetProto:    ipv6.ProtocolNumber,
			remoteAddr:     utils.Ipv6Addr1.AddressWithPrefix.Address,
			expectedResult: &stack.DADSucceeded{},
		},
		{
			name:           "IPv4 duplicate address",
			netProto:       ipv4.ProtocolNumber,
			dadNetProto:    arp.ProtocolNumber,
			remoteAddr:     utils.Ipv4Addr2.AddressWithPrefix.Address,
			expectedResult: &stack.DADDupAddrDetected{HolderLinkAddress: utils.LinkAddr2},
		},
		{
			name:           "IPv6 duplicate address",
			netProto:       ipv6.ProtocolNumber,
			dadNetProto:    ipv6.ProtocolNumber,
			remoteAddr:     utils.Ipv6Addr2.AddressWithPrefix.Address,
			expectedResult: &stack.DADDupAddrDetected{HolderLinkAddress: utils.LinkAddr2},
		},
		{
			name:           "IPv4 no duplicate address",
			netProto:       ipv4.ProtocolNumber,
			dadNetProto:    arp.ProtocolNumber,
			remoteAddr:     utils.Ipv4Addr3.AddressWithPrefix.Address,
			expectedResult: &stack.DADSucceeded{},
		},
		{
			name:           "IPv6 no duplicate address",
			netProto:       ipv6.ProtocolNumber,
			dadNetProto:    ipv6.ProtocolNumber,
			remoteAddr:     utils.Ipv6Addr3.AddressWithPrefix.Address,
			expectedResult: &stack.DADSucceeded{},
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

			host1Stack, _ := setupStack(t, stackOpts, utils.Host1NICID, utils.Host2NICID)

			// DAD should be disabled by default.
			if res, err := host1Stack.CheckDuplicateAddress(utils.Host1NICID, test.netProto, test.remoteAddr, func(r stack.DADResult) {
				t.Errorf("unexpectedly called DAD completion handler when DAD was supposed to be disabled")
			}); err != nil {
				t.Fatalf("host1Stack.CheckDuplicateAddress(%d, %d, %s, _): %s", utils.Host1NICID, test.netProto, test.remoteAddr, err)
			} else if res != stack.DADDisabled {
				t.Errorf("got host1Stack.CheckDuplicateAddress(%d, %d, %s, _) = %d, want = %d", utils.Host1NICID, test.netProto, test.remoteAddr, res, stack.DADDisabled)
			}

			// Enable DAD then attempt to check if an address is duplicated.
			netEP, err := host1Stack.GetNetworkEndpoint(utils.Host1NICID, test.dadNetProto)
			if err != nil {
				t.Fatalf("host1Stack.GetNetworkEndpoint(%d, %d): %s", utils.Host1NICID, test.dadNetProto, err)
			}
			dad, ok := netEP.(stack.DuplicateAddressDetector)
			if !ok {
				t.Fatalf("expected %T to implement stack.DuplicateAddressDetector", netEP)
			}
			dad.SetDADConfigurations(dadConfigs)
			ch := make(chan stack.DADResult, 3)
			if res, err := host1Stack.CheckDuplicateAddress(utils.Host1NICID, test.netProto, test.remoteAddr, func(r stack.DADResult) {
				ch <- r
			}); err != nil {
				t.Fatalf("host1Stack.CheckDuplicateAddress(%d, %d, %s, _): %s", utils.Host1NICID, test.netProto, test.remoteAddr, err)
			} else if res != stack.DADStarting {
				t.Errorf("got host1Stack.CheckDuplicateAddress(%d, %d, %s, _) = %d, want = %d", utils.Host1NICID, test.netProto, test.remoteAddr, res, stack.DADStarting)
			}

			expectResults := 1
			if _, ok := test.expectedResult.(*stack.DADSucceeded); ok {
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
				if res, err := host1Stack.CheckDuplicateAddress(utils.Host1NICID, test.netProto, test.remoteAddr, func(r stack.DADResult) {
					ch <- r
				}); err != nil {
					t.Fatalf("host1Stack.CheckDuplicateAddress(%d, %d, %s, _): %s", utils.Host1NICID, test.netProto, test.remoteAddr, err)
				} else if res != stack.DADAlreadyRunning {
					t.Errorf("got host1Stack.CheckDuplicateAddress(%d, %d, %s, _) = %d, want = %d", utils.Host1NICID, test.netProto, test.remoteAddr, res, stack.DADAlreadyRunning)
				}

				clock.Advance(delta)
			}

			for i := 0; i < expectResults; i++ {
				if diff := cmp.Diff(test.expectedResult, <-ch); diff != "" {
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
