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
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/tests/utils"
	tcptestutil "gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func setupStack(t *testing.T, stackOpts stack.Options, host1NICID, host2NICID tcpip.NICID) (*stack.Stack, *stack.Stack) {
	const maxFrameSize = header.IPv6MinimumMTU + header.EthernetMinimumSize

	host1Stack := stack.New(stackOpts)
	host2Stack := stack.New(stackOpts)

	host1NIC, host2NIC := pipe.New(utils.LinkAddr1, utils.LinkAddr2, maxFrameSize)

	if err := host1Stack.CreateNIC(host1NICID, utils.NewEthernetEndpoint(host1NIC)); err != nil {
		t.Fatalf("host1Stack.CreateNIC(%d, _): %s", host1NICID, err)
	}
	if err := host2Stack.CreateNIC(host2NICID, utils.NewEthernetEndpoint(host2NIC)); err != nil {
		t.Fatalf("host2Stack.CreateNIC(%d, _): %s", host2NICID, err)
	}

	if err := host1Stack.AddProtocolAddress(host1NICID, utils.Ipv4Addr1, stack.AddressProperties{}); err != nil {
		t.Fatalf("host1Stack.AddProtocolAddress(%d, %+v, {}): %s", host1NICID, utils.Ipv4Addr1, err)
	}
	if err := host2Stack.AddProtocolAddress(host2NICID, utils.Ipv4Addr2, stack.AddressProperties{}); err != nil {
		t.Fatalf("host2Stack.AddProtocolAddress(%d, %+v, {}): %s", host2NICID, utils.Ipv4Addr2, err)
	}
	if err := host1Stack.AddProtocolAddress(host1NICID, utils.Ipv6Addr1, stack.AddressProperties{}); err != nil {
		t.Fatalf("host1Stack.AddProtocolAddress(%d, %+v, {}): %s", host1NICID, utils.Ipv6Addr1, err)
	}
	if err := host2Stack.AddProtocolAddress(host2NICID, utils.Ipv6Addr2, stack.AddressProperties{}); err != nil {
		t.Fatalf("host2Stack.AddProtocolAddress(%d, %+v, {}): %s", host2NICID, utils.Ipv6Addr2, err)
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
			we, waiterCH := waiter.NewChannelEntry(waiter.ReadableEvents)
			wq.EventRegister(&we)
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
			clock := faketime.NewManualClock()
			stackOpts := stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
				Clock:              clock,
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
			we, ch := waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventErr)
			clientWQ.EventRegister(&we)
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
			if test.expectedWriteErr != nil {
				nudConfigs, err := host1Stack.NUDConfigurations(host1NICID, test.netProto)
				if err != nil {
					t.Fatalf("host1Stack.NUDConfigurations(%d, %d): %s", host1NICID, test.netProto, err)
				}
				clock.Advance(time.Duration(nudConfigs.MaxMulticastProbes) * nudConfigs.RetransmitTimer)
			} else {
				clock.RunImmediatelyScheduledJobs()
			}
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

func TestForwardingWithLinkResolutionFailure(t *testing.T) {
	const (
		incomingNICID                     = 1
		outgoingNICID                     = 2
		ttl                               = 2
		expectedHostUnreachableErrorCount = 1
	)
	outgoingLinkAddr := tcptestutil.MustParseLink("02:03:03:04:05:06")

	rxICMPv4EchoRequest := func(e *channel.Endpoint, src, dst tcpip.Address) {
		utils.RxICMPv4EchoRequest(e, src, dst, ttl)
	}

	rxICMPv6EchoRequest := func(e *channel.Endpoint, src, dst tcpip.Address) {
		utils.RxICMPv6EchoRequest(e, src, dst, ttl)
	}

	arpChecker := func(t *testing.T, request *stack.PacketBuffer, src, dst tcpip.Address) {
		if request.NetworkProtocolNumber != arp.ProtocolNumber {
			t.Errorf("got request.NetworkProtocolNumber = %d, want = %d", request.NetworkProtocolNumber, arp.ProtocolNumber)
		}
		if request.EgressRoute.RemoteLinkAddress != header.EthernetBroadcastAddress {
			t.Errorf("got request.EgressRoute.RemoteLinkAddress = %s, want = %s", request.EgressRoute.RemoteLinkAddress, header.EthernetBroadcastAddress)
		}
		rep := header.ARP(request.NetworkHeader().View())
		if got := rep.Op(); got != header.ARPRequest {
			t.Errorf("got Op() = %d, want = %d", got, header.ARPRequest)
		}
		if got := tcpip.LinkAddress(rep.HardwareAddressSender()); got != outgoingLinkAddr {
			t.Errorf("got HardwareAddressSender = %s, want = %s", got, outgoingLinkAddr)
		}
		if got := tcpip.Address(rep.ProtocolAddressSender()); got != src {
			t.Errorf("got ProtocolAddressSender = %s, want = %s", got, src)
		}
		if got := tcpip.Address(rep.ProtocolAddressTarget()); got != dst {
			t.Errorf("got ProtocolAddressTarget = %s, want = %s", got, dst)
		}
	}

	ndpChecker := func(t *testing.T, request *stack.PacketBuffer, src, dst tcpip.Address) {
		if request.NetworkProtocolNumber != header.IPv6ProtocolNumber {
			t.Fatalf("got Proto = %d, want = %d", request.NetworkProtocolNumber, header.IPv6ProtocolNumber)
		}

		snmc := header.SolicitedNodeAddr(dst)
		if want := header.EthernetAddressFromMulticastIPv6Address(snmc); request.EgressRoute.RemoteLinkAddress != want {
			t.Errorf("got remote link address = %s, want = %s", request.EgressRoute.RemoteLinkAddress, want)
		}

		checker.IPv6(t, stack.PayloadSince(request.NetworkHeader()),
			checker.SrcAddr(src),
			checker.DstAddr(snmc),
			checker.TTL(header.NDPHopLimit),
			checker.NDPNS(
				checker.NDPNSTargetAddress(dst),
			))
	}

	icmpv4Checker := func(t *testing.T, b []byte, src, dst tcpip.Address) {
		checker.IPv4(t, b,
			checker.SrcAddr(src),
			checker.DstAddr(dst),
			checker.TTL(ipv4.DefaultTTL),
			checker.ICMPv4(
				checker.ICMPv4Checksum(),
				checker.ICMPv4Type(header.ICMPv4DstUnreachable),
				checker.ICMPv4Code(header.ICMPv4HostUnreachable),
			),
		)
	}

	icmpv6Checker := func(t *testing.T, b []byte, src, dst tcpip.Address) {
		checker.IPv6(t, b,
			checker.SrcAddr(src),
			checker.DstAddr(dst),
			checker.TTL(ipv6.DefaultTTL),
			checker.ICMPv6(
				checker.ICMPv6Type(header.ICMPv6DstUnreachable),
				checker.ICMPv6Code(header.ICMPv6AddressUnreachable),
			),
		)
	}

	tests := []struct {
		name                         string
		networkProtocolFactory       []stack.NetworkProtocolFactory
		networkProtocolNumber        tcpip.NetworkProtocolNumber
		sourceAddr                   tcpip.Address
		destAddr                     tcpip.Address
		incomingAddr                 tcpip.AddressWithPrefix
		outgoingAddr                 tcpip.AddressWithPrefix
		transportProtocol            func(*stack.Stack) stack.TransportProtocol
		rx                           func(*channel.Endpoint, tcpip.Address, tcpip.Address)
		linkResolutionRequestChecker func(*testing.T, *stack.PacketBuffer, tcpip.Address, tcpip.Address)
		icmpReplyChecker             func(*testing.T, []byte, tcpip.Address, tcpip.Address)
		mtu                          uint32
	}{
		{
			name:                   "IPv4 Host unreachable",
			networkProtocolFactory: []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol},
			networkProtocolNumber:  header.IPv4ProtocolNumber,
			sourceAddr:             tcptestutil.MustParse4("10.0.0.2"),
			destAddr:               tcptestutil.MustParse4("11.0.0.2"),
			incomingAddr: tcpip.AddressWithPrefix{
				Address:   tcpip.Address(net.ParseIP("10.0.0.1").To4()),
				PrefixLen: 8,
			},
			outgoingAddr: tcpip.AddressWithPrefix{
				Address:   tcpip.Address(net.ParseIP("11.0.0.1").To4()),
				PrefixLen: 8,
			},
			transportProtocol:            icmp.NewProtocol4,
			linkResolutionRequestChecker: arpChecker,
			icmpReplyChecker:             icmpv4Checker,
			rx:                           rxICMPv4EchoRequest,
			mtu:                          ipv4.MaxTotalSize,
		},
		{
			name:                   "IPv6 Host unreachable",
			networkProtocolFactory: []stack.NetworkProtocolFactory{ipv6.NewProtocol},
			networkProtocolNumber:  header.IPv6ProtocolNumber,
			sourceAddr:             tcptestutil.MustParse6("10::2"),
			destAddr:               tcptestutil.MustParse6("11::2"),
			incomingAddr: tcpip.AddressWithPrefix{
				Address:   tcpip.Address(net.ParseIP("10::1").To16()),
				PrefixLen: 64,
			},
			outgoingAddr: tcpip.AddressWithPrefix{
				Address:   tcpip.Address(net.ParseIP("11::1").To16()),
				PrefixLen: 64,
			},
			transportProtocol:            icmp.NewProtocol6,
			linkResolutionRequestChecker: ndpChecker,
			icmpReplyChecker:             icmpv6Checker,
			rx:                           rxICMPv6EchoRequest,
			mtu:                          header.IPv6MinimumMTU,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()

			s := stack.New(stack.Options{
				NetworkProtocols:   test.networkProtocolFactory,
				TransportProtocols: []stack.TransportProtocolFactory{test.transportProtocol},
				Clock:              clock,
			})

			// Set up endpoint through which we will receive packets.
			incomingEndpoint := channel.New(1, test.mtu, "")
			if err := s.CreateNIC(incomingNICID, incomingEndpoint); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", incomingNICID, err)
			}
			incomingProtoAddr := tcpip.ProtocolAddress{
				Protocol:          test.networkProtocolNumber,
				AddressWithPrefix: test.incomingAddr,
			}
			if err := s.AddProtocolAddress(incomingNICID, incomingProtoAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", incomingNICID, incomingProtoAddr, err)
			}

			// Set up endpoint through which we will attempt to forward packets.
			outgoingEndpoint := channel.New(1, test.mtu, outgoingLinkAddr)
			outgoingEndpoint.LinkEPCapabilities |= stack.CapabilityResolutionRequired
			if err := s.CreateNIC(outgoingNICID, outgoingEndpoint); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", outgoingNICID, err)
			}
			outgoingProtoAddr := tcpip.ProtocolAddress{
				Protocol:          test.networkProtocolNumber,
				AddressWithPrefix: test.outgoingAddr,
			}
			if err := s.AddProtocolAddress(outgoingNICID, outgoingProtoAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", outgoingNICID, outgoingProtoAddr, err)
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: test.incomingAddr.Subnet(),
					NIC:         incomingNICID,
				},
				{
					Destination: test.outgoingAddr.Subnet(),
					NIC:         outgoingNICID,
				},
			})

			if err := s.SetForwardingDefaultAndAllNICs(test.networkProtocolNumber, true); err != nil {
				t.Fatalf("SetForwardingDefaultAndAllNICs(%d, true): %s", test.networkProtocolNumber, err)
			}

			test.rx(incomingEndpoint, test.sourceAddr, test.destAddr)

			nudConfigs, err := s.NUDConfigurations(outgoingNICID, test.networkProtocolNumber)
			if err != nil {
				t.Fatalf("s.NUDConfigurations(%d, %d): %s", outgoingNICID, test.networkProtocolNumber, err)
			}
			// Trigger the first packet on the endpoint.
			clock.RunImmediatelyScheduledJobs()

			for i := 0; i < int(nudConfigs.MaxMulticastProbes); i++ {
				request := outgoingEndpoint.Read()
				if request == nil {
					t.Fatal("expected ARP packet through outgoing NIC")
				}

				test.linkResolutionRequestChecker(t, request, test.outgoingAddr.Address, test.destAddr)

				// Advance the clock the span of one request timeout.
				clock.Advance(nudConfigs.RetransmitTimer)
			}

			// Next, we make a blocking read to retrieve the error packet. This is
			// necessary because outgoing packets are dequeued asynchronously when
			// link resolution fails, and this dequeue is what triggers the ICMP
			// error.
			reply := incomingEndpoint.Read()
			if reply == nil {
				t.Fatal("expected ICMP packet through incoming NIC")
			}

			test.icmpReplyChecker(t, stack.PayloadSince(reply.NetworkHeader()), test.incomingAddr.Address, test.sourceAddr)

			// Since link resolution failed, we don't expect the packet to be
			// forwarded.
			forwardedPacket := outgoingEndpoint.Read()
			if forwardedPacket != nil {
				t.Fatalf("expected no ICMP Echo packet through outgoing NIC, instead found: %#v", forwardedPacket)
			}

			if got, want := s.Stats().IP.Forwarding.HostUnreachable.Value(), expectedHostUnreachableErrorCount; int(got) != want {
				t.Errorf("got rt.Stats().IP.Forwarding.HostUnreachable.Value() = %d, want = %d", got, want)
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
			clock := faketime.NewManualClock()
			stackOpts := stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
				Clock:            clock,
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

			nudConfigs, err := host1Stack.NUDConfigurations(host1NICID, test.netProto)
			if err != nil {
				t.Fatalf("host1Stack.NUDConfigurations(%d, %d): %s", host1NICID, test.netProto, err)
			}

			clock.Advance(time.Duration(nudConfigs.MaxMulticastProbes) * nudConfigs.RetransmitTimer)
			select {
			case got := <-ch:
				if diff := cmp.Diff(wantRes, got); diff != "" {
					t.Fatalf("link resolution result mismatch (-want +got):\n%s", diff)
				}
			default:
				t.Fatal("event didn't arrive")
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
			clock := faketime.NewManualClock()
			stackOpts := stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
				Clock:            clock,
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

				nudConfigs, err := host1Stack.NUDConfigurations(host1NICID, test.netProto)
				if err != nil {
					t.Fatalf("host1Stack.NUDConfigurations(%d, %d): %s", host1NICID, test.netProto, err)
				}
				clock.Advance(time.Duration(nudConfigs.MaxMulticastProbes) * nudConfigs.RetransmitTimer)

				select {
				case got := <-ch:
					if diff := cmp.Diff(stack.ResolvedFieldsResult{RouteInfo: wantRouteInfo, Err: test.expectedErr}, got, cmp.AllowUnexported(stack.RouteInfo{})); diff != "" {
						t.Errorf("route resolve result mismatch (-want +got):\n%s", diff)
					}
				default:
					t.Fatalf("event didn't arrive")
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
			remoteAddr:       utils.Ipv4Addr2.AddressWithPrefix.Address,
			expectedWriteErr: nil,
		},
		{
			name:             "IPv6",
			netProto:         ipv6.ProtocolNumber,
			remoteAddr:       utils.Ipv6Addr2.AddressWithPrefix.Address,
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
			serverWE, serverCH := waiter.NewChannelEntry(waiter.ReadableEvents)
			serverWQ.EventRegister(&serverWE)
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

			params := stack.NetworkHeaderParams{
				Protocol: udp.ProtocolNumber,
				TTL:      64,
				TOS:      stack.DefaultTOS,
			}
			data := []byte{1, 2}
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
				xsum = header.ChecksumCombine(xsum, pkt.Data().AsRange().Checksum())
				udpHdr.SetChecksum(^udpHdr.CalculateChecksum(xsum))

				if err := r.WritePacket(params, pkt); err != nil {
					t.Fatalf("WritePacket(...): %s", err)
				}
				pkt.DecRef()
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

func (d *nudDispatcher) expectEvent(want eventInfo) error {
	select {
	case got := <-d.c:
		if diff := cmp.Diff(want, got, cmp.AllowUnexported(eventInfo{}), cmpopts.IgnoreFields(stack.NeighborEntry{}, "UpdatedAt")); diff != "" {
			return fmt.Errorf("got invalid event (-want +got):\n%s", diff)
		}
		return nil
	default:
		return fmt.Errorf("event didn't arrive")
	}
}

// TestTCPConfirmNeighborReachability tests that TCP informs layers beneath it
// that the neighbor used for a route is reachable.
func TestTCPConfirmNeighborReachability(t *testing.T) {
	tests := []struct {
		name            string
		netProto        tcpip.NetworkProtocolNumber
		remoteAddr      tcpip.Address
		neighborAddr    tcpip.Address
		getEndpoints    func(*testing.T, *stack.Stack, *stack.Stack, *stack.Stack) (tcpip.Endpoint, <-chan struct{}, tcpip.Endpoint, <-chan struct{})
		isHost1Listener bool
	}{
		{
			name:         "IPv4 active connection through neighbor",
			netProto:     ipv4.ProtocolNumber,
			remoteAddr:   utils.Host2IPv4Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, _, host2Stack *stack.Stack) (tcpip.Endpoint, <-chan struct{}, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerWE, listenerCH := waiter.NewChannelEntry(waiter.EventIn)
				listenerWQ.EventRegister(&listenerWE)
				listenerEP, err := host2Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host2Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}
				t.Cleanup(listenerEP.Close)

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.WritableEvents)
				clientWQ.EventRegister(&clientWE)
				clientEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &clientWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				return listenerEP, listenerCH, clientEP, clientCH
			},
		},
		{
			name:         "IPv6 active connection through neighbor",
			netProto:     ipv6.ProtocolNumber,
			remoteAddr:   utils.Host2IPv6Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, _, host2Stack *stack.Stack) (tcpip.Endpoint, <-chan struct{}, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerWE, listenerCH := waiter.NewChannelEntry(waiter.EventIn)
				listenerWQ.EventRegister(&listenerWE)
				listenerEP, err := host2Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host2Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}
				t.Cleanup(listenerEP.Close)

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.WritableEvents)
				clientWQ.EventRegister(&clientWE)
				clientEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &clientWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				return listenerEP, listenerCH, clientEP, clientCH
			},
		},
		{
			name:         "IPv4 active connection to neighbor",
			netProto:     ipv4.ProtocolNumber,
			remoteAddr:   utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, routerStack, _ *stack.Stack) (tcpip.Endpoint, <-chan struct{}, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerWE, listenerCH := waiter.NewChannelEntry(waiter.EventIn)
				listenerWQ.EventRegister(&listenerWE)
				listenerEP, err := routerStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("routerStack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}
				t.Cleanup(listenerEP.Close)

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.WritableEvents)
				clientWQ.EventRegister(&clientWE)
				clientEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &clientWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				return listenerEP, listenerCH, clientEP, clientCH
			},
		},
		{
			name:         "IPv6 active connection to neighbor",
			netProto:     ipv6.ProtocolNumber,
			remoteAddr:   utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, routerStack, _ *stack.Stack) (tcpip.Endpoint, <-chan struct{}, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerWE, listenerCH := waiter.NewChannelEntry(waiter.EventIn)
				listenerWQ.EventRegister(&listenerWE)
				listenerEP, err := routerStack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("routerStack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}
				t.Cleanup(listenerEP.Close)

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.WritableEvents)
				clientWQ.EventRegister(&clientWE)
				clientEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &clientWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				return listenerEP, listenerCH, clientEP, clientCH
			},
		},
		{
			name:         "IPv4 passive connection to neighbor",
			netProto:     ipv4.ProtocolNumber,
			remoteAddr:   utils.Host1IPv4Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, routerStack, _ *stack.Stack) (tcpip.Endpoint, <-chan struct{}, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerWE, listenerCH := waiter.NewChannelEntry(waiter.EventIn)
				listenerWQ.EventRegister(&listenerWE)
				listenerEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}
				t.Cleanup(listenerEP.Close)

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.WritableEvents)
				clientWQ.EventRegister(&clientWE)
				clientEP, err := routerStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &clientWQ)
				if err != nil {
					t.Fatalf("routerStack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				return listenerEP, listenerCH, clientEP, clientCH
			},
			isHost1Listener: true,
		},
		{
			name:         "IPv6 passive connection to neighbor",
			netProto:     ipv6.ProtocolNumber,
			remoteAddr:   utils.Host1IPv6Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, routerStack, _ *stack.Stack) (tcpip.Endpoint, <-chan struct{}, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerWE, listenerCH := waiter.NewChannelEntry(waiter.EventIn)
				listenerWQ.EventRegister(&listenerWE)
				listenerEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}
				t.Cleanup(listenerEP.Close)

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.WritableEvents)
				clientWQ.EventRegister(&clientWE)
				clientEP, err := routerStack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &clientWQ)
				if err != nil {
					t.Fatalf("routerStack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				return listenerEP, listenerCH, clientEP, clientCH
			},
			isHost1Listener: true,
		},
		{
			name:         "IPv4 passive connection through neighbor",
			netProto:     ipv4.ProtocolNumber,
			remoteAddr:   utils.Host1IPv4Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, _, host2Stack *stack.Stack) (tcpip.Endpoint, <-chan struct{}, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerWE, listenerCH := waiter.NewChannelEntry(waiter.EventIn)
				listenerWQ.EventRegister(&listenerWE)
				listenerEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}
				t.Cleanup(listenerEP.Close)

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.WritableEvents)
				clientWQ.EventRegister(&clientWE)
				clientEP, err := host2Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &clientWQ)
				if err != nil {
					t.Fatalf("host2Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, err)
				}

				return listenerEP, listenerCH, clientEP, clientCH
			},
			isHost1Listener: true,
		},
		{
			name:         "IPv6 passive connection through neighbor",
			netProto:     ipv6.ProtocolNumber,
			remoteAddr:   utils.Host1IPv6Addr.AddressWithPrefix.Address,
			neighborAddr: utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address,
			getEndpoints: func(t *testing.T, host1Stack, _, host2Stack *stack.Stack) (tcpip.Endpoint, <-chan struct{}, tcpip.Endpoint, <-chan struct{}) {
				var listenerWQ waiter.Queue
				listenerWE, listenerCH := waiter.NewChannelEntry(waiter.EventIn)
				listenerWQ.EventRegister(&listenerWE)
				listenerEP, err := host1Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &listenerWQ)
				if err != nil {
					t.Fatalf("host1Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}
				t.Cleanup(listenerEP.Close)

				var clientWQ waiter.Queue
				clientWE, clientCH := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.WritableEvents)
				clientWQ.EventRegister(&clientWE)
				clientEP, err := host2Stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &clientWQ)
				if err != nil {
					t.Fatalf("host2Stack.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv6.ProtocolNumber, err)
				}

				return listenerEP, listenerCH, clientEP, clientCH
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
			if err := nudDisp.expectEvent(eventInfo{
				eventType: entryAdded,
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Incomplete, Addr: test.neighborAddr},
			}); err != nil {
				t.Fatalf("error waiting for initial NUD event: %s", err)
			}
			if err := nudDisp.expectEvent(eventInfo{
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
			if err := nudDisp.expectEvent(eventInfo{
				eventType: entryChanged,
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Stale, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for stale NUD event: %s", err)
			}

			listenerEP, listenerCH, clientEP, clientCH := test.getEndpoints(t, host1Stack, routerStack, host2Stack)
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
			if err := nudDisp.expectEvent(eventInfo{
				eventType: entryChanged,
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Delay, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for delay NUD event: %s", err)
			}
			<-listenerCH
			if err := nudDisp.expectEvent(eventInfo{
				eventType: entryChanged,
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Reachable, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for reachable NUD event: %s", err)
			}

			peerEP, peerWQ, err := listenerEP.Accept(nil)
			if err != nil {
				t.Fatalf("listenerEP.Accept(): %s", err)
			}
			defer peerEP.Close()
			peerWE, peerCH := waiter.NewChannelEntry(waiter.ReadableEvents)
			peerWQ.EventRegister(&peerWE)

			// Wait for the neighbor to be stale again then send data to the remote.
			//
			// On successful transmission, the neighbor should become reachable
			// without probing the neighbor as a TCP ACK would be received which is an
			// indication of the neighbor being reachable.
			clock.Advance(maxReachableTime)
			if err := nudDisp.expectEvent(eventInfo{
				eventType: entryChanged,
				nicID:     utils.Host1NICID,
				entry:     stack.NeighborEntry{State: stack.Stale, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
			}); err != nil {
				t.Fatalf("error waiting for stale NUD event: %s", err)
			}
			{
				var r bytes.Reader
				r.Reset([]byte{0})
				var wOpts tcpip.WriteOptions
				if _, err := clientEP.Write(&r, wOpts); err != nil {
					t.Errorf("clientEP.Write(_, %#v): %s", wOpts, err)
				}
			}
			// Heads up, there is a race here.
			//
			// Incoming TCP segments are handled in
			// tcp.(*endpoint).handleSegmentLocked:
			//
			// - tcp.(*endpoint).rcv.handleRcvdSegment puts the segment on the
			// segment queue and notifies waiting readers (such as this channel)
			//
			// - tcp.(*endpoint).snd.handleRcvdSegment sends an ACK for the segment
			// and notifies the NUD machinery that the peer is reachable
			//
			// Thus we must permit a delay between the readable signal and the
			// expected NUD event.
			//
			// At the time of writing, this race is reliably hit with gotsan.
			<-peerCH
			for len(nudDisp.c) == 0 {
				runtime.Gosched()
			}
			if err := nudDisp.expectEvent(eventInfo{
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
				if err := nudDisp.expectEvent(eventInfo{
					eventType: entryChanged,
					nicID:     utils.Host1NICID,
					entry:     stack.NeighborEntry{State: stack.Probe, Addr: test.neighborAddr, LinkAddr: utils.LinkAddr2},
				}); err != nil {
					t.Fatalf("error waiting for probe NUD event: %s", err)
				}
			}
			{
				var r bytes.Reader
				r.Reset([]byte{0})
				var wOpts tcpip.WriteOptions
				if _, err := peerEP.Write(&r, wOpts); err != nil {
					t.Errorf("peerEP.Write(_, %#v): %s", wOpts, err)
				}
			}
			<-clientCH
			if err := nudDisp.expectEvent(eventInfo{
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
