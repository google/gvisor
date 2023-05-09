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

package netstack

import (
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// provider is an inet socket provider.
type provider struct {
	family   int
	netProto tcpip.NetworkProtocolNumber
}

var rawMissingLogger = log.BasicRateLimitedLogger(time.Minute)

// getTransportProtocol figures out transport protocol. Currently only TCP,
// UDP, and ICMP are supported. The bool return value is true when this socket
// is associated with a transport protocol. This is only false for SOCK_RAW,
// IPPROTO_IP sockets.
func getTransportProtocol(ctx context.Context, stype linux.SockType, protocol int) (tcpip.TransportProtocolNumber, bool, *syserr.Error) {
	switch stype {
	case linux.SOCK_STREAM:
		if protocol != 0 && protocol != unix.IPPROTO_TCP {
			return 0, true, syserr.ErrInvalidArgument
		}
		return tcp.ProtocolNumber, true, nil

	case linux.SOCK_DGRAM:
		switch protocol {
		case 0, unix.IPPROTO_UDP:
			return udp.ProtocolNumber, true, nil
		case unix.IPPROTO_ICMP:
			return header.ICMPv4ProtocolNumber, true, nil
		case unix.IPPROTO_ICMPV6:
			return header.ICMPv6ProtocolNumber, true, nil
		}

	case linux.SOCK_RAW:
		// Raw sockets require CAP_NET_RAW.
		creds := auth.CredentialsFromContext(ctx)
		if !creds.HasCapability(linux.CAP_NET_RAW) {
			rawMissingLogger.Infof("A process tried to create a raw socket without CAP_NET_RAW. Should the container config enable CAP_NET_RAW?")
			return 0, true, syserr.ErrNotPermitted
		}

		switch protocol {
		case unix.IPPROTO_ICMP:
			return header.ICMPv4ProtocolNumber, true, nil
		case unix.IPPROTO_ICMPV6:
			return header.ICMPv6ProtocolNumber, true, nil
		case unix.IPPROTO_UDP:
			return header.UDPProtocolNumber, true, nil
		case unix.IPPROTO_TCP:
			return header.TCPProtocolNumber, true, nil
		// IPPROTO_RAW signifies that the raw socket isn't assigned to
		// a transport protocol. Users will be able to write packets'
		// IP headers and won't receive anything.
		case unix.IPPROTO_RAW:
			return tcpip.TransportProtocolNumber(0), false, nil
		}
	}
	return 0, true, syserr.ErrProtocolNotSupported
}

// Socket creates a new socket object for the AF_INET, AF_INET6, or AF_PACKET
// family.
func (p *provider) Socket(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
	// Fail right away if we don't have a stack.
	stack := t.NetworkContext()
	if stack == nil {
		// Don't propagate an error here. Instead, allow the socket
		// code to continue searching for another provider.
		return nil, nil
	}
	eps, ok := stack.(*Stack)
	if !ok {
		return nil, nil
	}

	// Packet sockets are handled separately, since they are neither INET
	// nor INET6 specific.
	if p.family == linux.AF_PACKET {
		return packetSocket(t, eps, stype, protocol)
	}

	// Figure out the transport protocol.
	transProto, associated, err := getTransportProtocol(t, stype, protocol)
	if err != nil {
		return nil, err
	}

	// Create the endpoint.
	var ep tcpip.Endpoint
	var e tcpip.Error
	wq := &waiter.Queue{}
	if stype == linux.SOCK_RAW {
		ep, e = eps.Stack.NewRawEndpoint(transProto, p.netProto, wq, associated)
	} else {
		ep, e = eps.Stack.NewEndpoint(transProto, p.netProto, wq)

		// Assign task to PacketOwner interface to get the UID and GID for
		// iptables owner matching.
		if e == nil {
			ep.SetOwner(t)
		}
	}
	if e != nil {
		return nil, syserr.TranslateNetstackError(e)
	}

	return New(t, p.family, stype, int(transProto), wq, ep)
}

func packetSocket(t *kernel.Task, epStack *Stack, stype linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
	// Packet sockets require CAP_NET_RAW.
	creds := auth.CredentialsFromContext(t)
	if !creds.HasCapability(linux.CAP_NET_RAW) {
		rawMissingLogger.Infof("A process tried to create a raw socket without CAP_NET_RAW. Should the container config enable CAP_NET_RAW?")
		return nil, syserr.ErrNotPermitted
	}

	// "cooked" packets don't contain link layer information.
	var cooked bool
	switch stype {
	case linux.SOCK_DGRAM:
		cooked = true
	case linux.SOCK_RAW:
		cooked = false
	default:
		return nil, syserr.ErrProtocolNotSupported
	}

	// protocol is passed in network byte order, but netstack wants it in
	// host order.
	netProto := tcpip.NetworkProtocolNumber(socket.Ntohs(uint16(protocol)))

	wq := &waiter.Queue{}
	ep, err := epStack.Stack.NewPacketEndpoint(cooked, netProto, wq)
	if err != nil {
		return nil, syserr.TranslateNetstackError(err)
	}

	return New(t, linux.AF_PACKET, stype, protocol, wq, ep)
}

// Pair just returns nil sockets (not supported).
func (*provider) Pair(*kernel.Task, linux.SockType, int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error) {
	return nil, nil, nil
}

// init registers socket providers for AF_INET, AF_INET6, and AF_PACKET.
func init() {
	// Providers backed by netstack.
	p := []provider{
		{
			family:   linux.AF_INET,
			netProto: ipv4.ProtocolNumber,
		},
		{
			family:   linux.AF_INET6,
			netProto: ipv6.ProtocolNumber,
		},
		{
			family: linux.AF_PACKET,
		},
	}

	for i := range p {
		socket.RegisterProvider(p[i].family, &p[i])
	}
}
