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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/waiter"
)

// providerVFS2 is an inet socket provider.
type providerVFS2 struct {
	family   int
	netProto tcpip.NetworkProtocolNumber
}

// Socket creates a new socket object for the AF_INET, AF_INET6, or AF_PACKET
// family.
func (p *providerVFS2) Socket(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
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
		return packetSocketVFS2(t, eps, stype, protocol)
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

	return NewVFS2(t, p.family, stype, int(transProto), wq, ep)
}

func packetSocketVFS2(t *kernel.Task, epStack *Stack, stype linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
	// Packet sockets require CAP_NET_RAW.
	creds := auth.CredentialsFromContext(t)
	if !creds.HasCapability(linux.CAP_NET_RAW) {
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

	return NewVFS2(t, linux.AF_PACKET, stype, protocol, wq, ep)
}

// Pair just returns nil sockets (not supported).
func (*providerVFS2) Pair(*kernel.Task, linux.SockType, int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error) {
	return nil, nil, nil
}

// init registers socket providers for AF_INET, AF_INET6, and AF_PACKET.
func init() {
	// Providers backed by netstack.
	p := []providerVFS2{
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
		socket.RegisterProviderVFS2(p[i].family, &p[i])
	}
}
