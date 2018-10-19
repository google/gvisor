// Copyright 2018 Google LLC
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

package epsocket

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/udp"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// provider is an inet socket provider.
type provider struct {
	family   int
	netProto tcpip.NetworkProtocolNumber
}

// GetTransportProtocol figures out transport protocol. Currently only TCP,
// UDP, and ICMP are supported.
func GetTransportProtocol(stype transport.SockType, protocol int) (tcpip.TransportProtocolNumber, *syserr.Error) {
	switch stype {
	case linux.SOCK_STREAM:
		if protocol != 0 && protocol != syscall.IPPROTO_TCP {
			return 0, syserr.ErrInvalidArgument
		}
		return tcp.ProtocolNumber, nil

	case linux.SOCK_DGRAM:
		switch protocol {
		case 0, syscall.IPPROTO_UDP:
			return udp.ProtocolNumber, nil
		case syscall.IPPROTO_ICMP:
			return header.ICMPv4ProtocolNumber, nil
		case syscall.IPPROTO_ICMPV6:
			return header.ICMPv6ProtocolNumber, nil
		}
	}
	return 0, syserr.ErrInvalidArgument
}

// Socket creates a new socket object for the AF_INET or AF_INET6 family.
func (p *provider) Socket(t *kernel.Task, stype transport.SockType, protocol int) (*fs.File, *syserr.Error) {
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

	// Figure out the transport protocol.
	transProto, err := GetTransportProtocol(stype, protocol)
	if err != nil {
		return nil, err
	}

	// Create the endpoint.
	wq := &waiter.Queue{}
	ep, e := eps.Stack.NewEndpoint(transProto, p.netProto, wq)
	if e != nil {
		return nil, syserr.TranslateNetstackError(e)
	}

	return New(t, p.family, stype, wq, ep), nil
}

// Pair just returns nil sockets (not supported).
func (*provider) Pair(*kernel.Task, transport.SockType, int) (*fs.File, *fs.File, *syserr.Error) {
	return nil, nil, nil
}

// init registers socket providers for AF_INET and AF_INET6.
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
	}

	for i := range p {
		socket.RegisterProvider(p[i].family, &p[i])
	}
}
