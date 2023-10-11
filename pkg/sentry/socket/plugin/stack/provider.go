// Copyright 2023 The gVisor Authors.
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

package stack

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin/cgo"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

type provider struct {
	family   int
	netProto tcpip.NetworkProtocolNumber
}

// Socket creates a new socket object for the AF_INET or AF_INET6 family.
func (p *provider) Socket(t *kernel.Task, skType linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
	// Fail right away if there is no plugin stack registered.
	ctx := t.NetworkContext()
	if ctx == nil {
		return nil, nil
	}
	_, ok := ctx.(*Stack)
	if !ok {
		return nil, nil
	}

	// Only accept TCP and UDP.
	stype := skType & linux.SOCK_TYPE_MASK
	switch stype {
	case syscall.SOCK_STREAM:
		switch protocol {
		case 0, syscall.IPPROTO_TCP:
		default:
			return nil, syserr.ErrProtocolNotSupported
		}
	case syscall.SOCK_DGRAM:
		switch protocol {
		case 0, syscall.IPPROTO_UDP:
		default:
			return nil, syserr.ErrProtocolNotSupported
		}
	case syscall.SOCK_RAW:
		// Raw sockets require CAP_NET_RAW.
		creds := auth.CredentialsFromContext(t)
		if !creds.HasCapability(linux.CAP_NET_RAW) {
			return nil, syserr.ErrPermissionDenied
		}
	default:
		return nil, syserr.ErrSocketNotSupported
	}

	handle := cgo.Socket(p.family, int(skType), protocol)
	if handle < 0 {
		return nil, int2err(handle)
	}

	fd, err := newSocket(t, p.family, skType, protocol, stack.notifier, int(handle), uint32(skType&syscall.SOCK_NONBLOCK))
	return fd, err
}

// Pair just returns nil sockets (not supported).
func (*provider) Pair(*kernel.Task, linux.SockType, int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error) {
	return nil, nil, nil
}

func init() {
	// Providers backed by plugin stack.
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
