// Copyright 2018 Google Inc.
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

package netlink

import (
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
)

// Protocol is the implementation of a netlink socket protocol.
type Protocol interface {
	// Protocol returns the Linux netlink protocol value.
	Protocol() int

	// ProcessMessage processes a single message from userspace.
	//
	// If err == nil, any messages added to ms will be sent back to the
	// other end of the socket. Setting ms.Multi will cause an NLMSG_DONE
	// message to be sent even if ms contains no messages.
	ProcessMessage(ctx context.Context, hdr linux.NetlinkMessageHeader, data []byte, ms *MessageSet) *syserr.Error
}

// Provider is a function that creates a new Protocol for a specific netlink
// protocol.
//
// Note that this is distinct from socket.Provider, which is used for all
// socket families.
type Provider func(t *kernel.Task) (Protocol, *syserr.Error)

// protocols holds a map of all known address protocols and their provider.
var protocols = make(map[int]Provider)

// RegisterProvider registers the provider of a given address protocol so that
// netlink sockets of that type can be created via socket(2).
//
// Preconditions: May only be called before any netlink sockets are created.
func RegisterProvider(protocol int, provider Provider) {
	if p, ok := protocols[protocol]; ok {
		panic(fmt.Sprintf("Netlink protocol %d already provided by %+v", protocol, p))
	}

	protocols[protocol] = provider
}

// socketProvider implements socket.Provider.
type socketProvider struct {
}

// Socket implements socket.Provider.Socket.
func (*socketProvider) Socket(t *kernel.Task, stype transport.SockType, protocol int) (*fs.File, *syserr.Error) {
	// Netlink sockets must be specified as datagram or raw, but they
	// behave the same regardless of type.
	if stype != transport.SockDgram && stype != transport.SockRaw {
		return nil, syserr.ErrSocketNotSupported
	}

	provider, ok := protocols[protocol]
	if !ok {
		return nil, syserr.ErrProtocolNotSupported
	}

	p, err := provider(t)
	if err != nil {
		return nil, err
	}

	s, err := NewSocket(t, p)
	if err != nil {
		return nil, err
	}

	d := socket.NewDirent(t, netlinkSocketDevice)
	defer d.DecRef()
	return fs.NewFile(t, d, fs.FileFlags{Read: true, Write: true}, s), nil
}

// Pair implements socket.Provider.Pair by returning an error.
func (*socketProvider) Pair(*kernel.Task, transport.SockType, int) (*fs.File, *fs.File, *syserr.Error) {
	// Netlink sockets never supports creating socket pairs.
	return nil, nil, syserr.ErrNotSupported
}

// init registers the socket provider.
func init() {
	socket.RegisterProvider(linux.AF_NETLINK, &socketProvider{})
}
