// Copyright 2018 The gVisor Authors.
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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sockfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
)

// Protocol is the implementation of a netlink socket protocol.
type Protocol interface {
	// Protocol returns the Linux netlink protocol value.
	Protocol() int

	// CanSend returns true if this protocol may ever send messages.
	//
	// TODO(gvisor.dev/issue/1119): This is a workaround to allow
	// advertising support for otherwise unimplemented features on sockets
	// that will never send messages, thus making those features no-ops.
	CanSend() bool

	// ProcessMessage processes a single message from userspace.
	//
	// If err == nil, any messages added to ms will be sent back to the
	// other end of the socket. Setting ms.Multi will cause an NLMSG_DONE
	// message to be sent even if ms contains no messages.
	ProcessMessage(ctx context.Context, msg *Message, ms *MessageSet) *syserr.Error
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
func (*socketProvider) Socket(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
	// Netlink sockets must be specified as datagram or raw, but they
	// behave the same regardless of type.
	if stype != linux.SOCK_DGRAM && stype != linux.SOCK_RAW {
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

	s, err := New(t, stype, p)
	if err != nil {
		return nil, err
	}

	vfsfd := &s.vfsfd
	mnt := t.Kernel().SocketMount()
	d := sockfs.NewDentry(t, mnt)
	defer d.DecRef(t)
	if err := vfsfd.Init(s, linux.O_RDWR, mnt, d, &vfs.FileDescriptionOptions{
		DenyPRead:         true,
		DenyPWrite:        true,
		UseDentryMetadata: true,
	}); err != nil {
		return nil, syserr.FromError(err)
	}
	return vfsfd, nil
}

// Pair implements socket.Provider.Pair by returning an error.
func (*socketProvider) Pair(*kernel.Task, linux.SockType, int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error) {
	// Netlink sockets never supports creating socket pairs.
	return nil, nil, syserr.ErrNotSupported
}

// init registers the socket provider.
func init() {
	socket.RegisterProvider(linux.AF_NETLINK, &socketProvider{})
}
