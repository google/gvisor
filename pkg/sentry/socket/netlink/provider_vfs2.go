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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sockfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// socketProviderVFS2 implements socket.Provider.
type socketProviderVFS2 struct {
}

// Socket implements socket.Provider.Socket.
func (*socketProviderVFS2) Socket(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
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

	s, err := NewVFS2(t, stype, p)
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
func (*socketProviderVFS2) Pair(*kernel.Task, linux.SockType, int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error) {
	// Netlink sockets never supports creating socket pairs.
	return nil, nil, tcpip.SyserrNotSupported
}
