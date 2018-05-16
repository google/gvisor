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

package gofer

import (
	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/host"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// BoundEndpoint returns a gofer-backed unix.BoundEndpoint.
func (i *inodeOperations) BoundEndpoint(inode *fs.Inode, path string) unix.BoundEndpoint {
	if !fs.IsSocket(i.fileState.sattr) {
		return nil
	}

	if i.session().endpoints != nil {
		ep := i.session().endpoints.get(i.fileState.key)
		if ep != nil {
			return ep
		}

		// Not found in endpoints map, it may be a gofer backed unix socket...
	}

	inode.IncRef()
	return &endpoint{inode, i.fileState.file.file, path}
}

// endpoint is a Gofer-backed unix.BoundEndpoint.
//
// An endpoint's lifetime is the time between when InodeOperations.BoundEndpoint()
// is called and either BoundEndpoint.BidirectionalConnect or
// BoundEndpoint.UnidirectionalConnect is called.
type endpoint struct {
	// inode is the filesystem inode which produced this endpoint.
	inode *fs.Inode

	// file is the p9 file that contains a single unopened fid.
	file p9.File

	// path is the sentry path where this endpoint is bound.
	path string
}

func unixSockToP9(t unix.SockType) (p9.ConnectFlags, bool) {
	switch t {
	case unix.SockStream:
		return p9.StreamSocket, true
	case unix.SockSeqpacket:
		return p9.SeqpacketSocket, true
	case unix.SockDgram:
		return p9.DgramSocket, true
	}
	return 0, false
}

// BidirectionalConnect implements ConnectableEndpoint.BidirectionalConnect.
func (e *endpoint) BidirectionalConnect(ce unix.ConnectingEndpoint, returnConnect func(unix.Receiver, unix.ConnectedEndpoint)) *tcpip.Error {
	cf, ok := unixSockToP9(ce.Type())
	if !ok {
		return tcpip.ErrConnectionRefused
	}

	// No lock ordering required as only the ConnectingEndpoint has a mutex.
	ce.Lock()

	// Check connecting state.
	if ce.Connected() {
		ce.Unlock()
		return tcpip.ErrAlreadyConnected
	}
	if ce.Listening() {
		ce.Unlock()
		return tcpip.ErrInvalidEndpointState
	}

	hostFile, err := e.file.Connect(cf)
	if err != nil {
		ce.Unlock()
		return tcpip.ErrConnectionRefused
	}

	c, terr := host.NewConnectedEndpoint(hostFile, ce.WaiterQueue(), e.path)
	if terr != nil {
		ce.Unlock()
		return terr
	}

	returnConnect(c, c)
	ce.Unlock()
	c.Init()

	return nil
}

// UnidirectionalConnect implements unix.BoundEndpoint.UnidirectionalConnect.
func (e *endpoint) UnidirectionalConnect() (unix.ConnectedEndpoint, *tcpip.Error) {
	hostFile, err := e.file.Connect(p9.DgramSocket)
	if err != nil {
		return nil, tcpip.ErrConnectionRefused
	}

	c, terr := host.NewConnectedEndpoint(hostFile, &waiter.Queue{}, e.path)
	if terr != nil {
		return nil, terr
	}
	c.Init()

	// We don't need the receiver.
	c.CloseRecv()
	c.Release()

	return c, nil
}

// Release implements unix.BoundEndpoint.Release.
func (e *endpoint) Release() {
	e.inode.DecRef()
}
