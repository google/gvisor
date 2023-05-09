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

package gofer

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (d *dentry) isSocket() bool {
	return d.fileType() == linux.S_IFSOCK
}

func isSocketTypeSupported(sockType linux.SockType) bool {
	switch sockType {
	case unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_SEQPACKET:
		return true
	default:
		return false
	}
}

// endpoint is a Gofer-backed transport.BoundEndpoint.
//
// An endpoint's lifetime is the time between when filesystem.BoundEndpointAt()
// is called and either BoundEndpoint.BidirectionalConnect or
// BoundEndpoint.UnidirectionalConnect is called.
//
// +stateify savable
type endpoint struct {
	// dentry is the filesystem dentry which produced this endpoint. dentry is
	// not synthetic.
	dentry *dentry

	// path is the sentry path where this endpoint is bound.
	path string
}

// BidirectionalConnect implements BoundEndpoint.BidirectionalConnect.
func (e *endpoint) BidirectionalConnect(ctx context.Context, ce transport.ConnectingEndpoint, returnConnect func(transport.Receiver, transport.ConnectedEndpoint)) *syserr.Error {
	// No lock ordering required as only the ConnectingEndpoint has a mutex.
	ce.Lock()

	// Check connecting state.
	if ce.Connected() {
		ce.Unlock()
		return syserr.ErrAlreadyConnected
	}
	if ce.ListeningLocked() {
		ce.Unlock()
		return syserr.ErrInvalidEndpointState
	}

	c, err := e.newConnectedEndpoint(ctx, ce.Type(), ce.WaiterQueue())
	if err != nil {
		ce.Unlock()
		return err
	}

	returnConnect(c, c)
	ce.Unlock()
	if err := c.Init(); err != nil {
		return syserr.FromError(err)
	}

	return nil
}

// UnidirectionalConnect implements
// transport.BoundEndpoint.UnidirectionalConnect.
func (e *endpoint) UnidirectionalConnect(ctx context.Context) (transport.ConnectedEndpoint, *syserr.Error) {
	c, err := e.newConnectedEndpoint(ctx, linux.SOCK_DGRAM, &waiter.Queue{})
	if err != nil {
		return nil, err
	}

	if err := c.Init(); err != nil {
		return nil, syserr.FromError(err)
	}

	// We don't need the receiver.
	c.CloseRecv()
	c.Release(ctx)

	return c, nil
}

func (e *endpoint) newConnectedEndpoint(ctx context.Context, sockType linux.SockType, queue *waiter.Queue) (*transport.SCMConnectedEndpoint, *syserr.Error) {
	e.dentry.fs.renameMu.RLock()
	hostSockFD, err := e.dentry.connect(ctx, sockType)
	e.dentry.fs.renameMu.RUnlock()
	if err != nil {
		return nil, syserr.ErrConnectionRefused
	}

	c, serr := transport.NewSCMEndpoint(hostSockFD, queue, e.path)
	if serr != nil {
		unix.Close(hostSockFD)
		log.Warningf("NewSCMEndpoint failed: path=%q, err=%v", e.path, serr)
		return nil, serr
	}
	return c, nil
}

// Release implements transport.BoundEndpoint.Release.
func (e *endpoint) Release(ctx context.Context) {
	e.dentry.DecRef(ctx)
}

// Passcred implements transport.BoundEndpoint.Passcred.
func (e *endpoint) Passcred() bool {
	return false
}
