// Copyright 2026 The gVisor Authors.
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

package hostinet

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

// Host socket fds cannot cross a checkpoint boundary, so Socket.fd is not
// saved and the checkpointed sandbox retains ownership of it.
//
// Listening sockets carry no connection state, so beforeSave records what is
// needed to re-create them and Stack.Restore re-creates the host socket with
// socket/bind/listen. Connections that were pending in the backlog are lost.
// UDP sockets will not be recreated after restore.
//
// All other sockets are restored with fd -1. Host socket operations fail
// with ECONNRESET (or EPIPE/SIGPIPE for writes on connection oriented sockets)
// and Readiness reports hangup/error to wake pollers immediately.

// listenerState describes a listening host socket so restore can re-create it.
//
// +stateify savable
type listenerState struct {
	addr         []byte
	backlog      int32
	reuseAddr    int32
	reusePort    int32
	v6Only       int32
	bindToDevice string
}

var restoredListeners struct {
	mu      sync.Mutex
	sockets []*Socket
}

// beforeSave is invoked by stateify.
func (s *Socket) beforeSave() {
	s.savedListener = nil
	if s.fd < 0 {
		return
	}
	accepting, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil || accepting == 0 {
		return
	}
	addr, err := getsockname(s.fd)
	if err != nil {
		log.Warningf("getsockname on listening host socket failed during save: %v", err)
		return
	}
	l := &listenerState{
		addr:    addr,
		backlog: s.listenBacklog.Load(),
	}
	if v, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_REUSEADDR); err == nil {
		l.reuseAddr = int32(v)
	}
	if v, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_REUSEPORT); err == nil {
		l.reusePort = int32(v)
	}
	if s.family == unix.AF_INET6 {
		if v, err := unix.GetsockoptInt(s.fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY); err == nil {
			l.v6Only = int32(v)
		}
	}
	if dev, err := unix.GetsockoptString(s.fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE); err == nil {
		l.bindToDevice = dev
	}
	s.savedListener = l
}

// afterLoad is invoked by stateify.
func (s *Socket) afterLoad(context.Context) {
	s.fd = -1
	if s.savedListener != nil {
		restoredListeners.mu.Lock()
		restoredListeners.sockets = append(restoredListeners.sockets, s)
		restoredListeners.mu.Unlock()
	}
}

// restoreListeners re-creates the host sockets for saved listening sockets.
func restoreListeners() {
	restoredListeners.mu.Lock()
	sockets := restoredListeners.sockets
	restoredListeners.sockets = nil
	restoredListeners.mu.Unlock()
	for _, s := range sockets {
		if err := s.restoreListener(); err != nil {
			log.Warningf("Failed to restore listening host socket (family=%d, addr=%x): %v", s.family, s.savedListener.addr, err)
			s.savedListener = nil
		}
	}
}

// restoreListener attempts to re-create a saved listening socket. If any host
// operation fails, the socket is left unrestored with fd -1 and restore
// continues with other sockets.
func (s *Socket) restoreListener() error {
	l := s.savedListener
	fd, err := unix.Socket(s.family, int(s.stype)|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, s.protocol)
	if err != nil {
		return fmt.Errorf("creating socket: %w", err)
	}
	if l.reuseAddr != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, int(l.reuseAddr)); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("setting SO_REUSEADDR: %w", err)
		}
	}
	if l.reusePort != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, int(l.reusePort)); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("setting SO_REUSEPORT: %w", err)
		}
	}
	if s.family == unix.AF_INET6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, int(l.v6Only)); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("setting IPV6_V6ONLY: %w", err)
		}
	}
	if l.bindToDevice != "" {
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, l.bindToDevice); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("setting SO_BINDTODEVICE to %q: %w", l.bindToDevice, err)
		}
	}
	if err := bind(fd, l.addr); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("binding: %w", err)
	}
	if err := unix.Listen(fd, int(l.backlog)); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("listening: %w", err)
	}
	if err := fdnotifier.AddFD(int32(fd), &s.queue); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("registering with fdnotifier: %w", err)
	}
	s.fd = fd
	s.savedListener = nil
	return nil
}
