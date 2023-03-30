// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package portforward

import (
	"fmt"
	"io"
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	fileDescriptor "gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	localHost = [4]byte{127, 0, 0, 1}
)

// hostInetConn allows reading and writing to a local host socket for hostinet.
// hostInetConn implments proxyConn.
type hostInetConn struct {
	// wq is the WaitQueue registered with fdnotifier for this fd.
	wq waiter.Queue
	// fd is the file descriptor for the socket.
	fd *fileDescriptor.FD
	// port is the port on which to connect.
	port uint16
	// once makes sure we close only once.
	once sync.Once
}

// NewHostInetConn creates a hostInetConn backed by a host socket on the localhost address.
func NewHostInetConn(port uint16) (proxyConn, error) {
	// NOTE: Options must match sandbox seccomp filters. See filter/config.go
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	s := hostInetConn{
		fd:   fileDescriptor.New(fd),
		port: port,
	}

	cu := cleanup.Make(func() {
		s.fd.Close()
	})
	defer cu.Clean()
	if err := fdnotifier.AddFD(int32(s.fd.FD()), &s.wq); err != nil {
		return nil, err
	}
	cu.Add(func() { fdnotifier.RemoveFD(int32(s.fd.FD())) })
	sockAddr := &unix.SockaddrInet4{
		Addr: localHost,
		Port: int(s.port),
	}

	if err := unix.Connect(s.fd.FD(), sockAddr); err != nil {
		if err != unix.EINPROGRESS {
			return nil, fmt.Errorf("unix.Connect: %w", err)
		}

		// Connect is in progress. Wait for the socket to be writable.
		mask := waiter.WritableEvents
		waitEntry, notifyCh := waiter.NewChannelEntry(mask)
		s.eventRegister(&waitEntry)
		defer s.eventUnregister(&waitEntry)

		// Wait for connect to succeed.
		// Check the current socket state and if not ready, wait for the event.
		if fdnotifier.NonBlockingPoll(int32(s.fd.FD()), mask)&mask == 0 {
			<-notifyCh
		}

		// Call getsockopt to get the connection result.
		val, err := unix.GetsockoptInt(s.fd.FD(), unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return nil, fmt.Errorf("unix.GetSockoptInt: %w", err)
		}
		if val != 0 {
			return nil, fmt.Errorf("unix.GetSockoptInt: %w", unix.Errno(val))
		}
	}
	cu.Release()
	return &s, nil
}

func (s *hostInetConn) Name() string {
	return fmt.Sprintf("localhost:port:%d", s.port)
}

// Read implements io.Reader.Read. It performs a blocking read on the fd.
func (s *hostInetConn) Read(ctx context.Context, buf []byte, cancel <-chan struct{}) (int, error) {
	var ch chan struct{}
	var e waiter.Entry
	n, err := s.fd.Read(buf)
	for ctx.Err() == nil && linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
		if ch == nil {
			e, ch = waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventHUp | waiter.EventErr)
			// Register for when the endpoint is writable or disconnected.
			s.eventRegister(&e)
			defer s.eventUnregister(&e)
		}
		select {
		case <-ch:
		case <-cancel:
			return 0, io.EOF
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		n, err = s.fd.Read(buf)
	}
	return n, err
}

// Write implements io.Writer.Write. It performs a blocking write on the fd.
func (s *hostInetConn) Write(ctx context.Context, buf []byte, cancel <-chan struct{}) (int, error) {
	var ch chan struct{}
	var e waiter.Entry
	n, err := s.fd.Write(buf)
	for ctx.Err() == nil && linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
		if ch == nil {
			e, ch = waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
			// Register for when the endpoint is writable or disconnected.
			s.eventRegister(&e)
			defer s.eventUnregister(&e)

		}
		select {
		case <-ch:
		case <-cancel:
			return 0, io.EOF
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		n, err = s.fd.Write(buf)
	}
	return n, err
}

func (s *hostInetConn) eventRegister(e *waiter.Entry) {
	s.wq.EventRegister(e)
	fdnotifier.UpdateFD(int32(s.fd.FD()))
}

func (s *hostInetConn) eventUnregister(e *waiter.Entry) {
	s.wq.EventUnregister(e)
	fdnotifier.UpdateFD(int32(s.fd.FD()))
}

// Close closes the host socket and removes it from notifications.
func (s *hostInetConn) Close(_ context.Context) {
	s.once.Do(func() {
		fdnotifier.RemoveFD(int32(s.fd.FD()))
		s.fd.Close()
	})
}
