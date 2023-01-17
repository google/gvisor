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
	fileDescriptor "gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	localHost = [4]byte{127, 0, 0, 1}
)

// localHostSocket allows reading and writing to a local host socket for hostinet.
type localHostSocket struct {
	// wq is the WaitQueue registered with fdnotifier for this fd.
	wq waiter.Queue
	// fd is the file descriptor for the socket.
	fd *fileDescriptor.FD
}

// newLocalHostSocket creates a hostSocket for an FD and registers the fd for
// notifications.
func newLocalHostSocket() (*localHostSocket, error) {
	// NOTE: Options must match sandbox seccomp filters. See filter/config.go
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	s := localHostSocket{
		fd: fileDescriptor.New(fd),
	}
	if err := fdnotifier.AddFD(int32(s.fd.FD()), &s.wq); err != nil {
		return nil, err
	}
	return &s, nil
}

// Connect performs a blocking connect on the socket to an ipv4 address.
func (s *localHostSocket) Connect(port uint16) error {
	sockAddr := &unix.SockaddrInet4{
		Addr: localHost,
		Port: int(port),
	}

	if err := unix.Connect(s.fd.FD(), sockAddr); err != nil {
		if err != unix.EINPROGRESS {
			return err
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
			return nil
		}
		if val != 0 {
			return unix.Errno(val)
		}
	}

	return nil
}

// Read implements io.Reader.Read. It performs a blocking read on the fd.
func (s *localHostSocket) Read(buf []byte) (int, error) {
	var ch chan struct{}
	var e waiter.Entry
	n, err := s.fd.Read(buf)
	for err == unix.EWOULDBLOCK {
		if ch == nil {
			e, ch = waiter.NewChannelEntry(waiter.ReadableEvents | waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
			// Register for when the endpoint is writable or disconnected.
			s.eventRegister(&e)
			defer s.eventUnregister(&e)
		}
		<-ch
		n, err = s.fd.Read(buf)
	}
	return n, err
}

// Write implements io.Writer.Write. It performs a blocking write on the fd.
func (s *localHostSocket) Write(buf []byte) (int, error) {
	var ch chan struct{}
	var e waiter.Entry
	n, err := s.fd.Write(buf)
	for err == unix.EWOULDBLOCK {
		if ch == nil {
			e, ch = waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
			// Register for when the endpoint is writable or disconnected.
			s.eventRegister(&e)
			defer s.eventUnregister(&e)
		}
		<-ch
		n, err = s.fd.Write(buf)
	}
	return n, err
}

func (s *localHostSocket) eventRegister(e *waiter.Entry) {
	s.wq.EventRegister(e)
	fdnotifier.UpdateFD(int32(s.fd.FD()))
}

func (s *localHostSocket) eventUnregister(e *waiter.Entry) {
	s.wq.EventUnregister(e)
	fdnotifier.UpdateFD(int32(s.fd.FD()))
}

// Close closes the host socket and removes it from notifications.
func (s *localHostSocket) Close() {
	fdnotifier.RemoveFD(int32(s.fd.FD()))
	s.fd.Close()
}

// hostinetportForwardConn is a hostinet port forwarding connection.
type hostinetPortForwardConn struct {
	// cid is the container id that this connection is connecting to.
	cid string

	// Socket is the host socket connected to the application.
	socket *localHostSocket
	// fd is the FileDescription for the imported host UDS fd.
	fd *vfs.FileDescription

	// status holds the status of the connection.
	status struct {
		sync.Mutex
		// started indicates if the connection is started or not.
		started bool
		// closed indicates if the connection is closed or not.
		closed bool
	}

	// toDone is closed when the copy to the application port is finished.
	toDone chan struct{}

	// fromDone is closed when the copy from the application socket is finished.
	fromDone chan struct{}

	// cu is called when the connection finishes.
	cu cleanup.Cleanup
}

// newHostinetPortForward starts port forwarding to the given port in hostinet
// mode.
func newHostinetPortForward(ctx context.Context, cid string, fd *vfs.FileDescription, port uint16) (portForwardConn, error) {
	log.Debugf("Handling hostinet port forwarding request for %s on port %d", cid, port)
	appSocket, err := newLocalHostSocket()
	if err != nil {
		return nil, fmt.Errorf("hostinet socket: %w", err)
	}

	cu := cleanup.Make(func() { appSocket.Close() })
	defer cu.Clean()

	if err := appSocket.Connect(port); err != nil {
		return nil, fmt.Errorf("hostinet connect: %w", err)
	}

	pfConn := hostinetPortForwardConn{
		cid:      cid,
		socket:   appSocket,
		fd:       fd,
		toDone:   make(chan struct{}),
		fromDone: make(chan struct{}),
		cu:       cleanup.Cleanup{},
	}

	cu.Release()
	return &pfConn, nil
}

// Start implements portForwardConn.start.
func (c *hostinetPortForwardConn) start(ctx context.Context) error {
	c.status.Lock()
	defer c.status.Unlock()

	if c.status.closed {
		return fmt.Errorf("already closed")
	}
	if c.status.started {
		return fmt.Errorf("already started")
	}

	log.Debugf("Start forwarding to/from container %q and localhost", c.cid)

	importedRW := &fileDescriptionReadWriter{
		file: c.fd,
	}

	go func() {
		_, _ = io.Copy(c.socket, importedRW)
		// Indicate that this goroutine has completed.
		close(c.toDone)
		// Make sure to clean up when one half of the copy has finished.
		c.close(ctx)
	}()
	go func() {
		_, _ = io.Copy(importedRW, c.socket)
		// Indicate that this goroutine has completed.
		close(c.fromDone)
		// Make sure to clean up when one half of the copy has finished.
		c.close(ctx)
	}()

	c.status.started = true

	return nil
}

// close implements portForwardConn.close.
func (c *hostinetPortForwardConn) close(ctx context.Context) error {
	c.status.Lock()

	// This should be a no op if the connection is already closed.
	if c.status.closed {
		c.status.Unlock()
		return nil
	}

	log.Debugf("Stopping forwarding to/from container %q and localhost...", c.cid)

	// Closing the FileDescription and endpoint should make all
	// goroutines exit.
	c.fd.DecRef(ctx)
	c.socket.Close()

	// Wait for one goroutine to finish or for a save event.
	<-c.toDone
	log.Debugf("Stopped forwarding one-half of copy for %q", c.cid)

	// Wait on the other goroutine.
	<-c.fromDone
	log.Debugf("Stopped forwarding to/from container %q and localhost", c.cid)

	c.status.closed = true

	c.status.Unlock()

	// Call the cleanup object.
	c.cu.Clean()

	return nil
}

// cleanup implements portForwardConn.cleanup.
func (c *hostinetPortForwardConn) cleanup(f func()) {
	c.cu.Add(f)
}
