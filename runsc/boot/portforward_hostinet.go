// Copyright 2021 The gVisor Authors.
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

package boot

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

// hostSocket allows reading and writing to a host socket for hostinet.
type hostSocket struct {
	// wq is the WaitQueue registered with fdnotifier for this fd.
	wq waiter.Queue
	// fd is the file descriptor for the socket.
	fd int
}

// newHostSocket creates a hostSocket for an FD and registers the fd for
// notifications.
func newHostSocket() (*hostSocket, error) {
	// NOTE: Options must match sandbox seccomp filters. See filter/config.go
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	s := hostSocket{
		fd: fd,
	}
	if err := fdnotifier.AddFD(int32(fd), &s.wq); err != nil {
		return nil, err
	}
	return &s, nil
}

// Connect performs a blocking connect on the socket to a ipv4 address.
func (s *hostSocket) Connect(addr [4]byte, port int) error {
	sockAddr := &unix.SockaddrInet4{
		Addr: addr,
		Port: port,
	}

	if err := unix.Connect(s.fd, sockAddr); err != nil {
		if err != unix.EINPROGRESS {
			return err
		}

		// Connect is in progress. Wait for socket to be writable.
		mask := waiter.WritableEvents
		waitEntry, notifyCh := waiter.NewChannelEntry(nil)
		s.EventRegister(&waitEntry, mask)
		defer s.EventUnregister(&waitEntry)

		// Wait for connect to succeed.
		// Check the current socket state and if not ready, wait for the event.
		if fdnotifier.NonBlockingPoll(int32(s.fd), mask)&mask == 0 {
			<-notifyCh
		}

		// Call getsockopt to get the connection result.
		val, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_ERROR)
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
func (s *hostSocket) Read(buf []byte) (int, error) {
	var ch chan struct{}
	var e waiter.Entry
	n, err := unix.Read(s.fd, buf)
	for err == unix.EWOULDBLOCK {
		if ch == nil {
			e, ch = waiter.NewChannelEntry(nil)
			// Register for when the endpoint is writable or disconnected.
			s.EventRegister(&e, waiter.ReadableEvents|waiter.WritableEvents|waiter.EventHUp|waiter.EventErr)
			defer s.EventUnregister(&e)
		}
		<-ch
		n, err = unix.Read(s.fd, buf)
	}
	return n, err
}

// Write implements io.Writer.Write. It performs a blocking write on the fd.
func (s *hostSocket) Write(buf []byte) (int, error) {
	var ch chan struct{}
	var e waiter.Entry
	n, err := unix.Write(s.fd, buf)
	for err == unix.EWOULDBLOCK {
		if ch == nil {
			e, ch = waiter.NewChannelEntry(nil)
			// Register for when the endpoint is writable or disconnected.
			s.EventRegister(&e, waiter.WritableEvents|waiter.EventHUp|waiter.EventErr)
			defer s.EventUnregister(&e)
		}
		<-ch
		n, err = unix.Write(s.fd, buf)
	}
	return n, err
}

func (s *hostSocket) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	s.wq.EventRegister(e, mask)
	fdnotifier.UpdateFD(int32(s.fd))
}

func (s *hostSocket) EventUnregister(e *waiter.Entry) {
	s.wq.EventUnregister(e)
	fdnotifier.UpdateFD(int32(s.fd))
}

func (s *hostSocket) Close() {
	fdnotifier.RemoveFD(int32(s.fd))
	unix.Close(s.fd)
}

// hostinetportForwardConn is a hostinet port forwarding connection.
type hostinetPortForwardConn struct {
	// cid is the container id that this connection is connecting to.
	cid string

	// Socket is the host socket connected to the application.
	socket *hostSocket
	// streamFile is a host UDS file passed from the urpc client.
	streamFile *os.File
	// fd is the FileDescription for the imported host UDS fd.
	fd *vfs.FileDescription
	// ctx is the context for the sandbox.
	ctx context.Context

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

	// cleanup is called when the connection finishes.
	cleanup cleanup.Cleanup
}

// newHostinetPortForward starts port forwarding to the given port in hostinet
// mode.
func newHostinetPortForward(ctx context.Context, cid string, streamFile *os.File, fd *vfs.FileDescription, port int) (portForwardConn, error) {
	log.Debugf("Handling hostinet port forwarding request for %s on port %d", cid, port)
	appSocket, err := newHostSocket()
	if err != nil {
		return nil, fmt.Errorf("hostinet socket: %w", err)
	}

	cu := cleanup.Make(func() { appSocket.Close() })
	defer cu.Clean()

	if err := appSocket.Connect([4]byte{127, 0, 0, 1}, port); err != nil {
		return nil, fmt.Errorf("hostinet connect: %w", err)
	}

	pfConn := hostinetPortForwardConn{
		cid:        cid,
		socket:     appSocket,
		streamFile: streamFile,
		fd:         fd,
		ctx:        ctx,
		toDone:     make(chan struct{}),
		fromDone:   make(chan struct{}),
		cleanup:    cleanup.Make(nil),
	}

	cu.Release()
	return &pfConn, nil
}

// Start implements portForwardConn.Start.
func (c *hostinetPortForwardConn) Start() error {
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
		ctx:  c.ctx,
		file: c.fd,
	}

	go func() {
		_, _ = io.Copy(c.socket, importedRW)
		// Indicate that this goroutine has completed.
		close(c.toDone)
		// Make sure to clean up when one half of the copy has finished.
		c.Close()
	}()
	go func() {
		_, _ = io.Copy(importedRW, c.socket)
		// Indicate that this goroutine has completed.
		close(c.fromDone)
		// Make sure to clean up when one half of the copy has finished.
		c.Close()
	}()

	c.status.started = true

	return nil
}

// Close implements portForwardConn.Close.
func (c *hostinetPortForwardConn) Close() error {
	c.status.Lock()

	// This should be a no op if the connection is already closed.
	if c.status.closed {
		c.status.Unlock()
		return nil
	}

	log.Debugf("Stopping forwarding to/from container %q and localhost...", c.cid)

	// Closing the stream, FileDescription, and endpoint should make all
	// goroutines exit.
	c.streamFile.Close()
	c.fd.DecRef(c.ctx)
	c.socket.Close()

	// Wait for one goroutine to finish or for save event.
	<-c.toDone
	log.Debugf("Stopped forwarding one-half of copy for %q", c.cid)

	// Wait on the other goroutine.
	<-c.fromDone
	log.Debugf("Stopped forwarding to/from container %q and localhost", c.cid)

	c.status.closed = true

	c.status.Unlock()

	// Call the cleanup object.
	c.cleanup.Clean()

	return nil
}

// Cleanup implements portForwardConn.Cleanup.
func (c *hostinetPortForwardConn) Cleanup(f func()) {
	c.cleanup.Add(f)
}
