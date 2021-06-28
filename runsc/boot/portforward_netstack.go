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
	"bytes"
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// netstackPortForwardConn is a portForwardConn implementation for netstack.
type netstackPortForwardConn struct {
	// cid is the container id that this connection is connecting to.
	cid string

	// ep is the tcpip.Endpoint to the application port.
	ep tcpip.Endpoint
	// wq is the endpoint waiter.Queue.
	wq *waiter.Queue
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

// newNetstackPortForward creates a new port forwarding connection to the given
// port in netstack mode.
func newNetstackPortForward(ctx context.Context, stack *stack.Stack, cid string, streamFile *os.File, fd *vfs.FileDescription, port int) (portForwardConn, error) {
	var wq waiter.Queue
	ep, tcpErr := stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if tcpErr != nil {
		return nil, fmt.Errorf("creating endpoint: %v", tcpErr)
	}
	cu := cleanup.Make(func() { ep.Close() })
	defer cu.Clean()

	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.WritableEvents)
	defer wq.EventUnregister(&waitEntry)

	tcpErr = ep.Connect(tcpip.FullAddress{
		Addr: "\x7f\x00\x00\x01", // 127.0.0.1
		Port: uint16(port),
	})
	if _, ok := tcpErr.(*tcpip.ErrConnectStarted); ok {
		<-notifyCh
		tcpErr = ep.LastError()
	}
	if tcpErr != nil {
		return nil, fmt.Errorf("connecting endpoint: %v", tcpErr)
	}

	pfConn := netstackPortForwardConn{
		cid:        cid,
		ep:         ep,
		wq:         &wq,
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
func (c *netstackPortForwardConn) Start() error {
	c.status.Lock()
	defer c.status.Unlock()

	if c.status.closed {
		return fmt.Errorf("already closed")
	}
	if c.status.started {
		return fmt.Errorf("already started")
	}

	log.Debugf("Start forwarding to/from container %q and localhost", c.cid)

	go c.writeToEP()
	go c.readFromEP()

	c.status.started = true

	return nil
}

// Close implements portForwardConn.Close.
func (c *netstackPortForwardConn) Close() error {
	c.status.Lock()

	// This should be a no op if the connection is already closed.
	if c.status.closed {
		c.status.Unlock()
		return nil
	}

	log.Debugf("Stopping forwarding to/from container %q and localhost...", c.cid)

	// Closing the stream/endpoint will make the other goroutine exit.
	c.streamFile.Close()
	c.ep.Close()
	c.fd.DecRef(c.ctx)

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
func (c *netstackPortForwardConn) Cleanup(f func()) {
	c.cleanup.Add(f)
}

// readFromEP reads from the tcpip.Endpoint and writes to the given Writer.
func (c *netstackPortForwardConn) readFromEP() {
	w := &fileDescriptionReadWriter{
		ctx:  c.ctx,
		file: c.fd,
	}

	// Register for read notifications.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	// Register for when the endpoint is readable or disconnected.
	c.wq.EventRegister(&waitEntry, waiter.EventIn|waiter.EventHUp|waiter.EventErr)

	for {
		_, err := c.ep.Read(w, tcpip.ReadOptions{})
		if err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}

			break
		}
	}

	// Clean up when one half of the copy is finished.
	c.wq.EventUnregister(&waitEntry)
	c.ep.Shutdown(tcpip.ShutdownRead)
	close(c.fromDone)
	c.Close()
}

func (c *netstackPortForwardConn) writeToEP() {
	r := &fileDescriptionReadWriter{
		ctx:  c.ctx,
		file: c.fd,
	}

	// Register for write notifications.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	// Register for when the endpoint is writable or disconnected.
	c.wq.EventRegister(&waitEntry, waiter.WritableEvents|waiter.EventHUp|waiter.EventErr)

	v := make([]byte, 16384 /* 16kb read buffer size */)
	for {
		n, err := r.Read(v)
		if err != nil {
			break
		}
		var b bytes.Reader
		b.Reset(v[:n])
		for b.Len() != 0 {
			_, err := c.ep.Write(&b, tcpip.WriteOptions{Atomic: true})
			if err != nil {
				// If the channel is not ready for writing wait until it is.
				if _, ok := err.(*tcpip.ErrWouldBlock); ok {
					<-notifyCh
					continue
				}
				break
			}
		}
	}

	// Clean up when one half of the copy is finished.
	c.wq.EventUnregister(&waitEntry)
	c.ep.Shutdown(tcpip.ShutdownWrite)
	close(c.toDone)
	c.Close()
}
