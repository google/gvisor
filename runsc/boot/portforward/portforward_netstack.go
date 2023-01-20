// Copyright 2023 The gVisor Authors.
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

package portforward

import (
	"bytes"
	"fmt"

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

// newNetstackPortForward creates a new port forwarding connection to the given
// port in netstack mode.
func newNetstackPortForward(ctx context.Context, stack *stack.Stack, cid string, fd *vfs.FileDescription, port uint16) (portForwardConn, error) {
	var wq waiter.Queue
	ep, tcpErr := stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if tcpErr != nil {
		return nil, fmt.Errorf("creating endpoint: %v", tcpErr)
	}
	cu := cleanup.Make(func() { ep.Close() })
	defer cu.Clean()

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	tcpErr = ep.Connect(tcpip.FullAddress{
		Addr: "\x7f\x00\x00\x01", // 127.0.0.1
		Port: port,
	})
	if _, ok := tcpErr.(*tcpip.ErrConnectStarted); ok {
		<-notifyCh
		tcpErr = ep.LastError()
	}
	if tcpErr != nil {
		return nil, fmt.Errorf("connecting endpoint: %v", tcpErr)
	}

	pfConn := netstackPortForwardConn{
		cid:      cid,
		ep:       ep,
		wq:       &wq,
		fd:       fd,
		toDone:   make(chan struct{}),
		fromDone: make(chan struct{}),
		cu:       cleanup.Cleanup{},
	}

	cu.Release()
	return &pfConn, nil
}

// start implements portForwardConn.start.
func (c *netstackPortForwardConn) start(ctx context.Context) error {
	c.status.Lock()
	defer c.status.Unlock()

	if c.status.closed {
		return fmt.Errorf("already closed")
	}
	if c.status.started {
		return fmt.Errorf("already started")
	}

	log.Debugf("Start forwarding to/from container %q and localhost", c.cid)

	go c.writeToEP(ctx)
	go c.readFromEP(ctx)

	c.status.started = true

	return nil
}

// close implements portForwardConn.close.
func (c *netstackPortForwardConn) close(ctx context.Context) error {
	c.status.Lock()

	// This should be a no op if the connection is already closed.
	if c.status.closed {
		c.status.Unlock()
		return nil
	}

	log.Debugf("Stopping forwarding to/from container %q and localhost...", c.cid)

	// Closing the endpoint will make the other goroutine exit.
	c.ep.Close()
	c.fd.DecRef(ctx)

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
func (c *netstackPortForwardConn) cleanup(f func()) {
	c.cu.Add(f)
}

// readFromEP reads from the tcpip.Endpoint and writes to the given Writer.
func (c *netstackPortForwardConn) readFromEP(ctx context.Context) {
	w := &fileDescriptionReadWriter{
		file: c.fd,
	}

	// Register for read notifications.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn | waiter.EventHUp | waiter.EventErr)
	// Register for when the endpoint is readable or disconnected.
	c.wq.EventRegister(&waitEntry)

	for {
		_, err := c.ep.Read(w, tcpip.ReadOptions{})
		if err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}
			log.Infof("Port forward read error; cid: %q: %v", c.cid, err)
			break
		}
	}

	// Clean up when one half of the copy is finished.
	c.wq.EventUnregister(&waitEntry)
	c.ep.Shutdown(tcpip.ShutdownRead)
	close(c.fromDone)
	c.close(ctx)
}

func (c *netstackPortForwardConn) writeToEP(ctx context.Context) {
	r := &fileDescriptionReadWriter{
		file: c.fd,
	}

	// Register for write notifications.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
	// Register for when the endpoint is writable or disconnected.
	c.wq.EventRegister(&waitEntry)

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
				// If the channel is not ready for writing then wait until it is.
				if _, ok := err.(*tcpip.ErrWouldBlock); ok {
					<-notifyCh
					continue
				}
				log.Infof("Port forward read error; cid: %q: %v", c.cid, err)
				break
			}
		}
	}

	// Clean up when one half of the copy is finished.
	c.wq.EventUnregister(&waitEntry)
	c.ep.Shutdown(tcpip.ShutdownWrite)
	close(c.toDone)
	c.close(ctx)
}
