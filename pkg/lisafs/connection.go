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

package lisafs

import (
	"path"
	"path/filepath"
	"runtime/debug"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

// Connection represents a connection between a mount point in the client and a
// mount point in the server. It is owned by the server on which it was started
// and facilitates communication with the client mount.
//
// Each connection is set up using a unix domain socket. One end is owned by
// the server and the other end is owned by the client. The connection may
// spawn additional comunicational channels for the same mount for increased
// RPC concurrency.
//
// Reference model:
//   - When any FD is created, the connection takes a ref on it which represents
//     the client's ref on the FD.
//   - The client can drop its ref via the Close RPC which will in turn make the
//     connection drop its ref.
type Connection struct {
	// server is the server on which this connection was created. It is immutably
	// associated with it for its entire lifetime.
	server *Server

	// mountPath is the path to a file inside the server that is served to this
	// connection as its root FD. IOW, this connection is mounted at this path.
	// mountPath is trusted because it is configured by the server (trusted) as
	// per the user's sandbox configuration. mountPath is immutable.
	mountPath string

	// maxMessageSize is the cached value of server.impl.MaxMessageSize().
	maxMessageSize uint32

	// readonly indicates if this connection is readonly. All write operations
	// will fail with EROFS.
	readonly bool

	// sockComm is the main socket by which this connections is established.
	sockComm *sockCommunicator

	// channelsMu protects channels.
	channelsMu sync.Mutex
	// channels keeps track of all open channels.
	channels []*channel

	// activeWg represents active channels.
	activeWg sync.WaitGroup

	// reqGate counts requests that are still being handled.
	reqGate sync.Gate

	// channelAlloc is used to allocate memory for channels.
	channelAlloc *flipcall.PacketWindowAllocator

	fdsMu sync.RWMutex
	// fds keeps tracks of open FDs on this server. It is protected by fdsMu.
	fds map[FDID]genericFD
	// nextFDID is the next available FDID. It is protected by fdsMu.
	nextFDID FDID
}

// CreateConnection initializes a new connection which will be mounted at
// mountPath. The connection must be started separately.
func (s *Server) CreateConnection(sock *unet.Socket, mountPath string, readonly bool) (*Connection, error) {
	mountPath = path.Clean(mountPath)
	if !filepath.IsAbs(mountPath) {
		log.Warningf("mountPath %q is not absolute", mountPath)
		return nil, unix.EINVAL
	}

	c := &Connection{
		sockComm:       newSockComm(sock),
		server:         s,
		maxMessageSize: s.impl.MaxMessageSize(),
		mountPath:      mountPath,
		readonly:       readonly,
		channels:       make([]*channel, 0, maxChannels()),
		fds:            make(map[FDID]genericFD),
		nextFDID:       InvalidFDID + 1,
	}

	alloc, err := flipcall.NewPacketWindowAllocator()
	if err != nil {
		return nil, err
	}
	c.channelAlloc = alloc
	return c, nil
}

// ServerImpl returns the associated server implementation.
func (c *Connection) ServerImpl() ServerImpl {
	return c.server.impl
}

// Run defines the lifecycle of a connection.
func (c *Connection) Run() {
	defer c.close()

	// Start handling requests on this connection.
	for {
		m, payloadLen, err := c.sockComm.rcvMsg(0 /* wantFDs */)
		if err != nil {
			log.Debugf("sock read failed, closing connection: %v", err)
			return
		}

		respM, respPayloadLen, respFDs := c.handleMsg(c.sockComm, m, payloadLen)
		err = c.sockComm.sndPrepopulatedMsg(respM, respPayloadLen, respFDs)
		closeFDs(respFDs)
		if err != nil {
			log.Debugf("sock write failed, closing connection: %v", err)
			return
		}
	}
}

// service starts servicing the passed channel until the channel is shutdown.
// This is a blocking method and hence must be called in a separate goroutine.
func (c *Connection) service(ch *channel) error {
	rcvDataLen, err := ch.data.RecvFirst()
	if err != nil {
		return err
	}
	for rcvDataLen > 0 {
		m, payloadLen, err := ch.rcvMsg(rcvDataLen)
		if err != nil {
			return err
		}
		respM, respPayloadLen, respFDs := c.handleMsg(ch, m, payloadLen)
		numFDs := ch.sendFDs(respFDs)
		closeFDs(respFDs)

		ch.marshalHdr(respM, numFDs)
		rcvDataLen, err = ch.data.SendRecv(respPayloadLen + chanHeaderLen)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Connection) respondError(comm Communicator, err unix.Errno) (MID, uint32, []int) {
	resp := &ErrorResp{errno: uint32(err)}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return Error, respLen, nil
}

func (c *Connection) handleMsg(comm Communicator, m MID, payloadLen uint32) (retM MID, retPayloadLen uint32, retFDs []int) {
	if payloadLen > c.maxMessageSize {
		log.Warningf("received payload is too large: %d bytes", payloadLen)
		return c.respondError(comm, unix.EIO)
	}
	if !c.reqGate.Enter() {
		// c.close() has been called; the connection is shutting down.
		return c.respondError(comm, unix.ECONNRESET)
	}
	defer func() {
		c.reqGate.Leave()

		// Don't allow a panic to propagate.
		if err := recover(); err != nil {
			// Include a useful log message.
			log.Warningf("panic in handler: %v\n%s", err, debug.Stack())

			// Wrap in an EREMOTEIO error; we don't really have a better way to
			// describe this kind of error. EREMOTEIO is appropriate for a generic
			// failed RPC message.
			retM, retPayloadLen, retFDs = c.respondError(comm, unix.EREMOTEIO)
		}
	}()

	// Check if the message is supported for forward compatibility.
	if int(m) >= len(c.server.handlers) || c.server.handlers[m] == nil {
		log.Warningf("received request which is not supported by the server, MID = %d", m)
		return c.respondError(comm, unix.EOPNOTSUPP)
	}

	// Try handling the request.
	respPayloadLen, err := c.server.handlers[m](c, comm, payloadLen)
	fds := comm.ReleaseFDs()
	if err != nil {
		closeFDs(fds)
		return c.respondError(comm, p9.ExtractErrno(err))
	}
	if respPayloadLen > c.maxMessageSize {
		log.Warningf("handler for message %d responded with payload which is too large: %d bytes", m, respPayloadLen)
		closeFDs(fds)
		return c.respondError(comm, unix.EIO)
	}

	return m, respPayloadLen, fds
}

func (c *Connection) close() {
	// Wait for completion of all inflight requests. This is mostly so that if
	// a request is stuck, the sandbox supervisor has the opportunity to kill
	// us with SIGABRT to get a stack dump of the offending handler.
	c.reqGate.Close()

	// Shutdown and clean up channels.
	c.channelsMu.Lock()
	for _, ch := range c.channels {
		ch.shutdown()
	}
	c.activeWg.Wait()
	for _, ch := range c.channels {
		ch.destroy()
	}
	// This is to prevent additional channels from being created.
	c.channels = nil
	c.channelsMu.Unlock()

	// Free the channel memory.
	if c.channelAlloc != nil {
		c.channelAlloc.Destroy()
	}

	// Ensure the connection is closed.
	c.sockComm.destroy()

	// Cleanup all FDs.
	c.fdsMu.Lock()
	defer c.fdsMu.Unlock()
	for fdid := range c.fds {
		fd := c.stopTrackingFD(fdid)
		fd.DecRef(nil) // Drop the ref held by c.
	}
}

// Postcondition: The caller gains a ref on the FD on success.
func (c *Connection) lookupFD(id FDID) (genericFD, error) {
	c.fdsMu.RLock()
	defer c.fdsMu.RUnlock()

	fd, ok := c.fds[id]
	if !ok {
		return nil, unix.EBADF
	}
	fd.IncRef()
	return fd, nil
}

// lookupControlFD retrieves the control FD identified by id on this
// connection. On success, the caller gains a ref on the FD.
func (c *Connection) lookupControlFD(id FDID) (*ControlFD, error) {
	fd, err := c.lookupFD(id)
	if err != nil {
		return nil, err
	}

	cfd, ok := fd.(*ControlFD)
	if !ok {
		fd.DecRef(nil)
		return nil, unix.EINVAL
	}
	return cfd, nil
}

// lookupOpenFD retrieves the open FD identified by id on this
// connection. On success, the caller gains a ref on the FD.
func (c *Connection) lookupOpenFD(id FDID) (*OpenFD, error) {
	fd, err := c.lookupFD(id)
	if err != nil {
		return nil, err
	}

	ofd, ok := fd.(*OpenFD)
	if !ok {
		fd.DecRef(nil)
		return nil, unix.EINVAL
	}
	return ofd, nil
}

// lookupBoundSocketFD retrieves the boundSockedFD identified by id on this
// connection. On success, the caller gains a ref on the FD.
func (c *Connection) lookupBoundSocketFD(id FDID) (*BoundSocketFD, error) {
	fd, err := c.lookupFD(id)
	if err != nil {
		return nil, err
	}

	bsfd, ok := fd.(*BoundSocketFD)
	if !ok {
		fd.DecRef(nil)
		return nil, unix.EINVAL
	}
	return bsfd, nil
}

// insertFD inserts the passed fd into the internal datastructure to track FDs.
// The caller must hold a ref on fd which is transferred to the connection.
func (c *Connection) insertFD(fd genericFD) FDID {
	c.fdsMu.Lock()
	defer c.fdsMu.Unlock()

	res := c.nextFDID
	c.nextFDID++
	if c.nextFDID < res {
		panic("ran out of FDIDs")
	}
	c.fds[res] = fd
	return res
}

// removeFD makes c stop tracking the passed FDID and drops its ref on it.
func (c *Connection) removeFD(id FDID) {
	c.fdsMu.Lock()
	fd := c.stopTrackingFD(id)
	c.fdsMu.Unlock()
	if fd != nil {
		// Drop the ref held by c. This can take arbitrarily long. So do not hold
		// c.fdsMu while calling it.
		fd.DecRef(nil)
	}
}

// removeControlFDLocked is the same as removeFD with added preconditions.
//
// Preconditions:
//   - server's rename mutex must at least be read locked.
//   - id must be pointing to a control FD.
func (c *Connection) removeControlFDLocked(id FDID) {
	c.fdsMu.Lock()
	fd := c.stopTrackingFD(id)
	c.fdsMu.Unlock()
	if fd != nil {
		// Drop the ref held by c. This can take arbitrarily long. So do not hold
		// c.fdsMu while calling it.
		fd.(*ControlFD).decRefLocked()
	}
}

// stopTrackingFD makes c stop tracking the passed FDID. Note that the caller
// must drop ref on the returned fd (preferably without holding c.fdsMu).
//
// Precondition: c.fdsMu is locked.
func (c *Connection) stopTrackingFD(id FDID) genericFD {
	fd := c.fds[id]
	if fd == nil {
		log.Warningf("removeFDLocked called on non-existent FDID %d", id)
		return nil
	}
	delete(c.fds, id)
	return fd
}
