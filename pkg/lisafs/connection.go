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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

// ConnectionManager manages the lifetime (from creation to destruction) of
// connections in the gofer process. It is also responsible for server sharing.
type ConnectionManager struct {
	// servers contains a mapping between a server and the path at which it was
	// mounted. The path must be filepath.Clean()'d. It is protected by serversMu.
	servers   map[string]*server
	serversMu sync.Mutex

	wg sync.WaitGroup
}

// StartConnection starts a new connection.
func (cm *ConnectionManager) StartConnection(sock *unet.Socket, mountPath string, handlers []RPCHandler, connOpts interface{}) error {
	mountPath = filepath.Clean(mountPath)

	var s *server
	cm.serversMu.Lock()
	if cm.servers == nil {
		cm.servers = make(map[string]*server)
	}
	if s = cm.servers[mountPath]; s == nil {
		s = &server{
			mountPath: mountPath,
		}
		cm.servers[mountPath] = s
	}
	cm.serversMu.Unlock()

	c := &Connection{
		server:     s,
		sockComm:   newSockComm(sock),
		attachPath: mountPath,
		handlers:   handlers,
		opts:       connOpts,
		channels:   make([]*channel, 0, maxChannels),
		fds:        make(map[FDID]FD),
		nextFDID:   InvalidFDID + 1,
	}

	alloc, err := flipcall.NewPacketWindowAllocator()
	if err != nil {
		return err
	}
	c.channelAlloc = alloc

	// Each connection has its dedicated goroutine.
	cm.wg.Add(1)
	go func() {
		c.run()
		cm.wg.Done()
	}()
	return nil
}

// Wait waits for all connections to terminate.
func (cm *ConnectionManager) Wait() {
	cm.wg.Wait()
}

// Communicator is a server side utility which represents exactly how the
// server is communicating with the client.
type Communicator interface {
	// PayloadBuf returns a slice to the payload section of its internal buffer
	// where the message can be marshalled. The handlers should use this to
	// populate the payload buffer with the message. The payload buffer contents
	// are preserved across calls with different sizes.
	PayloadBuf(size uint32) []byte
}

// Connection represents a connection between a gofer mount in the sentry and
// the gofer process. This is owned by the gofer process and facilitates
// communication with the Client.
type Connection struct {
	// server serves a filesystem tree that this connection is immutably
	// associated with. This server might be shared across connections. This
	// helps when we have bind mounts that are shared between containers in a
	// runsc pod.
	server *server

	// sockComm is the main socket by which this connections is established.
	sockComm *sockCommunicator

	// attachPath is the host path where this connection is attached. This path
	// guaranteed to be inside server.mountPath.
	attachPath string

	// handlers contains all the message handlers which is defined by the server
	// implementation. It is indexed by MID. handlers is immutable. If
	// handlers[MID] is nil, then that MID is not supported.
	handlers []RPCHandler

	// channelsMu protects channels.
	channelsMu sync.Mutex
	// channels keeps track of all open channels.
	channels []*channel

	// activeWg represents active channels.
	activeWg sync.WaitGroup

	// pendingWg represents channels with pending requests.
	pendingWg sync.WaitGroup

	// channelAlloc is used to allocate memory for channels.
	channelAlloc *flipcall.PacketWindowAllocator

	// fds keeps tracks of open FDs on this server. It is protected by fdsMu.
	fds map[FDID]FD
	// nextFDID is the next available FDID. It is protected by fdsMu.
	nextFDID FDID
	fdsMu    sync.RWMutex

	// opts is the connection specific options and is immutable. This is supplied
	// to all operations and specific to a gofer implementation.
	opts interface{}
}

// server serves a filesystem tree. A server may be shared across various
// connections if they all connect to the same mouth path. Provides utilities
// to safely modify the filesystem tree.
type server struct {
	// renameMu synchronizes rename operations within this filesystem tree.
	renameMu sync.RWMutex

	// mountPath represents the host path at which this server is mounted.
	// mountPath is immutable.
	mountPath string
}

// Opts returns the connection specific options.
func (c *Connection) Opts() interface{} {
	return c.opts
}

// AttachAt attaches c at attachPath. Note that attachPath is interpreted wrt
// the server's mount point.
func (c *Connection) AttachAt(attachPath string) {
	// Must provide an absolute path.
	attachPath = path.Clean(attachPath)
	if path.IsAbs(attachPath) {
		// Trim off the leading / if the path is absolute. We always treat attach
		// paths as absolute and it is applied to the backing server's mount path.
		attachPath = attachPath[1:]
	}
	if len(attachPath) > 0 {
		c.attachPath = path.Join(c.server.mountPath, attachPath)
	}
}

// AttachPath returns the host path at which this connection is attached.
func (c *Connection) AttachPath() string {
	return c.attachPath
}

// WithRenameRLock invokes fn with the server's rename mutex locked for
// reading. This ensures that no rename operations are occuring while fn
// executes (assuming rename correctly locks the rename mutex for writing).
func (c *Connection) WithRenameRLock(fn func() error) error {
	c.server.renameMu.RLock()
	err := fn()
	c.server.renameMu.RUnlock()
	return err
}

// WithRenameLock invokes fn with the server's rename mutex locked for writing.
// The caller should be intending to change the filesystem tree structure.
func (c *Connection) WithRenameLock(fn func() error) error {
	c.server.renameMu.Lock()
	err := fn()
	c.server.renameMu.Unlock()
	return err
}

// run defines the lifecycle of a connection.
func (c *Connection) run() {
	defer c.close()

	// Start handling requests on this connection.
	for {
		m, payloadLen, err := c.sockComm.rcvMsg(nil)
		if err != nil {
			log.Debugf("sock read failed, closing connection: %v", err)
			return
		}
		respM, respMsgLen, respFDs := c.handleMsg(c.sockComm, m, payloadLen)
		if err := c.sockComm.sndPrepopulatedMsg(respM, respMsgLen, respFDs); err != nil {
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
		m, payloadLen, err := ch.rcvMsg(rcvDataLen, nil)
		if err != nil {
			return err
		}
		respM, respMsgLen, respFDs := c.handleMsg(ch, m, payloadLen)
		numFDs, err := ch.sndFDs(respFDs)
		if err != nil {
			return err
		}
		ch.marshalHdr(respM, numFDs)
		rcvDataLen, err = ch.data.SendRecv(uint32(chanHeaderLen) + respMsgLen)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Connection) handleErrFromHandler(comm Communicator, err unix.Errno) (MID, uint32, []int) {
	resp := &ErrorRes{errno: uint32(err)}
	respSize := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respSize))
	return Error, respSize, nil
}

func (c *Connection) handleMsg(comm Communicator, m MID, payloadLen uint32) (MID, uint32, []int) {
	c.pendingWg.Add(1)
	defer c.pendingWg.Done()

	// Check if the message is supported.
	if int(m) >= len(c.handlers) || c.handlers[m] == nil {
		log.Warningf("received request which is not supported by the server, MID = %d", m)
		return c.handleErrFromHandler(comm, unix.EOPNOTSUPP)
	}

	// Try handling the request.
	respSize, fds, err := c.handlers[m](c, comm, payloadLen)
	if err != nil {
		return c.handleErrFromHandler(comm, p9.ExtractErrno(err))
	}

	return m, respSize, fds
}

func (c *Connection) close() {
	// Wait for completion of all inflight requests. This is mostly so that if
	// a request is stuck, the sandbox supervisor has the opportunity to kill
	// us with SIGABRT to get a stack dump of the offending handler.
	c.pendingWg.Wait()

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
	for fdid := range c.fds {
		c.removeFDLocked(fdid)
	}
	c.fdsMu.Unlock()
}

// LookupFD retrives the FD identified by id on this connection. This operation
// increments the returned FD's ref which is owned by the caller.
func (c *Connection) LookupFD(id FDID) (FD, error) {
	c.fdsMu.RLock()
	defer c.fdsMu.RUnlock()

	fd, ok := c.fds[id]
	if !ok {
		return nil, unix.EBADF
	}
	fd.IncRef()
	return fd, nil
}

// InsertFD inserts the passed fd into the internal datastructure to track FDs.
// The caller must hold a ref on fd which is transferred to the connection.
func (c *Connection) InsertFD(fd FD) FDID {
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

// RemoveFD makes c stop tracking the passed FDID and drops its ref on it.
func (c *Connection) RemoveFD(id FDID) {
	c.fdsMu.Lock()
	c.removeFDLocked(id)
	c.fdsMu.Unlock()
}

// RemoveFDs makes c stop tracking the passed FDIDs. c drops its ref on the
// passed FDs.
func (c *Connection) RemoveFDs(ids []FDID) {
	c.fdsMu.Lock()
	defer c.fdsMu.Unlock()

	for _, id := range ids {
		c.removeFDLocked(id)
	}
}

// Precondition: c.fdsMu is locked.
func (c *Connection) removeFDLocked(id FDID) {
	fd, ok := c.fds[id]
	if !ok {
		log.Warningf("removeFDLocked called on non-existent FDID %d", id)
		return
	}
	delete(c.fds, id)
	fd.DecRef(nil) // Drop the ref held by c.
}

// UnsupportedMessages returns all message IDs that are not supported on this
// connection. An MID is unsupported if handlers[MID] == nil.
func (c *Connection) UnsupportedMessages() []MID {
	var res []MID
	for i := range c.handlers {
		if c.handlers[i] == nil {
			res = append(res, MID(i))
		}
	}
	return res
}

// MaxMessage is the maximum message ID supported on this connection.
func (c *Connection) MaxMessage() MID {
	return MID(len(c.handlers) - 1)
}
