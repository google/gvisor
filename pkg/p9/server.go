// Copyright 2018 The gVisor Authors.
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

package p9

import (
	"io"
	"runtime/debug"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fdchannel"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

// Server is a 9p2000.L server.
type Server struct {
	// attacher provides the attach function.
	attacher Attacher

	options AttacherOptions

	// pathTree is the full set of paths opened on this server.
	//
	// These may be across different connections, but rename operations
	// must be serialized globally for safely. There is a single pathTree
	// for the entire server, and not per connection.
	pathTree *pathNode

	// renameMu is a global lock protecting rename operations. With this
	// lock, we can be certain that any given rename operation can safely
	// acquire two path nodes in any order, as all other concurrent
	// operations acquire at most a single node.
	renameMu sync.RWMutex
}

// NewServer returns a new server. attacher may be nil.
func NewServer(attacher Attacher) *Server {
	opts := AttacherOptions{}
	if attacher != nil {
		opts = attacher.ServerOptions()
	}
	return &Server{
		attacher: attacher,
		options:  opts,
		pathTree: newPathNode(),
	}
}

// connState is the state for a single connection.
type connState struct {
	// server is the backing server.
	server *Server

	// fids is the set of active FIDs.
	//
	// This is used to find FIDs for files.
	fidMu sync.Mutex
	fids  map[FID]*fidRef

	// tags is the set of active tags.
	//
	// The given channel is closed when the
	// tag is finished with processing.
	tagMu sync.Mutex
	tags  map[Tag]chan struct{}

	// messageSize is the maximum message size. The server does not
	// do automatic splitting of messages.
	messageSize uint32

	// version is the agreed upon version X of 9P2000.L.Google.X.
	// version 0 implies 9P2000.L.
	version uint32

	// reqGate counts requests that are still being handled.
	reqGate sync.Gate

	// -- below relates to the legacy handler --

	// recvMu serializes receiving from conn.
	recvMu sync.Mutex

	// recvIdle is the number of goroutines in handleRequests() attempting to
	// lock recvMu so that they can receive from conn. recvIdle is accessed
	// using atomic memory operations.
	recvIdle int32

	// If recvShutdown is true, at least one goroutine has observed a
	// connection error while receiving from conn, and all goroutines in
	// handleRequests() should exit immediately. recvShutdown is protected by
	// recvMu.
	recvShutdown bool

	// sendMu serializes sending to conn.
	sendMu sync.Mutex

	// conn is the connection used by the legacy transport.
	conn *unet.Socket

	// -- below relates to the flipcall handler --

	// channelMu protects below.
	channelMu sync.Mutex

	// channelWg represents active workers.
	channelWg sync.WaitGroup

	// channelAlloc allocates channel memory.
	channelAlloc *flipcall.PacketWindowAllocator

	// channels are the set of initialized channels.
	channels []*channel
}

// fidRef wraps a node and tracks references.
type fidRef struct {
	// server is the associated server.
	server *Server

	// file is the associated File.
	file File

	// refs is an active refence count.
	//
	// The node above will be closed only when refs reaches zero.
	refs int64

	// opened indicates whether this has been opened already.
	//
	// This is updated in handlers.go.
	//
	// opened is protected by pathNode.opMu or renameMu (for write).
	opened bool

	// mode is the fidRef's mode from the walk. Only the type bits are
	// valid, the permissions may change. This is used to sanity check
	// operations on this element, and prevent walks across
	// non-directories.
	mode FileMode

	// openFlags is the mode used in the open.
	//
	// This is updated in handlers.go.
	//
	// openFlags is protected by pathNode.opMu or renameMu (for write).
	openFlags OpenFlags

	// pathNode is the current pathNode for this FID.
	pathNode *pathNode

	// parent is the parent fidRef. We hold on to a parent reference to
	// ensure that hooks, such as Renamed, can be executed safely by the
	// server code.
	//
	// Note that parent cannot be changed without holding both the global
	// rename lock and a writable lock on the associated pathNode for this
	// fidRef. Holding either of these locks is sufficient to examine
	// parent safely.
	//
	// The parent will be nil for root fidRefs, and non-nil otherwise. The
	// method maybeParent can be used to return a cyclical reference, and
	// isRoot should be used to check for root over looking at parent
	// directly.
	parent *fidRef

	// deleted indicates that the backing file has been deleted. We stop
	// many operations at the API level if they are incompatible with a
	// file that has already been unlinked.
	deleted uint32
}

// IncRef increases the references on a fid.
func (f *fidRef) IncRef() {
	atomic.AddInt64(&f.refs, 1)
}

// DecRef should be called when you're finished with a fid.
func (f *fidRef) DecRef() {
	if atomic.AddInt64(&f.refs, -1) == 0 {
		f.file.Close()

		// Drop the parent reference.
		//
		// Since this fidRef is guaranteed to be non-discoverable when
		// the references reach zero, we don't need to worry about
		// clearing the parent.
		if f.parent != nil {
			// If we've been previously deleted, this removing this
			// ref is a no-op. That's expected.
			f.parent.pathNode.removeChild(f)
			f.parent.DecRef()
		}
	}
}

// isDeleted returns true if this fidRef has been deleted.
func (f *fidRef) isDeleted() bool {
	return atomic.LoadUint32(&f.deleted) != 0
}

// isRoot indicates whether this is a root fid.
func (f *fidRef) isRoot() bool {
	return f.parent == nil
}

// maybeParent returns a cyclic reference for roots, and the parent otherwise.
func (f *fidRef) maybeParent() *fidRef {
	if f.parent != nil {
		return f.parent
	}
	return f // Root has itself.
}

// notifyDelete marks all fidRefs as deleted.
//
// Precondition: this must be called via safelyWrite or safelyGlobal.
func notifyDelete(pn *pathNode) {
	// Call on all local references.
	pn.forEachChildRef(func(ref *fidRef, _ string) {
		atomic.StoreUint32(&ref.deleted, 1)
	})

	// Call on all subtrees.
	pn.forEachChildNode(func(pn *pathNode) {
		notifyDelete(pn)
	})
}

// markChildDeleted marks all children below the given name as deleted.
//
// Precondition: this must be called via safelyWrite or safelyGlobal.
func (f *fidRef) markChildDeleted(name string) {
	origPathNode := f.pathNode.removeWithName(name, func(ref *fidRef) {
		atomic.StoreUint32(&ref.deleted, 1)
	})

	if origPathNode != nil {
		// Mark all children as deleted.
		notifyDelete(origPathNode)
	}
}

// notifyNameChange calls the relevant Renamed method on all nodes in the path,
// recursively. Note that this applies only for subtrees, as these
// notifications do not apply to the actual file whose name has changed.
//
// Precondition: this must be called via safelyGlobal.
func notifyNameChange(pn *pathNode) {
	// Call on all local references.
	pn.forEachChildRef(func(ref *fidRef, name string) {
		ref.file.Renamed(ref.parent.file, name)
	})

	// Call on all subtrees.
	pn.forEachChildNode(func(pn *pathNode) {
		notifyNameChange(pn)
	})
}

// renameChildTo renames the given child to the target.
//
// Precondition: this must be called via safelyGlobal.
func (f *fidRef) renameChildTo(oldName string, target *fidRef, newName string) {
	target.markChildDeleted(newName)
	origPathNode := f.pathNode.removeWithName(oldName, func(ref *fidRef) {
		// N.B. DecRef can take f.pathNode's parent's childMu. This is
		// allowed because renameMu is held for write via safelyGlobal.
		ref.parent.DecRef() // Drop original reference.
		ref.parent = target // Change parent.
		ref.parent.IncRef() // Acquire new one.
		if f.pathNode == target.pathNode {
			target.pathNode.addChildLocked(ref, newName)
		} else {
			target.pathNode.addChild(ref, newName)
		}
		ref.file.Renamed(target.file, newName)
	})

	if origPathNode != nil {
		// Replace the previous (now deleted) path node.
		target.pathNode.addPathNodeFor(newName, origPathNode)
		// Call Renamed on all children.
		notifyNameChange(origPathNode)
	}
}

// safelyRead executes the given operation with the local path node locked.
// This implies that paths will not change during the operation.
func (f *fidRef) safelyRead(fn func() error) (err error) {
	f.server.renameMu.RLock()
	defer f.server.renameMu.RUnlock()
	f.pathNode.opMu.RLock()
	defer f.pathNode.opMu.RUnlock()
	return fn()
}

// safelyWrite executes the given operation with the local path node locked in
// a writable fashion. This implies some paths may change.
func (f *fidRef) safelyWrite(fn func() error) (err error) {
	f.server.renameMu.RLock()
	defer f.server.renameMu.RUnlock()
	f.pathNode.opMu.Lock()
	defer f.pathNode.opMu.Unlock()
	return fn()
}

// safelyGlobal executes the given operation with the global path lock held.
func (f *fidRef) safelyGlobal(fn func() error) (err error) {
	f.server.renameMu.Lock()
	defer f.server.renameMu.Unlock()
	return fn()
}

// LookupFID finds the given FID.
//
// You should call fid.DecRef when you are finished using the fid.
func (cs *connState) LookupFID(fid FID) (*fidRef, bool) {
	cs.fidMu.Lock()
	defer cs.fidMu.Unlock()
	fidRef, ok := cs.fids[fid]
	if ok {
		fidRef.IncRef()
		return fidRef, true
	}
	return nil, false
}

// InsertFID installs the given FID.
//
// This fid starts with a reference count of one. If a FID exists in
// the slot already it is closed, per the specification.
func (cs *connState) InsertFID(fid FID, newRef *fidRef) {
	cs.fidMu.Lock()
	defer cs.fidMu.Unlock()
	origRef, ok := cs.fids[fid]
	if ok {
		defer origRef.DecRef()
	}
	newRef.IncRef()
	cs.fids[fid] = newRef
}

// DeleteFID removes the given FID.
//
// This simply removes it from the map and drops a reference.
func (cs *connState) DeleteFID(fid FID) bool {
	cs.fidMu.Lock()
	defer cs.fidMu.Unlock()
	fidRef, ok := cs.fids[fid]
	if !ok {
		return false
	}
	delete(cs.fids, fid)
	fidRef.DecRef()
	return true
}

// StartTag starts handling the tag.
//
// False is returned if this tag is already active.
func (cs *connState) StartTag(t Tag) bool {
	cs.tagMu.Lock()
	defer cs.tagMu.Unlock()
	_, ok := cs.tags[t]
	if ok {
		return false
	}
	cs.tags[t] = make(chan struct{})
	return true
}

// ClearTag finishes handling a tag.
func (cs *connState) ClearTag(t Tag) {
	cs.tagMu.Lock()
	defer cs.tagMu.Unlock()
	ch, ok := cs.tags[t]
	if !ok {
		// Should never happen.
		panic("unused tag cleared")
	}
	delete(cs.tags, t)

	// Notify.
	close(ch)
}

// WaitTag waits for a tag to finish.
func (cs *connState) WaitTag(t Tag) {
	cs.tagMu.Lock()
	ch, ok := cs.tags[t]
	cs.tagMu.Unlock()
	if !ok {
		return
	}

	// Wait for close.
	<-ch
}

// initializeChannels initializes all channels.
//
// This is a no-op if channels are already initialized.
func (cs *connState) initializeChannels() (err error) {
	cs.channelMu.Lock()
	defer cs.channelMu.Unlock()

	// Initialize our channel allocator.
	if cs.channelAlloc == nil {
		alloc, err := flipcall.NewPacketWindowAllocator()
		if err != nil {
			return err
		}
		cs.channelAlloc = alloc
	}

	// Create all the channels.
	for len(cs.channels) < channelsPerClient {
		res := &channel{
			done: make(chan struct{}),
		}

		res.desc, err = cs.channelAlloc.Allocate(channelSize)
		if err != nil {
			return err
		}
		if err := res.data.Init(flipcall.ServerSide, res.desc); err != nil {
			return err
		}

		socks, err := fdchannel.NewConnectedSockets()
		if err != nil {
			res.data.Destroy() // Cleanup.
			return err
		}
		res.fds.Init(socks[0])
		res.client = fd.New(socks[1])

		cs.channels = append(cs.channels, res)

		// Start servicing the channel.
		//
		// When we call stop, we will close all the channels and these
		// routines should finish. We need the wait group to ensure
		// that active handlers are actually finished before cleanup.
		cs.channelWg.Add(1)
		go func() { // S/R-SAFE: Server side.
			defer cs.channelWg.Done()
			if err := res.service(cs); err != nil {
				// Don't log flipcall.ShutdownErrors, which we expect to be
				// returned during server shutdown.
				if _, ok := err.(flipcall.ShutdownError); !ok {
					log.Warningf("p9.channel.service: %v", err)
				}
			}
		}()
	}

	return nil
}

// lookupChannel looks up the channel with given id.
//
// The function returns nil if no such channel is available.
func (cs *connState) lookupChannel(id uint32) *channel {
	cs.channelMu.Lock()
	defer cs.channelMu.Unlock()
	if id >= uint32(len(cs.channels)) {
		return nil
	}
	return cs.channels[id]
}

// handle handles a single message.
func (cs *connState) handle(m message) (r message) {
	if !cs.reqGate.Enter() {
		// connState.stop() has been called; the connection is shutting down.
		r = newErrFromLinuxerr(linuxerr.ECONNRESET)
		return
	}
	defer func() {
		cs.reqGate.Leave()
		if r == nil {
			// Don't allow a panic to propagate.
			err := recover()

			// Include a useful log message.
			log.Warningf("panic in handler: %v\n%s", err, debug.Stack())

			// Wrap in an EFAULT error; we don't really have a
			// better way to describe this kind of error. It will
			// usually manifest as a result of the test framework.
			r = newErrFromLinuxerr(linuxerr.EFAULT)
		}
	}()
	if handler, ok := m.(handler); ok {
		// Call the message handler.
		r = handler.handle(cs)
		// TODO(b/34162363):This is only here to make sure the server works with
		// only linuxerr Errors, as the handlers work with both client and server.
		// It will be removed a followup, when all the unix.Errno errors are
		// replaced with linuxerr.
		if rlError, ok := r.(*Rlerror); ok {
			e := linuxerr.ErrorFromUnix(unix.Errno(rlError.Error))
			r = newErrFromLinuxerr(e)
		}
	} else {
		// Produce an ENOSYS error.
		r = newErrFromLinuxerr(linuxerr.ENOSYS)
	}
	return
}

// handleRequest handles a single request. It returns true if the caller should
// continue handling requests and false if it should terminate.
func (cs *connState) handleRequest() bool {
	// Obtain the right to receive a message from cs.conn.
	atomic.AddInt32(&cs.recvIdle, 1)
	cs.recvMu.Lock()
	atomic.AddInt32(&cs.recvIdle, -1)

	if cs.recvShutdown {
		// Another goroutine already detected a connection problem; exit
		// immediately.
		cs.recvMu.Unlock()
		return false
	}

	messageSize := atomic.LoadUint32(&cs.messageSize)
	if messageSize == 0 {
		// Default or not yet negotiated.
		messageSize = maximumLength
	}

	// Receive a message.
	tag, m, err := recv(cs.conn, messageSize, msgRegistry.get)
	if errSocket, ok := err.(ErrSocket); ok {
		// Connection problem; stop serving.
		log.Debugf("p9.recv: %v", errSocket.error)
		cs.recvShutdown = true
		cs.recvMu.Unlock()
		return false
	}

	// Ensure that another goroutine is available to receive from cs.conn.
	if atomic.LoadInt32(&cs.recvIdle) == 0 {
		go cs.handleRequests() // S/R-SAFE: Irrelevant.
	}
	cs.recvMu.Unlock()

	// Deal with other errors.
	if err != nil && err != io.EOF {
		// If it's not a connection error, but some other protocol error,
		// we can send a response immediately.
		cs.sendMu.Lock()
		err := send(cs.conn, tag, newErrFromLinuxerr(err))
		cs.sendMu.Unlock()
		if err != nil {
			log.Debugf("p9.send: %v", err)
		}
		return true
	}

	// Try to start the tag.
	if !cs.StartTag(tag) {
		// Nothing we can do at this point; client is bogus.
		log.Debugf("no valid tag [%05d]", tag)
		return true
	}

	// Handle the message.
	r := cs.handle(m)

	// Clear the tag before sending. That's because as soon as this hits
	// the wire, the client can legally send the same tag.
	cs.ClearTag(tag)

	// Send back the result.
	cs.sendMu.Lock()
	err = send(cs.conn, tag, r)
	cs.sendMu.Unlock()
	if err != nil {
		log.Debugf("p9.send: %v", err)
	}

	// Return the message to the cache.
	msgRegistry.put(m)

	return true
}

func (cs *connState) handleRequests() {
	for {
		if !cs.handleRequest() {
			return
		}
	}
}

func (cs *connState) stop() {
	// Stop new requests from proceeding, and wait for completion of all
	// inflight requests. This is mostly so that if a request is stuck, the
	// sandbox supervisor has the opportunity to kill us with SIGABRT to get a
	// stack dump of the offending handler.
	cs.reqGate.Close()

	// Free the channels.
	cs.channelMu.Lock()
	for _, ch := range cs.channels {
		ch.Shutdown()
	}
	cs.channelWg.Wait()
	for _, ch := range cs.channels {
		ch.Close()
	}
	cs.channels = nil // Clear.
	cs.channelMu.Unlock()

	// Free the channel memory.
	if cs.channelAlloc != nil {
		cs.channelAlloc.Destroy()
	}

	// Ensure the connection is closed.
	cs.conn.Close()

	// Close all remaining fids.
	for fid, fidRef := range cs.fids {
		delete(cs.fids, fid)

		// Drop final reference in the FID table. Note this should
		// always close the file, since we've ensured that there are no
		// handlers running via the wait for Pending => 0 below.
		fidRef.DecRef()
	}
}

// Handle handles a single connection.
func (s *Server) Handle(conn *unet.Socket) error {
	cs := &connState{
		server: s,
		fids:   make(map[FID]*fidRef),
		tags:   make(map[Tag]chan struct{}),
		conn:   conn,
	}
	defer cs.stop()

	// Serve requests from conn in the current goroutine; handleRequests() will
	// create more goroutines as needed.
	cs.handleRequests()

	return nil
}

// Serve handles requests from the bound socket.
//
// The passed serverSocket _must_ be created in packet mode.
func (s *Server) Serve(serverSocket *unet.ServerSocket) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := serverSocket.Accept()
		if err != nil {
			// Something went wrong.
			//
			// Socket closed?
			return err
		}

		wg.Add(1)
		go func(conn *unet.Socket) { // S/R-SAFE: Irrelevant.
			s.Handle(conn)
			wg.Done()
		}(conn)
	}
}
