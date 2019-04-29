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
	"sync"
	"sync/atomic"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/unet"
)

// Server is a 9p2000.L server.
type Server struct {
	// attacher provides the attach function.
	attacher Attacher

	// pathTree is the full set of paths opened on this server.
	//
	// These may be across different connections, but rename operations
	// must be serialized globally for safely. There is a single pathTree
	// for the entire server, and not per connection.
	pathTree pathNode

	// renameMu is a global lock protecting rename operations. With this
	// lock, we can be certain that any given rename operation can safely
	// acquire two path nodes in any order, as all other concurrent
	// operations acquire at most a single node.
	renameMu sync.RWMutex
}

// NewServer returns a new server.
//
func NewServer(attacher Attacher) *Server {
	return &Server{
		attacher: attacher,
	}
}

// connState is the state for a single connection.
type connState struct {
	// server is the backing server.
	server *Server

	// sendMu is the send lock.
	sendMu sync.Mutex

	// conn is the connection.
	conn *unet.Socket

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

	// recvOkay indicates that a receive may start.
	recvOkay chan bool

	// recvDone is signalled when a message is received.
	recvDone chan error

	// sendDone is signalled when a send is finished.
	sendDone chan error
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

	// openedMu protects opened and openFlags.
	openedMu sync.Mutex

	// opened indicates whether this has been opened already.
	//
	// This is updated in handlers.go.
	opened bool

	// mode is the fidRef's mode from the walk. Only the type bits are
	// valid, the permissions may change. This is used to sanity check
	// operations on this element, and prevent walks across
	// non-directories.
	mode FileMode

	// openFlags is the mode used in the open.
	//
	// This is updated in handlers.go.
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

// OpenFlags returns the flags the file was opened with and true iff the fid was opened previously.
func (f *fidRef) OpenFlags() (OpenFlags, bool) {
	f.openedMu.Lock()
	defer f.openedMu.Unlock()
	return f.openFlags, f.opened
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
// Precondition: the write lock must be held on the given pathNode.
func notifyDelete(pn *pathNode) {
	// Call on all local references.
	pn.fidRefs.Range(func(key, _ interface{}) bool {
		ref := key.(*fidRef)
		atomic.StoreUint32(&ref.deleted, 1)
		return true
	})

	// Call on all subtrees.
	pn.children.Range(func(_, value interface{}) bool {
		notifyDelete(value.(*pathNode))
		return true
	})
}

// markChildDeleted marks all children below the given name as deleted.
//
// Precondition: this must be called via safelyWrite or safelyGlobal.
func (f *fidRef) markChildDeleted(name string) {
	origPathNode := f.pathNode.removeWithName(name, func(ref *fidRef) {
		atomic.StoreUint32(&ref.deleted, 1)
	})

	// Mark everything below as deleted.
	notifyDelete(origPathNode)
}

// notifyNameChange calls the relevant Renamed method on all nodes in the path,
// recursively. Note that this applies only for subtrees, as these
// notifications do not apply to the actual file whose name has changed.
//
// Precondition: the write lock must be held on the given pathNode.
func notifyNameChange(pn *pathNode) {
	// Call on all local references.
	pn.fidRefs.Range(func(key, value interface{}) bool {
		ref := key.(*fidRef)
		name := value.(string)
		ref.file.Renamed(ref.parent.file, name)
		return true
	})

	// Call on all subtrees.
	pn.children.Range(func(_, value interface{}) bool {
		notifyNameChange(value.(*pathNode))
		return true
	})
}

// renameChildTo renames the given child to the target.
//
// Precondition: this must be called via safelyGlobal.
func (f *fidRef) renameChildTo(oldName string, target *fidRef, newName string) {
	target.markChildDeleted(newName)
	origPathNode := f.pathNode.removeWithName(oldName, func(ref *fidRef) {
		ref.parent.DecRef() // Drop original reference.
		ref.parent = target // Change parent.
		ref.parent.IncRef() // Acquire new one.
		target.pathNode.addChild(ref, newName)
		ref.file.Renamed(target.file, newName)
	})

	// Replace the previous (now deleted) path node.
	f.pathNode.children.Store(newName, origPathNode)

	// Call Renamed on everything above.
	notifyNameChange(origPathNode)
}

// safelyRead executes the given operation with the local path node locked.
// This implies that paths will not change during the operation.
func (f *fidRef) safelyRead(fn func() error) (err error) {
	f.server.renameMu.RLock()
	defer f.server.renameMu.RUnlock()
	f.pathNode.mu.RLock()
	defer f.pathNode.mu.RUnlock()
	return fn()
}

// safelyWrite executes the given operation with the local path node locked in
// a writable fashion. This implies some paths may change.
func (f *fidRef) safelyWrite(fn func() error) (err error) {
	f.server.renameMu.RLock()
	defer f.server.renameMu.RUnlock()
	f.pathNode.mu.Lock()
	defer f.pathNode.mu.Unlock()
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

// handleRequest handles a single request.
//
// The recvDone channel is signaled when recv is done (with a error if
// necessary). The sendDone channel is signaled with the result of the send.
func (cs *connState) handleRequest() {
	messageSize := atomic.LoadUint32(&cs.messageSize)
	if messageSize == 0 {
		// Default or not yet negotiated.
		messageSize = maximumLength
	}

	// Receive a message.
	tag, m, err := recv(cs.conn, messageSize, msgRegistry.get)
	if errSocket, ok := err.(ErrSocket); ok {
		// Connection problem; stop serving.
		cs.recvDone <- errSocket.error
		return
	}

	// Signal receive is done.
	cs.recvDone <- nil

	// Deal with other errors.
	if err != nil && err != io.EOF {
		// If it's not a connection error, but some other protocol error,
		// we can send a response immediately.
		cs.sendMu.Lock()
		err := send(cs.conn, tag, newErr(err))
		cs.sendMu.Unlock()
		cs.sendDone <- err
		return
	}

	// Try to start the tag.
	if !cs.StartTag(tag) {
		// Nothing we can do at this point; client is bogus.
		log.Debugf("no valid tag [%05d]", tag)
		cs.sendDone <- ErrNoValidMessage
		return
	}

	// Handle the message.
	var r message // r is the response.
	defer func() {
		if r == nil {
			// Don't allow a panic to propagate.
			recover()

			// Include a useful log message.
			log.Warningf("panic in handler: %s", debug.Stack())

			// Wrap in an EFAULT error; we don't really have a
			// better way to describe this kind of error. It will
			// usually manifest as a result of the test framework.
			r = newErr(syscall.EFAULT)
		}

		// Clear the tag before sending. That's because as soon as this
		// hits the wire, the client can legally send another message
		// with the same tag.
		cs.ClearTag(tag)

		// Send back the result.
		cs.sendMu.Lock()
		err = send(cs.conn, tag, r)
		cs.sendMu.Unlock()
		cs.sendDone <- err
	}()
	if handler, ok := m.(handler); ok {
		// Call the message handler.
		r = handler.handle(cs)
	} else {
		// Produce an ENOSYS error.
		r = newErr(syscall.ENOSYS)
	}
	msgRegistry.put(m)
	m = nil // 'm' should not be touched after this point.
}

func (cs *connState) handleRequests() {
	for range cs.recvOkay {
		cs.handleRequest()
	}
}

func (cs *connState) stop() {
	// Close all channels.
	close(cs.recvOkay)
	close(cs.recvDone)
	close(cs.sendDone)

	for _, fidRef := range cs.fids {
		// Drop final reference in the FID table. Note this should
		// always close the file, since we've ensured that there are no
		// handlers running via the wait for Pending => 0 below.
		fidRef.DecRef()
	}

	// Ensure the connection is closed.
	cs.conn.Close()
}

// service services requests concurrently.
func (cs *connState) service() error {
	// Pending is the number of handlers that have finished receiving but
	// not finished processing requests. These must be waiting on properly
	// below. See the next comment for an explanation of the loop.
	pending := 0

	// Start the first request handler.
	go cs.handleRequests() // S/R-SAFE: Irrelevant.
	cs.recvOkay <- true

	// We loop and make sure there's always one goroutine waiting for a new
	// request. We process all the data for a single request in one
	// goroutine however, to ensure the best turnaround time possible.
	for {
		select {
		case err := <-cs.recvDone:
			if err != nil {
				// Wait for pending handlers.
				for i := 0; i < pending; i++ {
					<-cs.sendDone
				}
				return err
			}

			// This handler is now pending.
			pending++

			// Kick the next receiver, or start a new handler
			// if no receiver is currently waiting.
			select {
			case cs.recvOkay <- true:
			default:
				go cs.handleRequests() // S/R-SAFE: Irrelevant.
				cs.recvOkay <- true
			}

		case <-cs.sendDone:
			// This handler is finished.
			pending--

			// Error sending a response? Nothing can be done.
			//
			// We don't terminate on a send error though, since
			// we still have a pending receive. The error would
			// have been logged above, we just ignore it here.
		}
	}
}

// Handle handles a single connection.
func (s *Server) Handle(conn *unet.Socket) error {
	cs := &connState{
		server:   s,
		conn:     conn,
		fids:     make(map[FID]*fidRef),
		tags:     make(map[Tag]chan struct{}),
		recvOkay: make(chan bool),
		recvDone: make(chan error, 10),
		sendDone: make(chan error, 10),
	}
	defer cs.stop()
	return cs.service()
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
