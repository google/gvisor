// Copyright 2020 The gVisor Authors.
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

package fuse

import (
	goContext "context"
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// fuseDefaultMaxBackground is the default value for MaxBackground.
	fuseDefaultMaxBackground = 12

	// fuseDefaultCongestionThreshold is the default value for CongestionThreshold,
	// and is 75% of the default maximum of MaxGround.
	fuseDefaultCongestionThreshold = (fuseDefaultMaxBackground * 3 / 4)

	// fuseDefaultMaxPagesPerReq is the default value for MaxPagesPerReq.
	fuseDefaultMaxPagesPerReq = 32
)

// connection is the struct by which the sentry communicates with the FUSE server daemon.
//
// Lock order:
//   - conn.fd.mu
//   - conn.mu
//   - conn.asyncMu
//
// +stateify savable
type connection struct {
	connectionRefs

	// We target FUSE 7.23.
	// The following FUSE_INIT flags are currently unsupported by this implementation:
	//	- FUSE_EXPORT_SUPPORT
	//	- FUSE_POSIX_LOCKS: requires POSIX locks
	//	- FUSE_FLOCK_LOCKS: requires POSIX locks
	//	- FUSE_AUTO_INVAL_DATA: requires page caching eviction
	//	- FUSE_DO_READDIRPLUS/FUSE_READDIRPLUS_AUTO: requires FUSE_READDIRPLUS implementation
	//	- FUSE_ASYNC_DIO
	//	- FUSE_PARALLEL_DIROPS (7.25)
	//	- FUSE_HANDLE_KILLPRIV (7.26)
	//	- FUSE_POSIX_ACL: affects defaultPermissions, posixACL, xattr handler (7.26)
	//	- FUSE_ABORT_ERROR (7.27)
	//	- FUSE_CACHE_SYMLINKS (7.28)
	//	- FUSE_NO_OPENDIR_SUPPORT (7.29)
	//	- FUSE_EXPLICIT_INVAL_DATA: requires page caching eviction (7.30)
	//	- FUSE_MAP_ALIGNMENT (7.31)

	// initialized after receiving FUSE_INIT reply.
	// Until it's set, suspend sending FUSE requests.
	// Use SetInitialized() and IsInitialized() for atomic access.
	initialized atomicbitops.Int32

	// initializedChan is used to block requests before initialization.
	initializedChan chan struct{} `state:".(bool)"`

	// waitQueue is used to notify the readers that there is something to read.
	waitQueue waiter.Queue

	// fullQueueCh is a channel used to synchronize the readers with the writers.
	// Writers (inbound requests to the filesystem) block if there are too many
	// unprocessed in-flight requests.
	fullQueueCh chan struct{} `state:".(int)"`

	// mu protects access to struct members.
	mu sync.Mutex `state:"nosave"`

	// numActiveRequests is the number of active requests.
	//
	// +checklocks:mu
	numActiveRequests uint64

	// completions is used to map a request to its response. A Writer will use this
	// to notify the caller of a completed response.
	//
	// +checklocks:mu
	completions map[linux.FUSEOpID]*futureResponse

	// queue is the list of requests that need to be processed by the FUSE server.
	//
	// +checklocks:mu
	queue requestList

	// nextOpID is used to create new requests.
	//
	// +checklocks:mu
	nextOpID linux.FUSEOpID

	// writeBuf is the memory buffer used to copy in the FUSE out header from
	// userspace.
	//
	// +checklocks:mu
	writeBuf [fuseHeaderOutSize]byte

	// attributeVersion is the version of connection's attributes.
	attributeVersion atomicbitops.Uint64

	// connected (connection established) when a new FUSE file system is created.
	// Set to false when:
	//   umount,
	//   connection abort,
	//   device release.
	//
	// +checklocks:mu
	connected bool

	// connInitError if FUSE_INIT encountered error (major version mismatch).
	// Only set in INIT.
	//
	// +checklocks:mu
	connInitError bool

	// connInitSuccess if FUSE_INIT is successful.
	// Only set in INIT.
	// Used for destroy (not yet implemented).
	//
	// +checklocks:mu
	connInitSuccess bool

	// aborted via sysfs, and will send ECONNABORTED to read after disconnection (instead of ENODEV).
	// Set only if abortErr is true and via fuse control fs (not yet implemented).
	// TODO(gvisor.dev/issue/3525): set this to true when user aborts.
	aborted bool

	// numWaiting is the number of requests waiting to be
	// sent to FUSE device or being processed by FUSE daemon.
	numWaiting uint32

	// Terminology note:
	//
	//	- `asyncNumMax` is the `MaxBackground` in the FUSE_INIT_IN struct.
	//
	//	- `asyncCongestionThreshold` is the `CongestionThreshold` in the FUSE_INIT_IN struct.
	//
	// We call the "background" requests in unix term as async requests.
	// The "async requests" in unix term is our async requests that expect a reply,
	// i.e. `!request.noReply`

	// asyncMu protects the async request fields.
	asyncMu sync.Mutex `state:"nosave"`

	// asyncNum is the number of async requests.
	//
	// +checklocks:asyncMu
	asyncNum uint16

	// asyncCongestionThreshold the number of async requests.
	// Negotiated in FUSE_INIT as "CongestionThreshold".
	// TODO(gvisor.dev/issue/3529): add congestion control.
	//
	// +checklocks:asyncMu
	asyncCongestionThreshold uint16

	// asyncNumMax is the maximum number of asyncNum.
	// Connection blocks the async requests when it is reached.
	// Negotiated in FUSE_INIT as "MaxBackground".
	//
	// +checklocks:asyncMu
	asyncNumMax uint16

	// maxRead is the maximum size of a read buffer in in bytes.
	// Initialized from a fuse fs parameter.
	maxRead uint32

	// maxWrite is the maximum size of a write buffer in bytes.
	// Negotiated in FUSE_INIT.
	maxWrite uint32

	// maxPages is the maximum number of pages for a single request to use.
	// Negotiated in FUSE_INIT.
	maxPages uint16

	// maxActiveRequests specifies the maximum number of active requests that can
	// exist at any time. Any further requests will block when trying to CAll
	// the server.
	maxActiveRequests uint64

	// minor version of the FUSE protocol.
	// Negotiated and only set in INIT.
	minor uint32

	// atomicOTrunc is true when FUSE does not send a separate SETATTR request
	// before open with O_TRUNC flag.
	// Negotiated and only set in INIT.
	atomicOTrunc bool

	// asyncRead if read pages asynchronously.
	// Negotiated and only set in INIT.
	asyncRead bool

	// writebackCache is true for write-back cache policy,
	// false for write-through policy.
	// Negotiated and only set in INIT.
	writebackCache bool

	// bigWrites if doing multi-page cached writes.
	// Negotiated and only set in INIT.
	bigWrites bool

	// dontMask if filesystem does not apply umask to creation modes.
	// Negotiated in INIT.
	dontMask bool

	// noOpen if FUSE server doesn't support open operation.
	// This flag only influences performance, not correctness of the program.
	noOpen bool
}

func connError(err error) error {
	// The error may contain arbitrary errno values that can't be converted.
	switch e := err.(type) {
	case unix.Errno:
		if syserr.IsValid(e) {
			return err
		}
	default:
		return err
	}
	log.Warningf("fusefs: failed with invalid error: %v", err)
	return unix.EINVAL
}

func (conn *connection) saveInitializedChan() bool {
	select {
	case <-conn.initializedChan:
		return true // Closed.
	default:
		return false // Not closed.
	}
}

func (conn *connection) loadInitializedChan(_ goContext.Context, closed bool) {
	conn.initializedChan = make(chan struct{}, 1)
	if closed {
		close(conn.initializedChan)
	}
}

// newFUSEConnection creates a FUSE connection to fuseFD.
// +checklocks:fuseFD.mu
func newFUSEConnection(_ context.Context, fuseFD *DeviceFD, opts *filesystemOptions) (*connection, error) {
	// Mark the device as ready so it can be used.
	// FIXME(gvisor.dev/issue/4813): fuseFD's fields are accessed without
	// synchronization and without checking if fuseFD has already been used to
	// mount another filesystem.

	// Create the writeBuf for the header to be stored in.
	conn := &connection{
		completions:              make(map[linux.FUSEOpID]*futureResponse),
		fullQueueCh:              make(chan struct{}, opts.maxActiveRequests),
		asyncNumMax:              fuseDefaultMaxBackground,
		asyncCongestionThreshold: fuseDefaultCongestionThreshold,
		maxRead:                  opts.maxRead,
		maxPages:                 fuseDefaultMaxPagesPerReq,
		maxActiveRequests:        opts.maxActiveRequests,
		initializedChan:          make(chan struct{}),
		connected:                true,
	}
	conn.InitRefs()
	return conn, nil
}

func (conn *connection) DecRef(ctx context.Context) {
	conn.connectionRefs.DecRef(func() {
		conn.Abort(ctx)
		conn.waitQueue.Notify(waiter.ReadableEvents)
	})
}

// CallAsync makes an async (aka background) request.
// It's a simple wrapper around Call().
func (conn *connection) CallAsync(ctx context.Context, r *Request) error {
	r.async = true
	_, err := conn.Call(ctx, r)
	return err
}

// Call makes a request to the server.
// Block before the connection is initialized.
// When the Request is FUSE_INIT, it will not be blocked before initialization.
// Task should never be nil.
//
// For a sync request, it blocks the invoking task until
// a server responds with a response.
//
// For an async request (that do not expect a response immediately),
// it returns directly unless being blocked either before initialization
// or when there are too many async requests ongoing.
//
// Example for async request:
// init, readahead, write, async read/write, fuse_notify_reply,
// non-sync release, interrupt, forget.
//
// The forget request does not have a reply,
// as documented in include/uapi/linux/fuse.h:FUSE_FORGET.
func (conn *connection) Call(ctx context.Context, r *Request) (*Response, error) {
	// Block requests sent before connection is initialized.
	if !conn.Initialized() && r.hdr.Opcode != linux.FUSE_INIT {
		if err := ctx.Block(conn.initializedChan); err != nil {
			return nil, connError(err)
		}
	}

	conn.mu.Lock()
	connected := conn.connected
	connInitError := conn.connInitError
	conn.mu.Unlock()

	if !connected {
		return nil, linuxerr.ENOTCONN
	}

	if connInitError {
		return nil, linuxerr.ECONNREFUSED
	}

	fut, err := conn.callFuture(ctx, r)
	if err != nil {
		return nil, connError(err)
	}

	res, err := fut.resolve(ctx)
	if err != nil {
		return res, connError(err)
	}
	return res, nil
}

// callFuture makes a request to the server and returns a future response.
// Call resolve() when the response needs to be fulfilled.
func (conn *connection) callFuture(b context.Blocker, r *Request) (*futureResponse, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Is the queue full?
	//
	// We must busy wait here until the request can be queued. We don't
	// block on the fd.fullQueueCh with a lock - so after being signalled,
	// before we acquire the lock, it is possible that a barging task enters
	// and queues a request. As a result, upon acquiring the lock we must
	// again check if the room is available.
	//
	// This can potentially starve a request forever but this can only happen
	// if there are always too many ongoing requests all the time. The
	// supported maxActiveRequests setting should be really high to avoid this.
	for conn.numActiveRequests == conn.maxActiveRequests {
		log.Infof("Blocking request %v from being queued. Too many active requests: %v",
			r.id, conn.numActiveRequests)
		conn.mu.Unlock()
		err := b.Block(conn.fullQueueCh)
		conn.mu.Lock()
		if err != nil {
			return nil, err
		}
	}

	return conn.callFutureLocked(r)
}

// callFutureLocked makes a request to the server and returns a future response.
//
// +checklocks:conn.mu
func (conn *connection) callFutureLocked(r *Request) (*futureResponse, error) {
	// Check connected again holding conn.mu.
	if !conn.connected {
		// we checked connected before,
		// this must be due to aborted connection.
		return nil, linuxerr.ECONNABORTED
	}

	conn.queue.PushBack(r)
	conn.numActiveRequests++
	fut := newFutureResponse(r)
	conn.completions[r.id] = fut

	// Signal the readers that there is something to read.
	conn.waitQueue.Notify(waiter.ReadableEvents)

	return fut, nil
}

// sendResponse sends a response to the waiting task (if any).
//
// +checklocks:conn.mu
func (conn *connection) sendResponse(ctx context.Context, fut *futureResponse) error {
	// Signal the task waiting on a response if any.
	defer close(fut.ch)

	// Signal that the queue is no longer full.
	select {
	case conn.fullQueueCh <- struct{}{}:
	default:
	}
	conn.numActiveRequests--

	if fut.async {
		return conn.asyncCallBack(ctx, fut.getResponse())
	}

	return nil
}

// asyncCallBack executes pre-defined callback function for async requests.
// Currently used by: FUSE_INIT.
//
// +checklocks:conn.mu
func (conn *connection) asyncCallBack(ctx context.Context, r *Response) error {
	switch r.opcode {
	case linux.FUSE_INIT:
		creds := auth.CredentialsFromContext(ctx)
		rootUserNs := kernel.KernelFromContext(ctx).RootUserNamespace()
		return conn.InitRecv(r, creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, rootUserNs))
		// TODO(gvisor.dev/issue/3247): support async read: correctly process the response.
	}

	return nil
}

// readiness returns the readiness of the connection.
func (conn *connection) readiness(ready waiter.EventMask) waiter.EventMask {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	// FD is always writable.
	ready |= waiter.WritableEvents
	if !conn.queue.Empty() {
		// Have reqs available, FD is readable.
		ready |= waiter.ReadableEvents
	}
	return ready
}

func (conn *connection) read(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	minBuffSize := linux.FUSE_MIN_READ_BUFFER
	// We require that any Read done on this filesystem have a sane minimum
	// read buffer. It must have the capacity for the fixed parts of any request
	// header (Linux uses the request header and the FUSEWriteIn header for this
	// calculation) + the negotiated MaxWrite room for the data.
	negotiatedMinBuffSize := linux.SizeOfFUSEHeaderIn + linux.SizeOfFUSEHeaderOut + conn.maxWrite
	if minBuffSize < negotiatedMinBuffSize {
		minBuffSize = negotiatedMinBuffSize
	}

	// If the read buffer is too small, error out.
	if dst.NumBytes() < int64(minBuffSize) {
		return 0, linuxerr.EINVAL
	}
	// Find the first valid request. For the normal case this loop only executes
	// once.
	var req *Request
	for req = conn.queue.Front(); !conn.queue.Empty(); req = conn.queue.Front() {
		if int64(req.hdr.Len) <= dst.NumBytes() {
			break
		}
		// The request is too large so we cannot process it. All requests must be
		// smaller than the negotiated size as specified by Connection.MaxWrite set
		// as part of the FUSE_INIT handshake.
		errno := -int32(unix.EIO)
		if req.hdr.Opcode == linux.FUSE_SETXATTR {
			errno = -int32(unix.E2BIG)
		}

		if err := conn.sendError(ctx, errno, req.hdr.Unique); err != nil {
			return 0, err
		}
		conn.queue.Remove(req)
		req = nil
	}
	if req == nil {
		return 0, linuxerr.ErrWouldBlock
	}

	// We already checked the size: dst must be able to fit the whole request.
	n, err := dst.CopyOut(ctx, req.data)
	if err != nil {
		return 0, err
	}
	if n != len(req.data) {
		return 0, linuxerr.EIO
	}
	conn.queue.Remove(req)
	// Remove noReply ones from the map of requests expecting a reply.
	if req.noReply {
		conn.numActiveRequests--
		delete(conn.completions, req.hdr.Unique)
	}
	return int64(n), nil
}

func (conn *connection) write(ctx context.Context, src usermem.IOSequence) (int64, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	var hdr linux.FUSEHeaderOut
	if src.NumBytes() < int64(hdr.SizeBytes()) {
		return 0, linuxerr.EINVAL
	}
	n, err := src.CopyIn(ctx, conn.writeBuf[:])
	if err != nil {
		return 0, err
	}
	hdr.UnmarshalBytes(conn.writeBuf[:])
	if src.NumBytes() != int64(hdr.Len) {
		return 0, linuxerr.EINVAL
	}

	fut, ok := conn.completions[hdr.Unique]
	if !ok {
		// Server sent us a response for a request we never sent, or for which we
		// already received a reply (e.g. aborted), an unlikely event.
		return 0, linuxerr.EINVAL
	}
	delete(conn.completions, hdr.Unique)

	// Copy over the header into the future response. The rest of the payload
	// will be copied over to the FR's data in the next iteration.
	fut.hdr = &hdr
	fut.data = make([]byte, fut.hdr.Len)
	copy(fut.data, conn.writeBuf[:])
	if fut.hdr.Len > uint32(len(conn.writeBuf)) {
		src = src.DropFirst(len(conn.writeBuf))
		n2, err := src.CopyIn(ctx, fut.data[len(conn.writeBuf):])
		if err != nil {
			return 0, err
		}
		n += n2
	}
	if err := conn.sendResponse(ctx, fut); err != nil {
		return 0, err
	}
	return int64(n), nil
}
