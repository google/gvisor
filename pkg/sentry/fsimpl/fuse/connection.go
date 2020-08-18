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
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
)

// maxActiveRequestsDefault is the default setting controlling the upper bound
// on the number of active requests at any given time.
const maxActiveRequestsDefault = 10000

// Ordinary requests have even IDs, while interrupts IDs are odd.
// Used to increment the unique ID for each FUSE request.
var reqIDStep uint64 = 2

const (
	// fuseDefaultMaxBackground is the default value for MaxBackground.
	fuseDefaultMaxBackground = 12

	// fuseDefaultCongestionThreshold is the default value for CongestionThreshold,
	// and is 75% of the default maximum of MaxGround.
	fuseDefaultCongestionThreshold = (fuseDefaultMaxBackground * 3 / 4)

	// fuseDefaultMaxPagesPerReq is the default value for MaxPagesPerReq.
	fuseDefaultMaxPagesPerReq = 32
)

// Request represents a FUSE operation request that hasn't been sent to the
// server yet.
//
// +stateify savable
type Request struct {
	requestEntry

	id   linux.FUSEOpID
	hdr  *linux.FUSEHeaderIn
	data []byte
}

// Response represents an actual response from the server, including the
// response payload.
//
// +stateify savable
type Response struct {
	opcode linux.FUSEOpcode
	hdr    linux.FUSEHeaderOut
	data   []byte
}

// connection is the struct by which the sentry communicates with the FUSE server daemon.
type connection struct {
	fd *DeviceFD

	// The following FUSE_INIT flags are currently unsupported by this implementation:
	// - FUSE_ATOMIC_O_TRUNC: requires open(..., O_TRUNC)
	// - FUSE_EXPORT_SUPPORT
	// - FUSE_HANDLE_KILLPRIV
	// - FUSE_POSIX_LOCKS: requires POSIX locks
	// - FUSE_FLOCK_LOCKS: requires POSIX locks
	// - FUSE_AUTO_INVAL_DATA: requires page caching eviction
	// - FUSE_EXPLICIT_INVAL_DATA: requires page caching eviction
	// - FUSE_DO_READDIRPLUS/FUSE_READDIRPLUS_AUTO: requires FUSE_READDIRPLUS implementation
	// - FUSE_ASYNC_DIO
	// - FUSE_POSIX_ACL: affects defaultPermissions, posixACL, xattr handler

	// initialized after receiving FUSE_INIT reply.
	// Until it's set, suspend sending FUSE requests.
	// Use SetInitialized() and IsInitialized() for atomic access.
	initialized int32

	// initializedChan is used to block requests before initialization.
	initializedChan chan struct{}

	// blocked when there are too many outstading backgrounds requests (NumBackground == MaxBackground).
	// TODO(gvisor.dev/issue/3185): update the numBackground accordingly; use a channel to block.
	blocked bool

	// connected (connection established) when a new FUSE file system is created.
	// Set to false when:
	//   umount,
	//   connection abort,
	//   device release.
	connected bool

	// aborted via sysfs.
	// TODO(gvisor.dev/issue/3185): abort all queued requests.
	aborted bool

	// connInitError if FUSE_INIT encountered error (major version mismatch).
	// Only set in INIT.
	connInitError bool

	// connInitSuccess if FUSE_INIT is successful.
	// Only set in INIT.
	// Used for destory.
	connInitSuccess bool

	// TODO(gvisor.dev/issue/3185): All the queue logic are working in progress.

	// NumberBackground is the number of requests in the background.
	numBackground uint16

	// congestionThreshold for NumBackground.
	// Negotiated in FUSE_INIT.
	congestionThreshold uint16

	// maxBackground is the maximum number of NumBackground.
	// Block connection when it is reached.
	// Negotiated in FUSE_INIT.
	maxBackground uint16

	// numActiveBackground is the number of requests in background and has being marked as active.
	numActiveBackground uint16

	// numWating is the number of requests waiting for completion.
	numWaiting uint32

	// TODO(gvisor.dev/issue/3185): BgQueue
	// some queue for background queued requests.

	// bgLock protects:
	// MaxBackground, CongestionThreshold, NumBackground,
	// NumActiveBackground, BgQueue, Blocked.
	bgLock sync.Mutex

	// maxRead is the maximum size of a read buffer in in bytes.
	maxRead uint32

	// maxWrite is the maximum size of a write buffer in bytes.
	// Negotiated in FUSE_INIT.
	maxWrite uint32

	// maxPages is the maximum number of pages for a single request to use.
	// Negotiated in FUSE_INIT.
	maxPages uint16

	// minor version of the FUSE protocol.
	// Negotiated and only set in INIT.
	minor uint32

	// asyncRead if read pages asynchronously.
	// Negotiated and only set in INIT.
	asyncRead bool

	// abortErr is true if kernel need to return an unique read error after abort.
	// Negotiated and only set in INIT.
	abortErr bool

	// writebackCache is true for write-back cache policy,
	// false for write-through policy.
	// Negotiated and only set in INIT.
	writebackCache bool

	// cacheSymlinks if filesystem needs to cache READLINK responses in page cache.
	// Negotiated and only set in INIT.
	cacheSymlinks bool

	// bigWrites if doing multi-page cached writes.
	// Negotiated and only set in INIT.
	bigWrites bool

	// dontMask if filestestem does not apply umask to creation modes.
	// Negotiated in INIT.
	dontMask bool
}

// newFUSEConnection creates a FUSE connection to fd.
func newFUSEConnection(_ context.Context, fd *vfs.FileDescription, maxInFlightRequests uint64) (*connection, error) {
	// Mark the device as ready so it can be used. /dev/fuse can only be used if the FD was used to
	// mount a FUSE filesystem.
	fuseFD := fd.Impl().(*DeviceFD)
	fuseFD.mounted = true

	// Create the writeBuf for the header to be stored in.
	hdrLen := uint32((*linux.FUSEHeaderOut)(nil).SizeBytes())
	fuseFD.writeBuf = make([]byte, hdrLen)
	fuseFD.completions = make(map[linux.FUSEOpID]*futureResponse)
	fuseFD.fullQueueCh = make(chan struct{}, maxInFlightRequests)
	fuseFD.writeCursor = 0

	return &connection{
		fd:                  fuseFD,
		maxBackground:       fuseDefaultMaxBackground,
		congestionThreshold: fuseDefaultCongestionThreshold,
		maxPages:            fuseDefaultMaxPagesPerReq,
		initializedChan:     make(chan struct{}),
		connected:           true,
	}, nil
}

// SetInitialized atomically sets the connection as initialized.
func (conn *connection) SetInitialized() {
	// Unblock the requests sent before INIT.
	close(conn.initializedChan)

	// Close the channel first to avoid the non-atomic situation
	// where conn.initialized is true but there are
	// tasks being blocked on the channel.
	// And it prevents the newer tasks from gaining
	// unnecessary higher chance to be issued before the blocked one.

	atomic.StoreInt32(&(conn.initialized), int32(1))
}

// IsInitialized atomically check if the connection is initialized.
// pairs with SetInitialized().
func (conn *connection) Initialized() bool {
	return atomic.LoadInt32(&(conn.initialized)) != 0
}

// NewRequest creates a new request that can be sent to the FUSE server.
func (conn *connection) NewRequest(creds *auth.Credentials, pid uint32, ino uint64, opcode linux.FUSEOpcode, payload marshal.Marshallable) (*Request, error) {
	conn.fd.mu.Lock()
	defer conn.fd.mu.Unlock()
	conn.fd.nextOpID += linux.FUSEOpID(reqIDStep)

	hdrLen := (*linux.FUSEHeaderIn)(nil).SizeBytes()
	hdr := linux.FUSEHeaderIn{
		Len:    uint32(hdrLen + payload.SizeBytes()),
		Opcode: opcode,
		Unique: conn.fd.nextOpID,
		NodeID: ino,
		UID:    uint32(creds.EffectiveKUID),
		GID:    uint32(creds.EffectiveKGID),
		PID:    pid,
	}

	buf := make([]byte, hdr.Len)
	hdr.MarshalUnsafe(buf[:hdrLen])
	payload.MarshalUnsafe(buf[hdrLen:])

	return &Request{
		id:   hdr.Unique,
		hdr:  &hdr,
		data: buf,
	}, nil
}

// Call makes a request to the server and blocks the invoking task until a
// server responds with a response. Task should never be nil.
// Requests will not be sent before the connection is initialized.
// For async tasks, use CallAsync().
func (conn *connection) Call(t *kernel.Task, r *Request) (*Response, error) {
	// Block requests sent before connection is initalized.
	if !conn.Initialized() {
		if err := t.Block(conn.initializedChan); err != nil {
			return nil, err
		}
	}

	return conn.call(t, r)
}

// CallAsync makes an async (aka background) request.
// Those requests either do not expect a response (e.g. release) or
// the response should be handled by others (e.g. init).
// Return immediately unless the connection is blocked (before initialization).
// Async call example: init, release, forget, aio, interrupt.
// When the Request is FUSE_INIT, it will not be blocked before initialization.
func (conn *connection) CallAsync(t *kernel.Task, r *Request) error {
	// Block requests sent before connection is initalized.
	if !conn.Initialized() && r.hdr.Opcode != linux.FUSE_INIT {
		if err := t.Block(conn.initializedChan); err != nil {
			return err
		}
	}

	// This should be the only place that invokes call() with a nil task.
	_, err := conn.call(nil, r)
	return err
}

// call makes a call without blocking checks.
func (conn *connection) call(t *kernel.Task, r *Request) (*Response, error) {
	if !conn.connected {
		return nil, syserror.ENOTCONN
	}

	if conn.connInitError {
		return nil, syserror.ECONNREFUSED
	}

	fut, err := conn.callFuture(t, r)
	if err != nil {
		return nil, err
	}

	return fut.resolve(t)
}

// Error returns the error of the FUSE call.
func (r *Response) Error() error {
	errno := r.hdr.Error
	if errno >= 0 {
		return nil
	}

	sysErrNo := syscall.Errno(-errno)
	return error(sysErrNo)
}

// UnmarshalPayload unmarshals the response data into m.
func (r *Response) UnmarshalPayload(m marshal.Marshallable) error {
	hdrLen := r.hdr.SizeBytes()
	haveDataLen := r.hdr.Len - uint32(hdrLen)
	wantDataLen := uint32(m.SizeBytes())

	if haveDataLen < wantDataLen {
		return fmt.Errorf("payload too small. Minimum data lenth required: %d,  but got data length %d", wantDataLen, haveDataLen)
	}

	m.UnmarshalUnsafe(r.data[hdrLen:])
	return nil
}

// callFuture makes a request to the server and returns a future response.
// Call resolve() when the response needs to be fulfilled.
func (conn *connection) callFuture(t *kernel.Task, r *Request) (*futureResponse, error) {
	conn.fd.mu.Lock()
	defer conn.fd.mu.Unlock()

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
	for conn.fd.numActiveRequests == conn.fd.fs.opts.maxActiveRequests {
		if t == nil {
			// Since there is no task that is waiting. We must error out.
			return nil, errors.New("FUSE request queue full")
		}

		log.Infof("Blocking request %v from being queued. Too many active requests: %v",
			r.id, conn.fd.numActiveRequests)
		conn.fd.mu.Unlock()
		err := t.Block(conn.fd.fullQueueCh)
		conn.fd.mu.Lock()
		if err != nil {
			return nil, err
		}
	}

	return conn.callFutureLocked(t, r)
}

// callFutureLocked makes a request to the server and returns a future response.
func (conn *connection) callFutureLocked(t *kernel.Task, r *Request) (*futureResponse, error) {
	conn.fd.queue.PushBack(r)
	conn.fd.numActiveRequests += 1
	fut := newFutureResponse(r.hdr.Opcode)
	conn.fd.completions[r.id] = fut

	// Signal the readers that there is something to read.
	conn.fd.waitQueue.Notify(waiter.EventIn)

	return fut, nil
}

// futureResponse represents an in-flight request, that may or may not have
// completed yet. Convert it to a resolved Response by calling Resolve, but note
// that this may block.
//
// +stateify savable
type futureResponse struct {
	opcode linux.FUSEOpcode
	ch     chan struct{}
	hdr    *linux.FUSEHeaderOut
	data   []byte
}

// newFutureResponse creates a future response to a FUSE request.
func newFutureResponse(opcode linux.FUSEOpcode) *futureResponse {
	return &futureResponse{
		opcode: opcode,
		ch:     make(chan struct{}),
	}
}

// resolve blocks the task until the server responds to its corresponding request,
// then returns a resolved response.
func (f *futureResponse) resolve(t *kernel.Task) (*Response, error) {
	// If there is no Task associated with this request  - then we don't try to resolve
	// the response.  Instead, the task writing the response (proxy to the server) will
	// process the response on our behalf.
	if t == nil {
		log.Infof("fuse.Response.resolve: Not waiting on a response from server.")
		return nil, nil
	}

	if err := t.Block(f.ch); err != nil {
		return nil, err
	}

	return f.getResponse(), nil
}

// getResponse creates a Response from the data the futureResponse has.
func (f *futureResponse) getResponse() *Response {
	return &Response{
		opcode: f.opcode,
		hdr:    *f.hdr,
		data:   f.data,
	}
}
