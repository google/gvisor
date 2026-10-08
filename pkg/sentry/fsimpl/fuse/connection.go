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

// fuseConn abstracts the FUSE request/response transport. The connection
// struct delegates call dispatch to its fuseConn implementation.
type fuseConn interface {
	call(ctx context.Context, r *Request) (*Response, error)
	release(ctx context.Context)

	// interrupt notifies the FUSE server that the task waiting on fut has
	// been interrupted by a signal, by sending it a FUSE_INTERRUPT request
	// (immediately if the original request has already been sent, or as
	// soon as it is sent otherwise).
	//
	// Preconditions: conn.mu must be unlocked.
	interrupt(fut *futureResponse)
}

// deviceConn implements fuseConn for the in-sandbox /dev/fuse path.
// It uses the queue-based mechanism where the FUSE daemon reads requests
// from and writes responses to the DeviceFD.
type deviceConn struct {
	conn *connection
}

func (dc *deviceConn) call(ctx context.Context, r *Request) (*Response, error) {
	fut, err := dc.conn.callFuture(ctx, r)
	if err != nil {
		return nil, err
	}
	if fut.async {
		return nil, nil
	}
	return dc.conn.waitForResponse(ctx, r, fut)
}

func (dc *deviceConn) release(ctx context.Context) {}

// interrupt implements fuseConn.interrupt.
func (dc *deviceConn) interrupt(fut *futureResponse) {
	conn := dc.conn
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.markInterruptedLocked(fut) && fut.sent {
		conn.queueInterruptLocked(fut)
	}
	// Otherwise, if the request hasn't been sent yet, conn.read() will queue
	// the interrupt after the request has been transferred to the server.
}

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

	// fuseConn is the transport implementation. For the DeviceFD path this
	// is a *deviceConn; for host passthrough this is a *hostConnection.
	fuseConn fuseConn `state:"nosave"`

	// hostTransport is true if fuseConn is a *hostConnection, i.e. the FUSE
	// server is outside the sandbox. Unlike fuseConn, it is saved, so that
	// restore can tell that the connection to the server has been lost:
	// the host FD isn't carried across checkpoint/restore, and requests that
	// were in flight on it can never be answered.
	//
	// Immutable after mount.
	hostTransport bool

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
	// Use setInitialized() and isInitialized() for atomic access.
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

	// interrupts is the list of FUSE_INTERRUPT requests that need to be
	// processed by the FUSE server. As in Linux, interrupts take precedence
	// over the requests in queue.
	//
	// +checklocks:mu
	interrupts requestList

	// noInterrupt is set if the FUSE server replied to a FUSE_INTERRUPT
	// request with ENOSYS, indicating that it doesn't support interrupts. No
	// further FUSE_INTERRUPT requests are sent once it is set.
	//
	// +checklocks:mu
	noInterrupt bool

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

	// noAccess records an ENOSYS reply to FUSE_ACCESS. Permission checks on
	// different inodes access this connection-wide capability concurrently.
	noAccess atomicbitops.Bool

	// noOpen if FUSE server doesn't support open operation.
	// This flag only influences performance, not correctness of the program.
	noOpen bool

	// noCreate if FUSE server doesn't support the create operation. Files are
	// then created with FUSE_MKNOD followed by FUSE_OPEN, as Linux does.
	noCreate bool
}

func linuxError(err error) error {
	if err == nil {
		return nil
	}
	// The error may contain arbitrary errno values that can't be converted.
	switch e := err.(type) {
	case unix.Errno:
		if syserr.IsValid(e) {
			return linuxerr.ErrorFromUnix(e)
		}
	default:
		// FUSE requests are only abandoned with ErrInterrupted when the task
		// must enter a stop (e.g. for checkpointing), in which case the syscall
		// should be restarted once the stop ends (see
		// connection.waitForResponse). Most VFS syscalls don't convert
		// ErrInterrupted themselves (it would otherwise reach userspace as
		// EINTR), so request a restart here. Syscalls that can't be restarted
		// (close(2), for forced FUSE_FLUSH requests) must handle ERESTARTSYS
		// themselves.
		return linuxerr.ConvertIntr(err, linuxerr.ERESTARTSYS)
	}
	log.Warningf("fusefs: failed with invalid error: %v", err)
	return linuxerr.EINVAL
}

// blockKillable blocks until ch is ready. If ctx is a task, only fatal
// signals and stops (e.g. for checkpointing) interrupt the wait, as in Linux
// where tasks waiting to send FUSE requests are only killable.
func blockKillable(ctx context.Context, ch <-chan struct{}) error {
	if t := kernel.TaskFromContext(ctx); t != nil {
		return t.BlockKillable(ch)
	}
	return ctx.Block(ch)
}

// setInitializedLocked atomically sets the connection as initialized.
//
// +checklocks:conn.mu
func (conn *connection) setInitializedLocked() {
	if conn.initialized.Load() != 0 {
		return
	}

	// Unblock the requests sent before INIT.
	close(conn.initializedChan)

	// Close the channel first to avoid the non-atomic situation
	// where conn.initialized is true but there are
	// tasks being blocked on the channel.
	// And it prevents the newer tasks from gaining
	// unnecessary higher chance to be issued before the blocked one.

	conn.initialized.Store(1)
}

// setInitialized atomically sets the connection as initialized.
func (conn *connection) setInitialized() {
	if conn.isInitialized() {
		return
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.setInitializedLocked()
}

// isInitialized atomically check if the connection is initialized.
func (conn *connection) isInitialized() bool {
	return conn.initialized.Load() != 0
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

	return newFUSEConnectionOpts(opts)
}

// newFUSEConnectionOpts creates a FUSE connection with the given options.
// This is used by both the DeviceFD path and the host FD passthrough path.
func newFUSEConnectionOpts(opts *filesystemOptions) (*connection, error) {
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
	conn.fuseConn = &deviceConn{conn: conn}
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
	if !conn.isInitialized() && r.hdr.Opcode != linux.FUSE_INIT {
		if err := blockKillable(ctx, conn.initializedChan); err != nil {
			return nil, linuxError(err)
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

	res, err := conn.fuseConn.call(ctx, r)
	return res, linuxError(err)
}

// callFuture makes a request to the server and returns a future response.
// Call resolve() when the response needs to be fulfilled.
func (conn *connection) callFuture(ctx context.Context, r *Request) (*futureResponse, error) {
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
	//
	// As in Linux, forced requests (e.g. FUSE_FLUSH and FUSE_RELEASE, which
	// must reach the server even if the calling task is killed) aren't
	// subject to this limit.
	for !r.force && conn.numActiveRequests >= conn.maxActiveRequests {
		log.Infof("Blocking request %v from being queued. Too many active requests: %v",
			r.id, conn.numActiveRequests)
		conn.mu.Unlock()
		err := blockKillable(ctx, conn.fullQueueCh)
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

// waitForResponse waits for the server's reply to the synchronous request r.
// As in Linux (fs/fuse/dev.c:request_wait_answer()), a signal causes a
// FUSE_INTERRUPT request to be sent once r has been read by the server, after
// which only fatal signals end the wait. A fatal signal before r is read
// dequeues it.
//
// Unlike Linux, the wait also ends if:
//
//   - The task is killed after r was read. Waiting could hang task exit
//     forever, since the server may be dead. The reply is discarded.
//
//   - The task must enter a stop (e.g. for checkpointing), which requires
//     returning from the syscall. ErrInterrupted is returned, so that the
//     syscall is restarted (see linuxError). If r was read, a FUSE_INTERRUPT
//     request is sent and r is forgotten (the server's reply to it fails with
//     ENOENT); the restarted syscall resends it. If
//     the server doesn't honor the interrupt, the operation is executed twice,
//     which may cause spurious errors (e.g. EEXIST from mkdir(2)) or
//     duplicated effects for non-idempotent operations.
func (conn *connection) waitForResponse(ctx context.Context, r *Request, fut *futureResponse) (*Response, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		// Not running on a task goroutine, so there are no signals to handle;
		// treat an interruption like a stop.
		if err := ctx.Block(fut.ch); err != nil {
			conn.fuseConn.interrupt(fut)
			return conn.abandonRequest(r, fut, false /* killed */, err)
		}
		return fut.getResponse(), nil
	}

	err := t.Block(fut.ch)
	if err == nil {
		return fut.getResponse(), nil
	}

	// Interrupted by a signal or a stop: notify the server.
	conn.fuseConn.interrupt(fut)

	killed := t.Killed()
	if !killed && !t.StopRequested() {
		// Interrupted by a non-fatal signal. Only fatal signals (or stops) may
		// interrupt the wait from now on.
		if err = t.BlockKillable(fut.ch); err == nil {
			return fut.getResponse(), nil
		}
		killed = t.Killed()
	}
	if killed {
		err = linuxerr.EINTR
	}
	return conn.abandonRequest(r, fut, killed, err)
}

// abandonRequest is called when the task waiting on fut stops waiting for the
// response to r before receiving it, because it was killed or must enter a
// stop. If the response arrived in the meantime, it is returned. Otherwise,
// err is returned, and r is disposed of as described by waitForResponse.
func (conn *connection) abandonRequest(r *Request, fut *futureResponse, killed bool, err error) (*Response, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.completions[fut.unique] != fut {
		// The request has completed (or the connection has been aborted).
		return fut.getResponse(), nil
	}
	switch {
	case !fut.sent && !r.force:
		// The server hasn't seen the request; drop it.
		conn.queue.Remove(r)
		conn.releaseLocked(fut)
	case killed || r.force:
		// Leave the request outstanding. Forced requests (FUSE_FLUSH) must
		// reach the server, and their syscalls (close(2)) aren't restarted.
		// The eventual reply is discarded.
	default:
		// Stop with the request already in the server's hands. The
		// restarted syscall will send a new request.
		conn.releaseLocked(fut)
	}
	return nil, err
}

// releaseLocked forgets the outstanding request whose future response is
// fut, releasing its active request slot. Any reply subsequently sent by the
// server for it is rejected with ENOENT, as in Linux. A FUSE_INTERRUPT
// request that is already queued for it is still sent.
//
// +checklocks:conn.mu
func (conn *connection) releaseLocked(fut *futureResponse) {
	delete(conn.completions, fut.unique)
	fut.intrReq = nil
	conn.numActiveRequests--
	select {
	case conn.fullQueueCh <- struct{}{}:
	default:
	}
}

// markInterruptedLocked marks the request whose future response is fut as
// interrupted, and returns true if the server should be sent a
// FUSE_INTERRUPT request for it.
//
// +checklocks:conn.mu
func (conn *connection) markInterruptedLocked(fut *futureResponse) bool {
	if conn.noInterrupt || conn.completions[fut.unique] != fut {
		// Either the server doesn't support interrupts, or the request has
		// already been answered.
		return false
	}
	fut.interrupted = true
	return true
}

// queueInterruptLocked queues a FUSE_INTERRUPT request for fut, if one isn't
// already queued.
//
// Preconditions: fut has been sent to the server and has not been answered.
//
// +checklocks:conn.mu
func (conn *connection) queueInterruptLocked(fut *futureResponse) {
	if conn.noInterrupt || fut.intrReq != nil {
		return
	}
	fut.intrReq = newInterruptRequest(fut.unique)
	conn.interrupts.PushBack(fut.intrReq)
	conn.waitQueue.Notify(waiter.ReadableEvents)
}

// handleInterruptReplyLocked processes the FUSE server's reply to a
// FUSE_INTERRUPT request, as in Linux's fs/fuse/dev.c:fuse_dev_do_write().
// size is the total size of the reply.
//
// If the server replied with EAGAIN, the future response of the interrupted
// request is returned and the caller must re-send the FUSE_INTERRUPT request.
//
// +checklocks:conn.mu
func (conn *connection) handleInterruptReplyLocked(hdr *linux.FUSEHeaderOut, size int64) (*futureResponse, error) {
	fut, ok := conn.completions[hdr.Unique&^linux.FUSE_INT_REQ_BIT]
	if !ok || !fut.sent {
		return nil, linuxerr.ENOENT
	}
	if size != int64(linux.SizeOfFUSEHeaderOut) {
		return nil, linuxerr.EINVAL
	}
	switch hdr.Error {
	case -int32(unix.ENOSYS):
		conn.noInterrupt = true
	case -int32(unix.EAGAIN):
		if !fut.interrupted {
			return nil, linuxerr.EINVAL
		}
		return fut, nil
	}
	return nil, nil
}

// sendResponse sends a response to the waiting task (if any).
//
// +checklocks:conn.mu
func (conn *connection) sendResponse(ctx context.Context, fut *futureResponse) error {
	// Signal the task waiting on a response if any.
	defer close(fut.ch)

	// A pending FUSE_INTERRUPT request is moot now that the request has been
	// answered.
	if fut.intrReq != nil {
		conn.interrupts.Remove(fut.intrReq)
		fut.intrReq = nil
	}

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
	if !conn.queue.Empty() || !conn.interrupts.Empty() {
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
	negotiatedMinBuffSize := linux.SizeOfFUSEHeaderIn + linux.SizeOfFUSEWriteIn + conn.maxWrite
	if minBuffSize < negotiatedMinBuffSize {
		minBuffSize = negotiatedMinBuffSize
	}

	// If the read buffer is too small, error out.
	if dst.NumBytes() < int64(minBuffSize) {
		return 0, linuxerr.EINVAL
	}

	// Interrupts take precedence over other requests.
	if intr := conn.interrupts.Front(); intr != nil {
		n, err := dst.CopyOut(ctx, intr.data)
		if err != nil {
			return 0, err
		}
		if n != len(intr.data) {
			return 0, linuxerr.EIO
		}
		conn.interrupts.Remove(intr)
		if fut := conn.completions[intr.hdr.Unique&^linux.FUSE_INT_REQ_BIT]; fut != nil {
			fut.intrReq = nil
		}
		return int64(n), nil
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
	} else if fut, ok := conn.completions[req.hdr.Unique]; ok {
		fut.sent = true
		// If the waiting task was interrupted before the request was sent,
		// the server must now be notified.
		if fut.interrupted {
			conn.queueInterruptLocked(fut)
		}
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

	// Is this the reply to a FUSE_INTERRUPT request?
	if hdr.Unique&linux.FUSE_INT_REQ_BIT != 0 {
		fut, err := conn.handleInterruptReplyLocked(&hdr, src.NumBytes())
		if err != nil {
			return 0, err
		}
		if fut != nil {
			// The server asked us to re-send the interrupt.
			conn.queueInterruptLocked(fut)
		}
		return int64(n), nil
	}

	fut, ok := conn.completions[hdr.Unique]
	if !ok {
		// Server sent us a response for a request we never sent, or for which we
		// already received a reply, or which was abandoned (e.g. aborted). As in
		// Linux, return ENOENT, which FUSE servers expect in this case.
		return 0, linuxerr.ENOENT
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
