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
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
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
// Lock order:
// - conn.fd.mu
// - conn.mu
// - conn.asyncMu
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

	// protects the member fields.
	mu sync.Mutex

	// connected (connection established) when a new FUSE file system is created.
	// Set to false when:
	//   umount,
	//   connection abort,
	//   device release.
	connected bool

	// connInitError if FUSE_INIT encountered error (major version mismatch).
	// Only set in INIT.
	connInitError bool

	// connInitSuccess if FUSE_INIT is successful.
	// Only set in INIT.
	// Used for destory (not yet implemented).
	connInitSuccess bool

	// aborted via sysfs, and will send ECONNABORTED to read after disconnection (instead of ENODEV).
	// Set only if abortErr is true and via fuse control fs (not yet implemented).
	// TODO(gvisor.dev/issue/3525): set this to true when user aborts.
	aborted bool

	// numWating is the number of requests waiting to be
	// sent to FUSE device or being processed by FUSE daemon.
	numWaiting uint32

	// Terminology note:
	//
	// - `asyncNumMax` is the `MaxBackground` in the FUSE_INIT_IN struct.
	//
	// - `asyncCongestionThreshold` is the `CongestionThreshold` in the FUSE_INIT_IN struct.
	//
	// We call the "background" requests in unix term as async requests.
	// The "async requests" in unix term is our async requests that expect a reply,
	// i.e. `!requestOptions.noReply`

	// asyncMu protects the async request fields.
	asyncMu sync.Mutex

	// asyncNum is the number of async requests.
	// Protected by asyncMu.
	asyncNum uint16

	// asyncCongestionThreshold the number of async requests.
	// Negotiated in FUSE_INIT as "CongestionThreshold".
	// TODO(gvisor.dev/issue/3529): add congestion control.
	// Protected by asyncMu.
	asyncCongestionThreshold uint16

	// asyncNumMax is the maximum number of asyncNum.
	// Connection blocks the async requests when it is reached.
	// Negotiated in FUSE_INIT as "MaxBackground".
	// Protected by asyncMu.
	asyncNumMax uint16

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

	// abortErr is true if kernel need to return aborted error to read after abort.
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
		fd:                       fuseFD,
		asyncNumMax:              fuseDefaultMaxBackground,
		asyncCongestionThreshold: fuseDefaultCongestionThreshold,
		maxPages:                 fuseDefaultMaxPagesPerReq,
		initializedChan:          make(chan struct{}),
		connected:                true,
	}, nil
}

// Call makes a request to the server.
// Block before the connection is initialized.
// When the Request is FUSE_INIT, it will not be blocked before initialization.
// Task should never be bil.
//
// For a sync request, it blocks the invoking task until
// a server responds with a response.
//
// For an async request (that do not expect a response immediately),
// it return directly unless being blocked either before initialization
// or when there are too many async requests ongoing.
//
// Example for async request:
// init, readahead, write, async read/write, fuse_notify_reply, non-sync release, interrupt, forget.
//
// The forget request does not have a reply, as documented in include/uapi/linux/fuse.h:FUSE_FORGET.
func (conn *connection) Call(t *kernel.Task, r *Request) (*Response, error) {
	// Block requests sent before connection is initalized.
	if !conn.Initialized() && r.hdr.Opcode != linux.FUSE_INIT {
		if err := t.Block(conn.initializedChan); err != nil {
			return nil, err
		}
	}

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
	conn.fd.numActiveRequests++
	fut := newFutureResponse(r.hdr.Opcode, r.options)
	conn.fd.completions[r.id] = fut

	// Signal the readers that there is something to read.
	conn.fd.waitQueue.Notify(waiter.EventIn)

	return fut, nil
}
