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
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
)

const MaxInFlightRequestsDefault = 1000

var (
	// Ordinary requests have even IDs, while interrupts IDs are odd.
	InitReqBit uint64 = 1
	ReqIDStep  uint64 = 2
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

// futureResponse represents an in-flight request, that may or may not have
// completed yet. Convert it to a resolved Response by calling Resolve, but note
// that this may block.
//
// +stateify savable
type futureResponse struct {
	ch   chan struct{}
	hdr  *linux.FUSEHeaderOut
	data []byte
}

// Connection is the struct by which the sentry communicates with the FUSE server daemon.
type Connection struct {
	fd *DeviceFD

	// MaxInflightRequests specifies the maximum number of unread requests that can be
	// queued in the device at any time. Any further requests will block when trying to
	// Call the server.
	MaxInflightRequests uint64

	// Initialized after receiving FUSE_INIT reply.
	// Until it's set, suspend sending FUSE requests.
	Initialized bool

	// protects Initialized.
	initializedLock sync.Mutex

	// Blocked when:
	//   before the INIT reply is received (Initialized == false),
	//   if there are too many outstading backgrounds requests (NumBackground == MaxBackground).
	// TODO(gvisor.dev/issue/3185): use a channel to block.
	Blocked bool

	// Connected (connection established) when a new FUSE file system is created.
	// Set to false when:
	//   umount,
	//   connection abort,
	//   device release.
	Connected bool

	// Aborted via sysfs.
	Aborted bool

	// ConnInitError if FUSE_INIT encountered error (major version mismatch).
	// Only set in INIT.
	ConnInitError bool

	// ConnInitSuccess if FUSE_INIT is successful.
	// Only set in INIT.
	ConnInitSuccess bool

	// TODO(gvisor.dev/issue/3185): All the queue logic are working in progress.

	// NumberBackground is the number of requests in the background.
	NumBackground uint16

	// CongestionThreshold for NumBackground.
	// Negotiated in FUSE_INIT.
	CongestionThreshold uint16

	// MaxBackground is the maximum number of NumBackground.
	// Block connection when it is reached.
	// Negotiated in FUSE_INIT.
	MaxBackground uint16

	// NumActiveBackground is the number of requests in background and has being marked as active.
	NumActiveBackground uint16

	// NumWating is the number of requests waiting for completion.
	NumWaiting uint32

	// TODO(gvisor.dev/issue/3185): BgQueue
	// some queue for background queued requests.

	// BgLock protects:
	// MaxBackground, CongestionThreshold, NumBackground,
	// NumActiveBackground, BgQueue, Blocked.
	BgLock sync.Mutex

	// MaxRead is the maximum size of a read buffer in in bytes.
	MaxRead uint32

	// MaxWrite is the maximum size of a write buffer in bytes.
	// Negotiated in FUSE_INIT.
	MaxWrite uint32

	// MaxPages is the maximum number of pages for a single request to use.
	// Negotiated in FUSE_INIT.
	MaxPages uint16

	// Minor version of the FUSE protocol.
	// Negotiated and only set in INIT.
	Minor uint32

	// AsyncRead if read pages asynchronously.
	// Negotiated and only set in INIT.
	AsyncRead bool

	// AbortErr is true if kernel need to return an unique read error after abort.
	// Negotiated and only set in INIT.
	AbortErr bool

	// AtomicOTrunc is true when FUSE does not send a separate SETATTR request
	// before open with O_TRUNC flag.
	// Negotiated and only set in INIT.
	AtomicOTrunc bool

	// ExportSupport is true if the daemon filesystem supports NFS exporting.
	// Negotiated and only set in INIT.
	ExportSupport bool

	// WritebackCache is true for write-back cache policy,
	// false for write-through policy.
	// Negotiated and only set in INIT.
	WritebackCache bool

	// ParallelDirops is true if allowing lookup and readdir in parallel,
	// false if serialized.
	// Negotiated and only set in INIT.
	ParallelDirops bool

	// HandleKillpriv if the filesystem handles killing suid/sgid/cap on write/chown/trunc.
	// Negotiated and only set in INIT.
	HandleKillpriv bool

	// CacheSymlinks if filesystem needs to cache READLINK responses in page cache.
	// Negotiated and only set in INIT.
	CacheSymlinks bool

	// NoLock if posix file locking primitives not implemented.
	// Negotiated and only set in INIT.
	NoLock bool

	// BigWrites if doing multi-page cached writes.
	// Negotiated and only set in INIT.
	BigWrites bool

	// DontMask if filestestem does not apply umask to creation modes.
	// Negotiated in INIT.
	DontMask bool

	// NoFLock if BSD file locking primitives not implemented.
	// Negotiated and only set in INIT.
	NoFLock bool

	// AutoInvalData if filesystem uses enhanced/automatic page cache invalidation.
	// Negotiated and only set in INIT.
	AutoInvalData bool

	// ExplicitInvalData if filesystem is in charge of page cache invalidation.
	// Negotiated and only set in INIT.
	ExplicitInvalData bool

	// DoReaddirplus if the filesystem supports readdirplus.
	// Negotiated and only set in INIT.
	DoReaddirplus bool

	// ReaddirplusAuto if the filesystem wants adaptive readdirplus.
	// Negotiated and only set in INIT.
	ReaddirplusAuto bool

	// AsyncDio if the filesystem supports asynchronous direct-IO submission.
	// Negotiated and only set in INIT.
	AsyncDio bool

	// PosixACL if the filesystem supports posix ACL.
	// Negotiated and only set in INIT.
	PosixACL bool

	// DefaultPermissions if the filesystem needs to check permissions based on the file mode.
	// Negotiated in INIT.
	DefaultPermissions bool
}

// NewFUSEConnection creates a FUSE connection to fd
func NewFUSEConnection(_ context.Context, fd *vfs.FileDescription, maxInFlightRequests uint64) (*Connection, error) {
	// Mark the device as ready so it can be used. /dev/fuse can only be used if the FD was used to
	// mount a FUSE filesystem.
	fuseFD := fd.Impl().(*DeviceFD)
	fuseFD.mounted = true

	// Create the writeBuf for the header to be stored in.
	hdrLen := uint32((*linux.FUSEHeaderOut)(nil).SizeBytes())
	fuseFD.writeBuf = make([]byte, hdrLen)
	fuseFD.completions = make(map[linux.FUSEOpID]*futureResponse)
	fuseFD.requestKind = make(map[linux.FUSEOpID]linux.FUSEOpcode)
	fuseFD.emptyQueueCh = make(chan struct{}, maxInFlightRequests)
	fuseFD.fullQueueCh = make(chan struct{}, maxInFlightRequests)

	// This is emulating the behaviour of a counting semaphore. Is there a better
	// way to do this?
	for i := uint64(0); i < maxInFlightRequests; i++ {
		fuseFD.fullQueueCh <- struct{}{}
	}

	fuseFD.writeCursor = 0
	fuseFD.readCursor = 0

	return &Connection{
		fd:                  fuseFD,
		MaxInflightRequests: MaxInFlightRequestsDefault,
		MaxBackground:       fuseDefaultMaxBackground,
		CongestionThreshold: fuseDefaultCongestionThreshold,
		MaxPages:            fuseDefaultMaxPagesPerReq,
		Connected:           true,
	}, nil
}

// Atomically set the connection as initialized.
func (conn *Connection) setInitialized() {
	conn.initializedLock.Lock()
	defer conn.initializedLock.Unlock()

	conn.Initialized = true
}

// Atomically check if the connection is initialized.
// pairs with setInitialized().
func (conn *Connection) isInitialized() bool {
	conn.initializedLock.Lock()
	defer conn.initializedLock.Unlock()

	return conn.Initialized
}

// Marshallable defines the Marshallable interface for serialize/deserializing
// FUSE packets.
type Marshallable interface {
	MarshalUnsafe([]byte)
	SizeBytes() int
}

// NewRequest creates a new request that can be sent to the FUSE server.
func (conn *Connection) NewRequest(creds *auth.Credentials, pid uint32, ino uint64, opcode linux.FUSEOpcode, payload Marshallable) (*Request, error) {
	conn.fd.mu.Lock()
	defer conn.fd.mu.Unlock()
	conn.fd.nextOpID += linux.FUSEOpID(ReqIDStep)

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
// server responds with a response.
// NOTE: If no task is provided then the Call will simply enqueue the request
// and return a nil response. No blocking will happen in this case. Instead,
// this is used to signify that the processing of this request will happen by
// the kernel.Task that writes the response. See FUSE_INIT for such an
// invocation.
func (conn *Connection) Call(t *kernel.Task, r *Request) (*Response, error) {
	fut, err := conn.callFuture(t, r)
	if err != nil {
		return nil, err
	}

	return fut.resolve(t)
}

// callFuture makes a request to the server and returns a future response.
// Call resolve() when the response needs to be fulfilled.
func (conn *Connection) callFuture(t *kernel.Task, r *Request) (*futureResponse, error) {
	// Is the queue full?
	if conn.fd.numInFlightRequests == conn.fd.fs.opts.maxInflightRequests {
		// Can't add a new request into the queue until space is cleared up.
		if t == nil {
			// Since there is no task that is waiting. We must error out.
			return nil, errors.New("FUSE request queue full")
		}
	}

	// Consider possible starvation here if the queue is continuously full.
	// Will go channels respect FIFO order when unblocking threads?
	if err := t.Block(conn.fd.fullQueueCh); err != nil {
		log.Warningf("Connection.Call: couldn't wait on request queue: %v", err)
		return nil, syserror.EBUSY
	}

	conn.fd.mu.Lock()
	conn.fd.queue.PushBack(r)
	conn.fd.numInFlightRequests += 1
	fut := newFutureResponse()
	conn.fd.completions[r.id] = fut
	conn.fd.requestKind[r.id] = r.hdr.Opcode
	conn.fd.mu.Unlock()

	// Signal a reader notifying them about a queued request.
	select {
	case conn.fd.emptyQueueCh <- struct{}{}:
	default:
		log.Warningf("fuse.Connection: blocking when signalling the emptyQueueCh")
	}

	return fut, nil
}

// newFutureResponse creates a future response to a FUSE request.
func newFutureResponse() *futureResponse {
	return &futureResponse{
		ch: make(chan struct{}),
	}
}

// resolve blocks the task until the server responds to its corresponding request,
// then returns a resolved response.
func (f *futureResponse) resolve(t *kernel.Task) (*Response, error) {
	// If there is no Task associated with this request  - then we don't try to resolve
	// the response.  Instead, the task writing the response (proxy to the server) will
	// process the response on our behalf.
	if t == nil {
		log.Infof("fuse.Response: Not waiting on a response from server.")
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
		hdr:  *f.hdr,
		data: f.data,
	}
}

// Response represents an actual response from the server, including the
// response payload.
//
// +stateify savable
type Response struct {
	hdr  linux.FUSEHeaderOut
	data []byte
}

func (r *Response) Error() error {
	errno := r.hdr.Error
	if errno >= 0 {
		return nil
	}

	sysErrNo := syscall.Errno(-errno)
	return error(sysErrNo)
}

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
