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
	"fmt"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
)

// TODO: configure this properly.
const MaxInFlightRequests = 1000

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

// FutureResponse represents an in-flight request, that may or may not have
// completed yet. Convert it to a resolved Response by calling Resolve, but note
// that this may block.
//
// +stateify savable
type FutureResponse struct {
	ch   chan struct{}
	hdr  *linux.FUSEHeaderOut
	data []byte
}

// Connection is the struct by which the sentry communicates with the FUSE server daemon.
type Connection struct {
	fd *DeviceFD

	// MaxRead size in bytes
	MaxRead uint32

	// MaxWrite size in bytes
	MaxWrite uint32

	// MaxPages is the maximum number of pages for a single request to use
	MaxPages uint16

	// MaxBackground is the maximum number of outstanding background requests
	MaxBackground uint16

	// CongestionThreshold for number of background requests
	CongestionThreshold uint16

	// NumberBackground requests currently
	NumBackground uint16

	// ActiveBackground requests number currently queued for userspace
	ActiveBackground uint16

	// TODO: BgQuque
	// some queue for background queued requests

	// BgLock protects:
	// MaxBackground, CongestionThreshold, NumBackground,
	// ActiveBackground, BgQueue, Blocked
	BgLock sync.Mutex

	// Initialized if INIT reply has been received.
	// Until it's set, FUSE request allocation will be suspended
	Initialized bool

	// Blocked when:
	// before the INIT reply is received,
	// and if there are too many outstading backgrounds requests
	Blocked bool

	// Connected if connection established.
	// Unset when umount, connection abort and device release
	Connected bool

	// Aborted via sysfs
	Aborted bool

	// ConnError if connection failed (version mismatch).
	// Only set in INIT,
	// before any other request,
	// never unset.
	// Cannot race with other flags.
	ConnError bool

	// ConnInit if connection successful.
	// Only set in INIT.
	ConnInit bool

	// AsyncRead if read pages asynchronously.
	// Only set in INIT.
	AsyncRead bool

	// AbortErr is true when FUSE will return an unique read error after abort.
	// Only set in INIT.
	AbortErr bool

	// AtomicOTrunc is true when FUSE does not send a separate SETATTR request
	// before open with O_TRUNC flag.
	AtomicOTrunc bool

	// ExportSupport is true if Filesystem supports NFS exporting.
	// Only set in INIT.
	ExportSupport bool

	// WritebackCache is true if using write-back cache policy,
	// false if using write-through policy>
	WritebackCache bool

	// ParallelDirops is true if allowing lookup and readdir in parallel,
	// false if serialized.
	ParallelDirops bool

	// HandleKillpriv if fs handls killing suid/sgid/cap on write/chown/trunc.
	HandleKillpriv bool

	// CacheSymlinks if cache READLINK responses in page cache.
	CacheSymlinks bool

	/* Setting races on the following optimization-purpose flags are safe */

	// NoOpen if open/release not implemented by fs
	NoOpen bool

	// NoOpendir if opendir/releasedir not implemented by fs
	NoOpendir bool

	// NoFsync if fsync not implemented by fs
	NoFsync bool

	// NoFsyncdir if fsyncdir not implemented by fs
	NoFsyncdir bool

	// NoFlush if flush not implemented by fs
	NoFlush bool

	// NoSetxattr if setxattr not implemented by fs
	NoSetxattr bool

	// NoGetxattr if getxattr not implemented by fs
	NoGetxattr bool

	// NoListxattr if listxattr not implemented by fs
	NoListxattr bool

	// NoRemovexattr if removexattr not implemented by fs
	NoRemovexattr bool

	// NoLock if posix file locking primitives not implemented by fs
	NoLock bool

	// NoAccess if access not implemented by fs
	NoAccess bool

	// NoCreate if create not implemented by fs
	NoCreate bool

	// NoInterrupt if interrupt not implemented by fs
	NoInterrupt bool

	// NoBmap if bmap not implemented by fs
	NoBmap bool

	// NoPoll if poll not implemented by fs
	NoPoll bool

	// BigWrites if doing multi-page cached writes
	BigWrites bool

	// DontMask don't apply umask to creation modes
	DontMask bool

	// NoFLock if BSD file locking primitives not implemented by fs
	NoFLock bool

	// NoFallocate if fallocate not implemented by fs
	NoFallocate bool

	// NoRename2 if rename with flags not implemented by fs
	NoRename2 bool

	// AutoInvalData use enhanced/automatic page cache invalidation.
	AutoInvalData bool

	// ExplicitInvalData Filesystem is fully reponsible for page cache invalidation.
	ExplicitInvalData bool

	// DoReaddirplus if the filesystem supports readdirplus
	DoReaddirplus bool

	// ReaddirplusAuto if the filesystem wants adaptive readdirplus
	ReaddirplusAuto bool

	// AsyncDio if the filesystem supports asynchronous direct-IO submission
	AsyncDio bool

	// NoLseek if lseek() not implemented by fs
	NoLseek bool

	// PosixAcl if the filesystem supports posix acls
	PosixAcl bool

	// DefaultPermissions if to check permissions based on the file mode
	DefaultPermissions bool

	// AllowOther user who is not the mounter to access the filesystem
	AllowOther bool

	// NoCopyFileRange if the filesystem not supports copy_file_range
	NoCopyFileRange bool

	// Destroy request will be sent
	Destroy bool

	// DeleteStable dentries
	DeleteStable bool

	// NoControl if not create entry in fusectl fs
	NonControl bool

	// NoForceUmount if not allow MNT_FORCE umount
	NoForceUmount bool

	// NoMountOptions if not show mount options
	NoMountOptions bool

	// NumWating requests waiting for completion
	NumWaiting uint32

	// Minor version negotiated
	Minor uint32
}

// NewFUSEConnection creates a FUSE connection to fd
func NewFUSEConnection(ctx context.Context, fd *vfs.FileDescription) *Connection {
	conn := &Connection{}

	// Mark the device as ready so it can be used. /dev/fuse can only be used if the FD was used to
	// mount a FUSE filesystem.
	conn.fd = fd.Impl().(*DeviceFD)
	conn.fd.mounted = true

	// Create the writeBuf for the header to be stored in.
	hdrLen := uint32((*linux.FUSEHeaderOut)(nil).SizeBytes())
	conn.fd.writeBuf = make([]byte, hdrLen)
	conn.fd.completions = make(map[linux.FUSEOpID]*FutureResponse)
	conn.fd.waitCh = make(chan struct{}, MaxInFlightRequests)
	conn.fd.writeCursor = 0
	conn.fd.readCursor = 0

	// initialize other member fields

	atomic.StoreUint32(&conn.NumWaiting, 0)

	conn.MaxBackground = FUSE_DEFAULT_MAX_BACKGROUND
	conn.CongestionThreshold = FUSE_DEFAULT_CONGESTION_THRESHOLD

	conn.Blocked = false
	conn.Initialized = false
	conn.Connected = true

	conn.MaxPages = FUSE_DEFAULT_MAX_PAGES_PER_REQ

	return conn
}

// NewRequest creates a new request that can be sent to the FUSE server.
func (conn *Connection) NewRequest(creds *auth.Credentials, pid uint32, ino uint64, opcode linux.FUSEOpcode, payload marshal.Marshallable) (*Request, error) {
	conn.fd.mu.Lock()
	defer conn.fd.mu.Unlock()

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
	conn.fd.nextOpID++

	buf := make([]byte, hdr.Len)
	hdr.MarshalUnsafe(buf[:hdrLen])
	payload.MarshalUnsafe(buf[hdrLen:])

	return &Request{
		id:   hdr.Unique,
		hdr:  &hdr,
		data: buf,
	}, nil
}

// Call makes a request to the server and blocks until a server responds with a response.
func (conn *Connection) Call(t *kernel.Task, r *Request) (*Response, error) {
	fut, err := conn.CallFuture(t, r)
	if err != nil {
		return nil, err
	}

	return fut.Resolve(t)
}

// CallFuture makes a request to the server and returns a future response. Call Resolve()
// when the response needs to be fulfilled.
func (conn *Connection) CallFuture(t *kernel.Task, r *Request) (*FutureResponse, error) {
	conn.fd.mu.Lock()
	defer conn.fd.mu.Unlock()

	// Signal readers that a request is ready. This might block if
	// the number of in flight requests exceed MaxInFlightRequests.
	conn.fd.waitCh <- struct{}{}

	// After signalling readers, we insert the request in the queue
	// before releasing the lock and allowing them to read it.
	conn.fd.queue.PushBack(r)
	fut := newFutureResponse()
	conn.fd.completions[r.id] = fut

	return fut, nil
}

// newFutureResponse creates a future response to a FUSE request.
func newFutureResponse() *FutureResponse {
	return &FutureResponse{
		ch: make(chan struct{}),
	}
}

// Resolve blocks until the server responds to its corresponding request, then
// returns a resolved response.
func (r *FutureResponse) Resolve(t *kernel.Task) (*Response, error) {
	// TODO: Consider blocking with a timeout.
	if err := t.Block(r.ch); err != nil {
		return nil, err
	}

	return &Response{
		hdr:  *r.hdr,
		data: r.data,
	}, nil
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
	// TODO: Map r.hdr.Error to some error in the syserror package.
	return nil
}

func (r *Response) UnmarshalPayload(m marshal.Marshallable) error {
	hdrLen := r.hdr.SizeBytes()
	haveDataLen := r.hdr.Len - uint32(hdrLen)
	wantDataLen := uint32(m.SizeBytes())

	if haveDataLen < wantDataLen {
		return fmt.Errorf("payload too small. Wanted data lenth %d, have data length %d", wantDataLen, haveDataLen)
	}

	m.UnmarshalUnsafe(r.data[hdrLen:])
	return nil
}
