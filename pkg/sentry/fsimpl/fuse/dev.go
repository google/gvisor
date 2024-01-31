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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const fuseDevMinor = 229

// This is equivalent to linux.SizeOfFUSEHeaderIn
const fuseHeaderOutSize = 16

// fuseDevice implements vfs.Device for /dev/fuse.
//
// +stateify savable
type fuseDevice struct{}

// Open implements vfs.Device.Open.
func (fuseDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	var fd DeviceFD
	if err := fd.vfsfd.Init(&fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// DeviceFD implements vfs.FileDescriptionImpl for /dev/fuse.
//
// +stateify savable
type DeviceFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// waitQueue is used to notify interested parties when the device becomes
	// readable or writable.
	waitQueue waiter.Queue

	// fullQueueCh is a channel used to synchronize the readers with the writers.
	// Writers (inbound requests to the filesystem) block if there are too many
	// unprocessed in-flight requests.
	fullQueueCh chan struct{} `state:".(int)"`

	// mu protects all the queues, maps, buffers and cursors and nextOpID.
	mu sync.Mutex `state:"nosave"`

	// nextOpID is used to create new requests.
	// +checklocks:mu
	nextOpID linux.FUSEOpID

	// queue is the list of requests that need to be processed by the FUSE server.
	// +checklocks:mu
	queue requestList

	// numActiveRequests is the number of requests made by the Sentry that has
	// yet to be responded to.
	// +checklocks:mu
	numActiveRequests uint64

	// completions is used to map a request to its response. A Writer will use this
	// to notify the caller of a completed response.
	// +checklocks:mu
	completions map[linux.FUSEOpID]*futureResponse

	// writeBuf is the memory buffer used to copy in the FUSE out header from
	// userspace.
	// +checklocks:mu
	writeBuf [fuseHeaderOutSize]byte

	// conn is the FUSE connection that this FD is being used for.
	// +checklocks:mu
	conn *connection
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *DeviceFD) Release(ctx context.Context) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if fd.conn != nil {
		fd.conn.mu.Lock()
		fd.conn.connected = false
		fd.conn.mu.Unlock()

		fd.conn.Abort(ctx) // +checklocksforce: fd.conn.fd.mu=fd.mu
		fd.waitQueue.Notify(waiter.ReadableEvents)
		fd.conn = nil
	}
}

// connected returns true if fd.conn is set and the connection has not been
// aborted.
// +checklocks:fd.mu
func (fd *DeviceFD) connected() bool {
	if fd.conn != nil {
		fd.conn.mu.Lock()
		defer fd.conn.mu.Unlock()
		return fd.conn.connected
	}
	return false
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *DeviceFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	// Operations on /dev/fuse don't make sense until a FUSE filesystem is
	// mounted. If there is an active connection we know there is at least one
	// filesystem mounted.
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.connected() {
		return 0, linuxerr.EPERM
	}

	return 0, linuxerr.ENOSYS
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *DeviceFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.connected() {
		return 0, linuxerr.EPERM
	}
	// We require that any Read done on this filesystem have a sane minimum
	// read buffer. It must have the capacity for the fixed parts of any request
	// header (Linux uses the request header and the FUSEWriteIn header for this
	// calculation) + the negotiated MaxWrite room for the data.
	minBuffSize := linux.FUSE_MIN_READ_BUFFER
	fd.conn.mu.Lock()
	negotiatedMinBuffSize := linux.SizeOfFUSEHeaderIn + linux.SizeOfFUSEHeaderOut + fd.conn.maxWrite
	fd.conn.mu.Unlock()
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
	for req = fd.queue.Front(); !fd.queue.Empty(); req = fd.queue.Front() {
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

		if err := fd.sendError(ctx, errno, req.hdr.Unique); err != nil {
			return 0, err
		}
		fd.queue.Remove(req)
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
	fd.queue.Remove(req)
	// Remove noReply ones from the map of requests expecting a reply.
	if req.noReply {
		fd.numActiveRequests--
		delete(fd.completions, req.hdr.Unique)
	}
	return int64(n), nil
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *DeviceFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	// Operations on /dev/fuse don't make sense until a FUSE filesystem is
	// mounted. If there is an active connection we know there is at least one
	// filesystem mounted.
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.connected() {
		return 0, linuxerr.EPERM
	}

	return 0, linuxerr.ENOSYS
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *DeviceFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.connected() {
		return 0, linuxerr.EPERM
	}

	n, err := src.CopyIn(ctx, fd.writeBuf[:])
	if err != nil {
		return 0, err
	}
	var hdr linux.FUSEHeaderOut
	hdr.UnmarshalBytes(fd.writeBuf[:])

	fut, ok := fd.completions[hdr.Unique]
	if !ok {
		// Server sent us a response for a request we never sent, or for which we
		// already received a reply (e.g. aborted), an unlikely event.
		return 0, linuxerr.EINVAL
	}
	delete(fd.completions, hdr.Unique)

	// Copy over the header into the future response. The rest of the payload
	// will be copied over to the FR's data in the next iteration.
	fut.hdr = &hdr
	fut.data = make([]byte, fut.hdr.Len)
	copy(fut.data, fd.writeBuf[:])
	if fut.hdr.Len > uint32(len(fd.writeBuf)) {
		src = src.DropFirst(len(fd.writeBuf))
		n2, err := src.CopyIn(ctx, fut.data[len(fd.writeBuf):])
		if err != nil {
			return 0, err
		}
		n += n2
	}
	if err := fd.sendResponse(ctx, fut); err != nil {
		return 0, err
	}
	return int64(n), nil
}

// Readiness implements vfs.FileDescriptionImpl.Readiness.
func (fd *DeviceFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	var ready waiter.EventMask

	if !fd.connected() {
		ready |= waiter.EventErr
		return ready & mask
	}

	// FD is always writable.
	ready |= waiter.WritableEvents
	if !fd.queue.Empty() {
		// Have reqs available, FD is readable.
		ready |= waiter.ReadableEvents
	}

	return ready & mask
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *DeviceFD) EventRegister(e *waiter.Entry) error {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	fd.waitQueue.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *DeviceFD) EventUnregister(e *waiter.Entry) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	fd.waitQueue.EventUnregister(e)
}

// Epollable implements FileDescriptionImpl.Epollable.
func (fd *DeviceFD) Epollable() bool {
	return true
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *DeviceFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	// Operations on /dev/fuse don't make sense until a FUSE filesystem is
	// mounted. If there is an active connection we know there is at least one
	// filesystem mounted.
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.connected() {
		return 0, linuxerr.EPERM
	}

	return 0, linuxerr.ENOSYS
}

// sendResponse sends a response to the waiting task (if any).
//
// +checklocks:fd.mu
func (fd *DeviceFD) sendResponse(ctx context.Context, fut *futureResponse) error {
	// Signal the task waiting on a response if any.
	defer close(fut.ch)

	// Signal that the queue is no longer full.
	select {
	case fd.fullQueueCh <- struct{}{}:
	default:
	}
	fd.numActiveRequests--

	if fut.async {
		return fd.asyncCallBack(ctx, fut.getResponse())
	}

	return nil
}

// sendError sends an error response to the waiting task (if any) by calling sendResponse().
//
// +checklocks:fd.mu
func (fd *DeviceFD) sendError(ctx context.Context, errno int32, unique linux.FUSEOpID) error {
	// Return the error to the calling task.
	respHdr := linux.FUSEHeaderOut{
		Len:    linux.SizeOfFUSEHeaderOut,
		Error:  errno,
		Unique: unique,
	}

	fut, ok := fd.completions[respHdr.Unique]
	if !ok {
		// A response for a request we never sent,
		// or for which we already received a reply (e.g. aborted).
		return linuxerr.EINVAL
	}
	delete(fd.completions, respHdr.Unique)

	fut.hdr = &respHdr
	return fd.sendResponse(ctx, fut)
}

// asyncCallBack executes pre-defined callback function for async requests.
// Currently used by: FUSE_INIT.
// +checklocks:fd.mu
func (fd *DeviceFD) asyncCallBack(ctx context.Context, r *Response) error {
	switch r.opcode {
	case linux.FUSE_INIT:
		creds := auth.CredentialsFromContext(ctx)
		rootUserNs := kernel.KernelFromContext(ctx).RootUserNamespace()
		return fd.conn.InitRecv(r, creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, rootUserNs))
		// TODO(gvisor.dev/issue/3247): support async read: correctly process the response.
	}

	return nil
}
