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
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const fuseDevMinor = 229

// fuseDevice implements vfs.Device for /dev/fuse.
type fuseDevice struct{}

// Open implements vfs.Device.Open.
func (fuseDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	if !kernel.FUSEEnabled {
		return nil, syserror.ENOENT
	}

	var fd DeviceFD
	if err := fd.vfsfd.Init(&fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// DeviceFD implements vfs.FileDescriptionImpl for /dev/fuse.
type DeviceFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// mounted specifies whether a FUSE filesystem was mounted using the DeviceFD.
	mounted bool

	// nextOpID is used to create new requests.
	nextOpID linux.FUSEOpID

	// queue is the list of requests that need to be processed by the FUSE server.
	queue requestList

	// numActiveRequests is the number of requests made by the Sentry that has
	// yet to be responded to.
	numActiveRequests uint64

	// completions is used to map a request to its response. A Writer will use this
	// to notify the caller of a completed response.
	completions map[linux.FUSEOpID]*futureResponse

	writeCursor uint32

	// writeBuf is the memory buffer used to copy in the FUSE out header from
	// userspace.
	writeBuf []byte

	// writeCursorFR current FR being copied from server.
	writeCursorFR *futureResponse

	// mu protects all the queues, maps, buffers and cursors and nextOpID.
	mu sync.Mutex

	// waitQueue is used to notify interested parties when the device becomes
	// readable or writable.
	waitQueue waiter.Queue

	// fullQueueCh is a channel used to synchronize the readers with the writers.
	// Writers (inbound requests to the filesystem) block if there are too many
	// unprocessed in-flight requests.
	fullQueueCh chan struct{}

	// fs is the FUSE filesystem that this FD is being used for.
	fs *filesystem
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *DeviceFD) Release() {}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *DeviceFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	// Operations on /dev/fuse don't make sense until a FUSE filesystem is mounted.
	if !fd.mounted {
		return 0, syserror.EPERM
	}

	return 0, syserror.ENOSYS
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *DeviceFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	// Operations on /dev/fuse don't make sense until a FUSE filesystem is mounted.
	if !fd.mounted {
		return 0, syserror.EPERM
	}

	// We require that any Read done on this filesystem have a sane minimum
	// read buffer. It must have the capacity for the fixed parts of any request
	// header (Linux uses the request header and the FUSEWriteIn header for this
	// calculation) + the negotiated MaxWrite room for the data.
	minBuffSize := linux.FUSE_MIN_READ_BUFFER
	inHdrLen := uint32((*linux.FUSEHeaderIn)(nil).SizeBytes())
	writeHdrLen := uint32((*linux.FUSEWriteIn)(nil).SizeBytes())
	negotiatedMinBuffSize := inHdrLen + writeHdrLen + fd.fs.conn.MaxWrite
	if minBuffSize < negotiatedMinBuffSize {
		minBuffSize = negotiatedMinBuffSize
	}

	// If the read buffer is too small, error out.
	if dst.NumBytes() < int64(minBuffSize) {
		return 0, syserror.EINVAL
	}

	fd.mu.Lock()
	defer fd.mu.Unlock()
	return fd.readLocked(ctx, dst, opts)
}

// readLocked implements the reading of the fuse device while locked with DeviceFD.mu.
func (fd *DeviceFD) readLocked(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	if fd.queue.Empty() {
		return 0, syserror.ErrWouldBlock
	}

	var readCursor uint32
	var bytesRead int64
	for {
		req := fd.queue.Front()
		if dst.NumBytes() < int64(req.hdr.Len) {
			// The request is too large. Cannot process it. All requests must be smaller than the
			// negotiated size as specified by Connection.MaxWrite set as part of the FUSE_INIT
			// handshake.
			errno := -int32(syscall.EIO)
			if req.hdr.Opcode == linux.FUSE_SETXATTR {
				errno = -int32(syscall.E2BIG)
			}

			// Return the error to the calling task.
			if err := fd.sendError(ctx, errno, req); err != nil {
				return 0, err
			}

			// We're done with this request.
			fd.queue.Remove(req)

			// Restart the read as this request was invalid.
			log.Warningf("fuse.DeviceFD.Read: request found was too large. Restarting read.")
			return fd.readLocked(ctx, dst, opts)
		}

		n, err := dst.CopyOut(ctx, req.data[readCursor:])
		if err != nil {
			return 0, err
		}
		readCursor += uint32(n)
		bytesRead += int64(n)

		if readCursor >= req.hdr.Len {
			// Fully done with this req, remove it from the queue.
			fd.queue.Remove(req)
			break
		}
	}

	return bytesRead, nil
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *DeviceFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	// Operations on /dev/fuse don't make sense until a FUSE filesystem is mounted.
	if !fd.mounted {
		return 0, syserror.EPERM
	}

	return 0, syserror.ENOSYS
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *DeviceFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	return fd.writeLocked(ctx, src, opts)
}

// writeLocked implements writing to the fuse device while locked with DeviceFD.mu.
func (fd *DeviceFD) writeLocked(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	// Operations on /dev/fuse don't make sense until a FUSE filesystem is mounted.
	if !fd.mounted {
		return 0, syserror.EPERM
	}

	var cn, n int64
	hdrLen := uint32((*linux.FUSEHeaderOut)(nil).SizeBytes())

	for src.NumBytes() > 0 {
		if fd.writeCursorFR != nil {
			// Already have common header, and we're now copying the payload.
			wantBytes := fd.writeCursorFR.hdr.Len

			// Note that the FR data doesn't have the header. Copy it over if its necessary.
			if fd.writeCursorFR.data == nil {
				fd.writeCursorFR.data = make([]byte, wantBytes)
			}

			bytesCopied, err := src.CopyIn(ctx, fd.writeCursorFR.data[fd.writeCursor:wantBytes])
			if err != nil {
				return 0, err
			}
			src = src.DropFirst(bytesCopied)

			cn = int64(bytesCopied)
			n += cn
			fd.writeCursor += uint32(cn)
			if fd.writeCursor == wantBytes {
				// Done reading this full response. Clean up and unblock the
				// initiator.
				break
			}

			// Check if we have more data in src.
			continue
		}

		// Assert that the header isn't read into the writeBuf yet.
		if fd.writeCursor >= hdrLen {
			return 0, syserror.EINVAL
		}

		// We don't have the full common response header yet.
		wantBytes := hdrLen - fd.writeCursor
		bytesCopied, err := src.CopyIn(ctx, fd.writeBuf[fd.writeCursor:wantBytes])
		if err != nil {
			return 0, err
		}
		src = src.DropFirst(bytesCopied)

		cn = int64(bytesCopied)
		n += cn
		fd.writeCursor += uint32(cn)
		if fd.writeCursor == hdrLen {
			// Have full header in the writeBuf. Use it to fetch the actual futureResponse
			// from the device's completions map.
			var hdr linux.FUSEHeaderOut
			hdr.UnmarshalBytes(fd.writeBuf)

			// We have the header now and so the writeBuf has served its purpose.
			// We could reset it manually here but instead of doing that, at the
			// end of the write, the writeCursor will be set to 0 thereby allowing
			// the next request to overwrite whats in the buffer,

			fut, ok := fd.completions[hdr.Unique]
			if !ok {
				// Server sent us a response for a request we never sent?
				return 0, syserror.EINVAL
			}

			delete(fd.completions, hdr.Unique)

			// Copy over the header into the future response. The rest of the payload
			// will be copied over to the FR's data in the next iteration.
			fut.hdr = &hdr
			fd.writeCursorFR = fut

			// Next iteration will now try read the complete request, if src has
			// any data remaining. Otherwise we're done.
		}
	}

	if fd.writeCursorFR != nil {
		if err := fd.sendResponse(ctx, fd.writeCursorFR); err != nil {
			return 0, err
		}

		// Ready the device for the next request.
		fd.writeCursorFR = nil
		fd.writeCursor = 0
	}

	return n, nil
}

// Readiness implements vfs.FileDescriptionImpl.Readiness.
func (fd *DeviceFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	var ready waiter.EventMask
	ready |= waiter.EventOut // FD is always writable
	if !fd.queue.Empty() {
		// Have reqs available, FD is readable.
		ready |= waiter.EventIn
	}

	return ready & mask
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *DeviceFD) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	fd.waitQueue.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *DeviceFD) EventUnregister(e *waiter.Entry) {
	fd.waitQueue.EventUnregister(e)
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *DeviceFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	// Operations on /dev/fuse don't make sense until a FUSE filesystem is mounted.
	if !fd.mounted {
		return 0, syserror.EPERM
	}

	return 0, syserror.ENOSYS
}

// sendResponse sends a response to the waiting task (if any).
func (fd *DeviceFD) sendResponse(ctx context.Context, fut *futureResponse) error {
	// See if the running task need to perform some action before returning.
	// Since we just finished writing the future, we can be sure that
	// getResponse generates a populated response.
	if err := fd.noReceiverAction(ctx, fut.getResponse()); err != nil {
		return err
	}

	// Signal that the queue is no longer full.
	select {
	case fd.fullQueueCh <- struct{}{}:
	default:
	}
	fd.numActiveRequests -= 1

	// Signal the task waiting on a response.
	close(fut.ch)
	return nil
}

// sendError sends an error response to the waiting task (if any).
func (fd *DeviceFD) sendError(ctx context.Context, errno int32, req *Request) error {
	// Return the error to the calling task.
	outHdrLen := uint32((*linux.FUSEHeaderOut)(nil).SizeBytes())
	respHdr := linux.FUSEHeaderOut{
		Len:    outHdrLen,
		Error:  errno,
		Unique: req.hdr.Unique,
	}

	fut, ok := fd.completions[respHdr.Unique]
	if !ok {
		// Server sent us a response for a request we never sent?
		return syserror.EINVAL
	}
	delete(fd.completions, respHdr.Unique)

	fut.hdr = &respHdr
	if err := fd.sendResponse(ctx, fut); err != nil {
		return err
	}

	return nil
}

// noReceiverAction has the calling kernel.Task do some action if its known that no
// receiver is going to be waiting on the future channel. This is to be used by:
// FUSE_INIT.
func (fd *DeviceFD) noReceiverAction(ctx context.Context, r *Response) error {
	if r.opcode == linux.FUSE_INIT {
		// TODO: process init response here.
		// Maybe get the creds from the context?
		// creds := auth.CredentialsFromContext(ctx)
	}

	return nil
}
