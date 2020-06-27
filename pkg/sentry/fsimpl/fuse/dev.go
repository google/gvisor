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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
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

	// numInFlightRequests is the number of in flight requests in the queue that
	// needs to be processed.
	numInFlightRequests uint64

	// completions is used to map a request to its response. A Writer will use this
	// to notify the caller of a completed response.
	completions map[linux.FUSEOpID]*futureResponse

	// requestKind is a map to quickly identify the kind of operation based on the
	// opID.
	requestKind map[linux.FUSEOpID]linux.FUSEOpcode

	readCursor  uint32
	writeCursor uint32

	// writeBuf is the memory buffer used to copy in the FUSE out header from
	// userspace.
	writeBuf []byte

	// writeCursorFR current FR being copied from server.
	writeCursorFR *futureResponse

	// mu protects all the queues, maps, buffers and cursors and nextOpID.
	mu sync.Mutex

	// emptyQueueCh is a channel used to synchronize the readers with the writers.
	// Readers (FUSE daemon server) block if no requests are available.
	emptyQueueCh chan struct{}

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

	kernelTask := kernel.TaskFromContext(ctx)
	if kernelTask == nil {
		log.Warningf("fusefs.DeviceFD.Read: couldn't get kernel task from context")
		return 0, syserror.EINVAL
	}

	// Wait for a request to be made available.
	if err := kernelTask.Block(fd.emptyQueueCh); err != nil {
		log.Warningf("fusefs.DeviceFD.Read: couldn't wait on request queue: %v", err)
		return 0, syserror.EBUSY
	}

	fd.mu.Lock()
	defer fd.mu.Unlock()
	return fd.readLocked(ctx, dst, opts)
}

// readLocked implements the reading of the fuse device while locked with DeviceFD.mu.
func (fd *DeviceFD) readLocked(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	if fd.queue.Empty() {
		log.Warningf("fusefs.DeviceFD.Read: No requests to read but still signalled")
		return 0, syserror.EAGAIN
	}

	req := fd.queue.Front()
	if fd.readCursor >= req.hdr.Len {
		// Cursor points past end of current request payload? Reset the cursor,
		// remove the front request and try again.
		fd.readCursor = 0
		fd.queue.Remove(req)
		fd.numInFlightRequests -= 1

		// Signal that the queue is no longer full.
		select {
		case fd.fullQueueCh <- struct{}{}:
		default:
			log.Warningf("fuse.DeviceFD.Read: blocking when signalling the fullQueueCh")
		}
		return fd.readLocked(ctx, dst, opts)
	}

	n, err := dst.CopyOut(ctx, req.data[fd.readCursor:])
	fd.readCursor += uint32(n)

	if fd.readCursor >= req.hdr.Len {
		// Fully done with this req, remove it from the queue.
		fd.queue.Remove(req)
		fd.numInFlightRequests -= 1
		fd.readCursor = 0

		// Signal that the queue is no longer full.
		select {
		case fd.fullQueueCh <- struct{}{}:
		default:
			log.Warningf("fuse.DeviceFD.Read: blocking when signalling the fullQueueCh")
		}
	} else {
		// This read didn't dequeue a request yet and so shouldn't block
		// the next read as the queue is not empty yet.
		select {
		case fd.emptyQueueCh <- struct{}{}:
		default:
			log.Warningf("fuse.DeviceFD.Read: blocking when signalling the emptyQueueCh")
		}
	}

	return int64(n), err
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
		// See if the running task need to perform some action before returning.
		// Since we just finished writing the future, we can be sure that
		// getResponse generates a populated response.
		if err := fd.noReceiverAction(ctx, fd.writeCursorFR.getResponse()); err != nil {
			return 0, err
		}

		close(fd.writeCursorFR.ch)
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

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *DeviceFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	// Operations on /dev/fuse don't make sense until a FUSE filesystem is mounted.
	if !fd.mounted {
		return 0, syserror.EPERM
	}

	return 0, syserror.ENOSYS
}

// noReceiverAction has the calling kernel.Task do some action if its known that no
// receiver is going to be waiting on the future channel. This is to be used by:
// FUSE_INIT.
func (fd *DeviceFD) noReceiverAction(ctx context.Context, r *Response) error {
	opCode, ok := fd.requestKind[r.hdr.Unique]
	if !ok {
		// Server sent us a response for a request we don't know about.
		return syserror.EINVAL
	}
	delete(fd.requestKind, r.hdr.Unique)

	if opCode == linux.FUSE_INIT {
		return fd.fs.InitRecv(
			auth.CredentialsFromContext(ctx),
			kernel.KernelFromContext(ctx).RootUserNamespace(),
			r,
		)
	}

	return nil
}
