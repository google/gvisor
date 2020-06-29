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

package memdev

import (
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// BufferEntryMax is the maximum number of entries retained by kmsg before new entries overwrite old ones.
	BufferEntryMax = 512

	// BufferMax is the maximum size of an individual entry, in bytes.
	BufferMax = 1024
)

const kmsgDevMinor = 11

// kmsgDevice implements vfs.Device for /dev/kmsg.
type kmsgDevice struct{}

// Open implements vfs.Device.Open.
func (kmsgDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &kmsgFD{}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// kmsgFD implements vfs.FileDescriptionImpl for /dev/kmsg.
type kmsgFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// buffer is a circular buffer that store user's write to kmsg.
	m          sync.Mutex
	buffer     [BufferEntryMax]*buffer.View
	readIndex  int
	writeIndex int
	// bufferLength is the number of unread entries in the buffer
	bufferLength int
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *kmsgFD) Release() {
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *kmsgFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.m.Lock()
	defer fd.m.Unlock()

	// When an entry gets overwritten in the circular buffer, next read()
	// will return EPIPE and move readIndex to the next available record.
	// See Documentation/ABI/testing/dev-kmsg in the Linux source for reference.
	if fd.bufferLength > BufferEntryMax {
		fd.readIndex = fd.writeIndex
		fd.bufferLength = len(fd.buffer)
		return 0, syserror.EPIPE
	}
	if fd.bufferLength == 0 {
		if fd.vfsfd.StatusFlags()&^linux.O_NONBLOCK != 0 {
			return 0, syserror.EAGAIN
		}
		return 0, syserror.ErrWouldBlock
	}
	if fd.buffer[fd.readIndex].Size() > dst.NumBytes() {
		return 0, syserror.EINVAL
	}
	bytesCopied, err := dst.CopyOutFrom(ctx, fd.buffer[fd.readIndex])
	fd.readIndex++
	fd.bufferLength--
	if fd.readIndex == len(fd.buffer) {
		fd.readIndex = 0
	}
	return bytesCopied, err
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *kmsgFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	if src.NumBytes() > BufferMax {
		return 0, syserror.EINVAL
	}

	fd.m.Lock()
	defer fd.m.Unlock()
	fd.buffer[fd.writeIndex] = new(buffer.View)
	bytesCopied, err := src.CopyInTo(ctx, fd.buffer[fd.writeIndex])
	fd.writeIndex++
	fd.bufferLength++
	if fd.writeIndex == len(fd.buffer) {
		fd.writeIndex = 0
	}
	return bytesCopied, err
}

// Seek implements vfs.FileDescriptionImpl.Seek.
// Different from usual behavior, kmsg only support three type of seek:
//	- SEEK_SET seek to the first entry in the buffer.
//	- SEEK_END seek after the last entry in the buffer.
//	- SEEK_DATA perform same action as SEEK_END since gvisor doesn't have syslog yet.
func (fd *kmsgFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	if offset != 0 {
		return 0, syserror.ESPIPE
	}

	fd.m.Lock()
	defer fd.m.Unlock()
	switch whence {
	case linux.SEEK_SET:
		if fd.buffer[fd.writeIndex] == nil {
			fd.readIndex = 0
		} else {
			fd.readIndex = fd.writeIndex
		}
		return 0, nil
	case linux.SEEK_END, linux.SEEK_DATA:
		fd.readIndex = fd.writeIndex
		return 0, nil
	default:
		return 0, syserror.EINVAL
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *kmsgFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	var ready waiter.EventMask
	fd.m.Lock()
	defer fd.m.Unlock()
	if fd.bufferLength != 0 {
		ready |= waiter.EventIn
	}
	return ready
}
