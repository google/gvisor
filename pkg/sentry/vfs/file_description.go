// Copyright 2019 The gVisor Authors.
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

package vfs

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// A FileDescription represents an open file description, which is the entity
// referred to by a file descriptor (POSIX.1-2017 3.258 "Open File
// Description").
//
// FileDescriptions are reference-counted. Unless otherwise specified, all
// FileDescription methods require that a reference is held.
//
// FileDescription is analogous to Linux's struct file.
type FileDescription struct {
	// refs is the reference count. refs is accessed using atomic memory
	// operations.
	refs int64

	// vd is the filesystem location at which this FileDescription was opened.
	// A reference is held on vd. vd is immutable.
	vd VirtualDentry

	// impl is the FileDescriptionImpl associated with this Filesystem. impl is
	// immutable. This should be the last field in FileDescription.
	impl FileDescriptionImpl
}

// Init must be called before first use of fd. It takes references on mnt and
// d.
func (fd *FileDescription) Init(impl FileDescriptionImpl, mnt *Mount, d *Dentry) {
	fd.refs = 1
	fd.vd = VirtualDentry{
		mount:  mnt,
		dentry: d,
	}
	fd.vd.IncRef()
	fd.impl = impl
}

// Impl returns the FileDescriptionImpl associated with fd.
func (fd *FileDescription) Impl() FileDescriptionImpl {
	return fd.impl
}

// VirtualDentry returns the location at which fd was opened. It does not take
// a reference on the returned VirtualDentry.
func (fd *FileDescription) VirtualDentry() VirtualDentry {
	return fd.vd
}

// IncRef increments fd's reference count.
func (fd *FileDescription) IncRef() {
	atomic.AddInt64(&fd.refs, 1)
}

// DecRef decrements fd's reference count.
func (fd *FileDescription) DecRef() {
	if refs := atomic.AddInt64(&fd.refs, -1); refs == 0 {
		fd.impl.Release()
		fd.vd.DecRef()
	} else if refs < 0 {
		panic("FileDescription.DecRef() called without holding a reference")
	}
}

// FileDescriptionImpl contains implementation details for an FileDescription.
// Implementations of FileDescriptionImpl should contain their associated
// FileDescription by value as their first field.
//
// For all functions that return linux.Statx, Statx.Uid and Statx.Gid will
// be interpreted as IDs in the root UserNamespace (i.e. as auth.KUID and
// auth.KGID respectively).
//
// FileDescriptionImpl is analogous to Linux's struct file_operations.
type FileDescriptionImpl interface {
	// Release is called when the associated FileDescription reaches zero
	// references.
	Release()

	// OnClose is called when a file descriptor representing the
	// FileDescription is closed. Note that returning a non-nil error does not
	// prevent the file descriptor from being closed.
	OnClose() error

	// StatusFlags returns file description status flags, as for
	// fcntl(F_GETFL).
	StatusFlags(ctx context.Context) (uint32, error)

	// SetStatusFlags sets file description status flags, as for
	// fcntl(F_SETFL).
	SetStatusFlags(ctx context.Context, flags uint32) error

	// Stat returns metadata for the file represented by the FileDescription.
	Stat(ctx context.Context, opts StatOptions) (linux.Statx, error)

	// SetStat updates metadata for the file represented by the
	// FileDescription.
	SetStat(ctx context.Context, opts SetStatOptions) error

	// StatFS returns metadata for the filesystem containing the file
	// represented by the FileDescription.
	StatFS(ctx context.Context) (linux.Statfs, error)

	// waiter.Waitable methods may be used to poll for I/O events.
	waiter.Waitable

	// PRead reads from the file into dst, starting at the given offset, and
	// returns the number of bytes read. PRead is permitted to return partial
	// reads with a nil error.
	PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts ReadOptions) (int64, error)

	// Read is similar to PRead, but does not specify an offset.
	//
	// For files with an implicit FileDescription offset (e.g. regular files),
	// Read begins at the FileDescription offset, and advances the offset by
	// the number of bytes read; note that POSIX 2.9.7 "Thread Interactions
	// with Regular File Operations" requires that all operations that may
	// mutate the FileDescription offset are serialized.
	Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error)

	// PWrite writes src to the file, starting at the given offset, and returns
	// the number of bytes written. PWrite is permitted to return partial
	// writes with a nil error.
	//
	// As in Linux (but not POSIX), if O_APPEND is in effect for the
	// FileDescription, PWrite should ignore the offset and append data to the
	// end of the file.
	PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (int64, error)

	// Write is similar to PWrite, but does not specify an offset, which is
	// implied as for Read.
	//
	// Write is a FileDescriptionImpl method, instead of a wrapper around
	// PWrite that uses a FileDescription offset, to make it possible for
	// remote filesystems to implement O_APPEND correctly (i.e. atomically with
	// respect to writers outside the scope of VFS).
	Write(ctx context.Context, src usermem.IOSequence, opts WriteOptions) (int64, error)

	// IterDirents invokes cb on each entry in the directory represented by the
	// FileDescription. If IterDirents has been called since the last call to
	// Seek, it continues iteration from the end of the last call.
	IterDirents(ctx context.Context, cb IterDirentsCallback) error

	// Seek changes the FileDescription offset (assuming one exists) and
	// returns its new value.
	//
	// For directories, if whence == SEEK_SET and offset == 0, the caller is
	// rewinddir(), such that Seek "shall also cause the directory stream to
	// refer to the current state of the corresponding directory" -
	// POSIX.1-2017.
	Seek(ctx context.Context, offset int64, whence int32) (int64, error)

	// Sync requests that cached state associated with the file represented by
	// the FileDescription is synchronized with persistent storage, and blocks
	// until this is complete.
	Sync(ctx context.Context) error

	// ConfigureMMap mutates opts to implement mmap(2) for the file. Most
	// implementations that support memory mapping can call
	// GenericConfigureMMap with the appropriate memmap.Mappable.
	ConfigureMMap(ctx context.Context, opts memmap.MMapOpts) error

	// Ioctl implements the ioctl(2) syscall.
	Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error)

	// TODO: extended attributes; file locking
}

// Dirent holds the information contained in struct linux_dirent64.
type Dirent struct {
	// Name is the filename.
	Name string

	// Type is the file type, a linux.DT_* constant.
	Type uint8

	// Ino is the inode number.
	Ino uint64

	// Off is this Dirent's offset.
	Off int64
}

// IterDirentsCallback receives Dirents from FileDescriptionImpl.IterDirents.
type IterDirentsCallback interface {
	// Handle handles the given iterated Dirent. It returns true if iteration
	// should continue, and false if FileDescriptionImpl.IterDirents should
	// terminate now and restart with the same Dirent the next time it is
	// called.
	Handle(dirent Dirent) bool
}
