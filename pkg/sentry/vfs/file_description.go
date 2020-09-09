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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
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

	// flagsMu protects statusFlags and asyncHandler below.
	flagsMu sync.Mutex

	// statusFlags contains status flags, "initialized by open(2) and possibly
	// modified by fcntl()" - fcntl(2). statusFlags can be read using atomic
	// memory operations when it does not need to be synchronized with an
	// access to asyncHandler.
	statusFlags uint32

	// asyncHandler handles O_ASYNC signal generation. It is set with the
	// F_SETOWN or F_SETOWN_EX fcntls. For asyncHandler to be used, O_ASYNC must
	// also be set by fcntl(2).
	asyncHandler FileAsync

	// epolls is the set of epollInterests registered for this FileDescription.
	// epolls is protected by epollMu.
	epollMu sync.Mutex
	epolls  map[*epollInterest]struct{}

	// vd is the filesystem location at which this FileDescription was opened.
	// A reference is held on vd. vd is immutable.
	vd VirtualDentry

	// opts contains options passed to FileDescription.Init(). opts is
	// immutable.
	opts FileDescriptionOptions

	// readable is MayReadFileWithOpenFlags(statusFlags). readable is
	// immutable.
	//
	// readable is analogous to Linux's FMODE_READ.
	readable bool

	// writable is MayWriteFileWithOpenFlags(statusFlags). If writable is true,
	// the FileDescription holds a write count on vd.mount. writable is
	// immutable.
	//
	// writable is analogous to Linux's FMODE_WRITE.
	writable bool

	usedLockBSD uint32

	// impl is the FileDescriptionImpl associated with this Filesystem. impl is
	// immutable. This should be the last field in FileDescription.
	impl FileDescriptionImpl
}

// FileDescriptionOptions contains options to FileDescription.Init().
type FileDescriptionOptions struct {
	// If AllowDirectIO is true, allow O_DIRECT to be set on the file.
	AllowDirectIO bool

	// If DenyPRead is true, calls to FileDescription.PRead() return ESPIPE.
	DenyPRead bool

	// If DenyPWrite is true, calls to FileDescription.PWrite() return
	// ESPIPE.
	DenyPWrite bool

	// If UseDentryMetadata is true, calls to FileDescription methods that
	// interact with file and filesystem metadata (Stat, SetStat, StatFS,
	// Listxattr, Getxattr, Setxattr, Removexattr) are implemented by calling
	// the corresponding FilesystemImpl methods instead of the corresponding
	// FileDescriptionImpl methods.
	//
	// UseDentryMetadata is intended for file descriptions that are implemented
	// outside of individual filesystems, such as pipes, sockets, and device
	// special files. FileDescriptions for which UseDentryMetadata is true may
	// embed DentryMetadataFileDescriptionImpl to obtain appropriate
	// implementations of FileDescriptionImpl methods that should not be
	// called.
	UseDentryMetadata bool
}

// FileCreationFlags are the set of flags passed to FileDescription.Init() but
// omitted from FileDescription.StatusFlags().
const FileCreationFlags = linux.O_CREAT | linux.O_EXCL | linux.O_NOCTTY | linux.O_TRUNC

// Init must be called before first use of fd. If it succeeds, it takes
// references on mnt and d. flags is the initial file description flags, which
// is usually the full set of flags passed to open(2).
func (fd *FileDescription) Init(impl FileDescriptionImpl, flags uint32, mnt *Mount, d *Dentry, opts *FileDescriptionOptions) error {
	writable := MayWriteFileWithOpenFlags(flags)
	if writable {
		if err := mnt.CheckBeginWrite(); err != nil {
			return err
		}
	}

	fd.refs = 1

	// Remove "file creation flags" to mirror the behavior from file.f_flags in
	// fs/open.c:do_dentry_open.
	fd.statusFlags = flags &^ FileCreationFlags
	fd.vd = VirtualDentry{
		mount:  mnt,
		dentry: d,
	}
	mnt.IncRef()
	d.IncRef()
	fd.opts = *opts
	fd.readable = MayReadFileWithOpenFlags(flags)
	fd.writable = writable
	fd.impl = impl
	return nil
}

// IncRef increments fd's reference count.
func (fd *FileDescription) IncRef() {
	atomic.AddInt64(&fd.refs, 1)
}

// TryIncRef increments fd's reference count and returns true. If fd's
// reference count is already zero, TryIncRef does nothing and returns false.
//
// TryIncRef does not require that a reference is held on fd.
func (fd *FileDescription) TryIncRef() bool {
	for {
		refs := atomic.LoadInt64(&fd.refs)
		if refs <= 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(&fd.refs, refs, refs+1) {
			return true
		}
	}
}

// DecRef decrements fd's reference count.
func (fd *FileDescription) DecRef(ctx context.Context) {
	if refs := atomic.AddInt64(&fd.refs, -1); refs == 0 {
		// Unregister fd from all epoll instances.
		fd.epollMu.Lock()
		epolls := fd.epolls
		fd.epolls = nil
		fd.epollMu.Unlock()
		for epi := range epolls {
			ep := epi.epoll
			ep.interestMu.Lock()
			// Check that epi has not been concurrently unregistered by
			// EpollInstance.DeleteInterest() or EpollInstance.Release().
			if _, ok := ep.interest[epi.key]; ok {
				fd.EventUnregister(&epi.waiter)
				ep.removeLocked(epi)
			}
			ep.interestMu.Unlock()
		}

		// If BSD locks were used, release any lock that it may have acquired.
		if atomic.LoadUint32(&fd.usedLockBSD) != 0 {
			fd.impl.UnlockBSD(context.Background(), fd)
		}

		// Release implementation resources.
		fd.impl.Release(ctx)
		if fd.writable {
			fd.vd.mount.EndWrite()
		}
		fd.vd.DecRef(ctx)
		fd.flagsMu.Lock()
		// TODO(gvisor.dev/issue/1663): We may need to unregister during save, as we do in VFS1.
		if fd.statusFlags&linux.O_ASYNC != 0 && fd.asyncHandler != nil {
			fd.asyncHandler.Unregister(fd)
		}
		fd.asyncHandler = nil
		fd.flagsMu.Unlock()
	} else if refs < 0 {
		panic("FileDescription.DecRef() called without holding a reference")
	}
}

// Refs returns the current number of references. The returned count
// is inherently racy and is unsafe to use without external synchronization.
func (fd *FileDescription) Refs() int64 {
	return atomic.LoadInt64(&fd.refs)
}

// Mount returns the mount on which fd was opened. It does not take a reference
// on the returned Mount.
func (fd *FileDescription) Mount() *Mount {
	return fd.vd.mount
}

// Dentry returns the dentry at which fd was opened. It does not take a
// reference on the returned Dentry.
func (fd *FileDescription) Dentry() *Dentry {
	return fd.vd.dentry
}

// VirtualDentry returns the location at which fd was opened. It does not take
// a reference on the returned VirtualDentry.
func (fd *FileDescription) VirtualDentry() VirtualDentry {
	return fd.vd
}

// Options returns the options passed to fd.Init().
func (fd *FileDescription) Options() FileDescriptionOptions {
	return fd.opts
}

// StatusFlags returns file description status flags, as for fcntl(F_GETFL).
func (fd *FileDescription) StatusFlags() uint32 {
	return atomic.LoadUint32(&fd.statusFlags)
}

// SetStatusFlags sets file description status flags, as for fcntl(F_SETFL).
func (fd *FileDescription) SetStatusFlags(ctx context.Context, creds *auth.Credentials, flags uint32) error {
	// Compare Linux's fs/fcntl.c:setfl().
	oldFlags := fd.StatusFlags()
	// Linux documents this check as "O_APPEND cannot be cleared if the file is
	// marked as append-only and the file is open for write", which would make
	// sense. However, the check as actually implemented seems to be "O_APPEND
	// cannot be changed if the file is marked as append-only".
	if (flags^oldFlags)&linux.O_APPEND != 0 {
		stat, err := fd.Stat(ctx, StatOptions{
			// There is no mask bit for stx_attributes.
			Mask: 0,
			// Linux just reads inode::i_flags directly.
			Sync: linux.AT_STATX_DONT_SYNC,
		})
		if err != nil {
			return err
		}
		if (stat.AttributesMask&linux.STATX_ATTR_APPEND != 0) && (stat.Attributes&linux.STATX_ATTR_APPEND != 0) {
			return syserror.EPERM
		}
	}
	if (flags&linux.O_NOATIME != 0) && (oldFlags&linux.O_NOATIME == 0) {
		stat, err := fd.Stat(ctx, StatOptions{
			Mask: linux.STATX_UID,
			// Linux's inode_owner_or_capable() just reads inode::i_uid
			// directly.
			Sync: linux.AT_STATX_DONT_SYNC,
		})
		if err != nil {
			return err
		}
		if stat.Mask&linux.STATX_UID == 0 {
			return syserror.EPERM
		}
		if !CanActAsOwner(creds, auth.KUID(stat.UID)) {
			return syserror.EPERM
		}
	}
	if flags&linux.O_DIRECT != 0 && !fd.opts.AllowDirectIO {
		return syserror.EINVAL
	}
	// TODO(gvisor.dev/issue/1035): FileDescriptionImpl.SetOAsync()?
	const settableFlags = linux.O_APPEND | linux.O_ASYNC | linux.O_DIRECT | linux.O_NOATIME | linux.O_NONBLOCK
	fd.flagsMu.Lock()
	if fd.asyncHandler != nil {
		// Use fd.statusFlags instead of oldFlags, which may have become outdated,
		// to avoid double registering/unregistering.
		if fd.statusFlags&linux.O_ASYNC == 0 && flags&linux.O_ASYNC != 0 {
			fd.asyncHandler.Register(fd)
		} else if fd.statusFlags&linux.O_ASYNC != 0 && flags&linux.O_ASYNC == 0 {
			fd.asyncHandler.Unregister(fd)
		}
	}
	atomic.StoreUint32(&fd.statusFlags, (oldFlags&^settableFlags)|(flags&settableFlags))
	fd.flagsMu.Unlock()
	return nil
}

// IsReadable returns true if fd was opened for reading.
func (fd *FileDescription) IsReadable() bool {
	return fd.readable
}

// IsWritable returns true if fd was opened for writing.
func (fd *FileDescription) IsWritable() bool {
	return fd.writable
}

// Impl returns the FileDescriptionImpl associated with fd.
func (fd *FileDescription) Impl() FileDescriptionImpl {
	return fd.impl
}

// FileDescriptionImpl contains implementation details for an FileDescription.
// Implementations of FileDescriptionImpl should contain their associated
// FileDescription by value as their first field.
//
// For all functions that return linux.Statx, Statx.Uid and Statx.Gid will
// be interpreted as IDs in the root UserNamespace (i.e. as auth.KUID and
// auth.KGID respectively).
//
// All methods may return errors not specified.
//
// FileDescriptionImpl is analogous to Linux's struct file_operations.
type FileDescriptionImpl interface {
	// Release is called when the associated FileDescription reaches zero
	// references.
	Release(ctx context.Context)

	// OnClose is called when a file descriptor representing the
	// FileDescription is closed. Note that returning a non-nil error does not
	// prevent the file descriptor from being closed.
	OnClose(ctx context.Context) error

	// Stat returns metadata for the file represented by the FileDescription.
	Stat(ctx context.Context, opts StatOptions) (linux.Statx, error)

	// SetStat updates metadata for the file represented by the
	// FileDescription. Implementations are responsible for checking if the
	// operation can be performed (see vfs.CheckSetStat() for common checks).
	SetStat(ctx context.Context, opts SetStatOptions) error

	// StatFS returns metadata for the filesystem containing the file
	// represented by the FileDescription.
	StatFS(ctx context.Context) (linux.Statfs, error)

	// Allocate grows the file to offset + length bytes.
	// Only mode == 0 is supported currently.
	//
	// Preconditions: The FileDescription was opened for writing.
	Allocate(ctx context.Context, mode, offset, length uint64) error

	// waiter.Waitable methods may be used to poll for I/O events.
	waiter.Waitable

	// PRead reads from the file into dst, starting at the given offset, and
	// returns the number of bytes read. PRead is permitted to return partial
	// reads with a nil error.
	//
	// Errors:
	//
	// - If opts.Flags specifies unsupported options, PRead returns EOPNOTSUPP.
	//
	// Preconditions:
	// * The FileDescription was opened for reading.
	// * FileDescriptionOptions.DenyPRead == false.
	PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts ReadOptions) (int64, error)

	// Read is similar to PRead, but does not specify an offset.
	//
	// For files with an implicit FileDescription offset (e.g. regular files),
	// Read begins at the FileDescription offset, and advances the offset by
	// the number of bytes read; note that POSIX 2.9.7 "Thread Interactions
	// with Regular File Operations" requires that all operations that may
	// mutate the FileDescription offset are serialized.
	//
	// Errors:
	//
	// - If opts.Flags specifies unsupported options, Read returns EOPNOTSUPP.
	//
	// Preconditions: The FileDescription was opened for reading.
	Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error)

	// PWrite writes src to the file, starting at the given offset, and returns
	// the number of bytes written. PWrite is permitted to return partial
	// writes with a nil error.
	//
	// As in Linux (but not POSIX), if O_APPEND is in effect for the
	// FileDescription, PWrite should ignore the offset and append data to the
	// end of the file.
	//
	// Errors:
	//
	// - If opts.Flags specifies unsupported options, PWrite returns
	// EOPNOTSUPP.
	//
	// Preconditions:
	// * The FileDescription was opened for writing.
	// * FileDescriptionOptions.DenyPWrite == false.
	PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (int64, error)

	// Write is similar to PWrite, but does not specify an offset, which is
	// implied as for Read.
	//
	// Write is a FileDescriptionImpl method, instead of a wrapper around
	// PWrite that uses a FileDescription offset, to make it possible for
	// remote filesystems to implement O_APPEND correctly (i.e. atomically with
	// respect to writers outside the scope of VFS).
	//
	// Errors:
	//
	// - If opts.Flags specifies unsupported options, Write returns EOPNOTSUPP.
	//
	// Preconditions: The FileDescription was opened for writing.
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
	ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error

	// Ioctl implements the ioctl(2) syscall.
	Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error)

	// Listxattr returns all extended attribute names for the file.
	Listxattr(ctx context.Context, size uint64) ([]string, error)

	// Getxattr returns the value associated with the given extended attribute
	// for the file.
	Getxattr(ctx context.Context, opts GetxattrOptions) (string, error)

	// Setxattr changes the value associated with the given extended attribute
	// for the file.
	Setxattr(ctx context.Context, opts SetxattrOptions) error

	// Removexattr removes the given extended attribute from the file.
	Removexattr(ctx context.Context, name string) error

	// LockBSD tries to acquire a BSD-style advisory file lock.
	LockBSD(ctx context.Context, uid lock.UniqueID, t lock.LockType, block lock.Blocker) error

	// UnlockBSD releases a BSD-style advisory file lock.
	UnlockBSD(ctx context.Context, uid lock.UniqueID) error

	// LockPOSIX tries to acquire a POSIX-style advisory file lock.
	LockPOSIX(ctx context.Context, uid lock.UniqueID, t lock.LockType, start, length uint64, whence int16, block lock.Blocker) error

	// UnlockPOSIX releases a POSIX-style advisory file lock.
	UnlockPOSIX(ctx context.Context, uid lock.UniqueID, start, length uint64, whence int16) error
}

// Dirent holds the information contained in struct linux_dirent64.
type Dirent struct {
	// Name is the filename.
	Name string

	// Type is the file type, a linux.DT_* constant.
	Type uint8

	// Ino is the inode number.
	Ino uint64

	// NextOff is the offset of the *next* Dirent in the directory; that is,
	// FileDescription.Seek(NextOff, SEEK_SET) (as called by seekdir(3)) will
	// cause the next call to FileDescription.IterDirents() to yield the next
	// Dirent. (The offset of the first Dirent in a directory is always 0.)
	NextOff int64
}

// IterDirentsCallback receives Dirents from FileDescriptionImpl.IterDirents.
type IterDirentsCallback interface {
	// Handle handles the given iterated Dirent. If Handle returns a non-nil
	// error, FileDescriptionImpl.IterDirents must stop iteration and return
	// the error; the next call to FileDescriptionImpl.IterDirents should
	// restart with the same Dirent.
	Handle(dirent Dirent) error
}

// IterDirentsCallbackFunc implements IterDirentsCallback for a function with
// the semantics of IterDirentsCallback.Handle.
type IterDirentsCallbackFunc func(dirent Dirent) error

// Handle implements IterDirentsCallback.Handle.
func (f IterDirentsCallbackFunc) Handle(dirent Dirent) error {
	return f(dirent)
}

// OnClose is called when a file descriptor representing the FileDescription is
// closed. Returning a non-nil error should not prevent the file descriptor
// from being closed.
func (fd *FileDescription) OnClose(ctx context.Context) error {
	return fd.impl.OnClose(ctx)
}

// Stat returns metadata for the file represented by fd.
func (fd *FileDescription) Stat(ctx context.Context, opts StatOptions) (linux.Statx, error) {
	if fd.opts.UseDentryMetadata {
		vfsObj := fd.vd.mount.vfs
		rp := vfsObj.getResolvingPath(auth.CredentialsFromContext(ctx), &PathOperation{
			Root:  fd.vd,
			Start: fd.vd,
		})
		stat, err := fd.vd.mount.fs.impl.StatAt(ctx, rp, opts)
		vfsObj.putResolvingPath(ctx, rp)
		return stat, err
	}
	return fd.impl.Stat(ctx, opts)
}

// SetStat updates metadata for the file represented by fd.
func (fd *FileDescription) SetStat(ctx context.Context, opts SetStatOptions) error {
	if fd.opts.UseDentryMetadata {
		vfsObj := fd.vd.mount.vfs
		rp := vfsObj.getResolvingPath(auth.CredentialsFromContext(ctx), &PathOperation{
			Root:  fd.vd,
			Start: fd.vd,
		})
		err := fd.vd.mount.fs.impl.SetStatAt(ctx, rp, opts)
		vfsObj.putResolvingPath(ctx, rp)
		return err
	}
	return fd.impl.SetStat(ctx, opts)
}

// StatFS returns metadata for the filesystem containing the file represented
// by fd.
func (fd *FileDescription) StatFS(ctx context.Context) (linux.Statfs, error) {
	if fd.opts.UseDentryMetadata {
		vfsObj := fd.vd.mount.vfs
		rp := vfsObj.getResolvingPath(auth.CredentialsFromContext(ctx), &PathOperation{
			Root:  fd.vd,
			Start: fd.vd,
		})
		statfs, err := fd.vd.mount.fs.impl.StatFSAt(ctx, rp)
		vfsObj.putResolvingPath(ctx, rp)
		return statfs, err
	}
	return fd.impl.StatFS(ctx)
}

// Allocate grows file represented by FileDescription to offset + length bytes.
func (fd *FileDescription) Allocate(ctx context.Context, mode, offset, length uint64) error {
	if !fd.IsWritable() {
		return syserror.EBADF
	}
	return fd.impl.Allocate(ctx, mode, offset, length)
}

// Readiness implements waiter.Waitable.Readiness.
//
// It returns fd's I/O readiness.
func (fd *FileDescription) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fd.impl.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
//
// It registers e for I/O readiness events in mask.
func (fd *FileDescription) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	fd.impl.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
//
// It unregisters e for I/O readiness events.
func (fd *FileDescription) EventUnregister(e *waiter.Entry) {
	fd.impl.EventUnregister(e)
}

// PRead reads from the file represented by fd into dst, starting at the given
// offset, and returns the number of bytes read. PRead is permitted to return
// partial reads with a nil error.
func (fd *FileDescription) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts ReadOptions) (int64, error) {
	if fd.opts.DenyPRead {
		return 0, syserror.ESPIPE
	}
	if !fd.readable {
		return 0, syserror.EBADF
	}
	return fd.impl.PRead(ctx, dst, offset, opts)
}

// Read is similar to PRead, but does not specify an offset.
func (fd *FileDescription) Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error) {
	if !fd.readable {
		return 0, syserror.EBADF
	}
	return fd.impl.Read(ctx, dst, opts)
}

// PWrite writes src to the file represented by fd, starting at the given
// offset, and returns the number of bytes written. PWrite is permitted to
// return partial writes with a nil error.
func (fd *FileDescription) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (int64, error) {
	if fd.opts.DenyPWrite {
		return 0, syserror.ESPIPE
	}
	if !fd.writable {
		return 0, syserror.EBADF
	}
	return fd.impl.PWrite(ctx, src, offset, opts)
}

// Write is similar to PWrite, but does not specify an offset.
func (fd *FileDescription) Write(ctx context.Context, src usermem.IOSequence, opts WriteOptions) (int64, error) {
	if !fd.writable {
		return 0, syserror.EBADF
	}
	return fd.impl.Write(ctx, src, opts)
}

// IterDirents invokes cb on each entry in the directory represented by fd. If
// IterDirents has been called since the last call to Seek, it continues
// iteration from the end of the last call.
func (fd *FileDescription) IterDirents(ctx context.Context, cb IterDirentsCallback) error {
	return fd.impl.IterDirents(ctx, cb)
}

// Seek changes fd's offset (assuming one exists) and returns its new value.
func (fd *FileDescription) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return fd.impl.Seek(ctx, offset, whence)
}

// Sync has the semantics of fsync(2).
func (fd *FileDescription) Sync(ctx context.Context) error {
	return fd.impl.Sync(ctx)
}

// ConfigureMMap mutates opts to implement mmap(2) for the file represented by
// fd.
func (fd *FileDescription) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return fd.impl.ConfigureMMap(ctx, opts)
}

// Ioctl implements the ioctl(2) syscall.
func (fd *FileDescription) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return fd.impl.Ioctl(ctx, uio, args)
}

// Listxattr returns all extended attribute names for the file represented by
// fd.
//
// If the size of the list (including a NUL terminating byte after every entry)
// would exceed size, ERANGE may be returned. Note that implementations
// are free to ignore size entirely and return without error). In all cases,
// if size is 0, the list should be returned without error, regardless of size.
func (fd *FileDescription) Listxattr(ctx context.Context, size uint64) ([]string, error) {
	if fd.opts.UseDentryMetadata {
		vfsObj := fd.vd.mount.vfs
		rp := vfsObj.getResolvingPath(auth.CredentialsFromContext(ctx), &PathOperation{
			Root:  fd.vd,
			Start: fd.vd,
		})
		names, err := fd.vd.mount.fs.impl.ListxattrAt(ctx, rp, size)
		vfsObj.putResolvingPath(ctx, rp)
		return names, err
	}
	names, err := fd.impl.Listxattr(ctx, size)
	if err == syserror.ENOTSUP {
		// Linux doesn't actually return ENOTSUP in this case; instead,
		// fs/xattr.c:vfs_listxattr() falls back to allowing the security
		// subsystem to return security extended attributes, which by default
		// don't exist.
		return nil, nil
	}
	return names, err
}

// Getxattr returns the value associated with the given extended attribute for
// the file represented by fd.
//
// If the size of the return value exceeds opts.Size, ERANGE may be returned
// (note that implementations are free to ignore opts.Size entirely and return
// without error). In all cases, if opts.Size is 0, the value should be
// returned without error, regardless of size.
func (fd *FileDescription) Getxattr(ctx context.Context, opts *GetxattrOptions) (string, error) {
	if fd.opts.UseDentryMetadata {
		vfsObj := fd.vd.mount.vfs
		rp := vfsObj.getResolvingPath(auth.CredentialsFromContext(ctx), &PathOperation{
			Root:  fd.vd,
			Start: fd.vd,
		})
		val, err := fd.vd.mount.fs.impl.GetxattrAt(ctx, rp, *opts)
		vfsObj.putResolvingPath(ctx, rp)
		return val, err
	}
	return fd.impl.Getxattr(ctx, *opts)
}

// Setxattr changes the value associated with the given extended attribute for
// the file represented by fd.
func (fd *FileDescription) Setxattr(ctx context.Context, opts *SetxattrOptions) error {
	if fd.opts.UseDentryMetadata {
		vfsObj := fd.vd.mount.vfs
		rp := vfsObj.getResolvingPath(auth.CredentialsFromContext(ctx), &PathOperation{
			Root:  fd.vd,
			Start: fd.vd,
		})
		err := fd.vd.mount.fs.impl.SetxattrAt(ctx, rp, *opts)
		vfsObj.putResolvingPath(ctx, rp)
		return err
	}
	return fd.impl.Setxattr(ctx, *opts)
}

// Removexattr removes the given extended attribute from the file represented
// by fd.
func (fd *FileDescription) Removexattr(ctx context.Context, name string) error {
	if fd.opts.UseDentryMetadata {
		vfsObj := fd.vd.mount.vfs
		rp := vfsObj.getResolvingPath(auth.CredentialsFromContext(ctx), &PathOperation{
			Root:  fd.vd,
			Start: fd.vd,
		})
		err := fd.vd.mount.fs.impl.RemovexattrAt(ctx, rp, name)
		vfsObj.putResolvingPath(ctx, rp)
		return err
	}
	return fd.impl.Removexattr(ctx, name)
}

// SyncFS instructs the filesystem containing fd to execute the semantics of
// syncfs(2).
func (fd *FileDescription) SyncFS(ctx context.Context) error {
	return fd.vd.mount.fs.impl.Sync(ctx)
}

// MappedName implements memmap.MappingIdentity.MappedName.
func (fd *FileDescription) MappedName(ctx context.Context) string {
	vfsroot := RootFromContext(ctx)
	s, _ := fd.vd.mount.vfs.PathnameWithDeleted(ctx, vfsroot, fd.vd)
	if vfsroot.Ok() {
		vfsroot.DecRef(ctx)
	}
	return s
}

// DeviceID implements memmap.MappingIdentity.DeviceID.
func (fd *FileDescription) DeviceID() uint64 {
	stat, err := fd.Stat(context.Background(), StatOptions{
		// There is no STATX_DEV; we assume that Stat will return it if it's
		// available regardless of mask.
		Mask: 0,
		// fs/proc/task_mmu.c:show_map_vma() just reads inode::i_sb->s_dev
		// directly.
		Sync: linux.AT_STATX_DONT_SYNC,
	})
	if err != nil {
		return 0
	}
	return uint64(linux.MakeDeviceID(uint16(stat.DevMajor), stat.DevMinor))
}

// InodeID implements memmap.MappingIdentity.InodeID.
func (fd *FileDescription) InodeID() uint64 {
	stat, err := fd.Stat(context.Background(), StatOptions{
		Mask: linux.STATX_INO,
		// fs/proc/task_mmu.c:show_map_vma() just reads inode::i_ino directly.
		Sync: linux.AT_STATX_DONT_SYNC,
	})
	if err != nil || stat.Mask&linux.STATX_INO == 0 {
		return 0
	}
	return stat.Ino
}

// Msync implements memmap.MappingIdentity.Msync.
func (fd *FileDescription) Msync(ctx context.Context, mr memmap.MappableRange) error {
	return fd.Sync(ctx)
}

// LockBSD tries to acquire a BSD-style advisory file lock.
func (fd *FileDescription) LockBSD(ctx context.Context, lockType lock.LockType, blocker lock.Blocker) error {
	atomic.StoreUint32(&fd.usedLockBSD, 1)
	return fd.impl.LockBSD(ctx, fd, lockType, blocker)
}

// UnlockBSD releases a BSD-style advisory file lock.
func (fd *FileDescription) UnlockBSD(ctx context.Context) error {
	return fd.impl.UnlockBSD(ctx, fd)
}

// LockPOSIX locks a POSIX-style file range lock.
func (fd *FileDescription) LockPOSIX(ctx context.Context, uid lock.UniqueID, t lock.LockType, start, end uint64, whence int16, block lock.Blocker) error {
	return fd.impl.LockPOSIX(ctx, uid, t, start, end, whence, block)
}

// UnlockPOSIX unlocks a POSIX-style file range lock.
func (fd *FileDescription) UnlockPOSIX(ctx context.Context, uid lock.UniqueID, start, end uint64, whence int16) error {
	return fd.impl.UnlockPOSIX(ctx, uid, start, end, whence)
}

// A FileAsync sends signals to its owner when w is ready for IO. This is only
// implemented by pkg/sentry/fasync:FileAsync, but we unfortunately need this
// interface to avoid circular dependencies.
type FileAsync interface {
	Register(w waiter.Waitable)
	Unregister(w waiter.Waitable)
}

// AsyncHandler returns the FileAsync for fd.
func (fd *FileDescription) AsyncHandler() FileAsync {
	fd.flagsMu.Lock()
	defer fd.flagsMu.Unlock()
	return fd.asyncHandler
}

// SetAsyncHandler sets fd.asyncHandler if it has not been set before and
// returns it.
func (fd *FileDescription) SetAsyncHandler(newHandler func() FileAsync) FileAsync {
	fd.flagsMu.Lock()
	defer fd.flagsMu.Unlock()
	if fd.asyncHandler == nil {
		fd.asyncHandler = newHandler()
		if fd.statusFlags&linux.O_ASYNC != 0 {
			fd.asyncHandler.Register(fd)
		}
	}
	return fd.asyncHandler
}
