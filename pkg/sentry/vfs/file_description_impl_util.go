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
	"bytes"
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// The following design pattern is strongly recommended for filesystem
// implementations to adapt:
//   - Have a local fileDescription struct (containing FileDescription) which
//     embeds FileDescriptionDefaultImpl and overrides the default methods
//     which are common to all fd implementations for that for that filesystem
//     like StatusFlags, SetStatusFlags, Stat, SetStat, StatFS, etc.
//   - This should be embedded in all file description implementations as the
//     first field by value.
//   - Directory FDs would also embed DirectoryFileDescriptionDefaultImpl.

// FileDescriptionDefaultImpl may be embedded by implementations of
// FileDescriptionImpl to obtain implementations of many FileDescriptionImpl
// methods with default behavior analogous to Linux's.
type FileDescriptionDefaultImpl struct{}

// OnClose implements FileDescriptionImpl.OnClose analogously to
// file_operations::flush == NULL in Linux.
func (FileDescriptionDefaultImpl) OnClose(ctx context.Context) error {
	return nil
}

// StatFS implements FileDescriptionImpl.StatFS analogously to
// super_operations::statfs == NULL in Linux.
func (FileDescriptionDefaultImpl) StatFS(ctx context.Context) (linux.Statfs, error) {
	return linux.Statfs{}, syserror.ENOSYS
}

// Readiness implements waiter.Waitable.Readiness analogously to
// file_operations::poll == NULL in Linux.
func (FileDescriptionDefaultImpl) Readiness(mask waiter.EventMask) waiter.EventMask {
	// include/linux/poll.h:vfs_poll() => DEFAULT_POLLMASK
	return waiter.EventIn | waiter.EventOut
}

// EventRegister implements waiter.Waitable.EventRegister analogously to
// file_operations::poll == NULL in Linux.
func (FileDescriptionDefaultImpl) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
}

// EventUnregister implements waiter.Waitable.EventUnregister analogously to
// file_operations::poll == NULL in Linux.
func (FileDescriptionDefaultImpl) EventUnregister(e *waiter.Entry) {
}

// PRead implements FileDescriptionImpl.PRead analogously to
// file_operations::read == file_operations::read_iter == NULL in Linux.
func (FileDescriptionDefaultImpl) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts ReadOptions) (int64, error) {
	return 0, syserror.EINVAL
}

// Read implements FileDescriptionImpl.Read analogously to
// file_operations::read == file_operations::read_iter == NULL in Linux.
func (FileDescriptionDefaultImpl) Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error) {
	return 0, syserror.EINVAL
}

// PWrite implements FileDescriptionImpl.PWrite analogously to
// file_operations::write == file_operations::write_iter == NULL in Linux.
func (FileDescriptionDefaultImpl) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (int64, error) {
	return 0, syserror.EINVAL
}

// Write implements FileDescriptionImpl.Write analogously to
// file_operations::write == file_operations::write_iter == NULL in Linux.
func (FileDescriptionDefaultImpl) Write(ctx context.Context, src usermem.IOSequence, opts WriteOptions) (int64, error) {
	return 0, syserror.EINVAL
}

// IterDirents implements FileDescriptionImpl.IterDirents analogously to
// file_operations::iterate == file_operations::iterate_shared == NULL in
// Linux.
func (FileDescriptionDefaultImpl) IterDirents(ctx context.Context, cb IterDirentsCallback) error {
	return syserror.ENOTDIR
}

// Seek implements FileDescriptionImpl.Seek analogously to
// file_operations::llseek == NULL in Linux.
func (FileDescriptionDefaultImpl) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, syserror.ESPIPE
}

// Sync implements FileDescriptionImpl.Sync analogously to
// file_operations::fsync == NULL in Linux.
func (FileDescriptionDefaultImpl) Sync(ctx context.Context) error {
	return syserror.EINVAL
}

// ConfigureMMap implements FileDescriptionImpl.ConfigureMMap analogously to
// file_operations::mmap == NULL in Linux.
func (FileDescriptionDefaultImpl) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return syserror.ENODEV
}

// Ioctl implements FileDescriptionImpl.Ioctl analogously to
// file_operations::unlocked_ioctl == NULL in Linux.
func (FileDescriptionDefaultImpl) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return 0, syserror.ENOTTY
}

// Listxattr implements FileDescriptionImpl.Listxattr analogously to
// inode_operations::listxattr == NULL in Linux.
func (FileDescriptionDefaultImpl) Listxattr(ctx context.Context) ([]string, error) {
	// This isn't exactly accurate; see FileDescription.Listxattr.
	return nil, syserror.ENOTSUP
}

// Getxattr implements FileDescriptionImpl.Getxattr analogously to
// inode::i_opflags & IOP_XATTR == 0 in Linux.
func (FileDescriptionDefaultImpl) Getxattr(ctx context.Context, name string) (string, error) {
	return "", syserror.ENOTSUP
}

// Setxattr implements FileDescriptionImpl.Setxattr analogously to
// inode::i_opflags & IOP_XATTR == 0 in Linux.
func (FileDescriptionDefaultImpl) Setxattr(ctx context.Context, opts SetxattrOptions) error {
	return syserror.ENOTSUP
}

// Removexattr implements FileDescriptionImpl.Removexattr analogously to
// inode::i_opflags & IOP_XATTR == 0 in Linux.
func (FileDescriptionDefaultImpl) Removexattr(ctx context.Context, name string) error {
	return syserror.ENOTSUP
}

// DirectoryFileDescriptionDefaultImpl may be embedded by implementations of
// FileDescriptionImpl that always represent directories to obtain
// implementations of non-directory I/O methods that return EISDIR.
type DirectoryFileDescriptionDefaultImpl struct{}

// PRead implements FileDescriptionImpl.PRead.
func (DirectoryFileDescriptionDefaultImpl) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts ReadOptions) (int64, error) {
	return 0, syserror.EISDIR
}

// Read implements FileDescriptionImpl.Read.
func (DirectoryFileDescriptionDefaultImpl) Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error) {
	return 0, syserror.EISDIR
}

// PWrite implements FileDescriptionImpl.PWrite.
func (DirectoryFileDescriptionDefaultImpl) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (int64, error) {
	return 0, syserror.EISDIR
}

// Write implements FileDescriptionImpl.Write.
func (DirectoryFileDescriptionDefaultImpl) Write(ctx context.Context, src usermem.IOSequence, opts WriteOptions) (int64, error) {
	return 0, syserror.EISDIR
}

// DynamicBytesFileDescriptionImpl may be embedded by implementations of
// FileDescriptionImpl that represent read-only regular files whose contents
// are backed by a bytes.Buffer that is regenerated when necessary, consistent
// with Linux's fs/seq_file.c:single_open().
//
// DynamicBytesFileDescriptionImpl.SetDataSource() must be called before first
// use.
type DynamicBytesFileDescriptionImpl struct {
	data     DynamicBytesSource // immutable
	mu       sync.Mutex         // protects the following fields
	buf      bytes.Buffer
	off      int64
	lastRead int64 // offset at which the last Read, PRead, or Seek ended
}

// DynamicBytesSource represents a data source for a
// DynamicBytesFileDescriptionImpl.
type DynamicBytesSource interface {
	// Generate writes the file's contents to buf.
	Generate(ctx context.Context, buf *bytes.Buffer) error
}

// SetDataSource must be called exactly once on fd before first use.
func (fd *DynamicBytesFileDescriptionImpl) SetDataSource(data DynamicBytesSource) {
	fd.data = data
}

// Preconditions: fd.mu must be locked.
func (fd *DynamicBytesFileDescriptionImpl) preadLocked(ctx context.Context, dst usermem.IOSequence, offset int64, opts *ReadOptions) (int64, error) {
	// Regenerate the buffer if it's empty, or before pread() at a new offset.
	// Compare fs/seq_file.c:seq_read() => traverse().
	switch {
	case offset != fd.lastRead:
		fd.buf.Reset()
		fallthrough
	case fd.buf.Len() == 0:
		if err := fd.data.Generate(ctx, &fd.buf); err != nil {
			fd.buf.Reset()
			// fd.off is not updated in this case.
			fd.lastRead = 0
			return 0, err
		}
	}
	bs := fd.buf.Bytes()
	if offset >= int64(len(bs)) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, bs[offset:])
	fd.lastRead = offset + int64(n)
	return int64(n), err
}

// PRead implements FileDescriptionImpl.PRead.
func (fd *DynamicBytesFileDescriptionImpl) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts ReadOptions) (int64, error) {
	fd.mu.Lock()
	n, err := fd.preadLocked(ctx, dst, offset, &opts)
	fd.mu.Unlock()
	return n, err
}

// Read implements FileDescriptionImpl.Read.
func (fd *DynamicBytesFileDescriptionImpl) Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error) {
	fd.mu.Lock()
	n, err := fd.preadLocked(ctx, dst, fd.off, &opts)
	fd.off += n
	fd.mu.Unlock()
	return n, err
}

// Seek implements FileDescriptionImpl.Seek.
func (fd *DynamicBytesFileDescriptionImpl) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	switch whence {
	case linux.SEEK_SET:
		// Use offset as given.
	case linux.SEEK_CUR:
		offset += fd.off
	default:
		// fs/seq_file:seq_lseek() rejects SEEK_END etc.
		return 0, syserror.EINVAL
	}
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	if offset != fd.lastRead {
		// Regenerate the file's contents immediately. Compare
		// fs/seq_file.c:seq_lseek() => traverse().
		fd.buf.Reset()
		if err := fd.data.Generate(ctx, &fd.buf); err != nil {
			fd.buf.Reset()
			fd.off = 0
			fd.lastRead = 0
			return 0, err
		}
		fd.lastRead = offset
	}
	fd.off = offset
	return offset, nil
}

// GenericConfigureMMap may be used by most implementations of
// FileDescriptionImpl.ConfigureMMap.
func GenericConfigureMMap(fd *FileDescription, m memmap.Mappable, opts *memmap.MMapOpts) error {
	opts.Mappable = m
	opts.MappingIdentity = fd
	fd.IncRef()
	return nil
}
