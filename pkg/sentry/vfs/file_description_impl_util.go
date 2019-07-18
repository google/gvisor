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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// FileDescriptionDefaultImpl may be embedded by implementations of
// FileDescriptionImpl to obtain implementations of many FileDescriptionImpl
// methods with default behavior analogous to Linux's.
type FileDescriptionDefaultImpl struct{}

// OnClose implements FileDescriptionImpl.OnClose analogously to
// file_operations::flush == NULL in Linux.
func (FileDescriptionDefaultImpl) OnClose() error {
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
func (FileDescriptionDefaultImpl) ConfigureMMap(ctx context.Context, opts memmap.MMapOpts) error {
	return syserror.ENODEV
}

// Ioctl implements FileDescriptionImpl.Ioctl analogously to
// file_operations::unlocked_ioctl == NULL in Linux.
func (FileDescriptionDefaultImpl) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return 0, syserror.ENOTTY
}

// DirectoryFileDescriptionDefaultImpl may be embedded by implementations of
// FileDescriptionImpl that always represent directories to obtain
// implementations of non-directory I/O methods that return EISDIR, and
// implementations of other methods consistent with FileDescriptionDefaultImpl.
type DirectoryFileDescriptionDefaultImpl struct {
	FileDescriptionDefaultImpl
}

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
