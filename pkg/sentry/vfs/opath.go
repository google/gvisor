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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// opathFD implements vfs.FileDescriptionImpl.
//
// +stateify savable
type opathFD struct {
	vfsfd FileDescription
	FileDescriptionDefaultImpl
	NoLockFD
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *opathFD) Release(context.Context) {
	// noop
}

// Allocate implements vfs.FileDescriptionImpl.Allocate.
func (fd *opathFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	return syserror.ENODEV
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *opathFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts ReadOptions) (int64, error) {
	return 0, syserror.EBADF
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *opathFD) Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error) {
	return 0, syserror.EBADF
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *opathFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (int64, error) {
	return 0, syserror.EBADF
}

// pwrite returns the number of bytes written, final offset and error. The
// final offset should be ignored by PWrite.
func (fd *opathFD) pwrite(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (written, finalOff int64, err error) {
	return 0, 0, syserror.EBADF
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *opathFD) Write(ctx context.Context, src usermem.IOSequence, opts WriteOptions) (int64, error) {
	return 0, syserror.EBADF
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *opathFD) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return 0, syserror.EBADF
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *opathFD) IterDirents(ctx context.Context, cb IterDirentsCallback) error {
	return syserror.ENOTDIR
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *opathFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, syserror.EBADF
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *opathFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return syserror.EBADF
}

// ListXattr implements vfs.FileDescriptionImpl.ListXattr.
func (fd *opathFD) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	return nil, syserror.EBADF
}

// GetXattr implements vfs.FileDescriptionImpl.GetXattr.
func (fd *opathFD) GetXattr(ctx context.Context, opts GetXattrOptions) (string, error) {
	return "", syserror.EBADF
}

// SetXattr implements vfs.FileDescriptionImpl.SetXattr.
func (fd *opathFD) SetXattr(ctx context.Context, opts SetXattrOptions) error {
	return syserror.EBADF
}

// RemoveXattr implements vfs.FileDescriptionImpl.RemoveXattr.
func (fd *opathFD) RemoveXattr(ctx context.Context, name string) error {
	return syserror.EBADF
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (fd *opathFD) Sync(ctx context.Context) error {
	return syserror.EBADF
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *opathFD) SetStat(ctx context.Context, opts SetStatOptions) error {
	return syserror.EBADF
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *opathFD) Stat(ctx context.Context, opts StatOptions) (linux.Statx, error) {
	var stat linux.Statx
	return stat, nil
}
