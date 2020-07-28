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
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// fileDescription implements vfs.FileDescriptionImpl for fuse.
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.NoLockFD

	// the file handle used in userspace.
	Fh uint64

	// Nonseekable is indicate cannot perform seek on a file.
	Nonseekable bool

	// directIO suggest fuse to use direct io operation.
	directIO bool

	// OpenFlag is the flag returned by open.
	OpenFlag uint32

	// off is the file offset.
	off int64
}

func (fd *fileDescription) inode() *inode {
	return fd.vfsfd.Dentry().Impl().(*kernfs.Dentry).Inode().(*inode)
}

func (fd *fileDescription) statusFlags() uint32 {
	return fd.vfsfd.StatusFlags()
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *fileDescription) Release(ctx context.Context) {}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *fileDescription) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, nil
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *fileDescription) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return 0, nil
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *fileDescription) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, nil
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *fileDescription) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *fileDescription) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, nil
}

// Stat implements FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	return fd.inode().Stat(ctx, fd.inode().fs.VFSFilesystem(), opts)
}

// SetStat implements FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	creds := auth.CredentialsFromContext(ctx)
	return fd.inode().SetStat(ctx, fd.inode().fs.VFSFilesystem(), creds, opts)
}
