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

package kernfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// DynamicBytesFile implements kernfs.Inode and represents a read-only
// file whose contents are backed by a vfs.DynamicBytesSource.
//
// Must be initialized with Init before first use.
type DynamicBytesFile struct {
	InodeAttrs
	InodeNoopRefCount
	InodeNotDirectory
	InodeNotSymlink

	data vfs.DynamicBytesSource
}

// Init intializes a dynamic bytes file.
func (f *DynamicBytesFile) Init(creds *auth.Credentials, ino uint64, data vfs.DynamicBytesSource) {
	f.InodeAttrs.Init(creds, ino, linux.ModeRegular|0444)
	f.data = data
}

// Open implements Inode.Open.
func (f *DynamicBytesFile) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error) {
	fd := &DynamicBytesFD{}
	fd.Init(rp.Mount(), vfsd, f.data, flags)
	return &fd.vfsfd, nil
}

// SetStat implements Inode.SetStat.
func (f *DynamicBytesFile) SetStat(*vfs.Filesystem, vfs.SetStatOptions) error {
	// DynamicBytesFiles are immutable.
	return syserror.EPERM
}

// DynamicBytesFD implements vfs.FileDescriptionImpl for an FD backed by a
// DynamicBytesFile.
//
// Must be initialized with Init before first use.
type DynamicBytesFD struct {
	vfs.FileDescriptionDefaultImpl
	vfs.DynamicBytesFileDescriptionImpl

	vfsfd vfs.FileDescription
	inode Inode
	flags uint32
}

// Init initializes a DynamicBytesFD.
func (fd *DynamicBytesFD) Init(m *vfs.Mount, d *vfs.Dentry, data vfs.DynamicBytesSource, flags uint32) {
	m.IncRef() // DecRef in vfs.FileDescription.vd.DecRef on final ref.
	d.IncRef() // DecRef in vfs.FileDescription.vd.DecRef on final ref.
	fd.flags = flags
	fd.inode = d.Impl().(*Dentry).inode
	fd.SetDataSource(data)
	fd.vfsfd.Init(fd, m, d)
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *DynamicBytesFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.Seek(ctx, offset, whence)
}

// Read implmenets vfs.FileDescriptionImpl.Read.
func (fd *DynamicBytesFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.Read(ctx, dst, opts)
}

// PRead implmenets vfs.FileDescriptionImpl.PRead.
func (fd *DynamicBytesFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.PRead(ctx, dst, offset, opts)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *DynamicBytesFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return fd.FileDescriptionDefaultImpl.Write(ctx, src, opts)
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *DynamicBytesFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return fd.FileDescriptionDefaultImpl.PWrite(ctx, src, offset, opts)
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *DynamicBytesFD) Release() {}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *DynamicBytesFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	fs := fd.vfsfd.VirtualDentry().Mount().Filesystem()
	return fd.inode.Stat(fs), nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *DynamicBytesFD) SetStat(context.Context, vfs.SetStatOptions) error {
	// DynamicBytesFiles are immutable.
	return syserror.EPERM
}

// StatusFlags implements vfs.FileDescriptionImpl.StatusFlags.
func (fd *DynamicBytesFD) StatusFlags(ctx context.Context) (uint32, error) {
	return fd.flags, nil
}

// SetStatusFlags implements vfs.FileDescriptionImpl.SetStatusFlags.
func (fd *DynamicBytesFD) SetStatusFlags(ctx context.Context, flags uint32) error {
	// None of the flags settable by fcntl(F_SETFL) are supported, so this is a
	// no-op.
	return nil
}
