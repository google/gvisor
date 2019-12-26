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
	"fmt"

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
// Must be instantiated with NewDynamicBytesFile or initialized with Init
// before first use.
//
// +stateify savable
type DynamicBytesFile struct {
	InodeAttrs
	InodeNoopRefCount
	InodeNotDirectory
	InodeNotSymlink

	data vfs.DynamicBytesSource
}

var _ Inode = (*DynamicBytesFile)(nil)

// Init initializes a dynamic bytes file.
func (f *DynamicBytesFile) Init(creds *auth.Credentials, ino uint64, data vfs.DynamicBytesSource, perm linux.FileMode) {
	if perm&^linux.PermissionsMask != 0 {
		panic(fmt.Sprintf("Only permission mask must be set: %x", perm&linux.PermissionsMask))
	}
	f.InodeAttrs.Init(creds, ino, linux.ModeRegular|perm)
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
//
// +stateify savable
type DynamicBytesFD struct {
	vfs.FileDescriptionDefaultImpl
	vfs.DynamicBytesFileDescriptionImpl

	vfsfd vfs.FileDescription
	inode Inode
}

// Init initializes a DynamicBytesFD.
func (fd *DynamicBytesFD) Init(m *vfs.Mount, d *vfs.Dentry, data vfs.DynamicBytesSource, flags uint32) {
	m.IncRef() // DecRef in vfs.FileDescription.vd.DecRef on final ref.
	d.IncRef() // DecRef in vfs.FileDescription.vd.DecRef on final ref.
	fd.inode = d.Impl().(*Dentry).inode
	fd.SetDataSource(data)
	fd.vfsfd.Init(fd, flags, m, d, &vfs.FileDescriptionOptions{})
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
