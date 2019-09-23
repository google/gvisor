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

package memdirfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// DynamicBytesFileDefaultInodeImpl implements InodeImpl for read-only regular
// files whose contents are backed by a vfs.DynamicBytesSource.
//
// Must be initialized by DynamicBytesFileDefaultInodeImpl.Init() before first
// use.
type DynamicBytesFileDefaultInodeImpl struct {
	data vfs.DynamicBytesSource // Immutable after Init().
}

// Init initializes a DynamicBytesFileDefaultInodeImpl. This must be called once
// before the inode impl is used.
func (i *DynamicBytesFileDefaultInodeImpl) Init(data vfs.DynamicBytesSource) {
	i.data = data
}

// Open implements InodeImpl.Open.
func (i *DynamicBytesFileDefaultInodeImpl) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error) {
	return NewDynamicBytesFD(rp, vfsd, i, i.data, flags).VFSFileDescription(), nil
}

// DynamicLookup implements InodeImpl.DynamicLookup.
func (i *DynamicBytesFileDefaultInodeImpl) DynamicLookup(rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	return nil, syserror.ENOTDIR
}

// Stat implements InodeImpl.Stat.
func (i *DynamicBytesFileDefaultInodeImpl) Stat(stat *linux.Statx) {
	stat.Mode |= linux.S_IFREG
}

// DynamicBytesFD represents a file description backed by a read-only regular
// file where the contents of the files come from a vfs.DynamicBytesSource.
type DynamicBytesFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DynamicBytesFileDescriptionImpl

	inodeImpl InodeImpl
	flags     uint32
}

// NewDynamicBytesFD creates a new DynamicBytesFD.
func NewDynamicBytesFD(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, inodeImpl InodeImpl, data vfs.DynamicBytesSource, openFlags uint32) *DynamicBytesFD {
	mnt := rp.Mount()

	var fd DynamicBytesFD
	fd.flags = openFlags
	fd.inodeImpl = inodeImpl

	fd.SetDataSource(data)

	vfsd.Impl().IncRef(mnt.Filesystem()) // DecRef in DynamicBytesFD.Release
	fd.vfsfd.Init(&fd, mnt, vfsd)
	return &fd
}

// VFSFileDescription returns the vfs file description object for this fd.
func (fd *DynamicBytesFD) VFSFileDescription() *vfs.FileDescription {
	return &fd.vfsfd
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *DynamicBytesFD) Release() {
	vd := fd.vfsfd.VirtualDentry()
	vd.Dentry().Impl().DecRef(vd.Mount().Filesystem()) // IncRef from newDynamicBytesFile.
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *DynamicBytesFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	var stat linux.Statx
	fd.inodeImpl.Stat(&stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *DynamicBytesFD) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask == 0 {
		return nil
	}
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

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *DynamicBytesFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.Read(ctx, dst, opts)
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *DynamicBytesFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.PRead(ctx, dst, offset, opts)
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *DynamicBytesFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.Seek(ctx, offset, whence)
}
