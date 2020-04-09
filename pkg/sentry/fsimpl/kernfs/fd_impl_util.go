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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// GenericDirectoryFD implements vfs.FileDescriptionImpl for a generic directory
// inode that uses OrderChildren to track child nodes. GenericDirectoryFD is not
// compatible with dynamic directories.
//
// Note that GenericDirectoryFD holds a lock over OrderedChildren while calling
// IterDirents callback. The IterDirents callback therefore cannot hash or
// unhash children, or recursively call IterDirents on the same underlying
// inode.
//
// Must be initialize with Init before first use.
type GenericDirectoryFD struct {
	vfs.FileDescriptionDefaultImpl
	vfs.DirectoryFileDescriptionDefaultImpl

	vfsfd    vfs.FileDescription
	children *OrderedChildren
	off      int64
}

// Init initializes a GenericDirectoryFD.
func (fd *GenericDirectoryFD) Init(m *vfs.Mount, d *vfs.Dentry, children *OrderedChildren, opts *vfs.OpenOptions) error {
	if vfs.AccessTypesForOpenFlags(opts)&vfs.MayWrite != 0 {
		// Can't open directories for writing.
		return syserror.EISDIR
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, m, d, &vfs.FileDescriptionOptions{}); err != nil {
		return err
	}
	fd.children = children
	return nil
}

// VFSFileDescription returns a pointer to the vfs.FileDescription representing
// this object.
func (fd *GenericDirectoryFD) VFSFileDescription() *vfs.FileDescription {
	return &fd.vfsfd
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *GenericDirectoryFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return fd.FileDescriptionDefaultImpl.ConfigureMMap(ctx, opts)
}

// Read implmenets vfs.FileDescriptionImpl.Read.
func (fd *GenericDirectoryFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return fd.DirectoryFileDescriptionDefaultImpl.Read(ctx, dst, opts)
}

// PRead implmenets vfs.FileDescriptionImpl.PRead.
func (fd *GenericDirectoryFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return fd.DirectoryFileDescriptionDefaultImpl.PRead(ctx, dst, offset, opts)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *GenericDirectoryFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return fd.DirectoryFileDescriptionDefaultImpl.Write(ctx, src, opts)
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *GenericDirectoryFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return fd.DirectoryFileDescriptionDefaultImpl.PWrite(ctx, src, offset, opts)
}

// Release implements vfs.FileDecriptionImpl.Release.
func (fd *GenericDirectoryFD) Release() {}

func (fd *GenericDirectoryFD) filesystem() *vfs.Filesystem {
	return fd.vfsfd.VirtualDentry().Mount().Filesystem()
}

func (fd *GenericDirectoryFD) inode() Inode {
	return fd.vfsfd.VirtualDentry().Dentry().Impl().(*Dentry).inode
}

// IterDirents implements vfs.FileDecriptionImpl.IterDirents. IterDirents holds
// o.mu when calling cb.
func (fd *GenericDirectoryFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	vfsFS := fd.filesystem()
	fs := vfsFS.Impl().(*Filesystem)
	vfsd := fd.vfsfd.VirtualDentry().Dentry()

	fs.mu.Lock()
	defer fs.mu.Unlock()

	opts := vfs.StatOptions{Mask: linux.STATX_INO}
	// Handle ".".
	if fd.off == 0 {
		stat, err := fd.inode().Stat(vfsFS, opts)
		if err != nil {
			return err
		}
		dirent := vfs.Dirent{
			Name:    ".",
			Type:    linux.DT_DIR,
			Ino:     stat.Ino,
			NextOff: 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return err
		}
		fd.off++
	}

	// Handle "..".
	if fd.off == 1 {
		parentInode := vfsd.ParentOrSelf().Impl().(*Dentry).inode
		stat, err := parentInode.Stat(vfsFS, opts)
		if err != nil {
			return err
		}
		dirent := vfs.Dirent{
			Name:    "..",
			Type:    linux.FileMode(stat.Mode).DirentType(),
			Ino:     stat.Ino,
			NextOff: 2,
		}
		if err := cb.Handle(dirent); err != nil {
			return err
		}
		fd.off++
	}

	// Handle static children.
	fd.children.mu.RLock()
	defer fd.children.mu.RUnlock()
	// fd.off accounts for "." and "..", but fd.children do not track
	// these.
	childIdx := fd.off - 2
	for it := fd.children.nthLocked(childIdx); it != nil; it = it.Next() {
		inode := it.Dentry.Impl().(*Dentry).inode
		stat, err := inode.Stat(vfsFS, opts)
		if err != nil {
			return err
		}
		dirent := vfs.Dirent{
			Name:    it.Name,
			Type:    linux.FileMode(stat.Mode).DirentType(),
			Ino:     stat.Ino,
			NextOff: fd.off + 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return err
		}
		fd.off++
	}

	var err error
	relOffset := fd.off - int64(len(fd.children.set)) - 2
	fd.off, err = fd.inode().IterDirents(ctx, cb, fd.off, relOffset)
	return err
}

// Seek implements vfs.FileDecriptionImpl.Seek.
func (fd *GenericDirectoryFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fs := fd.filesystem().Impl().(*Filesystem)
	fs.mu.Lock()
	defer fs.mu.Unlock()

	switch whence {
	case linux.SEEK_SET:
		// Use offset as given.
	case linux.SEEK_CUR:
		offset += fd.off
	default:
		return 0, syserror.EINVAL
	}
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	fd.off = offset
	return offset, nil
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *GenericDirectoryFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	fs := fd.filesystem()
	inode := fd.inode()
	return inode.Stat(fs, opts)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *GenericDirectoryFD) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	creds := auth.CredentialsFromContext(ctx)
	inode := fd.vfsfd.VirtualDentry().Dentry().Impl().(*Dentry).inode
	return inode.SetStat(ctx, fd.filesystem(), creds, opts)
}
