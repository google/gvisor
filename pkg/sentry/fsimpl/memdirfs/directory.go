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
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Directory implements InodeImpl. A basic directory doesn't support
// any dynamic children. Dynamic directories should embed Diectory and
// override Directory.DynamicLookup.
type Directory struct {
	childList DentryList
}

// NewDirectoryInode creates a new inode representing a directory.
func (fs *Filesystem) NewDirectoryInode(creds *auth.Credentials, mode linux.FileMode) *Inode {
	return fs.NewInode(InodeOpts{Creds: creds, Mode: mode, Dir: true, Impl: &Directory{}})
}

// Open implements InodeImpl.Open.
func (d *Directory) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error) {
	// Can't open directories writably.
	if vfs.MayWriteFileWithOpenFlags(flags) {
		return nil, syserror.EISDIR
	}
	fd := &directoryFD{}
	fd.vfsfd.Init(fd, rp.Mount(), vfsd)
	fd.flags = flags
	return &fd.vfsfd, nil
}

// DynamicLookup implements InodeImpl.DynamicLookup.
func (d *Directory) DynamicLookup(rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	return nil, syserror.ENOENT
}

// Stat implements InodeImpl.Stat.
func (*Directory) Stat(stat *linux.Statx) {
	stat.Mode |= linux.S_IFDIR
}

type directoryFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl

	iter *Dentry
	off  int64
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *directoryFD) Release() {
	if fd.iter != nil {
		fs := fd.filesystem()
		dir := fd.inode().impl.(*Directory)
		fs.mu.Lock()
		dir.childList.Remove(fd.iter)
		fs.mu.Unlock()
		fd.iter = nil
	}
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *directoryFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	fs := fd.filesystem()
	vfsd := fd.vfsfd.VirtualDentry().Dentry()

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fd.off == 0 {
		if !cb.Handle(vfs.Dirent{
			Name:    ".",
			Type:    linux.DT_DIR,
			Ino:     vfsd.Impl().(*Dentry).inode.ino,
			NextOff: 1,
		}) {
			return nil
		}
		fd.off++
	}
	if fd.off == 1 {
		parentInode := vfsd.ParentOrSelf().Impl().(*Dentry).inode
		if !cb.Handle(vfs.Dirent{
			Name:    "..",
			Type:    parentInode.direntType(),
			Ino:     parentInode.ino,
			NextOff: 2,
		}) {
			return nil
		}
		fd.off++
	}

	// TODO: support iterating over dynamic children.

	dir := vfsd.Impl().(*Dentry).inode.impl.(*Directory)
	var child *Dentry
	if fd.iter == nil {
		// Start iteration at the beginning of dir.
		child = dir.childList.Front()
		fd.iter = &Dentry{}
	} else {
		// Continue iteration from where we left off.
		child = fd.iter.Next()
		dir.childList.Remove(fd.iter)
	}
	for child != nil {
		// Skip other directoryFD iterators.
		if child.inode != nil {
			if !cb.Handle(vfs.Dirent{
				Name:    child.vfsd.Name(),
				Type:    child.inode.direntType(),
				Ino:     child.inode.ino,
				NextOff: fd.off + 1,
			}) {
				dir.childList.InsertBefore(child, fd.iter)
				return nil
			}
			fd.off++
		}
		child = child.Next()
	}
	dir.childList.PushBack(fd.iter)
	return nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *directoryFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fs := fd.filesystem()
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

	// If the offset isn't changing (e.g. due to lseek(0, SEEK_CUR)), don't
	// seek even if doing so might reposition the iterator due to concurrent
	// mutation of the directory. Compare fs/libfs.c:dcache_dir_lseek().
	if fd.off == offset {
		return offset, nil
	}

	fd.off = offset
	// Compensate for "." and "..".
	remChildren := int64(0)
	if offset >= 2 {
		remChildren = offset - 2
	}

	// TODO: support seek for dynamic children.

	dir := fd.inode().impl.(*Directory)

	// Ensure that fd.iter exists and is not linked into dir.childList.
	if fd.iter == nil {
		fd.iter = &Dentry{}
	} else {
		dir.childList.Remove(fd.iter)
	}
	// Insert fd.iter before the remChildren'th child, or at the end of the
	// list if remChildren >= number of children.
	child := dir.childList.Front()
	for child != nil {
		// Skip other directoryFD iterators.
		if child.inode != nil {
			if remChildren == 0 {
				dir.childList.InsertBefore(child, fd.iter)
				return offset, nil
			}
			remChildren--
		}
		child = child.Next()
	}
	dir.childList.PushBack(fd.iter)
	return offset, nil
}
