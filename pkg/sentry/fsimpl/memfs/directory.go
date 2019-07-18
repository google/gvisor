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

package memfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

type directory struct {
	inode Inode

	// childList is a list containing (1) child Dentries and (2) fake Dentries
	// (with inode == nil) that represent the iteration position of
	// directoryFDs. childList is used to support directoryFD.IterDirents()
	// efficiently. childList is protected by Filesystem.mu.
	childList dentryList
}

func (fs *Filesystem) newDirectory(creds *auth.Credentials, mode uint16) *Inode {
	dir := &directory{}
	dir.inode.init(dir, fs, creds, mode)
	dir.inode.nlink = 2 // from "." and parent directory or ".." for root
	return &dir.inode
}

func (i *Inode) isDir() bool {
	_, ok := i.impl.(*directory)
	return ok
}

type directoryFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl

	// Protected by Filesystem.mu.
	iter *Dentry
	off  int64
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *directoryFD) Release() {
	if fd.iter != nil {
		fs := fd.filesystem()
		dir := fd.inode().impl.(*directory)
		fs.mu.Lock()
		dir.childList.Remove(fd.iter)
		fs.mu.Unlock()
		fd.iter = nil
	}
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *directoryFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	fs := fd.filesystem()
	d := fd.vfsfd.VirtualDentry().Dentry()

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fd.off == 0 {
		if !cb.Handle(vfs.Dirent{
			Name: ".",
			Type: linux.DT_DIR,
			Ino:  d.Impl().(*Dentry).inode.ino,
			Off:  0,
		}) {
			return nil
		}
		fd.off++
	}
	if fd.off == 1 {
		parentInode := d.ParentOrSelf().Impl().(*Dentry).inode
		if !cb.Handle(vfs.Dirent{
			Name: "..",
			Type: parentInode.direntType(),
			Ino:  parentInode.ino,
			Off:  1,
		}) {
			return nil
		}
		fd.off++
	}

	dir := d.Impl().(*Dentry).inode.impl.(*directory)
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
				Name: child.vfsd.Name(),
				Type: child.inode.direntType(),
				Ino:  child.inode.ino,
				Off:  fd.off,
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
	if whence != linux.SEEK_SET {
		// TODO: Linux also allows SEEK_CUR.
		return 0, syserror.EINVAL
	}
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	fd.off = offset
	// Compensate for "." and "..".
	var remChildren int64
	if offset < 2 {
		remChildren = 0
	} else {
		remChildren = offset - 2
	}

	fs := fd.filesystem()
	dir := fd.inode().impl.(*directory)

	fs.mu.Lock()
	defer fs.mu.Unlock()

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
