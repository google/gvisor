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

package tmpfs

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// +stateify savable
type directory struct {
	// Since directories can't be hard-linked, each directory can only be
	// associated with a single dentry, which we can store in the directory
	// struct.
	dentry dentry
	inode  inode

	// childMap maps the names of the directory's children to their dentries.
	// childMap is protected by filesystem.mu.
	childMap map[string]*dentry

	// numChildren is len(childMap), but accessed using atomic memory
	// operations to avoid locking in inode.statTo().
	numChildren int64

	// childList is a list containing (1) child dentries and (2) fake dentries
	// (with inode == nil) that represent the iteration position of
	// directoryFDs. childList is used to support directoryFD.IterDirents()
	// efficiently. childList is protected by iterMu.
	iterMu    sync.Mutex `state:"nosave"`
	childList dentryList
}

func (fs *filesystem) newDirectory(kuid auth.KUID, kgid auth.KGID, mode linux.FileMode, parentDir *directory) *directory {
	dir := &directory{}
	dir.inode.init(dir, fs, kuid, kgid, linux.S_IFDIR|mode, parentDir)
	dir.inode.nlink = 2 // from "." and parent directory or ".." for root
	dir.dentry.inode = &dir.inode
	dir.dentry.vfsd.Init(&dir.dentry)
	return dir
}

// Preconditions:
// * filesystem.mu must be locked for writing.
// * dir must not already contain a child with the given name.
func (dir *directory) insertChildLocked(child *dentry, name string) {
	child.parent = &dir.dentry
	child.name = name
	if dir.childMap == nil {
		dir.childMap = make(map[string]*dentry)
	}
	dir.childMap[name] = child
	atomic.AddInt64(&dir.numChildren, 1)
	dir.iterMu.Lock()
	dir.childList.PushBack(child)
	dir.iterMu.Unlock()
}

// Preconditions: filesystem.mu must be locked for writing.
func (dir *directory) removeChildLocked(child *dentry) {
	delete(dir.childMap, child.name)
	atomic.AddInt64(&dir.numChildren, -1)
	dir.iterMu.Lock()
	dir.childList.Remove(child)
	dir.iterMu.Unlock()
}

func (dir *directory) mayDelete(creds *auth.Credentials, child *dentry) error {
	return vfs.CheckDeleteSticky(
		creds,
		linux.FileMode(atomic.LoadUint32(&dir.inode.mode)),
		auth.KUID(atomic.LoadUint32(&dir.inode.uid)),
		auth.KUID(atomic.LoadUint32(&child.inode.uid)),
		auth.KGID(atomic.LoadUint32(&child.inode.gid)),
	)
}

// +stateify savable
type directoryFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl

	// Protected by directory.iterMu.
	iter *dentry
	off  int64
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *directoryFD) Release(ctx context.Context) {
	if fd.iter != nil {
		dir := fd.inode().impl.(*directory)
		dir.iterMu.Lock()
		dir.childList.Remove(fd.iter)
		dir.iterMu.Unlock()
		fd.iter = nil
	}
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *directoryFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	fs := fd.filesystem()
	dir := fd.inode().impl.(*directory)

	defer fd.dentry().InotifyWithParent(ctx, linux.IN_ACCESS, 0, vfs.PathEvent)

	// fs.mu is required to read d.parent and dentry.name.
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	dir.iterMu.Lock()
	defer dir.iterMu.Unlock()

	fd.inode().touchAtime(fd.vfsfd.Mount())

	if fd.off == 0 {
		if err := cb.Handle(vfs.Dirent{
			Name:    ".",
			Type:    linux.DT_DIR,
			Ino:     dir.inode.ino,
			NextOff: 1,
		}); err != nil {
			return err
		}
		fd.off++
	}

	if fd.off == 1 {
		parentInode := genericParentOrSelf(&dir.dentry).inode
		if err := cb.Handle(vfs.Dirent{
			Name:    "..",
			Type:    parentInode.direntType(),
			Ino:     parentInode.ino,
			NextOff: 2,
		}); err != nil {
			return err
		}
		fd.off++
	}

	var child *dentry
	if fd.iter == nil {
		// Start iteration at the beginning of dir.
		child = dir.childList.Front()
		fd.iter = &dentry{}
	} else {
		// Continue iteration from where we left off.
		child = fd.iter.Next()
		dir.childList.Remove(fd.iter)
	}
	for child != nil {
		// Skip other directoryFD iterators.
		if child.inode != nil {
			if err := cb.Handle(vfs.Dirent{
				Name:    child.name,
				Type:    child.inode.direntType(),
				Ino:     child.inode.ino,
				NextOff: fd.off + 1,
			}); err != nil {
				dir.childList.InsertBefore(child, fd.iter)
				return err
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
	dir := fd.inode().impl.(*directory)
	dir.iterMu.Lock()
	defer dir.iterMu.Unlock()

	switch whence {
	case linux.SEEK_SET:
		// Use offset as given.
	case linux.SEEK_CUR:
		offset += fd.off
	default:
		return 0, linuxerr.EINVAL
	}
	if offset < 0 {
		return 0, linuxerr.EINVAL
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

	// Ensure that fd.iter exists and is not linked into dir.childList.
	if fd.iter == nil {
		fd.iter = &dentry{}
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
