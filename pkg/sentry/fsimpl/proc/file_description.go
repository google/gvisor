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

package proc

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// fileDescription is embedded by procfs implementations of
// vfs.FileDescriptionImpl.
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl

	flags uint32 // status flags; immutable
}

func (fd *fileDescription) filesystem() *filesystem {
	return fd.vfsfd.VirtualDentry().Mount().Filesystem().Impl().(*filesystem)
}

func (fd *fileDescription) dentry() *dentry {
	return fd.vfsfd.VirtualDentry().Dentry().Impl().(*dentry)
}

// Release implements vfs.FileDescriptionImpl.Release.
func (*fileDescription) Release() {}

// StatusFlags implements vfs.FileDescriptionImpl.StatusFlags.
func (fd *fileDescription) StatusFlags(ctx context.Context) (uint32, error) {
	return fd.flags, nil
}

// SetStatusFlags implements vfs.FileDescriptionImpl.SetStatusFlags.
func (*fileDescription) SetStatusFlags(ctx context.Context, flags uint32) error {
	// None of the flags settable by fcntl(F_SETFL) are supported, so this is a
	// no-op.
	return nil
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	var stat linux.Statx
	fd.dentry().statTo(&stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (*fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask == 0 {
		return nil
	}

	// None of the stat fields supported are settable.
	return syserror.EPERM
}

// StatFS implements vfs.FileDescriptionImpl.StatFS.
func (*fileDescription) StatFS(ctx context.Context) (linux.Statfs, error) {
	return linux.Statfs{Type: linux.PROC_SUPER_MAGIC}, nil
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (*fileDescription) Sync(ctx context.Context) error {
	// Noop because procfs is completely in memory.
	return nil
}

// staticFileFD implements vfs.FileDescriptionImpl for a static file.
type staticFileFD struct {
	fileDescription
	vfs.StaticBytesFileDescriptionImpl
}

var _ vfs.FileDescriptionImpl = (*staticFileFD)(nil)

// open implements file.open. Analogous to staticFileFD constructor.
func (f *staticFile) open(mount *vfs.Mount, flags uint32) *vfs.FileDescription {
	fd := &staticFileFD{}
	fd.SetData(f.data)
	fd.flags = flags
	fd.vfsfd.Init(fd, mount, &f.dentry.vfsd)
	return &fd.vfsfd
}

// dynamicFileFD implements vfs.FileDescriptionImpl for a static file.
type dynamicFileFD struct {
	fileDescription
	vfs.DynamicBytesFileDescriptionImpl
}

var _ vfs.FileDescriptionImpl = (*dynamicFileFD)(nil)

// open implements file.open. Analogous to dynamicFileFD constructor.
func (f *dynamicFile) open(mount *vfs.Mount, flags uint32) *vfs.FileDescription {
	fd := &dynamicFileFD{}
	fd.SetDataSource(f.dataSource)
	fd.flags = flags
	fd.vfsfd.Init(fd, mount, &f.dentry.vfsd)
	return &fd.vfsfd
}

// directoryFD implements vfs.FileDsescriptionImpl for a directory.
type directoryFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl

	// Protected by filesystem.mu.
	iter *dentry
	off  int64
}

var _ vfs.FileDescriptionImpl = (*directoryFD)(nil)

// open implements file.open. Analogous to directoryFD constructor.
func (d *directory) open(mount *vfs.Mount, flags uint32) *vfs.FileDescription {
	fd := &directoryFD{}
	fd.flags = flags
	fd.vfsfd.Init(fd, mount, &d.dentry.vfsd)
	return &fd.vfsfd
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *directoryFD) Release() {
	if fd.iter != nil {
		fs := fd.filesystem()
		dir := fd.dentry().impl.(*directory)
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
			Name: ".",
			Type: linux.DT_DIR,
			Ino:  vfsd.Impl().(*dentry).ino,
			Off:  0,
		}) {
			return nil
		}
		fd.off++
	}
	if fd.off == 1 {
		parentDirent := vfsd.ParentOrSelf().Impl().(*dentry)
		if !cb.Handle(vfs.Dirent{
			Name: "..",
			Type: parentDirent.fileType(),
			Ino:  parentDirent.ino,
			Off:  1,
		}) {
			return nil
		}
		fd.off++
	}

	dir := vfsd.Impl().(*dentry).impl.(*directory)
	var child *dentry
	if fd.iter == nil {
		// Start iteration at the beginning of dir.
		child = dir.childList.Front()
		fd.iter = &dentry{isDirIterator: true}
	} else {
		// Continue iteration from where we left off.
		child = fd.iter.Next()
		dir.childList.Remove(fd.iter)
	}
	for child != nil {
		// Skip other directoryFD iterators.
		if !child.isDirIterator {
			if !cb.Handle(vfs.Dirent{
				Name: child.vfsd.Name(),
				Type: child.fileType(),
				Ino:  child.ino,
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

	dir := fd.dentry().impl.(*directory)

	// Ensure that fd.iter exists and is not linked into dir.childList.
	if fd.iter == nil {
		fd.iter = &dentry{isDirIterator: true}
	} else {
		dir.childList.Remove(fd.iter)
	}
	// Insert fd.iter before the remChildren'th child, or at the end of the
	// list if remChildren >= number of children.
	child := dir.childList.Front()
	for child != nil {
		// Skip other directoryFD iterators.
		if !child.isDirIterator {
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

// open implements file.open.
func (*symlink) open(mount *vfs.Mount, flags uint32) *vfs.FileDescription {
	// O_PATH is unimplemented, so there's no way to get a FileDescription
	// representing a symlink yet.
	return nil
}
