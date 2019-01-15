// Copyright 2018 Google LLC
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
	"fmt"
	"sort"
	"strconv"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// walkDescriptors finds the descriptor (file-flag pair) for the fd identified
// by p, and calls the toInodeOperations callback with that descriptor.  This is a helper
// method for implementing fs.InodeOperations.Lookup.
func walkDescriptors(t *kernel.Task, p string, toInode func(*fs.File, kernel.FDFlags) *fs.Inode) (*fs.Inode, error) {
	n, err := strconv.ParseUint(p, 10, 64)
	if err != nil {
		// Not found.
		return nil, syserror.ENOENT
	}

	var file *fs.File
	var fdFlags kernel.FDFlags
	t.WithMuLocked(func(t *kernel.Task) {
		if fdm := t.FDMap(); fdm != nil {
			file, fdFlags = fdm.GetDescriptor(kdefs.FD(n))
		}
	})
	if file == nil {
		return nil, syserror.ENOENT
	}
	return toInode(file, fdFlags), nil
}

// readDescriptors reads fds in the task starting at offset, and calls the
// toDentAttr callback for each to get a DentAttr, which it then emits. This is
// a helper for implementing fs.InodeOperations.Readdir.
func readDescriptors(t *kernel.Task, c *fs.DirCtx, offset int64, toDentAttr func(int) fs.DentAttr) (int64, error) {
	var fds kernel.FDs
	t.WithMuLocked(func(t *kernel.Task) {
		if fdm := t.FDMap(); fdm != nil {
			fds = fdm.GetFDs()
		}
	})

	fdInts := make([]int, 0, len(fds))
	for _, fd := range fds {
		fdInts = append(fdInts, int(fd))
	}

	// Find the fd to start at.
	idx := sort.SearchInts(fdInts, int(offset))
	if idx == len(fdInts) {
		return offset, nil
	}
	fdInts = fdInts[idx:]

	var fd int
	for _, fd = range fdInts {
		name := strconv.FormatUint(uint64(fd), 10)
		if err := c.DirEmit(name, toDentAttr(fd)); err != nil {
			// Returned offset is the next fd to serialize.
			return int64(fd), err
		}
	}
	// We serialized them all.  Next offset should be higher than last
	// serialized fd.
	return int64(fd + 1), nil
}

// fd implements fs.InodeOperations for a file in /proc/TID/fd/.
type fd struct {
	ramfs.Symlink
	*fs.File
}

var _ fs.InodeOperations = (*fd)(nil)

// newFd returns a new fd based on an existing file.
//
// This inherits one reference to the file.
func newFd(t *kernel.Task, f *fs.File, msrc *fs.MountSource) *fs.Inode {
	fd := &fd{
		// RootOwner overridden by taskOwnedInodeOps.UnstableAttrs().
		Symlink: *ramfs.NewSymlink(t, fs.RootOwner, ""),
		File:    f,
	}
	return newProcInode(fd, msrc, fs.Symlink, t)
}

// GetFile returns the fs.File backing this fd.  The dirent and flags
// arguments are ignored.
func (f *fd) GetFile(context.Context, *fs.Dirent, fs.FileFlags) (*fs.File, error) {
	// Take a reference on the fs.File.
	f.File.IncRef()
	return f.File, nil
}

// Readlink returns the current target.
func (f *fd) Readlink(ctx context.Context, _ *fs.Inode) (string, error) {
	root := fs.RootFromContext(ctx)
	defer root.DecRef()
	n, _ := f.Dirent.FullName(root)
	return n, nil
}

// Getlink implements fs.InodeOperations.Getlink.
func (f *fd) Getlink(context.Context, *fs.Inode) (*fs.Dirent, error) {
	f.Dirent.IncRef()
	return f.Dirent, nil
}

// Truncate is ignored.
func (f *fd) Truncate(context.Context, *fs.Inode, int64) error {
	return nil
}

func (f *fd) Release(ctx context.Context) {
	f.Symlink.Release(ctx)
	f.File.DecRef()
}

// Close releases the reference on the file.
func (f *fd) Close() error {
	f.DecRef()
	return nil
}

// fdDir is an InodeOperations for /proc/TID/fd.
//
// +stateify savable
type fdDir struct {
	ramfs.Dir

	// We hold a reference on the task's fdmap but only keep an indirect
	// task pointer to avoid Dirent loading circularity caused by fdmap's
	// potential back pointers into the dirent tree.
	t *kernel.Task
}

var _ fs.InodeOperations = (*fdDir)(nil)

// newFdDir creates a new fdDir.
func newFdDir(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	f := &fdDir{
		Dir: *ramfs.NewDir(t, nil, fs.RootOwner, fs.FilePermissions{User: fs.PermMask{Read: true, Execute: true}}),
		t:   t,
	}
	return newProcInode(f, msrc, fs.SpecialDirectory, t)
}

// Check implements InodeOperations.Check.
//
// This is to match Linux, which uses a special permission handler to guarantee
// that a process can still access /proc/self/fd after it has executed
// setuid. See fs/proc/fd.c:proc_fd_permission.
func (f *fdDir) Check(ctx context.Context, inode *fs.Inode, req fs.PermMask) bool {
	if fs.ContextCanAccessFile(ctx, inode, req) {
		return true
	}
	if t := kernel.TaskFromContext(ctx); t != nil {
		// Allow access if the task trying to access it is in the
		// thread group corresponding to this directory.
		if f.t.ThreadGroup() == t.ThreadGroup() {
			return true
		}
	}
	return false
}

// Lookup loads an Inode in /proc/TID/fd into a Dirent.
func (f *fdDir) Lookup(ctx context.Context, dir *fs.Inode, p string) (*fs.Dirent, error) {
	n, err := walkDescriptors(f.t, p, func(file *fs.File, _ kernel.FDFlags) *fs.Inode {
		return newFd(f.t, file, dir.MountSource)
	})
	if err != nil {
		return nil, err
	}
	return fs.NewDirent(n, p), nil
}

// GetFile implements fs.FileOperations.GetFile.
func (f *fdDir) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	fops := &fdDirFile{
		isInfoFile: false,
		t:          f.t,
	}
	return fs.NewFile(ctx, dirent, flags, fops), nil
}

// +stateify savable
type fdDirFile struct {
	fsutil.DirFileOperations `state:"nosave"`

	isInfoFile bool

	t *kernel.Task
}

var _ fs.FileOperations = (*fdDirFile)(nil)

// Readdir implements fs.FileOperations.Readdir.
func (f *fdDirFile) Readdir(ctx context.Context, file *fs.File, ser fs.DentrySerializer) (int64, error) {
	dirCtx := &fs.DirCtx{
		Serializer: ser,
	}
	typ := fs.RegularFile
	if f.isInfoFile {
		typ = fs.Symlink
	}
	return readDescriptors(f.t, dirCtx, file.Offset(), func(fd int) fs.DentAttr {
		return fs.GenericDentAttr(typ, device.ProcDevice)
	})
}

// fdInfoInode is a single file in /proc/TID/fdinfo/.
//
// +stateify savable
type fdInfoInode struct {
	staticFileInodeOps

	file    *fs.File
	flags   fs.FileFlags
	fdFlags kernel.FDFlags
}

var _ fs.InodeOperations = (*fdInfoInode)(nil)

// Release implements fs.InodeOperations.Release.
func (f *fdInfoInode) Release(ctx context.Context) {
	f.file.DecRef()
}

// fdInfoDir implements /proc/TID/fdinfo.  It embeds an fdDir, but overrides
// Lookup and Readdir.
//
// +stateify savable
type fdInfoDir struct {
	ramfs.Dir

	t *kernel.Task
}

// newFdInfoDir creates a new fdInfoDir.
func newFdInfoDir(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	fdid := &fdInfoDir{
		Dir: *ramfs.NewDir(t, nil, fs.RootOwner, fs.FilePermsFromMode(0500)),
		t:   t,
	}
	return newProcInode(fdid, msrc, fs.SpecialDirectory, t)
}

// Lookup loads an fd in /proc/TID/fdinfo into a Dirent.
func (fdid *fdInfoDir) Lookup(ctx context.Context, dir *fs.Inode, p string) (*fs.Dirent, error) {
	inode, err := walkDescriptors(fdid.t, p, func(file *fs.File, fdFlags kernel.FDFlags) *fs.Inode {
		// TODO: Using a static inode here means that the
		// data can be out-of-date if, for instance, the flags on the
		// FD change before we read this file. We should switch to
		// generating the data on Read(). Also, we should include pos,
		// locks, and other data.  For now we only have flags.
		// See https://www.kernel.org/doc/Documentation/filesystems/proc.txt
		flags := file.Flags().ToLinux() | fdFlags.ToLinuxFileFlags()
		contents := []byte(fmt.Sprintf("flags:\t0%o\n", flags))
		return newStaticProcInode(ctx, dir.MountSource, contents)
	})
	if err != nil {
		return nil, err
	}
	return fs.NewDirent(inode, p), nil
}

// GetFile implements fs.FileOperations.GetFile.
func (fdid *fdInfoDir) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	fops := &fdDirFile{
		isInfoFile: true,
		t:          fdid.t,
	}
	return fs.NewFile(ctx, dirent, flags, fops), nil
}
