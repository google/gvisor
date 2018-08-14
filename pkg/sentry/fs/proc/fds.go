// Copyright 2018 Google Inc.
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
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
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
func readDescriptors(t *kernel.Task, c *fs.DirCtx, offset int, toDentAttr func(int) fs.DentAttr) (int, error) {
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
	idx := sort.SearchInts(fdInts, offset)
	if idx == len(fdInts) {
		return offset, nil
	}
	fdInts = fdInts[idx:]

	var fd int
	for _, fd = range fdInts {
		name := strconv.FormatUint(uint64(fd), 10)
		if err := c.DirEmit(name, toDentAttr(fd)); err != nil {
			// Returned offset is the next fd to serialize.
			return fd, err
		}
	}
	// We serialized them all.  Next offset should be higher than last
	// serialized fd.
	return fd + 1, nil
}

// fd is a single file in /proc/TID/fd/.
type fd struct {
	ramfs.Symlink
	*fs.File
}

// newFd returns a new fd based on an existing file.
//
// This inherits one reference to the file.
func newFd(t *kernel.Task, f *fs.File, msrc *fs.MountSource) *fs.Inode {
	fd := &fd{File: f}
	// RootOwner by default, is overridden in UnstableAttr()
	fd.InitSymlink(t, fs.RootOwner, "")
	return newFile(fd, msrc, fs.Symlink, t)
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

// fdDir implements /proc/TID/fd.
//
// +stateify savable
type fdDir struct {
	ramfs.Dir

	// We hold a reference on the task's fdmap but only keep an indirect
	// task pointer to avoid Dirent loading circularity caused by fdmap's
	// potential back pointers into the dirent tree.
	t *kernel.Task
}

// newFdDir creates a new fdDir.
func newFdDir(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	f := &fdDir{t: t}
	f.InitDir(t, nil, fs.RootOwner, fs.FilePermissions{User: fs.PermMask{Read: true, Execute: true}})
	return newFile(f, msrc, fs.SpecialDirectory, t)
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
		//
		// N.B. Technically, in Linux 3.11, this compares what would be
		// the equivalent of task pointers. However, this was fixed
		// later in 54708d2858e7 ("proc: actually make
		// proc_fd_permission() thread-friendly").
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

// DeprecatedReaddir lists fds in /proc/TID/fd.
func (f *fdDir) DeprecatedReaddir(ctx context.Context, dirCtx *fs.DirCtx, offset int) (int, error) {
	return readDescriptors(f.t, dirCtx, offset, func(fd int) fs.DentAttr {
		return fs.GenericDentAttr(fs.Symlink, device.ProcDevice)
	})
}

// fdInfo is a single file in /proc/TID/fdinfo/.
//
// +stateify savable
type fdInfo struct {
	ramfs.File

	file    *fs.File
	flags   fs.FileFlags
	fdFlags kernel.FDFlags
}

// newFdInfo returns a new fdInfo based on an existing file.
func newFdInfo(t *kernel.Task, file *fs.File, fdFlags kernel.FDFlags, msrc *fs.MountSource) *fs.Inode {
	fdi := &fdInfo{file: file, flags: file.Flags(), fdFlags: fdFlags}
	fdi.InitFile(t, fs.RootOwner, fs.FilePermissions{User: fs.PermMask{Read: true}})
	// TODO: Get pos, locks, and other data.  For now we only
	// have flags.
	// See https://www.kernel.org/doc/Documentation/filesystems/proc.txt

	flags := file.Flags().ToLinux() | fdFlags.ToLinuxFileFlags()
	fdi.Append([]byte(fmt.Sprintf("flags:\t0%o\n", flags)))
	return newFile(fdi, msrc, fs.SpecialFile, t)
}

// DeprecatedPwritev implements fs.HandleOperations.DeprecatedPwritev.
func (*fdInfo) DeprecatedPwritev(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	return 0, ramfs.ErrInvalidOp
}

// Truncate implements fs.InodeOperations.Truncate.
func (*fdInfo) Truncate(ctx context.Context, inode *fs.Inode, size int64) error {
	return ramfs.ErrInvalidOp
}

func (f *fdInfo) Release(ctx context.Context) {
	f.File.Release(ctx)
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
	fdid := &fdInfoDir{t: t}
	fdid.InitDir(t, nil, fs.RootOwner, fs.FilePermsFromMode(0500))
	return newFile(fdid, msrc, fs.SpecialDirectory, t)
}

// Lookup loads an fd in /proc/TID/fdinfo into a Dirent.
func (fdid *fdInfoDir) Lookup(ctx context.Context, dir *fs.Inode, p string) (*fs.Dirent, error) {
	n, err := walkDescriptors(fdid.t, p, func(file *fs.File, fdFlags kernel.FDFlags) *fs.Inode {
		return newFdInfo(fdid.t, file, fdFlags, dir.MountSource)
	})
	if err != nil {
		return nil, err
	}
	return fs.NewDirent(n, p), nil
}

// DeprecatedReaddir lists fds in /proc/TID/fdinfo.
func (fdid *fdInfoDir) DeprecatedReaddir(ctx context.Context, dirCtx *fs.DirCtx, offset int) (int, error) {
	return readDescriptors(fdid.t, dirCtx, offset, func(fd int) fs.DentAttr {
		return fs.GenericDentAttr(fs.RegularFile, device.ProcDevice)
	})
}
