// Copyright 2020 The gVisor Authors.
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
	"bytes"
	"fmt"
	"sort"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

func getTaskFD(t *kernel.Task, fd int32) (*vfs.FileDescription, kernel.FDFlags) {
	var (
		file  *vfs.FileDescription
		flags kernel.FDFlags
	)
	t.WithMuLocked(func(t *kernel.Task) {
		if fdt := t.FDTable(); fdt != nil {
			file, flags = fdt.GetVFS2(fd)
		}
	})
	return file, flags
}

func taskFDExists(t *kernel.Task, fd int32) bool {
	file, _ := getTaskFD(t, fd)
	if file == nil {
		return false
	}
	file.DecRef()
	return true
}

type fdDir struct {
	inoGen InoGenerator
	task   *kernel.Task

	// When produceSymlinks is set, dirents produces for the FDs are reported
	// as symlink. Otherwise, they are reported as regular files.
	produceSymlink bool
}

// IterDirents implements kernfs.inodeDynamicLookup.
func (i *fdDir) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback, absOffset, relOffset int64) (int64, error) {
	var fds []int32
	i.task.WithMuLocked(func(t *kernel.Task) {
		if fdTable := t.FDTable(); fdTable != nil {
			fds = fdTable.GetFDs()
		}
	})

	offset := absOffset + relOffset
	typ := uint8(linux.DT_REG)
	if i.produceSymlink {
		typ = linux.DT_LNK
	}

	// Find the appropriate starting point.
	idx := sort.Search(len(fds), func(i int) bool { return fds[i] >= int32(relOffset) })
	if idx >= len(fds) {
		return offset, nil
	}
	for _, fd := range fds[idx:] {
		dirent := vfs.Dirent{
			Name:    strconv.FormatUint(uint64(fd), 10),
			Type:    typ,
			Ino:     i.inoGen.NextIno(),
			NextOff: offset + 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return offset, err
		}
		offset++
	}
	return offset, nil
}

// fdDirInode represents the inode for /proc/[pid]/fd directory.
//
// +stateify savable
type fdDirInode struct {
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeAttrs
	kernfs.OrderedChildren
	kernfs.AlwaysValid
	fdDir
}

var _ kernfs.Inode = (*fdDirInode)(nil)

func newFDDirInode(task *kernel.Task, inoGen InoGenerator) *kernfs.Dentry {
	inode := &fdDirInode{
		fdDir: fdDir{
			inoGen:         inoGen,
			task:           task,
			produceSymlink: true,
		},
	}
	inode.InodeAttrs.Init(task.Credentials(), inoGen.NextIno(), linux.ModeDirectory|0555)

	dentry := &kernfs.Dentry{}
	dentry.Init(inode)
	inode.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})

	return dentry
}

// Lookup implements kernfs.inodeDynamicLookup.
func (i *fdDirInode) Lookup(ctx context.Context, name string) (*vfs.Dentry, error) {
	fdInt, err := strconv.ParseInt(name, 10, 32)
	if err != nil {
		return nil, syserror.ENOENT
	}
	fd := int32(fdInt)
	if !taskFDExists(i.task, fd) {
		return nil, syserror.ENOENT
	}
	taskDentry := newFDSymlink(i.task, fd, i.inoGen.NextIno())
	return taskDentry.VFSDentry(), nil
}

// Open implements kernfs.Inode.
func (i *fdDirInode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), vfsd, &i.OrderedChildren, &opts)
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

// CheckPermissions implements kernfs.Inode.
//
// This is to match Linux, which uses a special permission handler to guarantee
// that a process can still access /proc/self/fd after it has executed
// setuid. See fs/proc/fd.c:proc_fd_permission.
func (i *fdDirInode) CheckPermissions(ctx context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	err := i.InodeAttrs.CheckPermissions(ctx, creds, ats)
	if err == nil {
		// Access granted, no extra check needed.
		return nil
	}
	if t := kernel.TaskFromContext(ctx); t != nil {
		// Allow access if the task trying to access it is in the thread group
		// corresponding to this directory.
		if i.task.ThreadGroup() == t.ThreadGroup() {
			// Access granted (overridden).
			return nil
		}
	}
	return err
}

// fdSymlink is an symlink for the /proc/[pid]/fd/[fd] file.
//
// +stateify savable
type fdSymlink struct {
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeSymlink

	task *kernel.Task
	fd   int32
}

var _ kernfs.Inode = (*fdSymlink)(nil)

func newFDSymlink(task *kernel.Task, fd int32, ino uint64) *kernfs.Dentry {
	inode := &fdSymlink{
		task: task,
		fd:   fd,
	}
	inode.Init(task.Credentials(), ino, linux.ModeSymlink|0777)

	d := &kernfs.Dentry{}
	d.Init(inode)
	return d
}

func (s *fdSymlink) Readlink(ctx context.Context) (string, error) {
	file, _ := getTaskFD(s.task, s.fd)
	if file == nil {
		return "", syserror.ENOENT
	}
	defer file.DecRef()
	root := vfs.RootFromContext(ctx)
	defer root.DecRef()
	return s.task.Kernel().VFS().PathnameWithDeleted(ctx, root, file.VirtualDentry())
}

func (s *fdSymlink) Getlink(ctx context.Context, mnt *vfs.Mount) (vfs.VirtualDentry, string, error) {
	file, _ := getTaskFD(s.task, s.fd)
	if file == nil {
		return vfs.VirtualDentry{}, "", syserror.ENOENT
	}
	defer file.DecRef()
	vd := file.VirtualDentry()
	vd.IncRef()
	return vd, "", nil
}

// fdInfoDirInode represents the inode for /proc/[pid]/fdinfo directory.
//
// +stateify savable
type fdInfoDirInode struct {
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeAttrs
	kernfs.OrderedChildren
	kernfs.AlwaysValid
	fdDir
}

var _ kernfs.Inode = (*fdInfoDirInode)(nil)

func newFDInfoDirInode(task *kernel.Task, inoGen InoGenerator) *kernfs.Dentry {
	inode := &fdInfoDirInode{
		fdDir: fdDir{
			inoGen: inoGen,
			task:   task,
		},
	}
	inode.InodeAttrs.Init(task.Credentials(), inoGen.NextIno(), linux.ModeDirectory|0555)

	dentry := &kernfs.Dentry{}
	dentry.Init(inode)
	inode.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})

	return dentry
}

// Lookup implements kernfs.inodeDynamicLookup.
func (i *fdInfoDirInode) Lookup(ctx context.Context, name string) (*vfs.Dentry, error) {
	fdInt, err := strconv.ParseInt(name, 10, 32)
	if err != nil {
		return nil, syserror.ENOENT
	}
	fd := int32(fdInt)
	if !taskFDExists(i.task, fd) {
		return nil, syserror.ENOENT
	}
	data := &fdInfoData{
		task: i.task,
		fd:   fd,
	}
	dentry := newTaskOwnedFile(i.task, i.inoGen.NextIno(), 0444, data)
	return dentry.VFSDentry(), nil
}

// Open implements kernfs.Inode.
func (i *fdInfoDirInode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), vfsd, &i.OrderedChildren, &opts)
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

// fdInfoData implements vfs.DynamicBytesSource for /proc/[pid]/fdinfo/[fd].
//
// +stateify savable
type fdInfoData struct {
	kernfs.DynamicBytesFile
	refs.AtomicRefCount

	task *kernel.Task
	fd   int32
}

var _ dynamicInode = (*fdInfoData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *fdInfoData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	file, descriptorFlags := getTaskFD(d.task, d.fd)
	if file == nil {
		return syserror.ENOENT
	}
	defer file.DecRef()
	// TODO(b/121266871): Include pos, locks, and other data. For now we only
	// have flags.
	// See https://www.kernel.org/doc/Documentation/filesystems/proc.txt
	flags := uint(file.StatusFlags()) | descriptorFlags.ToLinuxFileFlags()
	fmt.Fprintf(buf, "flags:\t0%o\n", flags)
	return nil
}
