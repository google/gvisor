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
	"sort"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// subtasksInode represents the inode for /proc/[pid]/task/ directory.
//
// +stateify savable
type subtasksInode struct {
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeAttrs
	kernfs.OrderedChildren
	kernfs.AlwaysValid

	locks vfs.FileLocks

	fs                *filesystem
	task              *kernel.Task
	pidns             *kernel.PIDNamespace
	cgroupControllers map[string]string
}

var _ kernfs.Inode = (*subtasksInode)(nil)

func (fs *filesystem) newSubtasks(task *kernel.Task, pidns *kernel.PIDNamespace, cgroupControllers map[string]string) *kernfs.Dentry {
	subInode := &subtasksInode{
		fs:                fs,
		task:              task,
		pidns:             pidns,
		cgroupControllers: cgroupControllers,
	}
	// Note: credentials are overridden by taskOwnedInode.
	subInode.InodeAttrs.Init(task.Credentials(), linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|0555)
	subInode.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})

	inode := &taskOwnedInode{Inode: subInode, owner: task}
	dentry := &kernfs.Dentry{}
	dentry.Init(inode)

	return dentry
}

// Lookup implements kernfs.inodeDynamicLookup.
func (i *subtasksInode) Lookup(ctx context.Context, name string) (*vfs.Dentry, error) {
	tid, err := strconv.ParseUint(name, 10, 32)
	if err != nil {
		return nil, syserror.ENOENT
	}

	subTask := i.pidns.TaskWithID(kernel.ThreadID(tid))
	if subTask == nil {
		return nil, syserror.ENOENT
	}
	if subTask.ThreadGroup() != i.task.ThreadGroup() {
		return nil, syserror.ENOENT
	}

	subTaskDentry := i.fs.newTaskInode(subTask, i.pidns, false, i.cgroupControllers)
	return subTaskDentry.VFSDentry(), nil
}

// IterDirents implements kernfs.inodeDynamicLookup.
func (i *subtasksInode) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback, offset, relOffset int64) (int64, error) {
	tasks := i.task.ThreadGroup().MemberIDs(i.pidns)
	if len(tasks) == 0 {
		return offset, syserror.ENOENT
	}
	if relOffset >= int64(len(tasks)) {
		return offset, nil
	}

	tids := make([]int, 0, len(tasks))
	for _, tid := range tasks {
		tids = append(tids, int(tid))
	}

	sort.Ints(tids)
	for _, tid := range tids[relOffset:] {
		dirent := vfs.Dirent{
			Name:    strconv.FormatUint(uint64(tid), 10),
			Type:    linux.DT_DIR,
			Ino:     i.fs.NextIno(),
			NextOff: offset + 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return offset, err
		}
		offset++
	}
	return offset, nil
}

type subtasksFD struct {
	kernfs.GenericDirectoryFD

	task *kernel.Task
}

func (fd *subtasksFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	if fd.task.ExitState() >= kernel.TaskExitZombie {
		return syserror.ENOENT
	}
	return fd.GenericDirectoryFD.IterDirents(ctx, cb)
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *subtasksFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	if fd.task.ExitState() >= kernel.TaskExitZombie {
		return 0, syserror.ENOENT
	}
	return fd.GenericDirectoryFD.Seek(ctx, offset, whence)
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *subtasksFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	if fd.task.ExitState() >= kernel.TaskExitZombie {
		return linux.Statx{}, syserror.ENOENT
	}
	return fd.GenericDirectoryFD.Stat(ctx, opts)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *subtasksFD) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	if fd.task.ExitState() >= kernel.TaskExitZombie {
		return syserror.ENOENT
	}
	return fd.GenericDirectoryFD.SetStat(ctx, opts)
}

// Open implements kernfs.Inode.
func (i *subtasksInode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &subtasksFD{task: i.task}
	if err := fd.Init(&i.OrderedChildren, &i.locks, &opts, kernfs.GenericDirectoryFDOptions{
		SeekEnd: kernfs.SeekEndZero,
	}); err != nil {
		return nil, err
	}
	if err := fd.VFSFileDescription().Init(fd, opts.Flags, rp.Mount(), vfsd, &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

// Stat implements kernfs.Inode.
func (i *subtasksInode) Stat(ctx context.Context, vsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	stat, err := i.InodeAttrs.Stat(ctx, vsfs, opts)
	if err != nil {
		return linux.Statx{}, err
	}
	if opts.Mask&linux.STATX_NLINK != 0 {
		stat.Nlink += uint32(i.task.ThreadGroup().Count())
	}
	return stat, nil
}

// SetStat implements Inode.SetStat not allowing inode attributes to be changed.
func (*subtasksInode) SetStat(context.Context, *vfs.Filesystem, *auth.Credentials, vfs.SetStatOptions) error {
	return syserror.EPERM
}
