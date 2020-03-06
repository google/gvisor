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

	task              *kernel.Task
	pidns             *kernel.PIDNamespace
	inoGen            InoGenerator
	cgroupControllers map[string]string
}

var _ kernfs.Inode = (*subtasksInode)(nil)

func newSubtasks(task *kernel.Task, pidns *kernel.PIDNamespace, inoGen InoGenerator, cgroupControllers map[string]string) *kernfs.Dentry {
	subInode := &subtasksInode{
		task:              task,
		pidns:             pidns,
		inoGen:            inoGen,
		cgroupControllers: cgroupControllers,
	}
	// Note: credentials are overridden by taskOwnedInode.
	subInode.InodeAttrs.Init(task.Credentials(), inoGen.NextIno(), linux.ModeDirectory|0555)
	subInode.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})

	inode := &taskOwnedInode{Inode: subInode, owner: task}
	dentry := &kernfs.Dentry{}
	dentry.Init(inode)

	return dentry
}

// Valid implements kernfs.inodeDynamicLookup.
func (i *subtasksInode) Valid(ctx context.Context) bool {
	return true
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

	subTaskDentry := newTaskInode(i.inoGen, subTask, i.pidns, false, i.cgroupControllers)
	return subTaskDentry.VFSDentry(), nil
}

// IterDirents implements kernfs.inodeDynamicLookup.
func (i *subtasksInode) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback, offset, relOffset int64) (int64, error) {
	tasks := i.task.ThreadGroup().MemberIDs(i.pidns)
	if len(tasks) == 0 {
		return offset, syserror.ENOENT
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

// Open implements kernfs.Inode.
func (i *subtasksInode) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &kernfs.GenericDirectoryFD{}
	fd.Init(rp.Mount(), vfsd, &i.OrderedChildren, &opts)
	return fd.VFSFileDescription(), nil
}

// Stat implements kernfs.Inode.
func (i *subtasksInode) Stat(vsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	stat, err := i.InodeAttrs.Stat(vsfs, opts)
	if err != nil {
		return linux.Statx{}, err
	}
	if opts.Mask&linux.STATX_NLINK != 0 {
		stat.Nlink += uint32(i.task.ThreadGroup().Count())
	}
	return stat, nil
}
