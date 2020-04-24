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
	"bytes"
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

const (
	selfName       = "self"
	threadSelfName = "thread-self"
)

// InoGenerator generates unique inode numbers for a given filesystem.
type InoGenerator interface {
	NextIno() uint64
}

// tasksInode represents the inode for /proc/ directory.
//
// +stateify savable
type tasksInode struct {
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeAttrs
	kernfs.OrderedChildren
	kernfs.AlwaysValid

	inoGen InoGenerator
	pidns  *kernel.PIDNamespace

	// '/proc/self' and '/proc/thread-self' have custom directory offsets in
	// Linux. So handle them outside of OrderedChildren.
	selfSymlink       *vfs.Dentry
	threadSelfSymlink *vfs.Dentry

	// cgroupControllers is a map of controller name to directory in the
	// cgroup hierarchy. These controllers are immutable and will be listed
	// in /proc/pid/cgroup if not nil.
	cgroupControllers map[string]string
}

var _ kernfs.Inode = (*tasksInode)(nil)

func newTasksInode(inoGen InoGenerator, k *kernel.Kernel, pidns *kernel.PIDNamespace, cgroupControllers map[string]string) (*tasksInode, *kernfs.Dentry) {
	root := auth.NewRootCredentials(pidns.UserNamespace())
	contents := map[string]*kernfs.Dentry{
		"cpuinfo":     newDentry(root, inoGen.NextIno(), 0444, newStaticFileSetStat(cpuInfoData(k))),
		"filesystems": newDentry(root, inoGen.NextIno(), 0444, &filesystemsData{}),
		"loadavg":     newDentry(root, inoGen.NextIno(), 0444, &loadavgData{}),
		"sys":         newSysDir(root, inoGen, k),
		"meminfo":     newDentry(root, inoGen.NextIno(), 0444, &meminfoData{}),
		"mounts":      kernfs.NewStaticSymlink(root, inoGen.NextIno(), "self/mounts"),
		"net":         kernfs.NewStaticSymlink(root, inoGen.NextIno(), "self/net"),
		"stat":        newDentry(root, inoGen.NextIno(), 0444, &statData{}),
		"uptime":      newDentry(root, inoGen.NextIno(), 0444, &uptimeData{}),
		"version":     newDentry(root, inoGen.NextIno(), 0444, &versionData{}),
	}

	inode := &tasksInode{
		pidns:             pidns,
		inoGen:            inoGen,
		selfSymlink:       newSelfSymlink(root, inoGen.NextIno(), pidns).VFSDentry(),
		threadSelfSymlink: newThreadSelfSymlink(root, inoGen.NextIno(), pidns).VFSDentry(),
		cgroupControllers: cgroupControllers,
	}
	inode.InodeAttrs.Init(root, inoGen.NextIno(), linux.ModeDirectory|0555)

	dentry := &kernfs.Dentry{}
	dentry.Init(inode)

	inode.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	links := inode.OrderedChildren.Populate(dentry, contents)
	inode.IncLinks(links)

	return inode, dentry
}

// Lookup implements kernfs.inodeDynamicLookup.
func (i *tasksInode) Lookup(ctx context.Context, name string) (*vfs.Dentry, error) {
	// Try to lookup a corresponding task.
	tid, err := strconv.ParseUint(name, 10, 64)
	if err != nil {
		// If it failed to parse, check if it's one of the special handled files.
		switch name {
		case selfName:
			return i.selfSymlink, nil
		case threadSelfName:
			return i.threadSelfSymlink, nil
		}
		return nil, syserror.ENOENT
	}

	task := i.pidns.TaskWithID(kernel.ThreadID(tid))
	if task == nil {
		return nil, syserror.ENOENT
	}

	taskDentry := newTaskInode(i.inoGen, task, i.pidns, true, i.cgroupControllers)
	return taskDentry.VFSDentry(), nil
}

// IterDirents implements kernfs.inodeDynamicLookup.
func (i *tasksInode) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback, offset, _ int64) (int64, error) {
	// fs/proc/internal.h: #define FIRST_PROCESS_ENTRY 256
	const FIRST_PROCESS_ENTRY = 256

	// Use maxTaskID to shortcut searches that will result in 0 entries.
	const maxTaskID = kernel.TasksLimit + 1
	if offset >= maxTaskID {
		return offset, nil
	}

	// According to Linux (fs/proc/base.c:proc_pid_readdir()), process directories
	// start at offset FIRST_PROCESS_ENTRY with '/proc/self', followed by
	// '/proc/thread-self' and then '/proc/[pid]'.
	if offset < FIRST_PROCESS_ENTRY {
		offset = FIRST_PROCESS_ENTRY
	}

	if offset == FIRST_PROCESS_ENTRY {
		dirent := vfs.Dirent{
			Name:    selfName,
			Type:    linux.DT_LNK,
			Ino:     i.inoGen.NextIno(),
			NextOff: offset + 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return offset, err
		}
		offset++
	}
	if offset == FIRST_PROCESS_ENTRY+1 {
		dirent := vfs.Dirent{
			Name:    threadSelfName,
			Type:    linux.DT_LNK,
			Ino:     i.inoGen.NextIno(),
			NextOff: offset + 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return offset, err
		}
		offset++
	}

	// Collect all tasks that TGIDs are greater than the offset specified. Per
	// Linux we only include in directory listings if it's the leader. But for
	// whatever crazy reason, you can still walk to the given node.
	var tids []int
	startTid := offset - FIRST_PROCESS_ENTRY - 2
	for _, tg := range i.pidns.ThreadGroups() {
		tid := i.pidns.IDOfThreadGroup(tg)
		if int64(tid) < startTid {
			continue
		}
		if leader := tg.Leader(); leader != nil {
			tids = append(tids, int(tid))
		}
	}

	if len(tids) == 0 {
		return offset, nil
	}

	sort.Ints(tids)
	for _, tid := range tids {
		dirent := vfs.Dirent{
			Name:    strconv.FormatUint(uint64(tid), 10),
			Type:    linux.DT_DIR,
			Ino:     i.inoGen.NextIno(),
			NextOff: FIRST_PROCESS_ENTRY + 2 + int64(tid) + 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return offset, err
		}
		offset++
	}
	return maxTaskID, nil
}

// Open implements kernfs.Inode.
func (i *tasksInode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), vfsd, &i.OrderedChildren, &opts)
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

func (i *tasksInode) Stat(vsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	stat, err := i.InodeAttrs.Stat(vsfs, opts)
	if err != nil {
		return linux.Statx{}, err
	}

	if opts.Mask&linux.STATX_NLINK != 0 {
		// Add dynamic children to link count.
		for _, tg := range i.pidns.ThreadGroups() {
			if leader := tg.Leader(); leader != nil {
				stat.Nlink++
			}
		}
	}

	return stat, nil
}

// staticFileSetStat implements a special static file that allows inode
// attributes to be set. This is to support /proc files that are readonly, but
// allow attributes to be set.
type staticFileSetStat struct {
	dynamicBytesFileSetAttr
	vfs.StaticData
}

var _ dynamicInode = (*staticFileSetStat)(nil)

func newStaticFileSetStat(data string) *staticFileSetStat {
	return &staticFileSetStat{StaticData: vfs.StaticData{Data: data}}
}

func cpuInfoData(k *kernel.Kernel) string {
	features := k.FeatureSet()
	if features == nil {
		// Kernel is always initialized with a FeatureSet.
		panic("cpuinfo read with nil FeatureSet")
	}
	var buf bytes.Buffer
	for i, max := uint(0), k.ApplicationCores(); i < max; i++ {
		features.WriteCPUInfoTo(i, &buf)
	}
	return buf.String()
}

func shmData(v uint64) dynamicInode {
	return newStaticFile(strconv.FormatUint(v, 10))
}
