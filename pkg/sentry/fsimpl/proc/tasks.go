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

// tasksInode represents the inode for /proc/ directory.
//
// +stateify savable
type tasksInode struct {
	implStatFS
	kernfs.InodeAlwaysValid
	kernfs.InodeAttrs
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeNotSymlink
	kernfs.InodeTemporary // This holds no meaning as this inode can't be Looked up and is always valid.
	kernfs.OrderedChildren
	tasksInodeRefs

	locks vfs.FileLocks

	fs    *filesystem
	pidns *kernel.PIDNamespace

	// '/proc/self' and '/proc/thread-self' have custom directory offsets in
	// Linux. So handle them outside of OrderedChildren.

	// cgroupControllers is a map of controller name to directory in the
	// cgroup hierarchy. These controllers are immutable and will be listed
	// in /proc/pid/cgroup if not nil.
	cgroupControllers map[string]string
}

var _ kernfs.Inode = (*tasksInode)(nil)

func (fs *filesystem) newTasksInode(ctx context.Context, k *kernel.Kernel, pidns *kernel.PIDNamespace, cgroupControllers map[string]string) *tasksInode {
	root := auth.NewRootCredentials(pidns.UserNamespace())
	contents := map[string]kernfs.Inode{
		"cpuinfo":     fs.newInode(ctx, root, 0444, newStaticFileSetStat(cpuInfoData(k))),
		"filesystems": fs.newInode(ctx, root, 0444, &filesystemsData{}),
		"loadavg":     fs.newInode(ctx, root, 0444, &loadavgData{}),
		"sys":         fs.newSysDir(ctx, root, k),
		"meminfo":     fs.newInode(ctx, root, 0444, &meminfoData{}),
		"mounts":      kernfs.NewStaticSymlink(ctx, root, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), "self/mounts"),
		"net":         kernfs.NewStaticSymlink(ctx, root, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), "self/net"),
		"stat":        fs.newInode(ctx, root, 0444, &statData{}),
		"uptime":      fs.newInode(ctx, root, 0444, &uptimeData{}),
		"version":     fs.newInode(ctx, root, 0444, &versionData{}),
	}

	inode := &tasksInode{
		pidns:             pidns,
		fs:                fs,
		cgroupControllers: cgroupControllers,
	}
	inode.InodeAttrs.Init(ctx, root, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|0555)
	inode.InitRefs()

	inode.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	links := inode.OrderedChildren.Populate(contents)
	inode.IncLinks(links)

	return inode
}

// Lookup implements kernfs.inodeDirectory.Lookup.
func (i *tasksInode) Lookup(ctx context.Context, name string) (kernfs.Inode, error) {
	// Check if a static entry was looked up.
	if d, err := i.OrderedChildren.Lookup(ctx, name); err == nil {
		return d, nil
	}

	// Not a static entry. Try to lookup a corresponding task.
	tid, err := strconv.ParseUint(name, 10, 64)
	if err != nil {
		root := auth.NewRootCredentials(i.pidns.UserNamespace())
		// If it failed to parse, check if it's one of the special handled files.
		switch name {
		case selfName:
			return i.newSelfSymlink(ctx, root), nil
		case threadSelfName:
			return i.newThreadSelfSymlink(ctx, root), nil
		}
		return nil, syserror.ENOENT
	}

	task := i.pidns.TaskWithID(kernel.ThreadID(tid))
	if task == nil {
		return nil, syserror.ENOENT
	}

	return i.fs.newTaskInode(task, i.pidns, true, i.cgroupControllers)
}

// IterDirents implements kernfs.inodeDirectory.IterDirents.
func (i *tasksInode) IterDirents(ctx context.Context, mnt *vfs.Mount, cb vfs.IterDirentsCallback, offset, _ int64) (int64, error) {
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
			Ino:     i.fs.NextIno(),
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
			Ino:     i.fs.NextIno(),
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
			Ino:     i.fs.NextIno(),
			NextOff: FIRST_PROCESS_ENTRY + 2 + int64(tid) + 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return offset, err
		}
		offset++
	}
	return maxTaskID, nil
}

// Open implements kernfs.Inode.Open.
func (i *tasksInode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), d, &i.OrderedChildren, &i.locks, &opts, kernfs.GenericDirectoryFDOptions{
		SeekEnd: kernfs.SeekEndZero,
	})
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

func (i *tasksInode) Stat(ctx context.Context, vsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	stat, err := i.InodeAttrs.Stat(ctx, vsfs, opts)
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

// DecRef implements kernfs.Inode.DecRef.
func (i *tasksInode) DecRef(ctx context.Context) {
	i.tasksInodeRefs.DecRef(func() { i.Destroy(ctx) })
}

// staticFileSetStat implements a special static file that allows inode
// attributes to be set. This is to support /proc files that are readonly, but
// allow attributes to be set.
//
// +stateify savable
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
