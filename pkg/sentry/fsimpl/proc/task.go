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
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// taskInode represents the inode for /proc/PID/ directory.
//
// +stateify savable
type taskInode struct {
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeNoDynamicLookup
	kernfs.InodeAttrs
	kernfs.OrderedChildren

	task *kernel.Task
}

var _ kernfs.Inode = (*taskInode)(nil)

func newTaskInode(inoGen InoGenerator, task *kernel.Task, pidns *kernel.PIDNamespace, isThreadGroup bool) *kernfs.Dentry {
	contents := map[string]*kernfs.Dentry{
		//"auxv":      newAuxvec(t, msrc),
		//"cmdline":   newExecArgInode(t, msrc, cmdlineExecArg),
		//"comm":      newComm(t, msrc),
		//"environ":   newExecArgInode(t, msrc, environExecArg),
		//"exe":       newExe(t, msrc),
		//"fd":        newFdDir(t, msrc),
		//"fdinfo":    newFdInfoDir(t, msrc),
		//"gid_map":   newGIDMap(t, msrc),
		"io":   newTaskOwnedFile(task, inoGen.NextIno(), defaultPermission, newIO(task, isThreadGroup)),
		"maps": newTaskOwnedFile(task, inoGen.NextIno(), defaultPermission, &mapsData{task: task}),
		//"mountinfo": seqfile.NewSeqFileInode(t, &mountInfoFile{t: t}, msrc),
		//"mounts":    seqfile.NewSeqFileInode(t, &mountsFile{t: t}, msrc),
		//"ns":        newNamespaceDir(t, msrc),
		"smaps":  newTaskOwnedFile(task, inoGen.NextIno(), defaultPermission, &smapsData{task: task}),
		"stat":   newTaskOwnedFile(task, inoGen.NextIno(), defaultPermission, &taskStatData{t: task, pidns: pidns, tgstats: isThreadGroup}),
		"statm":  newTaskOwnedFile(task, inoGen.NextIno(), defaultPermission, &statmData{t: task}),
		"status": newTaskOwnedFile(task, inoGen.NextIno(), defaultPermission, &statusData{t: task, pidns: pidns}),
		//"uid_map":   newUIDMap(t, msrc),
	}
	if isThreadGroup {
		//contents["task"] = p.newSubtasks(t, msrc)
	}
	//if len(p.cgroupControllers) > 0 {
	//	contents["cgroup"] = newCGroupInode(t, msrc, p.cgroupControllers)
	//}

	taskInode := &taskInode{task: task}
	// Note: credentials are overridden by taskOwnedInode.
	taskInode.InodeAttrs.Init(task.Credentials(), inoGen.NextIno(), linux.ModeDirectory|0555)

	inode := &taskOwnedInode{Inode: taskInode, owner: task}
	dentry := &kernfs.Dentry{}
	dentry.Init(inode)

	taskInode.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	links := taskInode.OrderedChildren.Populate(dentry, contents)
	taskInode.IncLinks(links)

	return dentry
}

// Valid implements kernfs.inodeDynamicLookup. This inode remains valid as long
// as the task is still running. When it's dead, another tasks with the same
// PID could replace it.
func (i *taskInode) Valid(ctx context.Context) bool {
	return i.task.ExitState() != kernel.TaskExitDead
}

// Open implements kernfs.Inode.
func (i *taskInode) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error) {
	fd := &kernfs.GenericDirectoryFD{}
	fd.Init(rp.Mount(), vfsd, &i.OrderedChildren, flags)
	return fd.VFSFileDescription(), nil
}

// SetStat implements kernfs.Inode.
func (i *taskInode) SetStat(_ *vfs.Filesystem, opts vfs.SetStatOptions) error {
	stat := opts.Stat
	if stat.Mask&linux.STATX_MODE != 0 {
		return syserror.EPERM
	}
	return nil
}

// taskOwnedInode implements kernfs.Inode and overrides inode owner with task
// effective user and group.
type taskOwnedInode struct {
	kernfs.Inode

	// owner is the task that owns this inode.
	owner *kernel.Task
}

var _ kernfs.Inode = (*taskOwnedInode)(nil)

func newTaskOwnedFile(task *kernel.Task, ino uint64, perm linux.FileMode, inode dynamicInode) *kernfs.Dentry {
	// Note: credentials are overridden by taskOwnedInode.
	inode.Init(task.Credentials(), ino, inode, perm)

	taskInode := &taskOwnedInode{Inode: inode, owner: task}
	d := &kernfs.Dentry{}
	d.Init(taskInode)
	return d
}

// Stat implements kernfs.Inode.
func (i *taskOwnedInode) Stat(fs *vfs.Filesystem) linux.Statx {
	stat := i.Inode.Stat(fs)
	uid, gid := i.getOwner(linux.FileMode(stat.Mode))
	stat.UID = uint32(uid)
	stat.GID = uint32(gid)
	return stat
}

// CheckPermissions implements kernfs.Inode.
func (i *taskOwnedInode) CheckPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	mode := i.Mode()
	uid, gid := i.getOwner(mode)
	return vfs.GenericCheckPermissions(
		creds,
		ats,
		mode.FileType() == linux.ModeDirectory,
		uint16(mode),
		uid,
		gid,
	)
}

func (i *taskOwnedInode) getOwner(mode linux.FileMode) (auth.KUID, auth.KGID) {
	// By default, set the task owner as the file owner.
	creds := i.owner.Credentials()
	uid := creds.EffectiveKUID
	gid := creds.EffectiveKGID

	// Linux doesn't apply dumpability adjustments to world readable/executable
	// directories so that applications can stat /proc/PID to determine the
	// effective UID of a process. See fs/proc/base.c:task_dump_owner.
	if mode.FileType() == linux.ModeDirectory && mode.Permissions() == 0555 {
		return uid, gid
	}

	// If the task is not dumpable, then root (in the namespace preferred)
	// owns the file.
	m := getMM(i.owner)
	if m == nil {
		return auth.RootKUID, auth.RootKGID
	}
	if m.Dumpability() != mm.UserDumpable {
		uid = auth.RootKUID
		if kuid := creds.UserNamespace.MapToKUID(auth.RootUID); kuid.Ok() {
			uid = kuid
		}
		gid = auth.RootKGID
		if kgid := creds.UserNamespace.MapToKGID(auth.RootGID); kgid.Ok() {
			gid = kgid
		}
	}
	return uid, gid
}

func newIO(t *kernel.Task, isThreadGroup bool) *ioData {
	if isThreadGroup {
		return &ioData{ioUsage: t.ThreadGroup()}
	}
	return &ioData{ioUsage: t}
}
