// Copyright 2018 The gVisor Authors.
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

// Package proc implements a partial in-memory file system for profs.
package proc

import (
	"fmt"
	"sort"
	"strconv"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/device"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/rpcinet"
	"gvisor.dev/gvisor/pkg/syserror"
)

// proc is a root proc node.
//
// +stateify savable
type proc struct {
	ramfs.Dir

	// k is the Kernel containing this proc node.
	k *kernel.Kernel

	// pidns is the PID namespace of the task that mounted the proc filesystem
	// that this node represents.
	pidns *kernel.PIDNamespace

	// cgroupControllers is a map of controller name to directory in the
	// cgroup hierarchy. These controllers are immutable and will be listed
	// in /proc/pid/cgroup if not nil.
	cgroupControllers map[string]string
}

// New returns the root node of a partial simple procfs.
func New(ctx context.Context, msrc *fs.MountSource, cgroupControllers map[string]string) (*fs.Inode, error) {
	k := kernel.KernelFromContext(ctx)
	if k == nil {
		return nil, fmt.Errorf("procfs requires a kernel")
	}
	pidns := kernel.PIDNamespaceFromContext(ctx)
	if pidns == nil {
		return nil, fmt.Errorf("procfs requires a PID namespace")
	}

	// Note that these are just the static members. There are dynamic
	// members populated in Readdir and Lookup below.
	contents := map[string]*fs.Inode{
		"cpuinfo":     newCPUInfo(ctx, msrc),
		"filesystems": seqfile.NewSeqFileInode(ctx, &filesystemsData{}, msrc),
		"loadavg":     seqfile.NewSeqFileInode(ctx, &loadavgData{}, msrc),
		"meminfo":     seqfile.NewSeqFileInode(ctx, &meminfoData{k}, msrc),
		"mounts":      newProcInode(ctx, ramfs.NewSymlink(ctx, fs.RootOwner, "self/mounts"), msrc, fs.Symlink, nil),
		"self":        newSelf(ctx, pidns, msrc),
		"stat":        seqfile.NewSeqFileInode(ctx, &statData{k}, msrc),
		"thread-self": newThreadSelf(ctx, pidns, msrc),
		"uptime":      newUptime(ctx, msrc),
		"version":     seqfile.NewSeqFileInode(ctx, &versionData{k}, msrc),
	}

	// Construct the proc InodeOperations.
	p := &proc{
		Dir:               *ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555)),
		k:                 k,
		pidns:             pidns,
		cgroupControllers: cgroupControllers,
	}

	// Add more contents that need proc to be initialized.
	p.AddChild(ctx, "sys", p.newSysDir(ctx, msrc))

	// If we're using rpcinet we will let it manage /proc/net.
	if _, ok := p.k.NetworkStack().(*rpcinet.Stack); ok {
		p.AddChild(ctx, "net", newRPCInetProcNet(ctx, msrc))
	} else {
		p.AddChild(ctx, "net", p.newNetDir(ctx, k, msrc))
	}

	return newProcInode(ctx, p, msrc, fs.SpecialDirectory, nil), nil
}

// self is a magical link.
//
// +stateify savable
type self struct {
	ramfs.Symlink

	pidns *kernel.PIDNamespace
}

// newSelf returns a new "self" node.
func newSelf(ctx context.Context, pidns *kernel.PIDNamespace, msrc *fs.MountSource) *fs.Inode {
	s := &self{
		Symlink: *ramfs.NewSymlink(ctx, fs.RootOwner, ""),
		pidns:   pidns,
	}
	return newProcInode(ctx, s, msrc, fs.Symlink, nil)
}

// newThreadSelf returns a new "threadSelf" node.
func newThreadSelf(ctx context.Context, pidns *kernel.PIDNamespace, msrc *fs.MountSource) *fs.Inode {
	s := &threadSelf{
		Symlink: *ramfs.NewSymlink(ctx, fs.RootOwner, ""),
		pidns:   pidns,
	}
	return newProcInode(ctx, s, msrc, fs.Symlink, nil)
}

// Readlink implements fs.InodeOperations.Readlink.
func (s *self) Readlink(ctx context.Context, inode *fs.Inode) (string, error) {
	if t := kernel.TaskFromContext(ctx); t != nil {
		tgid := s.pidns.IDOfThreadGroup(t.ThreadGroup())
		if tgid == 0 {
			return "", syserror.ENOENT
		}
		return strconv.FormatUint(uint64(tgid), 10), nil
	}

	// Who is reading this link?
	return "", syserror.EINVAL
}

// threadSelf is more magical than "self" link.
//
// +stateify savable
type threadSelf struct {
	ramfs.Symlink

	pidns *kernel.PIDNamespace
}

// Readlink implements fs.InodeOperations.Readlink.
func (s *threadSelf) Readlink(ctx context.Context, inode *fs.Inode) (string, error) {
	if t := kernel.TaskFromContext(ctx); t != nil {
		tgid := s.pidns.IDOfThreadGroup(t.ThreadGroup())
		tid := s.pidns.IDOfTask(t)
		if tid == 0 || tgid == 0 {
			return "", syserror.ENOENT
		}
		return fmt.Sprintf("%d/task/%d", tgid, tid), nil
	}

	// Who is reading this link?
	return "", syserror.EINVAL
}

// Lookup loads an Inode at name into a Dirent.
func (p *proc) Lookup(ctx context.Context, dir *fs.Inode, name string) (*fs.Dirent, error) {
	dirent, walkErr := p.Dir.Lookup(ctx, dir, name)
	if walkErr == nil {
		return dirent, nil
	}

	// Try to lookup a corresponding task.
	tid, err := strconv.ParseUint(name, 10, 64)
	if err != nil {
		// Ignore the parse error and return the original.
		return nil, walkErr
	}

	// Grab the other task.
	otherTask := p.pidns.TaskWithID(kernel.ThreadID(tid))
	if otherTask == nil {
		// Per above.
		return nil, walkErr
	}

	// Wrap it in a taskDir.
	td := p.newTaskDir(otherTask, dir.MountSource, true)
	return fs.NewDirent(ctx, td, name), nil
}

// GetFile implements fs.InodeOperations.
func (p *proc) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &rootProcFile{iops: p}), nil
}

// rootProcFile implements fs.FileOperations for the proc directory.
//
// +stateify savable
type rootProcFile struct {
	fsutil.DirFileOperations        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	iops *proc
}

var _ fs.FileOperations = (*rootProcFile)(nil)

// Readdir implements fs.FileOperations.Readdir.
func (rpf *rootProcFile) Readdir(ctx context.Context, file *fs.File, ser fs.DentrySerializer) (int64, error) {
	offset := file.Offset()
	dirCtx := &fs.DirCtx{
		Serializer: ser,
	}

	// Get normal directory contents from ramfs dir.
	names, m := rpf.iops.Dir.Children()

	// Add dot and dotdot.
	root := fs.RootFromContext(ctx)
	if root != nil {
		defer root.DecRef()
	}
	dot, dotdot := file.Dirent.GetDotAttrs(root)
	names = append(names, ".", "..")
	m["."] = dot
	m[".."] = dotdot

	// Collect tasks.
	// Per linux we only include it in directory listings if it's the leader.
	// But for whatever crazy reason, you can still walk to the given node.
	for _, tg := range rpf.iops.pidns.ThreadGroups() {
		if leader := tg.Leader(); leader != nil {
			name := strconv.FormatUint(uint64(tg.ID()), 10)
			m[name] = fs.GenericDentAttr(fs.SpecialDirectory, device.ProcDevice)
			names = append(names, name)
		}
	}

	if offset >= int64(len(m)) {
		return offset, nil
	}
	sort.Strings(names)
	names = names[offset:]
	for _, name := range names {
		if err := dirCtx.DirEmit(name, m[name]); err != nil {
			return offset, err
		}
		offset++
	}
	return offset, nil
}
