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

// Package proc implements a partial in-memory file system for profs.
package proc

import (
	"fmt"
	"io"
	"sort"
	"strconv"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
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
}

// stubProcFSFile is a file type that can be used to return file contents
// which are constant. This file is not writable and will always have mode
// 0444.
//
// +stateify savable
type stubProcFSFile struct {
	ramfs.Entry

	// contents are the immutable file contents that will always be returned.
	contents []byte
}

// DeprecatedPreadv implements fs.InodeOperations.DeprecatedPreadv.
func (s *stubProcFSFile) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	if offset >= int64(len(s.contents)) {
		return 0, io.EOF
	}

	n, err := dst.CopyOut(ctx, s.contents[offset:])
	return int64(n), err
}

// New returns the root node of a partial simple procfs.
func New(ctx context.Context, msrc *fs.MountSource) (*fs.Inode, error) {
	k := kernel.KernelFromContext(ctx)
	if k == nil {
		return nil, fmt.Errorf("procfs requires a kernel")
	}
	pidns := kernel.PIDNamespaceFromContext(ctx)
	if pidns == nil {
		return nil, fmt.Errorf("procfs requires a PID namespace")
	}

	p := &proc{k: k, pidns: pidns}
	p.InitDir(ctx, map[string]*fs.Inode{
		// Note that these are just the static members. There are
		// dynamic members populated in Readdir and Lookup below.
		"filesystems": seqfile.NewSeqFileInode(ctx, &filesystemsData{}, msrc),
		"loadavg":     seqfile.NewSeqFileInode(ctx, &loadavgData{}, msrc),
		"meminfo":     seqfile.NewSeqFileInode(ctx, &meminfoData{k}, msrc),
		"mounts":      newMountsSymlink(ctx, msrc),
		"stat":        seqfile.NewSeqFileInode(ctx, &statData{k}, msrc),
		"version":     seqfile.NewSeqFileInode(ctx, &versionData{k}, msrc),
	}, fs.RootOwner, fs.FilePermsFromMode(0555))

	p.AddChild(ctx, "cpuinfo", p.newCPUInfo(ctx, msrc))
	p.AddChild(ctx, "uptime", p.newUptime(ctx, msrc))

	return newFile(p, msrc, fs.SpecialDirectory, nil), nil
}

// self is a magical link.
type self struct {
	ramfs.Symlink

	pidns *kernel.PIDNamespace
}

// newSelf returns a new "self" node.
func (p *proc) newSelf(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	s := &self{pidns: p.pidns}
	s.InitSymlink(ctx, fs.RootOwner, "")
	return newFile(s, msrc, fs.Symlink, nil)
}

// newThreadSelf returns a new "threadSelf" node.
func (p *proc) newThreadSelf(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	s := &threadSelf{pidns: p.pidns}
	s.InitSymlink(ctx, fs.RootOwner, "")
	return newFile(s, msrc, fs.Symlink, nil)
}

// newStubProcFsFile returns a procfs file with constant contents.
func (p *proc) newStubProcFSFile(ctx context.Context, msrc *fs.MountSource, c []byte) *fs.Inode {
	u := &stubProcFSFile{
		contents: c,
	}
	u.InitEntry(ctx, fs.RootOwner, fs.FilePermsFromMode(0444))
	return newFile(u, msrc, fs.SpecialFile, nil)
}

// Readlink implements fs.InodeOperations.Readlink.
func (s *self) Readlink(ctx context.Context, inode *fs.Inode) (string, error) {
	if t := kernel.TaskFromContext(ctx); t != nil {
		tgid := s.pidns.IDOfThreadGroup(t.ThreadGroup())
		if tgid == 0 {
			return "", ramfs.ErrNotFound
		}
		return strconv.FormatUint(uint64(tgid), 10), nil
	}

	// Who is reading this link?
	return "", ramfs.ErrInvalidOp
}

// threadSelf is more magical than "self" link.
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
			return "", ramfs.ErrNotFound
		}
		return fmt.Sprintf("%d/task/%d", tgid, tid), nil
	}

	// Who is reading this link?
	return "", ramfs.ErrInvalidOp
}

// Lookup loads an Inode at name into a Dirent.
func (p *proc) Lookup(ctx context.Context, dir *fs.Inode, name string) (*fs.Dirent, error) {
	// Is it one of the static ones?
	dirent, walkErr := p.Dir.Lookup(ctx, dir, name)
	if walkErr == nil {
		return dirent, nil
	}

	// Is it a dynamic element?
	nfs := map[string]func() *fs.Inode{
		"net": func() *fs.Inode {
			// If we're using rpcinet we will let it manage /proc/net.
			if _, ok := p.k.NetworkStack().(*rpcinet.Stack); ok {
				return newRPCInetProcNet(ctx, dir.MountSource)
			}
			return p.newNetDir(ctx, dir.MountSource)
		},
		"self":        func() *fs.Inode { return p.newSelf(ctx, dir.MountSource) },
		"sys":         func() *fs.Inode { return p.newSysDir(ctx, dir.MountSource) },
		"thread-self": func() *fs.Inode { return p.newThreadSelf(ctx, dir.MountSource) },
	}
	if nf, ok := nfs[name]; ok {
		return fs.NewDirent(nf(), name), nil
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
	td := newTaskDir(otherTask, dir.MountSource, p.pidns, true)
	return fs.NewDirent(td, name), nil
}

// Readdir synthesizes proc contents.
func (p *proc) DeprecatedReaddir(ctx context.Context, dirCtx *fs.DirCtx, offset int) (int, error) {
	// Serialize normal contents.
	_, err := p.Dir.DeprecatedReaddir(ctx, dirCtx, offset)
	if err != nil {
		return offset, err
	}

	m := make(map[string]fs.DentAttr)
	var names []string

	// Add special files.
	m["sys"] = fs.GenericDentAttr(fs.SpecialFile, device.ProcDevice)
	names = append(names, "sys")

	// Collect tasks.
	// Per linux we only include it in directory listings if it's the leader.
	// But for whatever crazy reason, you can still walk to the given node.
	for _, tg := range p.pidns.ThreadGroups() {
		if leader := tg.Leader(); leader != nil {
			name := strconv.FormatUint(uint64(tg.ID()), 10)
			m[name] = fs.GenericDentAttr(fs.SpecialDirectory, device.ProcDevice)
			names = append(names, name)
		}
	}

	if offset >= len(m) {
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
	return offset, err
}

// newMountsSymlink returns a symlink to "self/mounts"
func newMountsSymlink(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	s := &ramfs.Symlink{}
	s.InitSymlink(ctx, fs.RootOwner, "self/mounts")
	return newFile(s, msrc, fs.Symlink, nil)
}
