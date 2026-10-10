// Copyright 2022 The gVisor Authors.
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

package boot

import (
	"bytes"
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/proc"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/runsc/boot/procfs"
)

// getMM returns t's MemoryManager. On success, the MemoryManager's users count
// is incremented, and must be decremented by the caller when it is no longer
// in use.
//
// +checklocksexclude:t.mu
func getMM(t *kernel.Task) *mm.MemoryManager {
	var mm *mm.MemoryManager
	t.WithMuLocked(func(*kernel.Task) {
		mm = t.MemoryManager()
	})
	if mm == nil || !mm.IncUsers() {
		return nil
	}
	return mm
}

func getExecutablePath(ctx context.Context, pid kernel.ThreadID, mm *mm.MemoryManager) string {
	exec := mm.Executable()
	if exec == nil {
		log.Warningf("No executable found for PID %s", pid)
		return ""
	}
	defer exec.DecRef(ctx)

	return exec.MappedName(ctx)
}

func getMetadataArray(ctx context.Context, pid kernel.ThreadID, mm *mm.MemoryManager, metaType proc.MetadataType) []string {
	buf := bytes.Buffer{}
	if err := proc.GetMetadata(ctx, mm, &buf, metaType); err != nil {
		log.Warningf("failed to get %v metadata for PID %s: %v", metaType, pid, err)
		return nil
	}
	// As per proc(5), /proc/[pid]/cmdline may have "a further null byte after
	// the last string". Similarly, for /proc/[pid]/environ "there may be a null
	// byte at the end". So trim off the last null byte if it exists.
	return strings.Split(strings.TrimSuffix(buf.String(), "\000"), "\000")
}

func getCWD(ctx context.Context, t *kernel.Task, pid kernel.ThreadID) string {
	cwdDentry := t.FSContext().WorkingDirectory()
	if !cwdDentry.Ok() {
		log.Warningf("No CWD dentry found for PID %s", pid)
		return ""
	}

	root := vfs.RootFromContext(ctx)
	if !root.Ok() {
		log.Warningf("no root could be found from context for PID %s", pid)
		return ""
	}
	defer root.DecRef(ctx)

	vfsObj := cwdDentry.Mount().Filesystem().VirtualFilesystem()
	name, err := vfsObj.PathnameWithDeleted(ctx, root, cwdDentry)
	if err != nil {
		log.Warningf("PathnameWithDeleted failed to find CWD: %v", err)
	}
	return name
}

// +checklocksexclude:t.mu
func getFDs(ctx context.Context, t *kernel.Task, pid kernel.ThreadID) []procfs.FDInfo {
	type fdInfo struct {
		fd *vfs.FileDescription
		no int32
	}
	var fds []fdInfo
	defer func() {
		for _, fd := range fds {
			fd.fd.DecRef(ctx)
		}
	}()

	t.WithMuLocked(func(t *kernel.Task) {
		if fdTable := t.FDTable(); fdTable != nil {
			fdNos := fdTable.GetFDs(ctx)
			fds = make([]fdInfo, 0, len(fdNos))
			for _, fd := range fdNos {
				file, _ := fdTable.Get(fd)
				if file != nil {
					fds = append(fds, fdInfo{fd: file, no: fd})
				}
			}
		}
	})

	root := vfs.RootFromContext(ctx)
	defer root.DecRef(ctx)

	res := make([]procfs.FDInfo, 0, len(fds))
	for _, fd := range fds {
		path, err := t.Kernel().VFS().PathnameWithDeleted(ctx, root, fd.fd.VirtualDentry())
		if err != nil {
			log.Warningf("PathnameWithDeleted failed to find path for fd %d in PID %s: %v", fd.no, pid, err)
			path = ""
		}
		mode := uint16(0)
		if statx, err := fd.fd.Stat(ctx, vfs.StatOptions{Mask: linux.STATX_MODE}); err != nil {
			log.Warningf("Stat(STATX_MODE) failed for fd %d in PID %s: %v", fd.no, pid, err)
		} else {
			mode = statx.Mode
		}
		res = append(res, procfs.FDInfo{Number: fd.no, Path: path, Mode: mode})
	}
	return res
}

func getRoot(t *kernel.Task, pid kernel.ThreadID) string {
	realRoot := t.MountNamespace().Root(t)
	defer realRoot.DecRef(t)
	root := t.FSContext().RootDirectory()
	defer root.DecRef(t)
	path, err := t.Kernel().VFS().PathnameWithDeleted(t, realRoot, root)
	if err != nil {
		log.Warningf("PathnameWithDeleted failed to find root path for PID %s: %v", pid, err)
		return ""
	}
	return path
}

func getFDLimit(ctx context.Context, pid kernel.ThreadID) (limits.Limit, error) {
	if limitSet := limits.FromContext(ctx); limitSet != nil {
		return limitSet.Get(limits.NumberOfFiles), nil
	}
	return limits.Limit{}, fmt.Errorf("could not find limit set for pid %s", pid)
}

func getStatus(t *kernel.Task, mm *mm.MemoryManager, pid kernel.ThreadID, pidns *kernel.PIDNamespace) procfs.Status {
	creds := t.Credentials()
	uns := creds.UserNamespace
	ppid := kernel.ThreadID(0)
	if parent := t.Parent(); parent != nil {
		ppid = pidns.IDOfThreadGroup(parent.ThreadGroup())
	}
	return procfs.Status{
		Comm: t.Name(),
		PID:  int32(pid),
		PPID: int32(ppid),
		UID: procfs.UIDGID{
			Real:      uint32(creds.RealKUID.In(uns).OrOverflow()),
			Effective: uint32(creds.EffectiveKUID.In(uns).OrOverflow()),
			Saved:     uint32(creds.SavedKUID.In(uns).OrOverflow()),
		},
		GID: procfs.UIDGID{
			Real:      uint32(creds.RealKGID.In(uns).OrOverflow()),
			Effective: uint32(creds.EffectiveKGID.In(uns).OrOverflow()),
			Saved:     uint32(creds.SavedKGID.In(uns).OrOverflow()),
		},
		VMSize: mm.VirtualMemorySize() >> 10,
		VMRSS:  mm.ResidentSetSize() >> 10,
	}
}

func getStat(t *kernel.Task, pid kernel.ThreadID, pidns *kernel.PIDNamespace) procfs.Stat {
	return procfs.Stat{
		PGID: int32(pidns.IDOfProcessGroup(t.ThreadGroup().ProcessGroup())),
		SID:  int32(pidns.IDOfSession(t.ThreadGroup().Session())),
	}
}

func getMappings(ctx context.Context, mm *mm.MemoryManager) []procfs.Mapping {
	var maps []procfs.Mapping
	mm.ReadMapsDataInto(ctx, func(start, end hostarch.Addr, permissions hostarch.AccessType, private string, offset uint64, devMajor, devMinor uint32, inode uint64, path string) {
		maps = append(maps, procfs.Mapping{
			Address: hostarch.AddrRange{
				Start: start,
				End:   end,
			},
			Permissions: permissions,
			Private:     private,
			Offset:      offset,
			DevMajor:    devMajor,
			DevMinor:    devMinor,
			Inode:       inode,
			Pathname:    path,
		})
	})

	return maps
}

// dumpProcfs returns a procfs dump for process pid. t must be a task in process pid.
//
// +checklocksexclude:t.mu
func dumpProcfs(t *kernel.Task, pid kernel.ThreadID, pidns *kernel.PIDNamespace) (procfs.ProcessProcfsDump, error) {
	ctx := t.AsyncContext()

	mm := getMM(t)
	if mm == nil {
		return procfs.ProcessProcfsDump{}, fmt.Errorf("no MM found for PID %s", pid)
	}
	defer mm.DecUsers(ctx)

	fdLimit, err := getFDLimit(ctx, pid)
	if err != nil {
		return procfs.ProcessProcfsDump{}, err
	}

	return procfs.ProcessProcfsDump{
		Exe:       getExecutablePath(ctx, pid, mm),
		Args:      getMetadataArray(ctx, pid, mm, proc.Cmdline),
		Env:       getMetadataArray(ctx, pid, mm, proc.Environ),
		CWD:       getCWD(ctx, t, pid),
		FDs:       getFDs(ctx, t, pid),
		StartTime: t.StartTime().Nanoseconds(),
		Root:      getRoot(t, pid),
		Limits: map[string]limits.Limit{
			"RLIMIT_NOFILE": fdLimit,
		},
		// We don't need to worry about fake cgroup controllers as that is not
		// supported in runsc.
		Cgroup: getCgroupEntries(t),
		Status: getStatus(t, mm, pid, pidns),
		Stat:   getStat(t, pid, pidns),
		Maps:   getMappings(ctx, mm),
	}, nil
}

func getCgroupEntries(t *kernel.Task) []procfs.CgroupEntry {
	entries := t.GetCgroupEntries()
	out := make([]procfs.CgroupEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, procfs.CgroupEntry(e))
	}
	return out
}
