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

// Package procfs holds utilities for getting procfs information for sandboxed
// processes.
package procfs

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
)

// FDInfo contains information about an application file descriptor.
type FDInfo struct {
	// Number is the FD number.
	Number int32 `json:"number"`
	// Path is the path of the file that FD represents.
	Path string `json:"path,omitempty"`
	// Mode is the file mode.
	Mode uint16 `json:"mode"`
}

// UIDGID contains information for /proc/[pid]/status/{uid,gid}.
type UIDGID struct {
	Real      uint32 `json:"real"`
	Effective uint32 `json:"effective"`
	Saved     uint32 `json:"saved"`
}

// Status contains information for /proc/[pid]/status.
type Status struct {
	Comm   string `json:"comm,omitempty"`
	PID    int32  `json:"pid"`
	PPID   int32  `json:"ppid"`
	UID    UIDGID `json:"uid,omitempty"`
	GID    UIDGID `json:"gid,omitempty"`
	VMSize uint64 `json:"vm_size,omitempty"`
	VMRSS  uint64 `json:"vm_rss,omitempty"`
}

// Stat contains information for /proc/[pid]/stat.
type Stat struct {
	PGID int32 `json:"pgid"`
	SID  int32 `json:"sid"`
}

// Mapping contains information for /proc/[pid]/maps.
type Mapping struct {
	Address     hostarch.AddrRange  `json:"address,omitempty"`
	Permissions hostarch.AccessType `json:"permissions"`
	Private     string              `json:"private,omitempty"`
	Offset      uint64              `json:"offset"`
	DevMajor    uint32              `json:"deviceMajor,omitempty"`
	DevMinor    uint32              `json:"deviceMinor,omitempty"`
	Inode       uint64              `json:"inode,omitempty"`
	Pathname    string              `json:"pathname,omitempty"`
}

// ProcessProcfsDump contains the procfs dump for one process. For more details
// on fields that directly correspond to /proc fields, see proc(5).
type ProcessProcfsDump struct {
	// Exe is the symlink target of /proc/[pid]/exe.
	Exe string `json:"exe,omitempty"`
	// Args is /proc/[pid]/cmdline split into an array.
	Args []string `json:"args,omitempty"`
	// Env is /proc/[pid]/environ split into an array.
	Env []string `json:"env,omitempty"`
	// CWD is the symlink target of /proc/[pid]/cwd.
	CWD string `json:"cwd,omitempty"`
	// FDs contains the directory entries of /proc/[pid]/fd and also contains the
	// symlink target for each FD.
	FDs []FDInfo `json:"fdlist,omitempty"`
	// StartTime is the process start time in nanoseconds since Unix epoch.
	StartTime int64 `json:"clone_ts,omitempty"`
	// Root is /proc/[pid]/root.
	Root string `json:"root,omitempty"`
	// Limits constains resource limits for this process. Currently only
	// RLIMIT_NOFILE is supported.
	Limits map[string]limits.Limit `json:"limits,omitempty"`
	// Cgroup is /proc/[pid]/cgroup split into an array.
	Cgroup []kernel.TaskCgroupEntry `json:"cgroup,omitempty"`
	// Status is /proc/[pid]/status.
	Status Status `json:"status,omitempty"`
	// Stat is /proc/[pid]/stat.
	Stat Stat `json:"stat,omitempty"`
	// Maps is /proc/[pid]/maps.
	Maps []Mapping `json:"maps,omitempty"`
}

// getMM returns t's MemoryManager. On success, the MemoryManager's users count
// is incremented, and must be decremented by the caller when it is no longer
// in use.
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

func getFDs(ctx context.Context, t *kernel.Task, pid kernel.ThreadID) []FDInfo {
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

	res := make([]FDInfo, 0, len(fds))
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
		res = append(res, FDInfo{Number: fd.no, Path: path, Mode: mode})
	}
	return res
}

func getRoot(t *kernel.Task, pid kernel.ThreadID) string {
	realRoot := t.MountNamespace().Root()
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

func getStatus(t *kernel.Task, mm *mm.MemoryManager, pid kernel.ThreadID, pidns *kernel.PIDNamespace) Status {
	creds := t.Credentials()
	uns := creds.UserNamespace
	ppid := kernel.ThreadID(0)
	if parent := t.Parent(); parent != nil {
		ppid = pidns.IDOfThreadGroup(parent.ThreadGroup())
	}
	return Status{
		Comm: t.Name(),
		PID:  int32(pid),
		PPID: int32(ppid),
		UID: UIDGID{
			Real:      uint32(creds.RealKUID.In(uns).OrOverflow()),
			Effective: uint32(creds.EffectiveKUID.In(uns).OrOverflow()),
			Saved:     uint32(creds.SavedKUID.In(uns).OrOverflow()),
		},
		GID: UIDGID{
			Real:      uint32(creds.RealKGID.In(uns).OrOverflow()),
			Effective: uint32(creds.EffectiveKGID.In(uns).OrOverflow()),
			Saved:     uint32(creds.SavedKGID.In(uns).OrOverflow()),
		},
		VMSize: mm.VirtualMemorySize() >> 10,
		VMRSS:  mm.ResidentSetSize() >> 10,
	}
}

func getStat(t *kernel.Task, pid kernel.ThreadID, pidns *kernel.PIDNamespace) Stat {
	return Stat{
		PGID: int32(pidns.IDOfProcessGroup(t.ThreadGroup().ProcessGroup())),
		SID:  int32(pidns.IDOfSession(t.ThreadGroup().Session())),
	}
}

func getMappings(ctx context.Context, mm *mm.MemoryManager) []Mapping {
	var maps []Mapping
	mm.ReadMapsDataInto(ctx, func(start, end hostarch.Addr, permissions hostarch.AccessType, private string, offset uint64, devMajor, devMinor uint32, inode uint64, path string) {
		maps = append(maps, Mapping{
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

// Dump returns a procfs dump for process pid. t must be a task in process pid.
func Dump(t *kernel.Task, pid kernel.ThreadID, pidns *kernel.PIDNamespace) (ProcessProcfsDump, error) {
	ctx := t.AsyncContext()

	mm := getMM(t)
	if mm == nil {
		return ProcessProcfsDump{}, fmt.Errorf("no MM found for PID %s", pid)
	}
	defer mm.DecUsers(ctx)

	fdLimit, err := getFDLimit(ctx, pid)
	if err != nil {
		return ProcessProcfsDump{}, err
	}

	return ProcessProcfsDump{
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
		Cgroup: t.GetCgroupEntries(),
		Status: getStatus(t, mm, pid, pidns),
		Stat:   getStat(t, pid, pidns),
		Maps:   getMappings(ctx, mm),
	}, nil
}
