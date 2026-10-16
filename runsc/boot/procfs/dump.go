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

// Package procfs holds the procfs information dumped for sandboxed processes.
package procfs

import (
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/limits"
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

// CgroupEntry is one line of /proc/[pid]/cgroup.
type CgroupEntry struct {
	HierarchyID uint32 `json:"hierarchy_id"`
	Controllers string `json:"controllers,omitempty"`
	Path        string `json:"path,omitempty"`
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
	// Limits constrains resource limits for this process. Currently only
	// RLIMIT_NOFILE is supported.
	Limits map[string]limits.Limit `json:"limits,omitempty"`
	// Cgroup is /proc/[pid]/cgroup split into an array.
	Cgroup []CgroupEntry `json:"cgroup,omitempty"`
	// Status is /proc/[pid]/status.
	Status Status `json:"status,omitempty"`
	// Stat is /proc/[pid]/stat.
	Stat Stat `json:"stat,omitempty"`
	// Maps is /proc/[pid]/maps.
	Maps []Mapping `json:"maps,omitempty"`
}
