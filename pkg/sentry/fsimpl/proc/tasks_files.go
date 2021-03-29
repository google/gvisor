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
	"fmt"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// +stateify savable
type selfSymlink struct {
	implStatFS
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeSymlink

	pidns *kernel.PIDNamespace
}

var _ kernfs.Inode = (*selfSymlink)(nil)

func (i *tasksInode) newSelfSymlink(ctx context.Context, creds *auth.Credentials) kernfs.Inode {
	inode := &selfSymlink{pidns: i.pidns}
	inode.Init(ctx, creds, linux.UNNAMED_MAJOR, i.fs.devMinor, i.fs.NextIno(), linux.ModeSymlink|0777)
	return inode
}

func (s *selfSymlink) Readlink(ctx context.Context, _ *vfs.Mount) (string, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		// Who is reading this link?
		return "", syserror.EINVAL
	}
	tgid := s.pidns.IDOfThreadGroup(t.ThreadGroup())
	if tgid == 0 {
		return "", syserror.ENOENT
	}
	return strconv.FormatUint(uint64(tgid), 10), nil
}

func (s *selfSymlink) Getlink(ctx context.Context, mnt *vfs.Mount) (vfs.VirtualDentry, string, error) {
	target, err := s.Readlink(ctx, mnt)
	return vfs.VirtualDentry{}, target, err
}

// SetStat implements kernfs.Inode.SetStat not allowing inode attributes to be changed.
func (*selfSymlink) SetStat(context.Context, *vfs.Filesystem, *auth.Credentials, vfs.SetStatOptions) error {
	return syserror.EPERM
}

// +stateify savable
type threadSelfSymlink struct {
	implStatFS
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeSymlink

	pidns *kernel.PIDNamespace
}

var _ kernfs.Inode = (*threadSelfSymlink)(nil)

func (i *tasksInode) newThreadSelfSymlink(ctx context.Context, creds *auth.Credentials) kernfs.Inode {
	inode := &threadSelfSymlink{pidns: i.pidns}
	inode.Init(ctx, creds, linux.UNNAMED_MAJOR, i.fs.devMinor, i.fs.NextIno(), linux.ModeSymlink|0777)
	return inode
}

func (s *threadSelfSymlink) Readlink(ctx context.Context, _ *vfs.Mount) (string, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		// Who is reading this link?
		return "", syserror.EINVAL
	}
	tgid := s.pidns.IDOfThreadGroup(t.ThreadGroup())
	tid := s.pidns.IDOfTask(t)
	if tid == 0 || tgid == 0 {
		return "", syserror.ENOENT
	}
	return fmt.Sprintf("%d/task/%d", tgid, tid), nil
}

func (s *threadSelfSymlink) Getlink(ctx context.Context, mnt *vfs.Mount) (vfs.VirtualDentry, string, error) {
	target, err := s.Readlink(ctx, mnt)
	return vfs.VirtualDentry{}, target, err
}

// SetStat implements kernfs.Inode.SetStat not allowing inode attributes to be changed.
func (*threadSelfSymlink) SetStat(context.Context, *vfs.Filesystem, *auth.Credentials, vfs.SetStatOptions) error {
	return syserror.EPERM
}

// dynamicBytesFileSetAttr implements a special file that allows inode
// attributes to be set. This is to support /proc files that are readonly, but
// allow attributes to be set.
//
// +stateify savable
type dynamicBytesFileSetAttr struct {
	kernfs.DynamicBytesFile
}

// SetStat implements kernfs.Inode.SetStat.
func (d *dynamicBytesFileSetAttr) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	return d.DynamicBytesFile.InodeAttrs.SetStat(ctx, fs, creds, opts)
}

// cpuStats contains the breakdown of CPU time for /proc/stat.
//
// +stateify savable
type cpuStats struct {
	// user is time spent in userspace tasks with non-positive niceness.
	user uint64

	// nice is time spent in userspace tasks with positive niceness.
	nice uint64

	// system is time spent in non-interrupt kernel context.
	system uint64

	// idle is time spent idle.
	idle uint64

	// ioWait is time spent waiting for IO.
	ioWait uint64

	// irq is time spent in interrupt context.
	irq uint64

	// softirq is time spent in software interrupt context.
	softirq uint64

	// steal is involuntary wait time.
	steal uint64

	// guest is time spent in guests with non-positive niceness.
	guest uint64

	// guestNice is time spent in guests with positive niceness.
	guestNice uint64
}

// String implements fmt.Stringer.
func (c cpuStats) String() string {
	return fmt.Sprintf("%d %d %d %d %d %d %d %d %d %d", c.user, c.nice, c.system, c.idle, c.ioWait, c.irq, c.softirq, c.steal, c.guest, c.guestNice)
}

// statData implements vfs.DynamicBytesSource for /proc/stat.
//
// +stateify savable
type statData struct {
	dynamicBytesFileSetAttr
}

var _ dynamicInode = (*statData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (*statData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	// TODO(b/37226836): We currently export only zero CPU stats. We could
	// at least provide some aggregate stats.
	var cpu cpuStats
	fmt.Fprintf(buf, "cpu  %s\n", cpu)

	k := kernel.KernelFromContext(ctx)
	for c, max := uint(0), k.ApplicationCores(); c < max; c++ {
		fmt.Fprintf(buf, "cpu%d %s\n", c, cpu)
	}

	// The total number of interrupts is dependent on the CPUs and PCI
	// devices on the system. See arch_probe_nr_irqs.
	//
	// Since we don't report real interrupt stats, just choose an arbitrary
	// value from a representative VM.
	const numInterrupts = 256

	// The Kernel doesn't handle real interrupts, so report all zeroes.
	// TODO(b/37226836): We could count page faults as #PF.
	fmt.Fprintf(buf, "intr 0") // total
	for i := 0; i < numInterrupts; i++ {
		fmt.Fprintf(buf, " 0")
	}
	fmt.Fprintf(buf, "\n")

	// Total number of context switches.
	// TODO(b/37226836): Count this.
	fmt.Fprintf(buf, "ctxt 0\n")

	// CLOCK_REALTIME timestamp from boot, in seconds.
	fmt.Fprintf(buf, "btime %d\n", k.Timekeeper().BootTime().Seconds())

	// Total number of clones.
	// TODO(b/37226836): Count this.
	fmt.Fprintf(buf, "processes 0\n")

	// Number of runnable tasks.
	// TODO(b/37226836): Count this.
	fmt.Fprintf(buf, "procs_running 0\n")

	// Number of tasks waiting on IO.
	// TODO(b/37226836): Count this.
	fmt.Fprintf(buf, "procs_blocked 0\n")

	// Number of each softirq handled.
	fmt.Fprintf(buf, "softirq 0") // total
	for i := 0; i < linux.NumSoftIRQ; i++ {
		fmt.Fprintf(buf, " 0")
	}
	fmt.Fprintf(buf, "\n")
	return nil
}

// loadavgData backs /proc/loadavg.
//
// +stateify savable
type loadavgData struct {
	dynamicBytesFileSetAttr
}

var _ dynamicInode = (*loadavgData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (*loadavgData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	// TODO(b/62345059): Include real data in fields.
	// Column 1-3: CPU and IO utilization of the last 1, 5, and 10 minute periods.
	// Column 4-5: currently running processes and the total number of processes.
	// Column 6: the last process ID used.
	fmt.Fprintf(buf, "%.2f %.2f %.2f %d/%d %d\n", 0.00, 0.00, 0.00, 0, 0, 0)
	return nil
}

// meminfoData implements vfs.DynamicBytesSource for /proc/meminfo.
//
// +stateify savable
type meminfoData struct {
	dynamicBytesFileSetAttr
}

var _ dynamicInode = (*meminfoData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (*meminfoData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	k := kernel.KernelFromContext(ctx)
	mf := k.MemoryFile()
	mf.UpdateUsage()
	snapshot, totalUsage := usage.MemoryAccounting.Copy()
	totalSize := usage.TotalMemory(mf.TotalSize(), totalUsage)
	anon := snapshot.Anonymous + snapshot.Tmpfs
	file := snapshot.PageCache + snapshot.Mapped
	// We don't actually have active/inactive LRUs, so just make up numbers.
	activeFile := (file / 2) &^ (hostarch.PageSize - 1)
	inactiveFile := file - activeFile

	fmt.Fprintf(buf, "MemTotal:       %8d kB\n", totalSize/1024)
	memFree := totalSize - totalUsage
	if memFree > totalSize {
		// Underflow.
		memFree = 0
	}
	// We use MemFree as MemAvailable because we don't swap.
	// TODO(rahat): When reclaim is implemented the value of MemAvailable
	// should change.
	fmt.Fprintf(buf, "MemFree:        %8d kB\n", memFree/1024)
	fmt.Fprintf(buf, "MemAvailable:   %8d kB\n", memFree/1024)
	fmt.Fprintf(buf, "Buffers:               0 kB\n") // memory usage by block devices
	fmt.Fprintf(buf, "Cached:         %8d kB\n", (file+snapshot.Tmpfs)/1024)
	// Emulate a system with no swap, which disables inactivation of anon pages.
	fmt.Fprintf(buf, "SwapCache:             0 kB\n")
	fmt.Fprintf(buf, "Active:         %8d kB\n", (anon+activeFile)/1024)
	fmt.Fprintf(buf, "Inactive:       %8d kB\n", inactiveFile/1024)
	fmt.Fprintf(buf, "Active(anon):   %8d kB\n", anon/1024)
	fmt.Fprintf(buf, "Inactive(anon):        0 kB\n")
	fmt.Fprintf(buf, "Active(file):   %8d kB\n", activeFile/1024)
	fmt.Fprintf(buf, "Inactive(file): %8d kB\n", inactiveFile/1024)
	fmt.Fprintf(buf, "Unevictable:           0 kB\n") // TODO(b/31823263)
	fmt.Fprintf(buf, "Mlocked:               0 kB\n") // TODO(b/31823263)
	fmt.Fprintf(buf, "SwapTotal:             0 kB\n")
	fmt.Fprintf(buf, "SwapFree:              0 kB\n")
	fmt.Fprintf(buf, "Dirty:                 0 kB\n")
	fmt.Fprintf(buf, "Writeback:             0 kB\n")
	fmt.Fprintf(buf, "AnonPages:      %8d kB\n", anon/1024)
	fmt.Fprintf(buf, "Mapped:         %8d kB\n", file/1024) // doesn't count mapped tmpfs, which we don't know
	fmt.Fprintf(buf, "Shmem:          %8d kB\n", snapshot.Tmpfs/1024)
	return nil
}

// uptimeData implements vfs.DynamicBytesSource for /proc/uptime.
//
// +stateify savable
type uptimeData struct {
	dynamicBytesFileSetAttr
}

var _ dynamicInode = (*uptimeData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (*uptimeData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	k := kernel.KernelFromContext(ctx)
	now := time.NowFromContext(ctx)

	// Pretend that we've spent zero time sleeping (second number).
	fmt.Fprintf(buf, "%.2f 0.00\n", now.Sub(k.Timekeeper().BootTime()).Seconds())
	return nil
}

// versionData implements vfs.DynamicBytesSource for /proc/version.
//
// +stateify savable
type versionData struct {
	dynamicBytesFileSetAttr
}

var _ dynamicInode = (*versionData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (*versionData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	k := kernel.KernelFromContext(ctx)
	init := k.GlobalInit()
	if init == nil {
		// Attempted to read before the init Task is created. This can
		// only occur during startup, which should never need to read
		// this file.
		panic("Attempted to read version before initial Task is available")
	}

	// /proc/version takes the form:
	//
	// "SYSNAME version RELEASE (COMPILE_USER@COMPILE_HOST)
	// (COMPILER_VERSION) VERSION"
	//
	// where:
	// - SYSNAME, RELEASE, and VERSION are the same as returned by
	// sys_utsname
	// - COMPILE_USER is the user that build the kernel
	// - COMPILE_HOST is the hostname of the machine on which the kernel
	// was built
	// - COMPILER_VERSION is the version reported by the building compiler
	//
	// Since we don't really want to expose build information to
	// applications, those fields are omitted.
	//
	// FIXME(mpratt): Using Version from the init task SyscallTable
	// disregards the different version a task may have (e.g., in a uts
	// namespace).
	ver := init.Leader().SyscallTable().Version
	fmt.Fprintf(buf, "%s version %s %s\n", ver.Sysname, ver.Release, ver.Version)
	return nil
}

// filesystemsData backs /proc/filesystems.
//
// +stateify savable
type filesystemsData struct {
	kernfs.DynamicBytesFile
}

var _ dynamicInode = (*filesystemsData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *filesystemsData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	k := kernel.KernelFromContext(ctx)
	k.VFS().GenerateProcFilesystems(buf)
	return nil
}
