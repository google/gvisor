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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// mm gets the kernel task's MemoryManager. No additional reference is taken on
// mm here. This is safe because MemoryManager.destroy is required to leave the
// MemoryManager in a state where it's still usable as a DynamicBytesSource.
func getMM(task *kernel.Task) *mm.MemoryManager {
	var tmm *mm.MemoryManager
	task.WithMuLocked(func(t *kernel.Task) {
		if mm := t.MemoryManager(); mm != nil {
			tmm = mm
		}
	})
	return tmm
}

// mapsData implements vfs.DynamicBytesSource for /proc/[pid]/maps.
//
// +stateify savable
type mapsData struct {
	kernfs.DynamicBytesFile

	task *kernel.Task
}

var _ dynamicInode = (*mapsData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *mapsData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if mm := getMM(d.task); mm != nil {
		mm.ReadMapsDataInto(ctx, buf)
	}
	return nil
}

// smapsData implements vfs.DynamicBytesSource for /proc/[pid]/smaps.
//
// +stateify savable
type smapsData struct {
	kernfs.DynamicBytesFile

	task *kernel.Task
}

var _ dynamicInode = (*smapsData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *smapsData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if mm := getMM(d.task); mm != nil {
		mm.ReadSmapsDataInto(ctx, buf)
	}
	return nil
}

// +stateify savable
type taskStatData struct {
	kernfs.DynamicBytesFile

	t *kernel.Task

	// If tgstats is true, accumulate fault stats (not implemented) and CPU
	// time across all tasks in t's thread group.
	tgstats bool

	// pidns is the PID namespace associated with the proc filesystem that
	// includes the file using this statData.
	pidns *kernel.PIDNamespace
}

var _ dynamicInode = (*taskStatData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (s *taskStatData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%d ", s.pidns.IDOfTask(s.t))
	fmt.Fprintf(buf, "(%s) ", s.t.Name())
	fmt.Fprintf(buf, "%c ", s.t.StateStatus()[0])
	ppid := kernel.ThreadID(0)
	if parent := s.t.Parent(); parent != nil {
		ppid = s.pidns.IDOfThreadGroup(parent.ThreadGroup())
	}
	fmt.Fprintf(buf, "%d ", ppid)
	fmt.Fprintf(buf, "%d ", s.pidns.IDOfProcessGroup(s.t.ThreadGroup().ProcessGroup()))
	fmt.Fprintf(buf, "%d ", s.pidns.IDOfSession(s.t.ThreadGroup().Session()))
	fmt.Fprintf(buf, "0 0 " /* tty_nr tpgid */)
	fmt.Fprintf(buf, "0 " /* flags */)
	fmt.Fprintf(buf, "0 0 0 0 " /* minflt cminflt majflt cmajflt */)
	var cputime usage.CPUStats
	if s.tgstats {
		cputime = s.t.ThreadGroup().CPUStats()
	} else {
		cputime = s.t.CPUStats()
	}
	fmt.Fprintf(buf, "%d %d ", linux.ClockTFromDuration(cputime.UserTime), linux.ClockTFromDuration(cputime.SysTime))
	cputime = s.t.ThreadGroup().JoinedChildCPUStats()
	fmt.Fprintf(buf, "%d %d ", linux.ClockTFromDuration(cputime.UserTime), linux.ClockTFromDuration(cputime.SysTime))
	fmt.Fprintf(buf, "%d %d ", s.t.Priority(), s.t.Niceness())
	fmt.Fprintf(buf, "%d ", s.t.ThreadGroup().Count())

	// itrealvalue. Since kernel 2.6.17, this field is no longer
	// maintained, and is hard coded as 0.
	fmt.Fprintf(buf, "0 ")

	// Start time is relative to boot time, expressed in clock ticks.
	fmt.Fprintf(buf, "%d ", linux.ClockTFromDuration(s.t.StartTime().Sub(s.t.Kernel().Timekeeper().BootTime())))

	var vss, rss uint64
	s.t.WithMuLocked(func(t *kernel.Task) {
		if mm := t.MemoryManager(); mm != nil {
			vss = mm.VirtualMemorySize()
			rss = mm.ResidentSetSize()
		}
	})
	fmt.Fprintf(buf, "%d %d ", vss, rss/usermem.PageSize)

	// rsslim.
	fmt.Fprintf(buf, "%d ", s.t.ThreadGroup().Limits().Get(limits.Rss).Cur)

	fmt.Fprintf(buf, "0 0 0 0 0 " /* startcode endcode startstack kstkesp kstkeip */)
	fmt.Fprintf(buf, "0 0 0 0 0 " /* signal blocked sigignore sigcatch wchan */)
	fmt.Fprintf(buf, "0 0 " /* nswap cnswap */)
	terminationSignal := linux.Signal(0)
	if s.t == s.t.ThreadGroup().Leader() {
		terminationSignal = s.t.ThreadGroup().TerminationSignal()
	}
	fmt.Fprintf(buf, "%d ", terminationSignal)
	fmt.Fprintf(buf, "0 0 0 " /* processor rt_priority policy */)
	fmt.Fprintf(buf, "0 0 0 " /* delayacct_blkio_ticks guest_time cguest_time */)
	fmt.Fprintf(buf, "0 0 0 0 0 0 0 " /* start_data end_data start_brk arg_start arg_end env_start env_end */)
	fmt.Fprintf(buf, "0\n" /* exit_code */)

	return nil
}

// statmData implements vfs.DynamicBytesSource for /proc/[pid]/statm.
//
// +stateify savable
type statmData struct {
	kernfs.DynamicBytesFile

	t *kernel.Task
}

var _ dynamicInode = (*statmData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (s *statmData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	var vss, rss uint64
	s.t.WithMuLocked(func(t *kernel.Task) {
		if mm := t.MemoryManager(); mm != nil {
			vss = mm.VirtualMemorySize()
			rss = mm.ResidentSetSize()
		}
	})

	fmt.Fprintf(buf, "%d %d 0 0 0 0 0\n", vss/usermem.PageSize, rss/usermem.PageSize)
	return nil
}

// statusData implements vfs.DynamicBytesSource for /proc/[pid]/status.
//
// +stateify savable
type statusData struct {
	kernfs.DynamicBytesFile

	t     *kernel.Task
	pidns *kernel.PIDNamespace
}

var _ dynamicInode = (*statusData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (s *statusData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "Name:\t%s\n", s.t.Name())
	fmt.Fprintf(buf, "State:\t%s\n", s.t.StateStatus())
	fmt.Fprintf(buf, "Tgid:\t%d\n", s.pidns.IDOfThreadGroup(s.t.ThreadGroup()))
	fmt.Fprintf(buf, "Pid:\t%d\n", s.pidns.IDOfTask(s.t))
	ppid := kernel.ThreadID(0)
	if parent := s.t.Parent(); parent != nil {
		ppid = s.pidns.IDOfThreadGroup(parent.ThreadGroup())
	}
	fmt.Fprintf(buf, "PPid:\t%d\n", ppid)
	tpid := kernel.ThreadID(0)
	if tracer := s.t.Tracer(); tracer != nil {
		tpid = s.pidns.IDOfTask(tracer)
	}
	fmt.Fprintf(buf, "TracerPid:\t%d\n", tpid)
	var fds int
	var vss, rss, data uint64
	s.t.WithMuLocked(func(t *kernel.Task) {
		if fdTable := t.FDTable(); fdTable != nil {
			fds = fdTable.Size()
		}
		if mm := t.MemoryManager(); mm != nil {
			vss = mm.VirtualMemorySize()
			rss = mm.ResidentSetSize()
			data = mm.VirtualDataSize()
		}
	})
	fmt.Fprintf(buf, "FDSize:\t%d\n", fds)
	fmt.Fprintf(buf, "VmSize:\t%d kB\n", vss>>10)
	fmt.Fprintf(buf, "VmRSS:\t%d kB\n", rss>>10)
	fmt.Fprintf(buf, "VmData:\t%d kB\n", data>>10)
	fmt.Fprintf(buf, "Threads:\t%d\n", s.t.ThreadGroup().Count())
	creds := s.t.Credentials()
	fmt.Fprintf(buf, "CapInh:\t%016x\n", creds.InheritableCaps)
	fmt.Fprintf(buf, "CapPrm:\t%016x\n", creds.PermittedCaps)
	fmt.Fprintf(buf, "CapEff:\t%016x\n", creds.EffectiveCaps)
	fmt.Fprintf(buf, "CapBnd:\t%016x\n", creds.BoundingCaps)
	fmt.Fprintf(buf, "Seccomp:\t%d\n", s.t.SeccompMode())
	// We unconditionally report a single NUMA node. See
	// pkg/sentry/syscalls/linux/sys_mempolicy.go.
	fmt.Fprintf(buf, "Mems_allowed:\t1\n")
	fmt.Fprintf(buf, "Mems_allowed_list:\t0\n")
	return nil
}

// ioUsage is the /proc/<pid>/io and /proc/<pid>/task/<tid>/io data provider.
type ioUsage interface {
	// IOUsage returns the io usage data.
	IOUsage() *usage.IO
}

// +stateify savable
type ioData struct {
	kernfs.DynamicBytesFile

	ioUsage
}

var _ dynamicInode = (*ioData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (i *ioData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	io := usage.IO{}
	io.Accumulate(i.IOUsage())

	fmt.Fprintf(buf, "char: %d\n", io.CharsRead)
	fmt.Fprintf(buf, "wchar: %d\n", io.CharsWritten)
	fmt.Fprintf(buf, "syscr: %d\n", io.ReadSyscalls)
	fmt.Fprintf(buf, "syscw: %d\n", io.WriteSyscalls)
	fmt.Fprintf(buf, "read_bytes: %d\n", io.BytesRead)
	fmt.Fprintf(buf, "write_bytes: %d\n", io.BytesWritten)
	fmt.Fprintf(buf, "cancelled_write_bytes: %d\n", io.BytesWriteCancelled)
	return nil
}
