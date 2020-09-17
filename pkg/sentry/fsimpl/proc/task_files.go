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
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/safemem"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/fsbridge"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// "There is an (arbitrary) limit on the number of lines in the file. As at
// Linux 3.18, the limit is five lines." - user_namespaces(7)
const maxIDMapLines = 5

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

// getMMIncRef returns t's MemoryManager. If getMMIncRef succeeds, the
// MemoryManager's users count is incremented, and must be decremented by the
// caller when it is no longer in use.
func getMMIncRef(task *kernel.Task) (*mm.MemoryManager, error) {
	if task.ExitState() == kernel.TaskExitDead {
		return nil, syserror.ESRCH
	}
	var m *mm.MemoryManager
	task.WithMuLocked(func(t *kernel.Task) {
		m = t.MemoryManager()
	})
	if m == nil || !m.IncUsers() {
		return nil, io.EOF
	}
	return m, nil
}

func checkTaskState(t *kernel.Task) error {
	switch t.ExitState() {
	case kernel.TaskExitZombie:
		return syserror.EACCES
	case kernel.TaskExitDead:
		return syserror.ESRCH
	}
	return nil
}

type bufferWriter struct {
	buf *bytes.Buffer
}

// WriteFromBlocks writes up to srcs.NumBytes() bytes from srcs and returns
// the number of bytes written. It may return a partial write without an
// error (i.e. (n, nil) where 0 < n < srcs.NumBytes()). It should not
// return a full write with an error (i.e. srcs.NumBytes(), err) where err
// != nil).
func (w *bufferWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	written := srcs.NumBytes()
	for !srcs.IsEmpty() {
		w.buf.Write(srcs.Head().ToSlice())
		srcs = srcs.Tail()
	}
	return written, nil
}

// auxvData implements vfs.DynamicBytesSource for /proc/[pid]/auxv.
//
// +stateify savable
type auxvData struct {
	kernfs.DynamicBytesFile

	task *kernel.Task
}

var _ dynamicInode = (*auxvData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *auxvData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	m, err := getMMIncRef(d.task)
	if err != nil {
		return err
	}
	defer m.DecUsers(ctx)

	auxv := m.Auxv()
	// Space for buffer with AT_NULL (0) terminator at the end.
	buf.Grow((len(auxv) + 1) * 16)
	for _, e := range auxv {
		var tmp [16]byte
		usermem.ByteOrder.PutUint64(tmp[:8], e.Key)
		usermem.ByteOrder.PutUint64(tmp[8:], uint64(e.Value))
		buf.Write(tmp[:])
	}
	var atNull [16]byte
	buf.Write(atNull[:])

	return nil
}

// execArgType enumerates the types of exec arguments that are exposed through
// proc.
type execArgType int

const (
	cmdlineDataArg execArgType = iota
	environDataArg
)

// cmdlineData implements vfs.DynamicBytesSource for /proc/[pid]/cmdline.
//
// +stateify savable
type cmdlineData struct {
	kernfs.DynamicBytesFile

	task *kernel.Task

	// arg is the type of exec argument this file contains.
	arg execArgType
}

var _ dynamicInode = (*cmdlineData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *cmdlineData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	m, err := getMMIncRef(d.task)
	if err != nil {
		return err
	}
	defer m.DecUsers(ctx)

	// Figure out the bounds of the exec arg we are trying to read.
	var ar usermem.AddrRange
	switch d.arg {
	case cmdlineDataArg:
		ar = usermem.AddrRange{
			Start: m.ArgvStart(),
			End:   m.ArgvEnd(),
		}
	case environDataArg:
		ar = usermem.AddrRange{
			Start: m.EnvvStart(),
			End:   m.EnvvEnd(),
		}
	default:
		panic(fmt.Sprintf("unknown exec arg type %v", d.arg))
	}
	if ar.Start == 0 || ar.End == 0 {
		// Don't attempt to read before the start/end are set up.
		return io.EOF
	}

	// N.B. Technically this should be usermem.IOOpts.IgnorePermissions = true
	// until Linux 4.9 (272ddc8b3735 "proc: don't use FOLL_FORCE for reading
	// cmdline and environment").
	writer := &bufferWriter{buf: buf}
	if n, err := m.CopyInTo(ctx, usermem.AddrRangeSeqOf(ar), writer, usermem.IOOpts{}); n == 0 || err != nil {
		// Nothing to copy or something went wrong.
		return err
	}

	// On Linux, if the NULL byte at the end of the argument vector has been
	// overwritten, it continues reading the environment vector as part of
	// the argument vector.
	if d.arg == cmdlineDataArg && buf.Bytes()[buf.Len()-1] != 0 {
		if end := bytes.IndexByte(buf.Bytes(), 0); end != -1 {
			// If we found a NULL character somewhere else in argv, truncate the
			// return up to the NULL terminator (including it).
			buf.Truncate(end)
			return nil
		}

		// There is no NULL terminator in the string, return into envp.
		arEnvv := usermem.AddrRange{
			Start: m.EnvvStart(),
			End:   m.EnvvEnd(),
		}

		// Upstream limits the returned amount to one page of slop.
		// https://elixir.bootlin.com/linux/v4.20/source/fs/proc/base.c#L208
		// we'll return one page total between argv and envp because of the
		// above page restrictions.
		if buf.Len() >= usermem.PageSize {
			// Returned at least one page already, nothing else to add.
			return nil
		}
		remaining := usermem.PageSize - buf.Len()
		if int(arEnvv.Length()) > remaining {
			end, ok := arEnvv.Start.AddLength(uint64(remaining))
			if !ok {
				return syserror.EFAULT
			}
			arEnvv.End = end
		}
		if _, err := m.CopyInTo(ctx, usermem.AddrRangeSeqOf(arEnvv), writer, usermem.IOOpts{}); err != nil {
			return err
		}

		// Linux will return envp up to and including the first NULL character,
		// so find it.
		envStart := int(ar.Length())
		if nullIdx := bytes.IndexByte(buf.Bytes()[envStart:], 0); nullIdx != -1 {
			buf.Truncate(envStart + nullIdx)
		}
	}

	return nil
}

// +stateify savable
type commInode struct {
	kernfs.DynamicBytesFile

	task *kernel.Task
}

func (fs *filesystem) newComm(task *kernel.Task, ino uint64, perm linux.FileMode) *kernfs.Dentry {
	inode := &commInode{task: task}
	inode.DynamicBytesFile.Init(task.Credentials(), linux.UNNAMED_MAJOR, fs.devMinor, ino, &commData{task: task}, perm)

	d := &kernfs.Dentry{}
	d.Init(inode)
	return d
}

func (i *commInode) CheckPermissions(ctx context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	// This file can always be read or written by members of the same thread
	// group. See fs/proc/base.c:proc_tid_comm_permission.
	//
	// N.B. This check is currently a no-op as we don't yet support writing and
	// this file is world-readable anyways.
	t := kernel.TaskFromContext(ctx)
	if t != nil && t.ThreadGroup() == i.task.ThreadGroup() && !ats.MayExec() {
		return nil
	}

	return i.DynamicBytesFile.CheckPermissions(ctx, creds, ats)
}

// commData implements vfs.DynamicBytesSource for /proc/[pid]/comm.
//
// +stateify savable
type commData struct {
	kernfs.DynamicBytesFile

	task *kernel.Task
}

var _ dynamicInode = (*commData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *commData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString(d.task.Name())
	buf.WriteString("\n")
	return nil
}

// idMapData implements vfs.WritableDynamicBytesSource for
// /proc/[pid]/{gid_map|uid_map}.
//
// +stateify savable
type idMapData struct {
	kernfs.DynamicBytesFile

	task *kernel.Task
	gids bool
}

var _ dynamicInode = (*idMapData)(nil)

// Generate implements vfs.WritableDynamicBytesSource.Generate.
func (d *idMapData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	var entries []auth.IDMapEntry
	if d.gids {
		entries = d.task.UserNamespace().GIDMap()
	} else {
		entries = d.task.UserNamespace().UIDMap()
	}
	for _, e := range entries {
		fmt.Fprintf(buf, "%10d %10d %10d\n", e.FirstID, e.FirstParentID, e.Length)
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *idMapData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	// "In addition, the number of bytes written to the file must be less than
	// the system page size, and the write must be performed at the start of
	// the file ..." - user_namespaces(7)
	srclen := src.NumBytes()
	if srclen >= usermem.PageSize || offset != 0 {
		return 0, syserror.EINVAL
	}
	b := make([]byte, srclen)
	if _, err := src.CopyIn(ctx, b); err != nil {
		return 0, err
	}

	// Truncate from the first NULL byte.
	var nul int64
	nul = int64(bytes.IndexByte(b, 0))
	if nul == -1 {
		nul = srclen
	}
	b = b[:nul]
	// Remove the last \n.
	if nul >= 1 && b[nul-1] == '\n' {
		b = b[:nul-1]
	}
	lines := bytes.SplitN(b, []byte("\n"), maxIDMapLines+1)
	if len(lines) > maxIDMapLines {
		return 0, syserror.EINVAL
	}

	entries := make([]auth.IDMapEntry, len(lines))
	for i, l := range lines {
		var e auth.IDMapEntry
		_, err := fmt.Sscan(string(l), &e.FirstID, &e.FirstParentID, &e.Length)
		if err != nil {
			return 0, syserror.EINVAL
		}
		entries[i] = e
	}
	var err error
	if d.gids {
		err = d.task.UserNamespace().SetGIDMap(ctx, entries)
	} else {
		err = d.task.UserNamespace().SetUIDMap(ctx, entries)
	}
	if err != nil {
		return 0, err
	}

	// On success, Linux's kernel/user_namespace.c:map_write() always returns
	// count, even if fewer bytes were used.
	return int64(srclen), nil
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

	task *kernel.Task

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
	fmt.Fprintf(buf, "%d ", s.pidns.IDOfTask(s.task))
	fmt.Fprintf(buf, "(%s) ", s.task.Name())
	fmt.Fprintf(buf, "%c ", s.task.StateStatus()[0])
	ppid := kernel.ThreadID(0)
	if parent := s.task.Parent(); parent != nil {
		ppid = s.pidns.IDOfThreadGroup(parent.ThreadGroup())
	}
	fmt.Fprintf(buf, "%d ", ppid)
	fmt.Fprintf(buf, "%d ", s.pidns.IDOfProcessGroup(s.task.ThreadGroup().ProcessGroup()))
	fmt.Fprintf(buf, "%d ", s.pidns.IDOfSession(s.task.ThreadGroup().Session()))
	fmt.Fprintf(buf, "0 0 " /* tty_nr tpgid */)
	fmt.Fprintf(buf, "0 " /* flags */)
	fmt.Fprintf(buf, "0 0 0 0 " /* minflt cminflt majflt cmajflt */)
	var cputime usage.CPUStats
	if s.tgstats {
		cputime = s.task.ThreadGroup().CPUStats()
	} else {
		cputime = s.task.CPUStats()
	}
	fmt.Fprintf(buf, "%d %d ", linux.ClockTFromDuration(cputime.UserTime), linux.ClockTFromDuration(cputime.SysTime))
	cputime = s.task.ThreadGroup().JoinedChildCPUStats()
	fmt.Fprintf(buf, "%d %d ", linux.ClockTFromDuration(cputime.UserTime), linux.ClockTFromDuration(cputime.SysTime))
	fmt.Fprintf(buf, "%d %d ", s.task.Priority(), s.task.Niceness())
	fmt.Fprintf(buf, "%d ", s.task.ThreadGroup().Count())

	// itrealvalue. Since kernel 2.6.17, this field is no longer
	// maintained, and is hard coded as 0.
	fmt.Fprintf(buf, "0 ")

	// Start time is relative to boot time, expressed in clock ticks.
	fmt.Fprintf(buf, "%d ", linux.ClockTFromDuration(s.task.StartTime().Sub(s.task.Kernel().Timekeeper().BootTime())))

	var vss, rss uint64
	s.task.WithMuLocked(func(t *kernel.Task) {
		if mm := t.MemoryManager(); mm != nil {
			vss = mm.VirtualMemorySize()
			rss = mm.ResidentSetSize()
		}
	})
	fmt.Fprintf(buf, "%d %d ", vss, rss/usermem.PageSize)

	// rsslim.
	fmt.Fprintf(buf, "%d ", s.task.ThreadGroup().Limits().Get(limits.Rss).Cur)

	fmt.Fprintf(buf, "0 0 0 0 0 " /* startcode endcode startstack kstkesp kstkeip */)
	fmt.Fprintf(buf, "0 0 0 0 0 " /* signal blocked sigignore sigcatch wchan */)
	fmt.Fprintf(buf, "0 0 " /* nswap cnswap */)
	terminationSignal := linux.Signal(0)
	if s.task == s.task.ThreadGroup().Leader() {
		terminationSignal = s.task.ThreadGroup().TerminationSignal()
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

	task *kernel.Task
}

var _ dynamicInode = (*statmData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (s *statmData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	var vss, rss uint64
	s.task.WithMuLocked(func(t *kernel.Task) {
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

	task  *kernel.Task
	pidns *kernel.PIDNamespace
}

var _ dynamicInode = (*statusData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (s *statusData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "Name:\t%s\n", s.task.Name())
	fmt.Fprintf(buf, "State:\t%s\n", s.task.StateStatus())
	fmt.Fprintf(buf, "Tgid:\t%d\n", s.pidns.IDOfThreadGroup(s.task.ThreadGroup()))
	fmt.Fprintf(buf, "Pid:\t%d\n", s.pidns.IDOfTask(s.task))
	ppid := kernel.ThreadID(0)
	if parent := s.task.Parent(); parent != nil {
		ppid = s.pidns.IDOfThreadGroup(parent.ThreadGroup())
	}
	fmt.Fprintf(buf, "PPid:\t%d\n", ppid)
	tpid := kernel.ThreadID(0)
	if tracer := s.task.Tracer(); tracer != nil {
		tpid = s.pidns.IDOfTask(tracer)
	}
	fmt.Fprintf(buf, "TracerPid:\t%d\n", tpid)
	var fds int
	var vss, rss, data uint64
	s.task.WithMuLocked(func(t *kernel.Task) {
		if fdTable := t.FDTable(); fdTable != nil {
			fds = fdTable.CurrentMaxFDs()
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
	fmt.Fprintf(buf, "Threads:\t%d\n", s.task.ThreadGroup().Count())
	creds := s.task.Credentials()
	fmt.Fprintf(buf, "CapInh:\t%016x\n", creds.InheritableCaps)
	fmt.Fprintf(buf, "CapPrm:\t%016x\n", creds.PermittedCaps)
	fmt.Fprintf(buf, "CapEff:\t%016x\n", creds.EffectiveCaps)
	fmt.Fprintf(buf, "CapBnd:\t%016x\n", creds.BoundingCaps)
	fmt.Fprintf(buf, "Seccomp:\t%d\n", s.task.SeccompMode())
	// We unconditionally report a single NUMA node. See
	// pkg/sentry/syscalls/linux/sys_mempolicy.go.
	fmt.Fprintf(buf, "Mems_allowed:\t1\n")
	fmt.Fprintf(buf, "Mems_allowed_list:\t0\n")
	return nil
}

// ioUsage is the /proc/[pid]/io and /proc/[pid]/task/[tid]/io data provider.
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

// oomScoreAdj is a stub of the /proc/<pid>/oom_score_adj file.
//
// +stateify savable
type oomScoreAdj struct {
	kernfs.DynamicBytesFile

	task *kernel.Task
}

var _ vfs.WritableDynamicBytesSource = (*oomScoreAdj)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (o *oomScoreAdj) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if o.task.ExitState() == kernel.TaskExitDead {
		return syserror.ESRCH
	}
	fmt.Fprintf(buf, "%d\n", o.task.OOMScoreAdj())
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (o *oomScoreAdj) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() == 0 {
		return 0, nil
	}

	// Limit input size so as not to impact performance if input size is large.
	src = src.TakeFirst(usermem.PageSize - 1)

	var v int32
	n, err := usermem.CopyInt32StringInVec(ctx, src.IO, src.Addrs, &v, src.Opts)
	if err != nil {
		return 0, err
	}

	if o.task.ExitState() == kernel.TaskExitDead {
		return 0, syserror.ESRCH
	}
	if err := o.task.SetOOMScoreAdj(v); err != nil {
		return 0, err
	}

	return n, nil
}

// exeSymlink is an symlink for the /proc/[pid]/exe file.
//
// +stateify savable
type exeSymlink struct {
	implStatFS
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeSymlink

	task *kernel.Task
}

var _ kernfs.Inode = (*exeSymlink)(nil)

func (fs *filesystem) newExeSymlink(task *kernel.Task, ino uint64) *kernfs.Dentry {
	inode := &exeSymlink{task: task}
	inode.Init(task.Credentials(), linux.UNNAMED_MAJOR, fs.devMinor, ino, linux.ModeSymlink|0777)

	d := &kernfs.Dentry{}
	d.Init(inode)
	return d
}

// Readlink implements kernfs.Inode.
func (s *exeSymlink) Readlink(ctx context.Context, _ *vfs.Mount) (string, error) {
	if !kernel.ContextCanTrace(ctx, s.task, false) {
		return "", syserror.EACCES
	}

	// Pull out the executable for /proc/[pid]/exe.
	exec, err := s.executable()
	if err != nil {
		return "", err
	}
	defer exec.DecRef(ctx)

	return exec.PathnameWithDeleted(ctx), nil
}

// Getlink implements kernfs.Inode.Getlink.
func (s *exeSymlink) Getlink(ctx context.Context, _ *vfs.Mount) (vfs.VirtualDentry, string, error) {
	if !kernel.ContextCanTrace(ctx, s.task, false) {
		return vfs.VirtualDentry{}, "", syserror.EACCES
	}

	exec, err := s.executable()
	if err != nil {
		return vfs.VirtualDentry{}, "", err
	}
	defer exec.DecRef(ctx)

	vd := exec.(*fsbridge.VFSFile).FileDescription().VirtualDentry()
	vd.IncRef()
	return vd, "", nil
}

func (s *exeSymlink) executable() (file fsbridge.File, err error) {
	if err := checkTaskState(s.task); err != nil {
		return nil, err
	}

	s.task.WithMuLocked(func(t *kernel.Task) {
		mm := t.MemoryManager()
		if mm == nil {
			err = syserror.EACCES
			return
		}

		// The MemoryManager may be destroyed, in which case
		// MemoryManager.destroy will simply set the executable to nil
		// (with locks held).
		file = mm.Executable()
		if file == nil {
			err = syserror.ESRCH
		}
	})
	return
}

// mountInfoData is used to implement /proc/[pid]/mountinfo.
//
// +stateify savable
type mountInfoData struct {
	kernfs.DynamicBytesFile

	task *kernel.Task
}

var _ dynamicInode = (*mountInfoData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (i *mountInfoData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	var fsctx *kernel.FSContext
	i.task.WithMuLocked(func(t *kernel.Task) {
		fsctx = t.FSContext()
	})
	if fsctx == nil {
		// The task has been destroyed. Nothing to show here.
		return nil
	}
	rootDir := fsctx.RootDirectoryVFS2()
	if !rootDir.Ok() {
		// Root has been destroyed. Don't try to read mounts.
		return nil
	}
	defer rootDir.DecRef(ctx)
	i.task.Kernel().VFS().GenerateProcMountInfo(ctx, rootDir, buf)
	return nil
}

// mountsData is used to implement /proc/[pid]/mounts.
//
// +stateify savable
type mountsData struct {
	kernfs.DynamicBytesFile

	task *kernel.Task
}

var _ dynamicInode = (*mountsData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (i *mountsData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	var fsctx *kernel.FSContext
	i.task.WithMuLocked(func(t *kernel.Task) {
		fsctx = t.FSContext()
	})
	if fsctx == nil {
		// The task has been destroyed. Nothing to show here.
		return nil
	}
	rootDir := fsctx.RootDirectoryVFS2()
	if !rootDir.Ok() {
		// Root has been destroyed. Don't try to read mounts.
		return nil
	}
	defer rootDir.DecRef(ctx)
	i.task.Kernel().VFS().GenerateProcMounts(ctx, rootDir, buf)
	return nil
}

type namespaceSymlink struct {
	kernfs.StaticSymlink

	task *kernel.Task
}

func (fs *filesystem) newNamespaceSymlink(task *kernel.Task, ino uint64, ns string) *kernfs.Dentry {
	// Namespace symlinks should contain the namespace name and the inode number
	// for the namespace instance, so for example user:[123456]. We currently fake
	// the inode number by sticking the symlink inode in its place.
	target := fmt.Sprintf("%s:[%d]", ns, ino)

	inode := &namespaceSymlink{task: task}
	// Note: credentials are overridden by taskOwnedInode.
	inode.Init(task.Credentials(), linux.UNNAMED_MAJOR, fs.devMinor, ino, target)

	taskInode := &taskOwnedInode{Inode: inode, owner: task}
	d := &kernfs.Dentry{}
	d.Init(taskInode)
	return d
}

// Readlink implements Inode.
func (s *namespaceSymlink) Readlink(ctx context.Context, mnt *vfs.Mount) (string, error) {
	if err := checkTaskState(s.task); err != nil {
		return "", err
	}
	return s.StaticSymlink.Readlink(ctx, mnt)
}

// Getlink implements Inode.Getlink.
func (s *namespaceSymlink) Getlink(ctx context.Context, mnt *vfs.Mount) (vfs.VirtualDentry, string, error) {
	if err := checkTaskState(s.task); err != nil {
		return vfs.VirtualDentry{}, "", err
	}

	// Create a synthetic inode to represent the namespace.
	dentry := &kernfs.Dentry{}
	dentry.Init(&namespaceInode{})
	vd := vfs.MakeVirtualDentry(mnt, dentry.VFSDentry())
	vd.IncRef()
	dentry.DecRef(ctx)
	return vd, "", nil
}

// namespaceInode is a synthetic inode created to represent a namespace in
// /proc/[pid]/ns/*.
type namespaceInode struct {
	implStatFS
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink

	locks vfs.FileLocks
}

var _ kernfs.Inode = (*namespaceInode)(nil)

// Init initializes a namespace inode.
func (i *namespaceInode) Init(creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, perm linux.FileMode) {
	if perm&^linux.PermissionsMask != 0 {
		panic(fmt.Sprintf("Only permission mask must be set: %x", perm&linux.PermissionsMask))
	}
	i.InodeAttrs.Init(creds, devMajor, devMinor, ino, linux.ModeRegular|perm)
}

// Open implements Inode.Open.
func (i *namespaceInode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &namespaceFD{inode: i}
	i.IncRef()
	fd.LockFD.Init(&i.locks)
	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Mount(), vfsd, &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// namespace FD is a synthetic file that represents a namespace in
// /proc/[pid]/ns/*.
type namespaceFD struct {
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	vfsfd vfs.FileDescription
	inode *namespaceInode
}

var _ vfs.FileDescriptionImpl = (*namespaceFD)(nil)

// Stat implements FileDescriptionImpl.
func (fd *namespaceFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	vfs := fd.vfsfd.VirtualDentry().Mount().Filesystem()
	return fd.inode.Stat(ctx, vfs, opts)
}

// SetStat implements FileDescriptionImpl.
func (fd *namespaceFD) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	vfs := fd.vfsfd.VirtualDentry().Mount().Filesystem()
	creds := auth.CredentialsFromContext(ctx)
	return fd.inode.SetStat(ctx, vfs, creds, opts)
}

// Release implements FileDescriptionImpl.
func (fd *namespaceFD) Release(ctx context.Context) {
	fd.inode.DecRef(ctx)
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (fd *namespaceFD) LockPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker) error {
	return fd.Locks().LockPOSIX(ctx, &fd.vfsfd, uid, t, start, length, whence, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (fd *namespaceFD) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, start, length uint64, whence int16) error {
	return fd.Locks().UnlockPOSIX(ctx, &fd.vfsfd, uid, start, length, whence)
}
