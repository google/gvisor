// Copyright 2018 Google Inc.
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
	"sort"
	"strconv"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/mm"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// getTaskMM returns t's MemoryManager. If getTaskMM succeeds, the MemoryManager's
// users count is incremented, and must be decremented by the caller when it is
// no longer in use.
func getTaskMM(t *kernel.Task) (*mm.MemoryManager, error) {
	if t.ExitState() == kernel.TaskExitDead {
		return nil, syserror.ESRCH
	}
	var m *mm.MemoryManager
	t.WithMuLocked(func(t *kernel.Task) {
		m = t.MemoryManager()
	})
	if m == nil || !m.IncUsers() {
		return nil, io.EOF
	}
	return m, nil
}

// taskDir represents a task-level directory.
type taskDir struct {
	ramfs.Dir

	// t is the associated kernel task that owns this file.
	t *kernel.Task
}

// newTaskDir creates a new proc task entry.
func newTaskDir(t *kernel.Task, msrc *fs.MountSource, pidns *kernel.PIDNamespace, showSubtasks bool) *fs.Inode {
	d := &taskDir{t: t}
	// TODO: Set EUID/EGID based on dumpability.
	d.InitDir(t, map[string]*fs.Inode{
		"auxv":    newAuxvec(t, msrc),
		"cmdline": newExecArgFile(t, msrc, cmdlineExecArg),
		"comm":    newComm(t, msrc),
		"environ": newExecArgFile(t, msrc, environExecArg),
		"exe":     newExe(t, msrc),
		"fd":      newFdDir(t, msrc),
		"fdinfo":  newFdInfoDir(t, msrc),
		"gid_map": newGIDMap(t, msrc),
		// TODO: This is incorrect for /proc/[pid]/task/[tid]/io, i.e. if
		// showSubtasks is false:
		// http://lxr.free-electrons.com/source/fs/proc/base.c?v=3.11#L2980
		"io":        newIO(t, msrc),
		"maps":      newMaps(t, msrc),
		"mountinfo": seqfile.NewSeqFileInode(t, &mountInfoFile{t: t}, msrc),
		"mounts":    seqfile.NewSeqFileInode(t, &mountsFile{t: t}, msrc),
		"ns":        newNamespaceDir(t, msrc),
		"stat":      newTaskStat(t, msrc, showSubtasks, pidns),
		"statm":     newStatm(t, msrc),
		"status":    newStatus(t, msrc, pidns),
		"uid_map":   newUIDMap(t, msrc),
	}, fs.RootOwner, fs.FilePermsFromMode(0555))
	if showSubtasks {
		d.AddChild(t, "task", newSubtasks(t, msrc, pidns))
	}
	return newFile(d, msrc, fs.SpecialDirectory, t)
}

// subtasks represents a /proc/TID/task directory.
type subtasks struct {
	ramfs.Dir

	t *kernel.Task

	pidns *kernel.PIDNamespace
}

func newSubtasks(t *kernel.Task, msrc *fs.MountSource, pidns *kernel.PIDNamespace) *fs.Inode {
	s := &subtasks{t: t, pidns: pidns}
	s.InitDir(t, nil, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newFile(s, msrc, fs.SpecialDirectory, t)
}

// UnstableAttr returns unstable attributes of the subtasks.
func (s *subtasks) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	uattr, err := s.Dir.UnstableAttr(ctx, inode)
	if err != nil {
		return fs.UnstableAttr{}, err
	}
	// We can't rely on ramfs' implementation because the task directories are
	// generated dynamically.
	uattr.Links = uint64(2 + s.t.ThreadGroup().Count())
	return uattr, nil
}

// Lookup loads an Inode in a task's subtask directory into a Dirent.
func (s *subtasks) Lookup(ctx context.Context, dir *fs.Inode, p string) (*fs.Dirent, error) {
	tid, err := strconv.ParseUint(p, 10, 32)
	if err != nil {
		return nil, syserror.ENOENT
	}

	task := s.pidns.TaskWithID(kernel.ThreadID(tid))
	if task == nil {
		return nil, syserror.ENOENT
	}
	if task.ThreadGroup() != s.t.ThreadGroup() {
		return nil, syserror.ENOENT
	}

	td := newTaskDir(task, dir.MountSource, s.pidns, false)
	return fs.NewDirent(td, p), nil
}

// DeprecatedReaddir lists a task's subtask directory.
func (s *subtasks) DeprecatedReaddir(ctx context.Context, dirCtx *fs.DirCtx, offset int) (int, error) {
	tasks := s.t.ThreadGroup().MemberIDs(s.pidns)
	taskInts := make([]int, 0, len(tasks))
	for _, tid := range tasks {
		taskInts = append(taskInts, int(tid))
	}

	// Find the task to start at.
	idx := sort.SearchInts(taskInts, offset)
	if idx == len(taskInts) {
		return offset, nil
	}
	taskInts = taskInts[idx:]

	var tid int
	for _, tid = range taskInts {
		name := strconv.FormatUint(uint64(tid), 10)
		attr := fs.GenericDentAttr(fs.SpecialDirectory, device.ProcDevice)
		if err := dirCtx.DirEmit(name, attr); err != nil {
			// Returned offset is next tid to serialize.
			return tid, err
		}
	}
	// We serialized them all.  Next offset should be higher than last
	// serialized tid.
	return tid + 1, nil
}

// exe is an fs.InodeOperations symlink for the /proc/PID/exe file.
type exe struct {
	ramfs.Symlink

	t *kernel.Task
}

func newExe(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	exeSymlink := &exe{t: t}
	exeSymlink.InitSymlink(t, fs.RootOwner, "")
	return newFile(exeSymlink, msrc, fs.Symlink, t)
}

func (e *exe) executable() (d *fs.Dirent, err error) {
	e.t.WithMuLocked(func(t *kernel.Task) {
		mm := t.MemoryManager()
		if mm == nil {
			// TODO: Check shouldn't allow Readlink once the
			// Task is zombied.
			err = syserror.EACCES
			return
		}

		// The MemoryManager may be destroyed, in which case
		// MemoryManager.destroy will simply set the executable to nil
		// (with locks held).
		d = mm.Executable()
		if d == nil {
			err = syserror.ENOENT
		}
	})
	return
}

// Readlink implements fs.InodeOperations.
func (e *exe) Readlink(ctx context.Context, inode *fs.Inode) (string, error) {
	if !kernel.ContextCanTrace(ctx, e.t, false) {
		return "", syserror.EACCES
	}

	// Pull out the executable for /proc/TID/exe.
	exec, err := e.executable()
	if err != nil {
		return "", err
	}
	defer exec.DecRef()

	root := fs.RootFromContext(ctx)
	if root == nil {
		// This doesn't correspond to anything in Linux because the vfs is
		// global there.
		return "", syserror.EINVAL
	}
	defer root.DecRef()
	n, _ := exec.FullName(root)
	return n, nil
}

// namespaceFile represents a file in the namespacefs, such as the files in
// /proc/<pid>/ns.
type namespaceFile struct {
	ramfs.Symlink

	t *kernel.Task
}

func newNamespaceFile(t *kernel.Task, msrc *fs.MountSource, name string) *fs.Inode {
	n := &namespaceFile{t: t}
	n.InitSymlink(t, fs.RootOwner, "")

	// TODO: Namespace symlinks should contain the namespace name and the
	// inode number for the namespace instance, so for example user:[123456]. We
	// currently fake the inode number by sticking the symlink inode in its
	// place.
	n.Target = fmt.Sprintf("%s:[%d]", name, device.ProcDevice.NextIno())

	return newFile(n, msrc, fs.Symlink, t)
}

// Getlink implements fs.InodeOperations.Getlink.
func (n *namespaceFile) Getlink(ctx context.Context, inode *fs.Inode) (*fs.Dirent, error) {
	if !kernel.ContextCanTrace(ctx, n.t, false) {
		return nil, syserror.EACCES
	}

	// Create a new regular file to fake the namespace file.
	node := &ramfs.Entry{}
	node.InitEntry(ctx, fs.RootOwner, fs.FilePermsFromMode(0777))
	sattr := fs.StableAttr{
		DeviceID:  device.ProcDevice.DeviceID(),
		InodeID:   device.ProcDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.RegularFile,
	}
	return fs.NewDirent(fs.NewInode(node, inode.MountSource, sattr), n.Symlink.Target), nil
}

func newNamespaceDir(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(t, map[string]*fs.Inode{
		"net":  newNamespaceFile(t, msrc, "net"),
		"pid":  newNamespaceFile(t, msrc, "pid"),
		"user": newNamespaceFile(t, msrc, "user"),
	}, fs.RootOwner, fs.FilePermsFromMode(0511))
	return newFile(d, msrc, fs.SpecialDirectory, t)
}

// mapsData implements seqfile.SeqSource for /proc/[pid]/maps.
type mapsData struct {
	t *kernel.Task
}

func newMaps(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	return newFile(seqfile.NewSeqFile(t, &mapsData{t}), msrc, fs.SpecialFile, t)
}

func (md *mapsData) mm() *mm.MemoryManager {
	var tmm *mm.MemoryManager
	md.t.WithMuLocked(func(t *kernel.Task) {
		if mm := t.MemoryManager(); mm != nil {
			// No additional reference is taken on mm here. This is safe
			// because MemoryManager.destroy is required to leave the
			// MemoryManager in a state where it's still usable as a SeqSource.
			tmm = mm
		}
	})
	return tmm
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (md *mapsData) NeedsUpdate(generation int64) bool {
	if mm := md.mm(); mm != nil {
		return mm.NeedsUpdate(generation)
	}
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (md *mapsData) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if mm := md.mm(); mm != nil {
		return mm.ReadSeqFileData(ctx, h)
	}
	return []seqfile.SeqData{}, 0
}

type taskStatData struct {
	t *kernel.Task

	// If tgstats is true, accumulate fault stats (not implemented) and CPU
	// time across all tasks in t's thread group.
	tgstats bool

	// pidns is the PID namespace associated with the proc filesystem that
	// includes the file using this statData.
	pidns *kernel.PIDNamespace
}

func newTaskStat(t *kernel.Task, msrc *fs.MountSource, showSubtasks bool, pidns *kernel.PIDNamespace) *fs.Inode {
	return newFile(seqfile.NewSeqFile(t, &taskStatData{t, showSubtasks /* tgstats */, pidns}), msrc, fs.SpecialFile, t)
}

// NeedsUpdate returns whether the generation is old or not.
func (s *taskStatData) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData returns data for the SeqFile reader.
// SeqData, the current generation and where in the file the handle corresponds to.
func (s *taskStatData) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if h != nil {
		return nil, 0
	}

	var buf bytes.Buffer

	fmt.Fprintf(&buf, "%d ", s.pidns.IDOfTask(s.t))
	fmt.Fprintf(&buf, "(%s) ", s.t.Name())
	fmt.Fprintf(&buf, "%c ", s.t.StateStatus()[0])
	ppid := kernel.ThreadID(0)
	if parent := s.t.Parent(); parent != nil {
		ppid = s.pidns.IDOfThreadGroup(parent.ThreadGroup())
	}
	fmt.Fprintf(&buf, "%d ", ppid)
	fmt.Fprintf(&buf, "%d ", s.pidns.IDOfProcessGroup(s.t.ThreadGroup().ProcessGroup()))
	fmt.Fprintf(&buf, "%d ", s.pidns.IDOfSession(s.t.ThreadGroup().Session()))
	fmt.Fprintf(&buf, "0 0 " /* tty_nr tpgid */)
	fmt.Fprintf(&buf, "0 " /* flags */)
	fmt.Fprintf(&buf, "0 0 0 0 " /* minflt cminflt majflt cmajflt */)
	var cputime usage.CPUStats
	if s.tgstats {
		cputime = s.t.ThreadGroup().CPUStats()
	} else {
		cputime = s.t.CPUStats()
	}
	fmt.Fprintf(&buf, "%d %d ", linux.ClockTFromDuration(cputime.UserTime), linux.ClockTFromDuration(cputime.SysTime))
	cputime = s.t.ThreadGroup().JoinedChildCPUStats()
	fmt.Fprintf(&buf, "%d %d ", linux.ClockTFromDuration(cputime.UserTime), linux.ClockTFromDuration(cputime.SysTime))
	fmt.Fprintf(&buf, "%d %d ", s.t.Priority(), s.t.Niceness())
	fmt.Fprintf(&buf, "%d ", s.t.ThreadGroup().Count())
	fmt.Fprintf(&buf, "0 0 " /* itrealvalue starttime */)
	var vss, rss uint64
	s.t.WithMuLocked(func(t *kernel.Task) {
		if mm := t.MemoryManager(); mm != nil {
			vss = mm.VirtualMemorySize()
			rss = mm.ResidentSetSize()
		}
	})
	fmt.Fprintf(&buf, "%d %d ", vss, rss/usermem.PageSize)
	fmt.Fprintf(&buf, "0 0 0 0 0 0 " /* rsslim startcode endcode startstack kstkesp kstkeip */)
	fmt.Fprintf(&buf, "0 0 0 0 0 " /* signal blocked sigignore sigcatch wchan */)
	fmt.Fprintf(&buf, "0 0 " /* nswap cnswap */)
	terminationSignal := linux.Signal(0)
	if s.t == s.t.ThreadGroup().Leader() {
		terminationSignal = s.t.ThreadGroup().TerminationSignal()
	}
	fmt.Fprintf(&buf, "%d ", terminationSignal)
	fmt.Fprintf(&buf, "0 0 0 " /* processor rt_priority policy */)
	fmt.Fprintf(&buf, "0 0 0 " /* delayacct_blkio_ticks guest_time cguest_time */)
	fmt.Fprintf(&buf, "0 0 0 0 0 0 0 " /* start_data end_data start_brk arg_start arg_end env_start env_end */)
	fmt.Fprintf(&buf, "0\n" /* exit_code */)

	return []seqfile.SeqData{{Buf: buf.Bytes(), Handle: (*taskStatData)(nil)}}, 0
}

// statmData implements seqfile.SeqSource for /proc/[pid]/statm.
type statmData struct {
	t *kernel.Task
}

func newStatm(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	return newFile(seqfile.NewSeqFile(t, &statmData{t}), msrc, fs.SpecialFile, t)
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (s *statmData) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (s *statmData) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if h != nil {
		return nil, 0
	}

	var vss, rss uint64
	s.t.WithMuLocked(func(t *kernel.Task) {
		if mm := t.MemoryManager(); mm != nil {
			vss = mm.VirtualMemorySize()
			rss = mm.ResidentSetSize()
		}
	})

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%d %d 0 0 0 0 0\n", vss/usermem.PageSize, rss/usermem.PageSize)

	return []seqfile.SeqData{{Buf: buf.Bytes(), Handle: (*statmData)(nil)}}, 0
}

// statusData implements seqfile.SeqSource for /proc/[pid]/status.
type statusData struct {
	t     *kernel.Task
	pidns *kernel.PIDNamespace
}

func newStatus(t *kernel.Task, msrc *fs.MountSource, pidns *kernel.PIDNamespace) *fs.Inode {
	return newFile(seqfile.NewSeqFile(t, &statusData{t, pidns}), msrc, fs.SpecialFile, t)
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (s *statusData) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (s *statusData) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if h != nil {
		return nil, 0
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Name:\t%s\n", s.t.Name())
	fmt.Fprintf(&buf, "State:\t%s\n", s.t.StateStatus())
	fmt.Fprintf(&buf, "Tgid:\t%d\n", s.pidns.IDOfThreadGroup(s.t.ThreadGroup()))
	fmt.Fprintf(&buf, "Pid:\t%d\n", s.pidns.IDOfTask(s.t))
	ppid := kernel.ThreadID(0)
	if parent := s.t.Parent(); parent != nil {
		ppid = s.pidns.IDOfThreadGroup(parent.ThreadGroup())
	}
	fmt.Fprintf(&buf, "PPid:\t%d\n", ppid)
	tpid := kernel.ThreadID(0)
	if tracer := s.t.Tracer(); tracer != nil {
		tpid = s.pidns.IDOfTask(tracer)
	}
	fmt.Fprintf(&buf, "TracerPid:\t%d\n", tpid)
	var fds int
	var vss, rss uint64
	s.t.WithMuLocked(func(t *kernel.Task) {
		if fdm := t.FDMap(); fdm != nil {
			fds = fdm.Size()
		}
		if mm := t.MemoryManager(); mm != nil {
			vss = mm.VirtualMemorySize()
			rss = mm.ResidentSetSize()
		}
	})
	fmt.Fprintf(&buf, "FDSize:\t%d\n", fds)
	fmt.Fprintf(&buf, "VmSize:\t%d kB\n", vss>>10)
	fmt.Fprintf(&buf, "VmRSS:\t%d kB\n", rss>>10)
	fmt.Fprintf(&buf, "Threads:\t%d\n", s.t.ThreadGroup().Count())
	creds := s.t.Credentials()
	fmt.Fprintf(&buf, "CapInh:\t%016x\n", creds.InheritableCaps)
	fmt.Fprintf(&buf, "CapPrm:\t%016x\n", creds.PermittedCaps)
	fmt.Fprintf(&buf, "CapEff:\t%016x\n", creds.EffectiveCaps)
	fmt.Fprintf(&buf, "CapBnd:\t%016x\n", creds.BoundingCaps)
	fmt.Fprintf(&buf, "Seccomp:\t%d\n", s.t.SeccompMode())
	return []seqfile.SeqData{{Buf: buf.Bytes(), Handle: (*statusData)(nil)}}, 0
}

// ioUsage is the /proc/<pid>/io and /proc/<pid>/task/<tid>/io data provider.
type ioUsage interface {
	// IOUsage returns the io usage data.
	IOUsage() *usage.IO
}

type ioData struct {
	ioUsage
}

func newIO(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	return newFile(seqfile.NewSeqFile(t, &ioData{t.ThreadGroup()}), msrc, fs.SpecialFile, t)
}

// NeedsUpdate returns whether the generation is old or not.
func (i *ioData) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData returns data for the SeqFile reader.
// SeqData, the current generation and where in the file the handle corresponds to.
func (i *ioData) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if h != nil {
		return nil, 0
	}

	io := usage.IO{}
	io.Accumulate(i.IOUsage())

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "char: %d\n", io.CharsRead)
	fmt.Fprintf(&buf, "wchar: %d\n", io.CharsWritten)
	fmt.Fprintf(&buf, "syscr: %d\n", io.ReadSyscalls)
	fmt.Fprintf(&buf, "syscw: %d\n", io.WriteSyscalls)
	fmt.Fprintf(&buf, "read_bytes: %d\n", io.BytesRead)
	fmt.Fprintf(&buf, "write_bytes: %d\n", io.BytesWritten)
	fmt.Fprintf(&buf, "cancelled_write_bytes: %d\n", io.BytesWriteCancelled)

	return []seqfile.SeqData{{Buf: buf.Bytes(), Handle: (*ioData)(nil)}}, 0
}

// comm is a file containing the command name for a task.
//
// On Linux, /proc/[pid]/comm is writable, and writing to the comm file changes
// the thread name. We don't implement this yet as there are no known users of
// this feature.
type comm struct {
	ramfs.Entry

	t *kernel.Task
}

// newComm returns a new comm file.
func newComm(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	c := &comm{t: t}
	c.InitEntry(t, fs.RootOwner, fs.FilePermsFromMode(0444))
	return newFile(c, msrc, fs.SpecialFile, t)
}

// DeprecatedPreadv reads the current command name.
func (c *comm) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	buf := []byte(c.t.Name() + "\n")
	if offset >= int64(len(buf)) {
		return 0, io.EOF
	}

	n, err := dst.CopyOut(ctx, buf[offset:])
	return int64(n), err
}

// auxvec is a file containing the auxiliary vector for a task.
type auxvec struct {
	ramfs.Entry

	t *kernel.Task
}

// newAuxvec returns a new auxvec file.
func newAuxvec(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	a := &auxvec{t: t}
	a.InitEntry(t, fs.RootOwner, fs.FilePermsFromMode(0400))
	return newFile(a, msrc, fs.SpecialFile, t)
}

// DeprecatedPreadv reads the current auxiliary vector.
func (a *auxvec) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	m, err := getTaskMM(a.t)
	if err != nil {
		return 0, err
	}
	defer m.DecUsers(ctx)
	auxv := m.Auxv()

	// Space for buffer with AT_NULL (0) terminator at the end.
	size := (len(auxv) + 1) * 16
	if offset >= int64(size) {
		return 0, io.EOF
	}

	buf := make([]byte, size)
	for i, e := range auxv {
		usermem.ByteOrder.PutUint64(buf[16*i:], e.Key)
		usermem.ByteOrder.PutUint64(buf[16*i+8:], uint64(e.Value))
	}

	n, err := dst.CopyOut(ctx, buf[offset:])
	return int64(n), err
}
