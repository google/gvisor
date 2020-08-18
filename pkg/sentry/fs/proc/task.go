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

package proc

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/device"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/fsbridge"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// LINT.IfChange

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

func checkTaskState(t *kernel.Task) error {
	switch t.ExitState() {
	case kernel.TaskExitZombie:
		return syserror.EACCES
	case kernel.TaskExitDead:
		return syserror.ESRCH
	}
	return nil
}

// taskDir represents a task-level directory.
//
// +stateify savable
type taskDir struct {
	ramfs.Dir

	t *kernel.Task
}

var _ fs.InodeOperations = (*taskDir)(nil)

// newTaskDir creates a new proc task entry.
func (p *proc) newTaskDir(t *kernel.Task, msrc *fs.MountSource, isThreadGroup bool) *fs.Inode {
	contents := map[string]*fs.Inode{
		"auxv":          newAuxvec(t, msrc),
		"cmdline":       newExecArgInode(t, msrc, cmdlineExecArg),
		"comm":          newComm(t, msrc),
		"environ":       newExecArgInode(t, msrc, environExecArg),
		"exe":           newExe(t, msrc),
		"fd":            newFdDir(t, msrc),
		"fdinfo":        newFdInfoDir(t, msrc),
		"gid_map":       newGIDMap(t, msrc),
		"io":            newIO(t, msrc, isThreadGroup),
		"maps":          newMaps(t, msrc),
		"mountinfo":     seqfile.NewSeqFileInode(t, &mountInfoFile{t: t}, msrc),
		"mounts":        seqfile.NewSeqFileInode(t, &mountsFile{t: t}, msrc),
		"net":           newNetDir(t, msrc),
		"ns":            newNamespaceDir(t, msrc),
		"oom_score":     newOOMScore(t, msrc),
		"oom_score_adj": newOOMScoreAdj(t, msrc),
		"smaps":         newSmaps(t, msrc),
		"stat":          newTaskStat(t, msrc, isThreadGroup, p.pidns),
		"statm":         newStatm(t, msrc),
		"status":        newStatus(t, msrc, p.pidns),
		"uid_map":       newUIDMap(t, msrc),
	}
	if isThreadGroup {
		contents["task"] = p.newSubtasks(t, msrc)
	}
	if len(p.cgroupControllers) > 0 {
		contents["cgroup"] = newCGroupInode(t, msrc, p.cgroupControllers)
	}

	// N.B. taskOwnedInodeOps enforces dumpability-based ownership.
	d := &taskDir{
		Dir: *ramfs.NewDir(t, contents, fs.RootOwner, fs.FilePermsFromMode(0555)),
		t:   t,
	}
	return newProcInode(t, d, msrc, fs.SpecialDirectory, t)
}

// subtasks represents a /proc/TID/task directory.
//
// +stateify savable
type subtasks struct {
	ramfs.Dir

	t *kernel.Task
	p *proc
}

var _ fs.InodeOperations = (*subtasks)(nil)

func (p *proc) newSubtasks(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	s := &subtasks{
		Dir: *ramfs.NewDir(t, nil, fs.RootOwner, fs.FilePermsFromMode(0555)),
		t:   t,
		p:   p,
	}
	return newProcInode(t, s, msrc, fs.SpecialDirectory, t)
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

// GetFile implements fs.InodeOperations.GetFile.
func (s *subtasks) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &subtasksFile{t: s.t, pidns: s.p.pidns}), nil
}

// +stateify savable
type subtasksFile struct {
	fsutil.DirFileOperations        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	t     *kernel.Task
	pidns *kernel.PIDNamespace
}

// Readdir implements fs.FileOperations.Readdir.
func (f *subtasksFile) Readdir(ctx context.Context, file *fs.File, ser fs.DentrySerializer) (int64, error) {
	dirCtx := fs.DirCtx{
		Serializer: ser,
	}

	// Note that unlike most Readdir implementations, the offset here is
	// not an index into the subtasks, but rather the TID of the next
	// subtask to emit.
	offset := file.Offset()

	tasks := f.t.ThreadGroup().MemberIDs(f.pidns)
	if len(tasks) == 0 {
		return offset, syserror.ENOENT
	}

	if offset == 0 {
		// Serialize "." and "..".
		root := fs.RootFromContext(ctx)
		if root != nil {
			defer root.DecRef(ctx)
		}
		dot, dotdot := file.Dirent.GetDotAttrs(root)
		if err := dirCtx.DirEmit(".", dot); err != nil {
			return offset, err
		}
		if err := dirCtx.DirEmit("..", dotdot); err != nil {
			return offset, err
		}
	}

	// Serialize tasks.
	taskInts := make([]int, 0, len(tasks))
	for _, tid := range tasks {
		taskInts = append(taskInts, int(tid))
	}

	sort.Sort(sort.IntSlice(taskInts))
	// Find the task to start at.
	idx := sort.SearchInts(taskInts, int(offset))
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
			return int64(tid), err
		}
	}
	// We serialized them all.  Next offset should be higher than last
	// serialized tid.
	return int64(tid) + 1, nil
}

var _ fs.FileOperations = (*subtasksFile)(nil)

// Lookup loads an Inode in a task's subtask directory into a Dirent.
func (s *subtasks) Lookup(ctx context.Context, dir *fs.Inode, p string) (*fs.Dirent, error) {
	tid, err := strconv.ParseUint(p, 10, 32)
	if err != nil {
		return nil, syserror.ENOENT
	}

	task := s.p.pidns.TaskWithID(kernel.ThreadID(tid))
	if task == nil {
		return nil, syserror.ENOENT
	}
	if task.ThreadGroup() != s.t.ThreadGroup() {
		return nil, syserror.ENOENT
	}

	td := s.p.newTaskDir(task, dir.MountSource, false)
	return fs.NewDirent(ctx, td, p), nil
}

// exe is an fs.InodeOperations symlink for the /proc/PID/exe file.
//
// +stateify savable
type exe struct {
	ramfs.Symlink

	t *kernel.Task
}

func newExe(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	exeSymlink := &exe{
		Symlink: *ramfs.NewSymlink(t, fs.RootOwner, ""),
		t:       t,
	}
	return newProcInode(t, exeSymlink, msrc, fs.Symlink, t)
}

func (e *exe) executable() (file fsbridge.File, err error) {
	if err := checkTaskState(e.t); err != nil {
		return nil, err
	}
	e.t.WithMuLocked(func(t *kernel.Task) {
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
	defer exec.DecRef(ctx)

	return exec.PathnameWithDeleted(ctx), nil
}

// namespaceSymlink represents a symlink in the namespacefs, such as the files
// in /proc/<pid>/ns.
//
// +stateify savable
type namespaceSymlink struct {
	ramfs.Symlink

	t *kernel.Task
}

func newNamespaceSymlink(t *kernel.Task, msrc *fs.MountSource, name string) *fs.Inode {
	// TODO(rahat): Namespace symlinks should contain the namespace name and the
	// inode number for the namespace instance, so for example user:[123456]. We
	// currently fake the inode number by sticking the symlink inode in its
	// place.
	target := fmt.Sprintf("%s:[%d]", name, device.ProcDevice.NextIno())
	n := &namespaceSymlink{
		Symlink: *ramfs.NewSymlink(t, fs.RootOwner, target),
		t:       t,
	}
	return newProcInode(t, n, msrc, fs.Symlink, t)
}

// Readlink reads the symlink value.
func (n *namespaceSymlink) Readlink(ctx context.Context, inode *fs.Inode) (string, error) {
	if err := checkTaskState(n.t); err != nil {
		return "", err
	}
	return n.Symlink.Readlink(ctx, inode)
}

// Getlink implements fs.InodeOperations.Getlink.
func (n *namespaceSymlink) Getlink(ctx context.Context, inode *fs.Inode) (*fs.Dirent, error) {
	if !kernel.ContextCanTrace(ctx, n.t, false) {
		return nil, syserror.EACCES
	}
	if err := checkTaskState(n.t); err != nil {
		return nil, err
	}

	// Create a new regular file to fake the namespace file.
	iops := fsutil.NewNoReadWriteFileInode(ctx, fs.RootOwner, fs.FilePermsFromMode(0777), linux.PROC_SUPER_MAGIC)
	return fs.NewDirent(ctx, newProcInode(ctx, iops, inode.MountSource, fs.RegularFile, nil), n.Symlink.Target), nil
}

func newNamespaceDir(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	contents := map[string]*fs.Inode{
		"net":  newNamespaceSymlink(t, msrc, "net"),
		"pid":  newNamespaceSymlink(t, msrc, "pid"),
		"user": newNamespaceSymlink(t, msrc, "user"),
	}
	d := ramfs.NewDir(t, contents, fs.RootOwner, fs.FilePermsFromMode(0511))
	return newProcInode(t, d, msrc, fs.SpecialDirectory, t)
}

// mapsData implements seqfile.SeqSource for /proc/[pid]/maps.
//
// +stateify savable
type mapsData struct {
	t *kernel.Task
}

func newMaps(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	return newProcInode(t, seqfile.NewSeqFile(t, &mapsData{t}), msrc, fs.SpecialFile, t)
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
		return mm.ReadMapsSeqFileData(ctx, h)
	}
	return []seqfile.SeqData{}, 0
}

// smapsData implements seqfile.SeqSource for /proc/[pid]/smaps.
//
// +stateify savable
type smapsData struct {
	t *kernel.Task
}

func newSmaps(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	return newProcInode(t, seqfile.NewSeqFile(t, &smapsData{t}), msrc, fs.SpecialFile, t)
}

func (sd *smapsData) mm() *mm.MemoryManager {
	var tmm *mm.MemoryManager
	sd.t.WithMuLocked(func(t *kernel.Task) {
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
func (sd *smapsData) NeedsUpdate(generation int64) bool {
	if mm := sd.mm(); mm != nil {
		return mm.NeedsUpdate(generation)
	}
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (sd *smapsData) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if mm := sd.mm(); mm != nil {
		return mm.ReadSmapsSeqFileData(ctx, h)
	}
	return []seqfile.SeqData{}, 0
}

// +stateify savable
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
	return newProcInode(t, seqfile.NewSeqFile(t, &taskStatData{t, showSubtasks /* tgstats */, pidns}), msrc, fs.SpecialFile, t)
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

	// itrealvalue. Since kernel 2.6.17, this field is no longer
	// maintained, and is hard coded as 0.
	fmt.Fprintf(&buf, "0 ")

	// Start time is relative to boot time, expressed in clock ticks.
	fmt.Fprintf(&buf, "%d ", linux.ClockTFromDuration(s.t.StartTime().Sub(s.t.Kernel().Timekeeper().BootTime())))

	var vss, rss uint64
	s.t.WithMuLocked(func(t *kernel.Task) {
		if mm := t.MemoryManager(); mm != nil {
			vss = mm.VirtualMemorySize()
			rss = mm.ResidentSetSize()
		}
	})
	fmt.Fprintf(&buf, "%d %d ", vss, rss/usermem.PageSize)

	// rsslim.
	fmt.Fprintf(&buf, "%d ", s.t.ThreadGroup().Limits().Get(limits.Rss).Cur)

	fmt.Fprintf(&buf, "0 0 0 0 0 " /* startcode endcode startstack kstkesp kstkeip */)
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
//
// +stateify savable
type statmData struct {
	t *kernel.Task
}

func newStatm(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	return newProcInode(t, seqfile.NewSeqFile(t, &statmData{t}), msrc, fs.SpecialFile, t)
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
//
// +stateify savable
type statusData struct {
	t     *kernel.Task
	pidns *kernel.PIDNamespace
}

func newStatus(t *kernel.Task, msrc *fs.MountSource, pidns *kernel.PIDNamespace) *fs.Inode {
	return newProcInode(t, seqfile.NewSeqFile(t, &statusData{t, pidns}), msrc, fs.SpecialFile, t)
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
	fmt.Fprintf(&buf, "FDSize:\t%d\n", fds)
	fmt.Fprintf(&buf, "VmSize:\t%d kB\n", vss>>10)
	fmt.Fprintf(&buf, "VmRSS:\t%d kB\n", rss>>10)
	fmt.Fprintf(&buf, "VmData:\t%d kB\n", data>>10)
	fmt.Fprintf(&buf, "Threads:\t%d\n", s.t.ThreadGroup().Count())
	creds := s.t.Credentials()
	fmt.Fprintf(&buf, "CapInh:\t%016x\n", creds.InheritableCaps)
	fmt.Fprintf(&buf, "CapPrm:\t%016x\n", creds.PermittedCaps)
	fmt.Fprintf(&buf, "CapEff:\t%016x\n", creds.EffectiveCaps)
	fmt.Fprintf(&buf, "CapBnd:\t%016x\n", creds.BoundingCaps)
	fmt.Fprintf(&buf, "Seccomp:\t%d\n", s.t.SeccompMode())
	// We unconditionally report a single NUMA node. See
	// pkg/sentry/syscalls/linux/sys_mempolicy.go.
	fmt.Fprintf(&buf, "Mems_allowed:\t1\n")
	fmt.Fprintf(&buf, "Mems_allowed_list:\t0\n")
	return []seqfile.SeqData{{Buf: buf.Bytes(), Handle: (*statusData)(nil)}}, 0
}

// ioUsage is the /proc/<pid>/io and /proc/<pid>/task/<tid>/io data provider.
type ioUsage interface {
	// IOUsage returns the io usage data.
	IOUsage() *usage.IO
}

// +stateify savable
type ioData struct {
	ioUsage
}

func newIO(t *kernel.Task, msrc *fs.MountSource, isThreadGroup bool) *fs.Inode {
	if isThreadGroup {
		return newProcInode(t, seqfile.NewSeqFile(t, &ioData{t.ThreadGroup()}), msrc, fs.SpecialFile, t)
	}
	return newProcInode(t, seqfile.NewSeqFile(t, &ioData{t}), msrc, fs.SpecialFile, t)
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
	fmt.Fprintf(&buf, "rchar: %d\n", io.CharsRead)
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
//
// +stateify savable
type comm struct {
	fsutil.SimpleFileInode

	t *kernel.Task
}

// newComm returns a new comm file.
func newComm(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	c := &comm{
		SimpleFileInode: *fsutil.NewSimpleFileInode(t, fs.RootOwner, fs.FilePermsFromMode(0444), linux.PROC_SUPER_MAGIC),
		t:               t,
	}
	return newProcInode(t, c, msrc, fs.SpecialFile, t)
}

// Check implements fs.InodeOperations.Check.
func (c *comm) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	// This file can always be read or written by members of the same
	// thread group. See fs/proc/base.c:proc_tid_comm_permission.
	//
	// N.B. This check is currently a no-op as we don't yet support writing
	// and this file is world-readable anyways.
	t := kernel.TaskFromContext(ctx)
	if t != nil && t.ThreadGroup() == c.t.ThreadGroup() && !p.Execute {
		return true
	}

	return fs.ContextCanAccessFile(ctx, inode, p)
}

// GetFile implements fs.InodeOperations.GetFile.
func (c *comm) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &commFile{t: c.t}), nil
}

// +stateify savable
type commFile struct {
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoWrite              `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`

	t *kernel.Task
}

var _ fs.FileOperations = (*commFile)(nil)

// Read implements fs.FileOperations.Read.
func (f *commFile) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	buf := []byte(f.t.Name() + "\n")
	if offset >= int64(len(buf)) {
		return 0, io.EOF
	}

	n, err := dst.CopyOut(ctx, buf[offset:])
	return int64(n), err
}

// auxvec is a file containing the auxiliary vector for a task.
//
// +stateify savable
type auxvec struct {
	fsutil.SimpleFileInode

	t *kernel.Task
}

// newAuxvec returns a new auxvec file.
func newAuxvec(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	a := &auxvec{
		SimpleFileInode: *fsutil.NewSimpleFileInode(t, fs.RootOwner, fs.FilePermsFromMode(0444), linux.PROC_SUPER_MAGIC),
		t:               t,
	}
	return newProcInode(t, a, msrc, fs.SpecialFile, t)
}

// GetFile implements fs.InodeOperations.GetFile.
func (a *auxvec) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &auxvecFile{t: a.t}), nil
}

// +stateify savable
type auxvecFile struct {
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoWrite              `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`

	t *kernel.Task
}

// Read implements fs.FileOperations.Read.
func (f *auxvecFile) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	m, err := getTaskMM(f.t)
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

// newOOMScore returns a oom_score file. It is a stub that always returns 0.
// TODO(gvisor.dev/issue/1967)
func newOOMScore(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	return newStaticProcInode(t, msrc, []byte("0\n"))
}

// oomScoreAdj is a file containing the oom_score adjustment for a task.
//
// +stateify savable
type oomScoreAdj struct {
	fsutil.SimpleFileInode

	t *kernel.Task
}

// +stateify savable
type oomScoreAdjFile struct {
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`

	t *kernel.Task
}

// newOOMScoreAdj returns a oom_score_adj file.
func newOOMScoreAdj(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	i := &oomScoreAdj{
		SimpleFileInode: *fsutil.NewSimpleFileInode(t, fs.RootOwner, fs.FilePermsFromMode(0644), linux.PROC_SUPER_MAGIC),
		t:               t,
	}
	return newProcInode(t, i, msrc, fs.SpecialFile, t)
}

// Truncate implements fs.InodeOperations.Truncate. Truncate is called when
// O_TRUNC is specified for any kind of existing Dirent but is not called via
// (f)truncate for proc files.
func (*oomScoreAdj) Truncate(context.Context, *fs.Inode, int64) error {
	return nil
}

// GetFile implements fs.InodeOperations.GetFile.
func (o *oomScoreAdj) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &oomScoreAdjFile{t: o.t}), nil
}

// Read implements fs.FileOperations.Read.
func (f *oomScoreAdjFile) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if f.t.ExitState() == kernel.TaskExitDead {
		return 0, syserror.ESRCH
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%d\n", f.t.OOMScoreAdj())
	if offset >= int64(buf.Len()) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, buf.Bytes()[offset:])
	return int64(n), err
}

// Write implements fs.FileOperations.Write.
func (f *oomScoreAdjFile) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
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

	if f.t.ExitState() == kernel.TaskExitDead {
		return 0, syserror.ESRCH
	}
	if err := f.t.SetOOMScoreAdj(v); err != nil {
		return 0, err
	}

	return n, nil
}

// LINT.ThenChange(../../fsimpl/proc/task.go|../../fsimpl/proc/task_files.go)
