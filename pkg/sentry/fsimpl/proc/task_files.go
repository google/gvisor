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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// "There is an (arbitrary) limit on the number of lines in the file. As at
// Linux 3.18, the limit is five lines." - user_namespaces(7)
const maxIDMapLines = 5

// getMM gets the kernel task's MemoryManager. No additional reference is taken on
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
		return linuxerr.EACCES
	case kernel.TaskExitDead:
		return linuxerr.ESRCH
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
	if d.task.ExitState() == kernel.TaskExitDead {
		return linuxerr.ESRCH
	}
	m, err := getMMIncRef(d.task)
	if err != nil {
		// Return empty file.
		return nil
	}
	defer m.DecUsers(ctx)

	auxv := m.Auxv()
	// Space for buffer with AT_NULL (0) terminator at the end.
	buf.Grow((len(auxv) + 1) * 16)
	for _, e := range auxv {
		var tmp [16]byte
		hostarch.ByteOrder.PutUint64(tmp[:8], e.Key)
		hostarch.ByteOrder.PutUint64(tmp[8:], uint64(e.Value))
		buf.Write(tmp[:])
	}
	var atNull [16]byte
	buf.Write(atNull[:])

	return nil
}

// MetadataType enumerates the types of metadata that is exposed through proc.
type MetadataType int

const (
	// Cmdline represents /proc/[pid]/cmdline.
	Cmdline MetadataType = iota

	// Environ represents /proc/[pid]/environ.
	Environ
)

// GetMetadata fetches the process's metadata of type t and writes it into
// buf. The process is identified by mm.
func GetMetadata(ctx context.Context, mm *mm.MemoryManager, buf *bytes.Buffer, t MetadataType) error {
	// Figure out the bounds of the exec arg we are trying to read.
	var ar hostarch.AddrRange
	switch t {
	case Cmdline:
		ar = hostarch.AddrRange{
			Start: mm.ArgvStart(),
			End:   mm.ArgvEnd(),
		}
	case Environ:
		ar = hostarch.AddrRange{
			Start: mm.EnvvStart(),
			End:   mm.EnvvEnd(),
		}
	default:
		panic(fmt.Sprintf("unknown exec arg type %v", t))
	}
	if ar.Start == 0 || ar.End == 0 {
		// Don't attempt to read before the start/end are set up.
		return io.EOF
	}

	// N.B. Technically this should be usermem.IOOpts.IgnorePermissions = true
	// until Linux 4.9 (272ddc8b3735 "proc: don't use FOLL_FORCE for reading
	// cmdline and environment").
	writer := &bufferWriter{buf: buf}
	if n, err := mm.CopyInTo(ctx, hostarch.AddrRangeSeqOf(ar), writer, usermem.IOOpts{}); n == 0 || err != nil {
		// Nothing to copy or something went wrong.
		return err
	}

	// On Linux, if the NULL byte at the end of the argument vector has been
	// overwritten, it continues reading the environment vector as part of
	// the argument vector.
	if t == Cmdline && buf.Bytes()[buf.Len()-1] != 0 {
		if end := bytes.IndexByte(buf.Bytes(), 0); end != -1 {
			// If we found a NULL character somewhere else in argv, truncate the
			// return up to the NULL terminator (including it).
			buf.Truncate(end)
			return nil
		}

		// There is no NULL terminator in the string, return into envp.
		arEnvv := hostarch.AddrRange{
			Start: mm.EnvvStart(),
			End:   mm.EnvvEnd(),
		}

		// Upstream limits the returned amount to one page of slop.
		// https://elixir.bootlin.com/linux/v4.20/source/fs/proc/base.c#L208
		// we'll return one page total between argv and envp because of the
		// above page restrictions.
		if buf.Len() >= hostarch.PageSize {
			// Returned at least one page already, nothing else to add.
			return nil
		}
		remaining := hostarch.PageSize - buf.Len()
		if int(arEnvv.Length()) > remaining {
			end, ok := arEnvv.Start.AddLength(uint64(remaining))
			if !ok {
				return linuxerr.EFAULT
			}
			arEnvv.End = end
		}
		if _, err := mm.CopyInTo(ctx, hostarch.AddrRangeSeqOf(arEnvv), writer, usermem.IOOpts{}); err != nil {
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

// metadataData implements vfs.DynamicBytesSource for proc metadata fields like:
//
//   - /proc/[pid]/cmdline
//   - /proc/[pid]/environ
//
// +stateify savable
type metadataData struct {
	kernfs.DynamicBytesFile

	task *kernel.Task

	// arg is the type of exec argument this file contains.
	metaType MetadataType
}

var _ dynamicInode = (*metadataData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *metadataData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if d.task.ExitState() == kernel.TaskExitDead {
		return linuxerr.ESRCH
	}
	m, err := getMMIncRef(d.task)
	if err != nil {
		// Return empty file.
		return nil
	}
	defer m.DecUsers(ctx)
	return GetMetadata(ctx, m, buf, d.metaType)
}

// +stateify savable
type commInode struct {
	kernfs.DynamicBytesFile

	task *kernel.Task
}

func (fs *filesystem) newComm(ctx context.Context, task *kernel.Task, ino uint64, perm linux.FileMode) kernfs.Inode {
	inode := &commInode{task: task}
	inode.DynamicBytesFile.Init(ctx, task.Credentials(), linux.UNNAMED_MAJOR, fs.devMinor, ino, &commData{task: task}, perm)
	return inode
}

func (i *commInode) CheckPermissions(ctx context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	// This file can always be read or written by members of the same thread
	// group. See fs/proc/base.c:proc_tid_comm_permission.
	t := kernel.TaskFromContext(ctx)
	if t != nil && t.ThreadGroup() == i.task.ThreadGroup() && !ats.MayExec() {
		return nil
	}

	return i.DynamicBytesFile.CheckPermissions(ctx, creds, ats)
}

// commData implements vfs.WritableDynamicBytesSource for /proc/[pid]/comm.
//
// +stateify savable
type commData struct {
	kernfs.DynamicBytesFile

	task *kernel.Task
}

var _ dynamicInode = (*commData)(nil)
var _ vfs.WritableDynamicBytesSource = (*commData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *commData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString(d.task.Name())
	buf.WriteString("\n")
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *commData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	srclen := src.NumBytes()
	name := make([]byte, srclen)
	if _, err := src.CopyIn(ctx, name); err != nil {
		return 0, err
	}

	// Only allow writes from the same thread group, otherwise return
	// EINVAL. See fs/proc/base.c:comm_write.
	//
	// Note that this check exists in addition to the same-thread-group
	// check in CheckPermissions.
	t := kernel.TaskFromContext(ctx)
	if t == nil || t.ThreadGroup() != d.task.ThreadGroup() {
		return 0, linuxerr.EINVAL
	}
	d.task.SetName(string(name))
	return int64(srclen), nil
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
var _ vfs.WritableDynamicBytesSource = (*idMapData)(nil)

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
func (d *idMapData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	// "In addition, the number of bytes written to the file must be less than
	// the system page size, and the write must be performed at the start of
	// the file ..." - user_namespaces(7)
	srclen := src.NumBytes()
	if srclen >= hostarch.PageSize || offset != 0 {
		return 0, linuxerr.EINVAL
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
		return 0, linuxerr.EINVAL
	}

	entries := make([]auth.IDMapEntry, len(lines))
	for i, l := range lines {
		var e auth.IDMapEntry
		_, err := fmt.Sscan(string(l), &e.FirstID, &e.FirstParentID, &e.Length)
		if err != nil {
			return 0, linuxerr.EINVAL
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

var _ kernfs.Inode = (*memInode)(nil)

// memInode implements kernfs.Inode for /proc/[pid]/mem.
//
// +stateify savable
type memInode struct {
	kernfs.InodeAttrs
	kernfs.InodeNoStatFS
	kernfs.InodeNoopRefCount
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	kernfs.InodeWatches

	task  *kernel.Task
	locks vfs.FileLocks
}

func (fs *filesystem) newMemInode(ctx context.Context, task *kernel.Task, ino uint64, perm linux.FileMode) kernfs.Inode {
	// Note: credentials are overridden by taskOwnedInode.
	inode := &memInode{task: task}
	inode.init(ctx, task.Credentials(), linux.UNNAMED_MAJOR, fs.devMinor, ino, perm)
	return &taskOwnedInode{Inode: inode, owner: task}
}

func (f *memInode) init(ctx context.Context, creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, perm linux.FileMode) {
	if perm&^linux.PermissionsMask != 0 {
		panic(fmt.Sprintf("Only permission mask must be set: %x", perm&linux.PermissionsMask))
	}
	f.InodeAttrs.Init(ctx, creds, devMajor, devMinor, ino, linux.ModeRegular|perm)
}

// Open implements kernfs.Inode.Open.
func (f *memInode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// TODO(gvisor.dev/issue/260): Add check for PTRACE_MODE_ATTACH_FSCREDS
	// Permission to read this file is governed by PTRACE_MODE_ATTACH_FSCREDS
	// Since we dont implement setfsuid/setfsgid we can just use PTRACE_MODE_ATTACH
	if !kernel.ContextCanTrace(ctx, f.task, true) {
		return nil, linuxerr.EACCES
	}
	if err := checkTaskState(f.task); err != nil {
		return nil, err
	}
	fd := &memFD{}
	if err := fd.Init(rp.Mount(), d, f, opts.Flags); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// SetStat implements kernfs.Inode.SetStat.
func (*memInode) SetStat(context.Context, *vfs.Filesystem, *auth.Credentials, vfs.SetStatOptions) error {
	return linuxerr.EPERM
}

var _ vfs.FileDescriptionImpl = (*memFD)(nil)

// memFD implements vfs.FileDescriptionImpl for /proc/[pid]/mem.
//
// +stateify savable
type memFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	inode *memInode

	// mu guards the fields below.
	mu     sync.Mutex `state:"nosave"`
	offset int64
}

// Init initializes memFD.
func (fd *memFD) Init(m *vfs.Mount, d *kernfs.Dentry, inode *memInode, flags uint32) error {
	fd.LockFD.Init(&inode.locks)
	if err := fd.vfsfd.Init(fd, flags, m, d.VFSDentry(), &vfs.FileDescriptionOptions{}); err != nil {
		return err
	}
	fd.inode = inode
	return nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *memFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	switch whence {
	case linux.SEEK_SET:
	case linux.SEEK_CUR:
		offset += fd.offset
	default:
		return 0, linuxerr.EINVAL
	}
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	fd.offset = offset
	return offset, nil
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *memFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if dst.NumBytes() == 0 {
		return 0, nil
	}
	m, err := getMMIncRef(fd.inode.task)
	if err != nil {
		return 0, err
	}
	defer m.DecUsers(ctx)
	// Buffer the read data because of MM locks
	buf := make([]byte, dst.NumBytes())
	n, readErr := m.CopyIn(ctx, hostarch.Addr(offset), buf, usermem.IOOpts{IgnorePermissions: true})
	if n > 0 {
		if _, err := dst.CopyOut(ctx, buf[:n]); err != nil {
			return 0, linuxerr.EFAULT
		}
		return int64(n), nil
	}
	if readErr != nil {
		return 0, linuxerr.EIO
	}
	return 0, nil
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *memFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.mu.Lock()
	n, err := fd.PRead(ctx, dst, fd.offset, opts)
	fd.offset += n
	fd.mu.Unlock()
	return n, err
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *memFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	fs := fd.vfsfd.VirtualDentry().Mount().Filesystem()
	return fd.inode.Stat(ctx, fs, opts)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *memFD) SetStat(context.Context, vfs.SetStatOptions) error {
	return linuxerr.EPERM
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *memFD) Release(context.Context) {}

// limitsData implements vfs.DynamicBytesSource for /proc/[pid]/limits.
//
// +stateify savable
type limitsData struct {
	kernfs.DynamicBytesFile

	task *kernel.Task
}

func (d *limitsData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	taskLimits := d.task.Limits()
	// formatting matches the kernel output from linux/fs/proc/base.c:proc_pid_limits()
	fmt.Fprintf(buf, "Limit                     Soft Limit           Hard Limit           Units     \n")
	for _, lt := range limits.AllLimitTypes {
		fmt.Fprintf(buf, "%-25s ", lt.Name())

		l := taskLimits.Get(lt)
		if l.Cur == limits.Infinity {
			fmt.Fprintf(buf, "%-20s ", "unlimited")
		} else {
			fmt.Fprintf(buf, "%-20d ", l.Cur)
		}

		if l.Max == limits.Infinity {
			fmt.Fprintf(buf, "%-20s ", "unlimited")
		} else {
			fmt.Fprintf(buf, "%-20d ", l.Max)
		}

		if u := lt.Unit(); u != "" {
			fmt.Fprintf(buf, "%-10s", u)
		}

		buf.WriteByte('\n')
	}
	return nil
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
		mm.ReadMapsDataInto(ctx, mm.MapsCallbackFuncForBuffer(buf))
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
	if mm := getMM(s.task); mm != nil {
		vss = mm.VirtualMemorySize()
		rss = mm.ResidentSetSize()
	}
	fmt.Fprintf(buf, "%d %d ", vss, rss/hostarch.PageSize)

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
	if mm := getMM(s.task); mm != nil {
		vss = mm.VirtualMemorySize()
		rss = mm.ResidentSetSize()
	}
	fmt.Fprintf(buf, "%d %d 0 0 0 0 0\n", vss/hostarch.PageSize, rss/hostarch.PageSize)
	return nil
}

// statusInode implements kernfs.Inode for /proc/[pid]/status.
//
// +stateify savable
type statusInode struct {
	kernfs.InodeAttrs
	kernfs.InodeNoStatFS
	kernfs.InodeNoopRefCount
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	kernfs.InodeWatches

	task  *kernel.Task
	pidns *kernel.PIDNamespace
	locks vfs.FileLocks
}

// statusFD implements vfs.FileDescriptionImpl and vfs.DynamicByteSource for
// /proc/[pid]/status.
//
// +stateify savable
type statusFD struct {
	statusFDLowerBase
	vfs.DynamicBytesFileDescriptionImpl
	vfs.LockFD

	vfsfd vfs.FileDescription

	inode  *statusInode
	task   *kernel.Task
	pidns  *kernel.PIDNamespace
	userns *auth.UserNamespace // equivalent to struct file::f_cred::user_ns
}

// statusFDLowerBase is a dumb hack to ensure that statusFD prefers
// vfs.DynamicBytesFileDescriptionImpl methods to vfs.FileDescriptinDefaultImpl
// methods.
//
// +stateify savable
type statusFDLowerBase struct {
	vfs.FileDescriptionDefaultImpl
}

func (fs *filesystem) newStatusInode(ctx context.Context, task *kernel.Task, pidns *kernel.PIDNamespace, ino uint64, perm linux.FileMode) kernfs.Inode {
	// Note: credentials are overridden by taskOwnedInode.
	inode := &statusInode{
		task:  task,
		pidns: pidns,
	}
	inode.InodeAttrs.Init(ctx, task.Credentials(), linux.UNNAMED_MAJOR, fs.devMinor, ino, linux.ModeRegular|perm)
	return &taskOwnedInode{Inode: inode, owner: task}
}

// Open implements kernfs.Inode.Open.
func (s *statusInode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &statusFD{
		inode:  s,
		task:   s.task,
		pidns:  s.pidns,
		userns: rp.Credentials().UserNamespace,
	}
	fd.LockFD.Init(&s.locks)
	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Mount(), d.VFSDentry(), &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	fd.DynamicBytesFileDescriptionImpl.Init(&fd.vfsfd, fd)
	return &fd.vfsfd, nil
}

// SetStat implements kernfs.Inode.SetStat.
func (*statusInode) SetStat(ctx context.Context, vfsfs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	return linuxerr.EPERM
}

// Release implements vfs.FileDescriptionImpl.Release.
func (s *statusFD) Release(ctx context.Context) {
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (s *statusFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	fs := s.vfsfd.VirtualDentry().Mount().Filesystem()
	return s.inode.Stat(ctx, fs, opts)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (s *statusFD) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	return linuxerr.EPERM
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (s *statusFD) Generate(ctx context.Context, buf *bytes.Buffer) error {
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

	creds := s.task.Credentials()
	ruid := creds.RealKUID.In(s.userns).OrOverflow()
	euid := creds.EffectiveKUID.In(s.userns).OrOverflow()
	suid := creds.SavedKUID.In(s.userns).OrOverflow()
	rgid := creds.RealKGID.In(s.userns).OrOverflow()
	egid := creds.EffectiveKGID.In(s.userns).OrOverflow()
	sgid := creds.SavedKGID.In(s.userns).OrOverflow()
	var fds int
	var vss, rss, data uint64
	s.task.WithMuLocked(func(t *kernel.Task) {
		if fdTable := t.FDTable(); fdTable != nil {
			fds = fdTable.CurrentMaxFDs()
		}
	})
	if mm := getMM(s.task); mm != nil {
		vss = mm.VirtualMemorySize()
		rss = mm.ResidentSetSize()
		data = mm.VirtualDataSize()
	}
	// Filesystem user/group IDs aren't implemented; effective UID/GID are used
	// instead.
	fmt.Fprintf(buf, "Uid:\t%d\t%d\t%d\t%d\n", ruid, euid, suid, euid)
	fmt.Fprintf(buf, "Gid:\t%d\t%d\t%d\t%d\n", rgid, egid, sgid, egid)
	fmt.Fprintf(buf, "FDSize:\t%d\n", fds)
	buf.WriteString("Groups:\t")
	// There is a space between each pair of supplemental GIDs, as well as an
	// unconditional trailing space that some applications actually depend on.
	var sep string
	for _, kgid := range creds.ExtraKGIDs {
		fmt.Fprintf(buf, "%s%d", sep, kgid.In(s.userns).OrOverflow())
		sep = " "
	}
	buf.WriteString(" \n")

	fmt.Fprintf(buf, "VmSize:\t%d kB\n", vss>>10)
	fmt.Fprintf(buf, "VmRSS:\t%d kB\n", rss>>10)
	fmt.Fprintf(buf, "VmData:\t%d kB\n", data>>10)

	fmt.Fprintf(buf, "Threads:\t%d\n", s.task.ThreadGroup().Count())
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

	fmt.Fprintf(buf, "char: %d\n", io.CharsRead.RacyLoad())
	fmt.Fprintf(buf, "wchar: %d\n", io.CharsWritten.RacyLoad())
	fmt.Fprintf(buf, "syscr: %d\n", io.ReadSyscalls.RacyLoad())
	fmt.Fprintf(buf, "syscw: %d\n", io.WriteSyscalls.RacyLoad())
	fmt.Fprintf(buf, "read_bytes: %d\n", io.BytesRead.RacyLoad())
	fmt.Fprintf(buf, "write_bytes: %d\n", io.BytesWritten.RacyLoad())
	fmt.Fprintf(buf, "cancelled_write_bytes: %d\n", io.BytesWriteCancelled.RacyLoad())
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
		return linuxerr.ESRCH
	}
	fmt.Fprintf(buf, "%d\n", o.task.OOMScoreAdj())
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (o *oomScoreAdj) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() == 0 {
		return 0, nil
	}

	// Limit input size so as not to impact performance if input size is large.
	src = src.TakeFirst(hostarch.PageSize - 1)

	var v int32
	n, err := usermem.CopyInt32StringInVec(ctx, src.IO, src.Addrs, &v, src.Opts)
	if err != nil {
		return 0, err
	}

	if o.task.ExitState() == kernel.TaskExitDead {
		return 0, linuxerr.ESRCH
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
	kernfs.InodeWatches

	fs   *filesystem
	task *kernel.Task
}

var _ kernfs.Inode = (*exeSymlink)(nil)

func (fs *filesystem) newExeSymlink(ctx context.Context, task *kernel.Task, ino uint64) kernfs.Inode {
	inode := &exeSymlink{
		fs:   fs,
		task: task,
	}
	inode.Init(ctx, task.Credentials(), linux.UNNAMED_MAJOR, fs.devMinor, ino, linux.ModeSymlink|0777)
	return inode
}

// Readlink implements kernfs.Inode.Readlink.
func (s *exeSymlink) Readlink(ctx context.Context, _ *vfs.Mount) (string, error) {
	exec, _, err := s.Getlink(ctx, nil)
	if err != nil {
		return "", err
	}
	defer s.fs.SafeDecRef(ctx, exec)

	root := vfs.RootFromContext(ctx)
	if !root.Ok() {
		panic("procfs Readlink requires context with root value")
	}
	defer s.fs.SafeDecRef(ctx, root)

	vfsObj := exec.Mount().Filesystem().VirtualFilesystem()
	name, _ := vfsObj.PathnameWithDeleted(ctx, root, exec)
	return name, nil
}

// Getlink implements kernfs.Inode.Getlink.
func (s *exeSymlink) Getlink(ctx context.Context, _ *vfs.Mount) (vfs.VirtualDentry, string, error) {
	if !kernel.ContextCanTrace(ctx, s.task, false) {
		return vfs.VirtualDentry{}, "", linuxerr.EACCES
	}
	if err := checkTaskState(s.task); err != nil {
		return vfs.VirtualDentry{}, "", err
	}

	mm := getMM(s.task)
	if mm == nil {
		return vfs.VirtualDentry{}, "", linuxerr.EACCES
	}

	// The MemoryManager may be destroyed, in which case
	// MemoryManager.destroy will simply set the executable to nil
	// (with locks held).
	exec := mm.Executable()
	if exec == nil {
		return vfs.VirtualDentry{}, "", linuxerr.ESRCH
	}
	defer exec.DecRef(ctx)

	vd := exec.VirtualDentry()
	vd.IncRef()
	return vd, "", nil
}

// cwdSymlink is an symlink for the /proc/[pid]/cwd file.
//
// +stateify savable
type cwdSymlink struct {
	implStatFS
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeSymlink
	kernfs.InodeWatches

	fs   *filesystem
	task *kernel.Task
}

var _ kernfs.Inode = (*cwdSymlink)(nil)

func (fs *filesystem) newCwdSymlink(ctx context.Context, task *kernel.Task, ino uint64) kernfs.Inode {
	inode := &cwdSymlink{
		fs:   fs,
		task: task,
	}
	inode.Init(ctx, task.Credentials(), linux.UNNAMED_MAJOR, fs.devMinor, ino, linux.ModeSymlink|0777)
	return inode
}

// Readlink implements kernfs.Inode.Readlink.
func (s *cwdSymlink) Readlink(ctx context.Context, _ *vfs.Mount) (string, error) {
	cwd, _, err := s.Getlink(ctx, nil)
	if err != nil {
		return "", err
	}
	defer s.fs.SafeDecRef(ctx, cwd)

	root := vfs.RootFromContext(ctx)
	if !root.Ok() {
		panic("procfs Readlink requires context with root value")
	}
	defer s.fs.SafeDecRef(ctx, root)

	vfsObj := cwd.Mount().Filesystem().VirtualFilesystem()
	name, _ := vfsObj.PathnameWithDeleted(ctx, root, cwd)
	return name, nil
}

// Getlink implements kernfs.Inode.Getlink.
func (s *cwdSymlink) Getlink(ctx context.Context, _ *vfs.Mount) (vfs.VirtualDentry, string, error) {
	if !kernel.ContextCanTrace(ctx, s.task, false) {
		return vfs.VirtualDentry{}, "", linuxerr.EACCES
	}
	if err := checkTaskState(s.task); err != nil {
		return vfs.VirtualDentry{}, "", err
	}
	cwd := s.task.FSContext().WorkingDirectory()
	if !cwd.Ok() {
		// It could have raced with process deletion.
		return vfs.VirtualDentry{}, "", linuxerr.ESRCH
	}
	// The reference is transferred to the caller.
	return cwd, "", nil
}

// rootSymlink is an symlink for the /proc/[pid]/root file.
//
// +stateify savable
type rootSymlink struct {
	implStatFS
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeSymlink
	kernfs.InodeWatches

	fs   *filesystem
	task *kernel.Task
}

var _ kernfs.Inode = (*rootSymlink)(nil)

func (fs *filesystem) newRootSymlink(ctx context.Context, task *kernel.Task, ino uint64) kernfs.Inode {
	inode := &rootSymlink{
		fs:   fs,
		task: task,
	}
	inode.Init(ctx, task.Credentials(), linux.UNNAMED_MAJOR, fs.devMinor, ino, linux.ModeSymlink|0777)
	return inode
}

// Readlink implements kernfs.Inode.Readlink.
func (s *rootSymlink) Readlink(ctx context.Context, _ *vfs.Mount) (string, error) {
	root, _, err := s.Getlink(ctx, nil)
	if err != nil {
		return "", err
	}
	defer s.fs.SafeDecRef(ctx, root)

	vfsRoot := vfs.RootFromContext(ctx)
	if !vfsRoot.Ok() {
		panic("procfs Readlink requires context with root value")
	}
	defer s.fs.SafeDecRef(ctx, vfsRoot)

	vfsObj := root.Mount().Filesystem().VirtualFilesystem()
	name, _ := vfsObj.PathnameWithDeleted(ctx, vfsRoot, root)
	return name, nil
}

// Getlink implements kernfs.Inode.Getlink.
func (s *rootSymlink) Getlink(ctx context.Context, _ *vfs.Mount) (vfs.VirtualDentry, string, error) {
	if !kernel.ContextCanTrace(ctx, s.task, false) {
		return vfs.VirtualDentry{}, "", linuxerr.EACCES
	}
	if err := checkTaskState(s.task); err != nil {
		return vfs.VirtualDentry{}, "", err
	}
	root := s.task.FSContext().RootDirectory()
	if !root.Ok() {
		// It could have raced with process deletion.
		return vfs.VirtualDentry{}, "", linuxerr.ESRCH
	}
	// The reference is transferred to the caller.
	return root, "", nil
}

// mountInfoData is used to implement /proc/[pid]/mountinfo.
//
// +stateify savable
type mountInfoData struct {
	kernfs.DynamicBytesFile

	fs   *filesystem
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
	rootDir := fsctx.RootDirectory()
	if !rootDir.Ok() {
		// Root has been destroyed. Don't try to read mounts.
		return nil
	}
	defer i.fs.SafeDecRef(ctx, rootDir)
	i.task.Kernel().VFS().GenerateProcMountInfo(ctx, rootDir, buf)
	return nil
}

// mountsData is used to implement /proc/[pid]/mounts.
//
// +stateify savable
type mountsData struct {
	kernfs.DynamicBytesFile

	fs   *filesystem
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
	rootDir := fsctx.RootDirectory()
	if !rootDir.Ok() {
		// Root has been destroyed. Don't try to read mounts.
		return nil
	}
	defer i.fs.SafeDecRef(ctx, rootDir)
	i.task.Kernel().VFS().GenerateProcMounts(ctx, rootDir, buf)
	return nil
}

// +stateify savable
type namespaceSymlink struct {
	kernfs.StaticSymlink

	task *kernel.Task
}

func (fs *filesystem) newNamespaceSymlink(ctx context.Context, task *kernel.Task, ino uint64, ns string) kernfs.Inode {
	// Namespace symlinks should contain the namespace name and the inode number
	// for the namespace instance, so for example user:[123456]. We currently fake
	// the inode number by sticking the symlink inode in its place.
	target := fmt.Sprintf("%s:[%d]", ns, ino)

	inode := &namespaceSymlink{task: task}
	// Note: credentials are overridden by taskOwnedInode.
	inode.Init(ctx, task.Credentials(), linux.UNNAMED_MAJOR, fs.devMinor, ino, target)

	taskInode := &taskOwnedInode{Inode: inode, owner: task}
	return taskInode
}

// Readlink implements kernfs.Inode.Readlink.
func (s *namespaceSymlink) Readlink(ctx context.Context, mnt *vfs.Mount) (string, error) {
	if err := checkTaskState(s.task); err != nil {
		return "", err
	}
	return s.StaticSymlink.Readlink(ctx, mnt)
}

// Getlink implements kernfs.Inode.Getlink.
func (s *namespaceSymlink) Getlink(ctx context.Context, mnt *vfs.Mount) (vfs.VirtualDentry, string, error) {
	if err := checkTaskState(s.task); err != nil {
		return vfs.VirtualDentry{}, "", err
	}

	// Create a synthetic inode to represent the namespace.
	fs := mnt.Filesystem().Impl().(*filesystem)
	nsInode := &namespaceInode{}
	nsInode.Init(ctx, auth.CredentialsFromContext(ctx), linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), 0444)
	dentry := &kernfs.Dentry{}
	dentry.Init(&fs.Filesystem, nsInode)
	vd := vfs.MakeVirtualDentry(mnt, dentry.VFSDentry())
	// Only IncRef vd.Mount() because vd.Dentry() already holds a ref of 1.
	mnt.IncRef()
	return vd, "", nil
}

// namespaceInode is a synthetic inode created to represent a namespace in
// /proc/[pid]/ns/*.
//
// +stateify savable
type namespaceInode struct {
	implStatFS
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	kernfs.InodeWatches

	locks vfs.FileLocks
}

var _ kernfs.Inode = (*namespaceInode)(nil)

// Init initializes a namespace inode.
func (i *namespaceInode) Init(ctx context.Context, creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, perm linux.FileMode) {
	if perm&^linux.PermissionsMask != 0 {
		panic(fmt.Sprintf("Only permission mask must be set: %x", perm&linux.PermissionsMask))
	}
	i.InodeAttrs.Init(ctx, creds, devMajor, devMinor, ino, linux.ModeRegular|perm)
}

// Open implements kernfs.Inode.Open.
func (i *namespaceInode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &namespaceFD{inode: i}
	i.IncRef()
	fd.LockFD.Init(&i.locks)
	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Mount(), d.VFSDentry(), &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// namespace FD is a synthetic file that represents a namespace in
// /proc/[pid]/ns/*.
//
// +stateify savable
type namespaceFD struct {
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	vfsfd vfs.FileDescription
	inode *namespaceInode
}

var _ vfs.FileDescriptionImpl = (*namespaceFD)(nil)

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *namespaceFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	vfs := fd.vfsfd.VirtualDentry().Mount().Filesystem()
	return fd.inode.Stat(ctx, vfs, opts)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *namespaceFD) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	vfs := fd.vfsfd.VirtualDentry().Mount().Filesystem()
	creds := auth.CredentialsFromContext(ctx)
	return fd.inode.SetStat(ctx, vfs, creds, opts)
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *namespaceFD) Release(ctx context.Context) {
	fd.inode.DecRef(ctx)
}

// taskCgroupData generates data for /proc/[pid]/cgroup.
//
// +stateify savable
type taskCgroupData struct {
	dynamicBytesFileSetAttr
	task *kernel.Task
}

var _ dynamicInode = (*taskCgroupData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *taskCgroupData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	// When a task is existing on Linux, a task's cgroup set is cleared and
	// reset to the initial cgroup set, which is essentially the set of root
	// cgroups. Because of this, the /proc/<pid>/cgroup file is always readable
	// on Linux throughout a task's lifetime.
	//
	// The sentry removes tasks from cgroups during the exit process, but
	// doesn't move them into an initial cgroup set, so partway through task
	// exit this file show a task is in no cgroups, which is incorrect. Instead,
	// once a task has left its cgroups, we return an error.
	if d.task.ExitState() >= kernel.TaskExitInitiated {
		return linuxerr.ESRCH
	}

	d.task.GenerateProcTaskCgroup(buf)
	return nil
}
