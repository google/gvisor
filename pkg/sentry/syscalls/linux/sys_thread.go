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

package linux

import (
	"path"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
)

const (
	// ExecMaxTotalSize is the maximum length of all argv and envv entries.
	//
	// N.B. The behavior here is different than Linux. Linux provides a limit on
	// individual arguments of 32 pages, and an aggregate limit of at least 32 pages
	// but otherwise bounded by min(stack size / 4, 8 MB * 3 / 4). We don't implement
	// any behavior based on the stack size, and instead provide a fixed hard-limit of
	// 2 MB (which should work well given that 8 MB stack limits are common).
	ExecMaxTotalSize = 2 * 1024 * 1024

	// ExecMaxElemSize is the maximum length of a single argv or envv entry.
	ExecMaxElemSize = 32 * usermem.PageSize

	// exitSignalMask is the signal mask to be sent at exit. Same as CSIGNAL in linux.
	exitSignalMask = 0xff
)

// Getppid implements linux syscall getppid(2).
func Getppid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	parent := t.Parent()
	if parent == nil {
		return 0, nil, nil
	}
	return uintptr(t.PIDNamespace().IDOfThreadGroup(parent.ThreadGroup())), nil, nil
}

// Getpid implements linux syscall getpid(2).
func Getpid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return uintptr(t.ThreadGroup().ID()), nil, nil
}

// Gettid implements linux syscall gettid(2).
func Gettid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return uintptr(t.ThreadID()), nil, nil
}

// Execve implements linux syscall execve(2).
func Execve(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	filenameAddr := args[0].Pointer()
	argvAddr := args[1].Pointer()
	envvAddr := args[2].Pointer()

	return execveat(t, linux.AT_FDCWD, filenameAddr, argvAddr, envvAddr, 0)
}

// Execveat implements linux syscall execveat(2).
func Execveat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirFD := args[0].Int()
	pathnameAddr := args[1].Pointer()
	argvAddr := args[2].Pointer()
	envvAddr := args[3].Pointer()
	flags := args[4].Int()

	return execveat(t, dirFD, pathnameAddr, argvAddr, envvAddr, flags)
}

func execveat(t *kernel.Task, dirFD int32, pathnameAddr, argvAddr, envvAddr usermem.Addr, flags int32) (uintptr, *kernel.SyscallControl, error) {
	pathname, err := t.CopyInString(pathnameAddr, linux.PATH_MAX)
	if err != nil {
		return 0, nil, err
	}

	var argv, envv []string
	if argvAddr != 0 {
		var err error
		argv, err = t.CopyInVector(argvAddr, ExecMaxElemSize, ExecMaxTotalSize)
		if err != nil {
			return 0, nil, err
		}
	}
	if envvAddr != 0 {
		var err error
		envv, err = t.CopyInVector(envvAddr, ExecMaxElemSize, ExecMaxTotalSize)
		if err != nil {
			return 0, nil, err
		}
	}

	if flags != 0 {
		// TODO(b/128449944): Handle AT_EMPTY_PATH and AT_SYMLINK_NOFOLLOW.
		t.Kernel().EmitUnimplementedEvent(t)
		return 0, nil, syserror.ENOSYS
	}

	root := t.FSContext().RootDirectory()
	defer root.DecRef()

	var wd *fs.Dirent
	if dirFD == linux.AT_FDCWD || path.IsAbs(pathname) {
		// If pathname is absolute, LoadTaskImage() will ignore the wd.
		wd = t.FSContext().WorkingDirectory()
	} else {
		// Need to extract the given FD.
		f := t.GetFile(dirFD)
		if f == nil {
			return 0, nil, syserror.EBADF
		}
		defer f.DecRef()

		wd = f.Dirent
		wd.IncRef()
		if !fs.IsDir(wd.Inode.StableAttr) {
			return 0, nil, syserror.ENOTDIR
		}
	}
	defer wd.DecRef()

	// Load the new TaskContext.
	maxTraversals := uint(linux.MaxSymlinkTraversals)
	tc, se := t.Kernel().LoadTaskImage(t, t.MountNamespace(), root, wd, &maxTraversals, pathname, nil, argv, envv, t.Arch().FeatureSet())
	if se != nil {
		return 0, nil, se.ToError()
	}

	ctrl, err := t.Execve(tc)
	return 0, ctrl, err
}

// Exit implements linux syscall exit(2).
func Exit(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	status := int(args[0].Int())
	t.PrepareExit(kernel.ExitStatus{Code: status})
	return 0, kernel.CtrlDoExit, nil
}

// ExitGroup implements linux syscall exit_group(2).
func ExitGroup(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	status := int(args[0].Int())
	t.PrepareGroupExit(kernel.ExitStatus{Code: status})
	return 0, kernel.CtrlDoExit, nil
}

// clone is used by Clone, Fork, and VFork.
func clone(t *kernel.Task, flags int, stack usermem.Addr, parentTID usermem.Addr, childTID usermem.Addr, tls usermem.Addr) (uintptr, *kernel.SyscallControl, error) {
	opts := kernel.CloneOptions{
		SharingOptions: kernel.SharingOptions{
			NewAddressSpace:     flags&linux.CLONE_VM == 0,
			NewSignalHandlers:   flags&linux.CLONE_SIGHAND == 0,
			NewThreadGroup:      flags&linux.CLONE_THREAD == 0,
			TerminationSignal:   linux.Signal(flags & exitSignalMask),
			NewPIDNamespace:     flags&linux.CLONE_NEWPID == linux.CLONE_NEWPID,
			NewUserNamespace:    flags&linux.CLONE_NEWUSER == linux.CLONE_NEWUSER,
			NewNetworkNamespace: flags&linux.CLONE_NEWNET == linux.CLONE_NEWNET,
			NewFiles:            flags&linux.CLONE_FILES == 0,
			NewFSContext:        flags&linux.CLONE_FS == 0,
			NewUTSNamespace:     flags&linux.CLONE_NEWUTS == linux.CLONE_NEWUTS,
			NewIPCNamespace:     flags&linux.CLONE_NEWIPC == linux.CLONE_NEWIPC,
		},
		Stack:         stack,
		SetTLS:        flags&linux.CLONE_SETTLS == linux.CLONE_SETTLS,
		TLS:           tls,
		ChildClearTID: flags&linux.CLONE_CHILD_CLEARTID == linux.CLONE_CHILD_CLEARTID,
		ChildSetTID:   flags&linux.CLONE_CHILD_SETTID == linux.CLONE_CHILD_SETTID,
		ChildTID:      childTID,
		ParentSetTID:  flags&linux.CLONE_PARENT_SETTID == linux.CLONE_PARENT_SETTID,
		ParentTID:     parentTID,
		Vfork:         flags&linux.CLONE_VFORK == linux.CLONE_VFORK,
		Untraced:      flags&linux.CLONE_UNTRACED == linux.CLONE_UNTRACED,
		InheritTracer: flags&linux.CLONE_PTRACE == linux.CLONE_PTRACE,
	}
	ntid, ctrl, err := t.Clone(&opts)
	return uintptr(ntid), ctrl, err
}

// Clone implements linux syscall clone(2).
// sys_clone has so many flavors. We implement the default one in linux 3.11
// x86_64:
//    sys_clone(clone_flags, newsp, parent_tidptr, child_tidptr, tls_val)
func Clone(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	flags := int(args[0].Int())
	stack := args[1].Pointer()
	parentTID := args[2].Pointer()
	childTID := args[3].Pointer()
	tls := args[4].Pointer()
	return clone(t, flags, stack, parentTID, childTID, tls)
}

// Fork implements Linux syscall fork(2).
func Fork(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// "A call to fork() is equivalent to a call to clone(2) specifying flags
	// as just SIGCHLD." - fork(2)
	return clone(t, int(linux.SIGCHLD), 0, 0, 0, 0)
}

// Vfork implements Linux syscall vfork(2).
func Vfork(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// """
	// A call to vfork() is equivalent to calling clone(2) with flags specified as:
	//
	//     CLONE_VM | CLONE_VFORK | SIGCHLD
	// """ - vfork(2)
	return clone(t, linux.CLONE_VM|linux.CLONE_VFORK|int(linux.SIGCHLD), 0, 0, 0, 0)
}

// parseCommonWaitOptions applies the options common to wait4 and waitid to
// wopts.
func parseCommonWaitOptions(wopts *kernel.WaitOptions, options int) error {
	switch options & (linux.WCLONE | linux.WALL) {
	case 0:
		wopts.NonCloneTasks = true
	case linux.WCLONE:
		wopts.CloneTasks = true
	case linux.WALL:
		wopts.NonCloneTasks = true
		wopts.CloneTasks = true
	default:
		return syserror.EINVAL
	}
	if options&linux.WCONTINUED != 0 {
		wopts.Events |= kernel.EventGroupContinue
	}
	if options&linux.WNOHANG == 0 {
		wopts.BlockInterruptErr = kernel.ERESTARTSYS
	}
	if options&linux.WNOTHREAD == 0 {
		wopts.SiblingChildren = true
	}
	return nil
}

// wait4 waits for the given child process to exit.
func wait4(t *kernel.Task, pid int, statusAddr usermem.Addr, options int, rusageAddr usermem.Addr) (uintptr, error) {
	if options&^(linux.WNOHANG|linux.WUNTRACED|linux.WCONTINUED|linux.WNOTHREAD|linux.WALL|linux.WCLONE) != 0 {
		return 0, syserror.EINVAL
	}
	wopts := kernel.WaitOptions{
		Events:       kernel.EventExit | kernel.EventTraceeStop,
		ConsumeEvent: true,
	}
	// There are four cases to consider:
	//
	// pid < -1    any child process whose process group ID is equal to the absolute value of pid
	// pid == -1   any child process
	// pid == 0    any child process whose process group ID is equal to that of the calling process
	// pid > 0     the child whose process ID is equal to the value of pid
	switch {
	case pid < -1:
		wopts.SpecificPGID = kernel.ProcessGroupID(-pid)
	case pid == -1:
		// Any process is the default.
	case pid == 0:
		wopts.SpecificPGID = t.PIDNamespace().IDOfProcessGroup(t.ThreadGroup().ProcessGroup())
	default:
		wopts.SpecificTID = kernel.ThreadID(pid)
	}

	if err := parseCommonWaitOptions(&wopts, options); err != nil {
		return 0, err
	}
	if options&linux.WUNTRACED != 0 {
		wopts.Events |= kernel.EventChildGroupStop
	}

	wr, err := t.Wait(&wopts)
	if err != nil {
		if err == kernel.ErrNoWaitableEvent {
			return 0, nil
		}
		return 0, err
	}
	if statusAddr != 0 {
		if _, err := t.CopyOut(statusAddr, wr.Status); err != nil {
			return 0, err
		}
	}
	if rusageAddr != 0 {
		ru := getrusage(wr.Task, linux.RUSAGE_BOTH)
		if _, err := t.CopyOut(rusageAddr, &ru); err != nil {
			return 0, err
		}
	}
	return uintptr(wr.TID), nil
}

// Wait4 implements linux syscall wait4(2).
func Wait4(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pid := int(args[0].Int())
	statusAddr := args[1].Pointer()
	options := int(args[2].Uint())
	rusageAddr := args[3].Pointer()

	n, err := wait4(t, pid, statusAddr, options, rusageAddr)
	return n, nil, err
}

// WaitPid implements linux syscall waitpid(2).
func WaitPid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pid := int(args[0].Int())
	statusAddr := args[1].Pointer()
	options := int(args[2].Uint())

	n, err := wait4(t, pid, statusAddr, options, 0)
	return n, nil, err
}

// Waitid implements linux syscall waitid(2).
func Waitid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	idtype := args[0].Int()
	id := args[1].Int()
	infop := args[2].Pointer()
	options := int(args[3].Uint())
	rusageAddr := args[4].Pointer()

	if options&^(linux.WNOHANG|linux.WEXITED|linux.WSTOPPED|linux.WCONTINUED|linux.WNOWAIT|linux.WNOTHREAD|linux.WALL|linux.WCLONE) != 0 {
		return 0, nil, syserror.EINVAL
	}
	if options&(linux.WEXITED|linux.WSTOPPED|linux.WCONTINUED) == 0 {
		return 0, nil, syserror.EINVAL
	}
	wopts := kernel.WaitOptions{
		Events:       kernel.EventTraceeStop,
		ConsumeEvent: options&linux.WNOWAIT == 0,
	}
	switch idtype {
	case linux.P_ALL:
	case linux.P_PID:
		wopts.SpecificTID = kernel.ThreadID(id)
	case linux.P_PGID:
		wopts.SpecificPGID = kernel.ProcessGroupID(id)
	default:
		return 0, nil, syserror.EINVAL
	}

	if err := parseCommonWaitOptions(&wopts, options); err != nil {
		return 0, nil, err
	}
	if options&linux.WEXITED != 0 {
		wopts.Events |= kernel.EventExit
	}
	if options&linux.WSTOPPED != 0 {
		wopts.Events |= kernel.EventChildGroupStop
	}

	wr, err := t.Wait(&wopts)
	if err != nil {
		if err == kernel.ErrNoWaitableEvent {
			err = nil
			// "If WNOHANG was specified in options and there were no children
			// in a waitable state, then waitid() returns 0 immediately and the
			// state of the siginfo_t structure pointed to by infop is
			// unspecified." - waitid(2). But Linux's waitid actually zeroes
			// out the fields it would set for a successful waitid in this case
			// as well.
			if infop != 0 {
				var si arch.SignalInfo
				_, err = t.CopyOut(infop, &si)
			}
		}
		return 0, nil, err
	}
	if rusageAddr != 0 {
		ru := getrusage(wr.Task, linux.RUSAGE_BOTH)
		if _, err := t.CopyOut(rusageAddr, &ru); err != nil {
			return 0, nil, err
		}
	}
	if infop == 0 {
		return 0, nil, nil
	}
	si := arch.SignalInfo{
		Signo: int32(linux.SIGCHLD),
	}
	si.SetPid(int32(wr.TID))
	si.SetUid(int32(wr.UID))
	// TODO(b/73541790): convert kernel.ExitStatus to functions and make
	// WaitResult.Status a linux.WaitStatus.
	s := syscall.WaitStatus(wr.Status)
	switch {
	case s.Exited():
		si.Code = arch.CLD_EXITED
		si.SetStatus(int32(s.ExitStatus()))
	case s.Signaled():
		si.Code = arch.CLD_KILLED
		si.SetStatus(int32(s.Signal()))
	case s.CoreDump():
		si.Code = arch.CLD_DUMPED
		si.SetStatus(int32(s.Signal()))
	case s.Stopped():
		if wr.Event == kernel.EventTraceeStop {
			si.Code = arch.CLD_TRAPPED
			si.SetStatus(int32(s.TrapCause()))
		} else {
			si.Code = arch.CLD_STOPPED
			si.SetStatus(int32(s.StopSignal()))
		}
	case s.Continued():
		si.Code = arch.CLD_CONTINUED
		si.SetStatus(int32(linux.SIGCONT))
	default:
		t.Warningf("waitid got incomprehensible wait status %d", s)
	}
	_, err = t.CopyOut(infop, &si)
	return 0, nil, err
}

// SetTidAddress implements linux syscall set_tid_address(2).
func SetTidAddress(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	// Always succeed, return caller's tid.
	t.SetClearTID(addr)
	return uintptr(t.ThreadID()), nil, nil
}

// Unshare implements linux syscall unshare(2).
func Unshare(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	flags := args[0].Int()
	opts := kernel.SharingOptions{
		NewAddressSpace:     flags&linux.CLONE_VM == linux.CLONE_VM,
		NewSignalHandlers:   flags&linux.CLONE_SIGHAND == linux.CLONE_SIGHAND,
		NewThreadGroup:      flags&linux.CLONE_THREAD == linux.CLONE_THREAD,
		NewPIDNamespace:     flags&linux.CLONE_NEWPID == linux.CLONE_NEWPID,
		NewUserNamespace:    flags&linux.CLONE_NEWUSER == linux.CLONE_NEWUSER,
		NewNetworkNamespace: flags&linux.CLONE_NEWNET == linux.CLONE_NEWNET,
		NewFiles:            flags&linux.CLONE_FILES == linux.CLONE_FILES,
		NewFSContext:        flags&linux.CLONE_FS == linux.CLONE_FS,
		NewUTSNamespace:     flags&linux.CLONE_NEWUTS == linux.CLONE_NEWUTS,
		NewIPCNamespace:     flags&linux.CLONE_NEWIPC == linux.CLONE_NEWIPC,
	}
	// "CLONE_NEWPID automatically implies CLONE_THREAD as well." - unshare(2)
	if opts.NewPIDNamespace {
		opts.NewThreadGroup = true
	}
	// "... specifying CLONE_NEWUSER automatically implies CLONE_THREAD. Since
	// Linux 3.9, CLONE_NEWUSER also automatically implies CLONE_FS."
	if opts.NewUserNamespace {
		opts.NewThreadGroup = true
		opts.NewFSContext = true
	}
	return 0, nil, t.Unshare(&opts)
}

// SchedYield implements linux syscall sched_yield(2).
func SchedYield(t *kernel.Task, _ arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	t.Yield()
	return 0, nil, nil
}

// SchedSetaffinity implements linux syscall sched_setaffinity(2).
func SchedSetaffinity(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	tid := args[0].Int()
	size := args[1].SizeT()
	maskAddr := args[2].Pointer()

	var task *kernel.Task
	if tid == 0 {
		task = t
	} else {
		task = t.PIDNamespace().TaskWithID(kernel.ThreadID(tid))
		if task == nil {
			return 0, nil, syserror.ESRCH
		}
	}

	mask := sched.NewCPUSet(t.Kernel().ApplicationCores())
	if size > mask.Size() {
		size = mask.Size()
	}
	if _, err := t.CopyInBytes(maskAddr, mask[:size]); err != nil {
		return 0, nil, err
	}
	return 0, nil, task.SetCPUMask(mask)
}

// SchedGetaffinity implements linux syscall sched_getaffinity(2).
func SchedGetaffinity(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	tid := args[0].Int()
	size := args[1].SizeT()
	maskAddr := args[2].Pointer()

	// This limitation is because linux stores the cpumask
	// in an array of "unsigned long" so the buffer needs to
	// be a multiple of the word size.
	if size&(t.Arch().Width()-1) > 0 {
		return 0, nil, syserror.EINVAL
	}

	var task *kernel.Task
	if tid == 0 {
		task = t
	} else {
		task = t.PIDNamespace().TaskWithID(kernel.ThreadID(tid))
		if task == nil {
			return 0, nil, syserror.ESRCH
		}
	}

	mask := task.CPUMask()
	// The buffer needs to be big enough to hold a cpumask with
	// all possible cpus.
	if size < mask.Size() {
		return 0, nil, syserror.EINVAL
	}
	_, err := t.CopyOutBytes(maskAddr, mask)

	// NOTE: The syscall interface is slightly different than the glibc
	// interface. The raw sched_getaffinity syscall returns the number of
	// bytes used to represent a cpu mask.
	return uintptr(mask.Size()), nil, err
}

// Getcpu implements linux syscall getcpu(2).
func Getcpu(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	cpu := args[0].Pointer()
	node := args[1].Pointer()
	// third argument to this system call is nowadays unused.

	if cpu != 0 {
		buf := t.CopyScratchBuffer(4)
		usermem.ByteOrder.PutUint32(buf, uint32(t.CPU()))
		if _, err := t.CopyOutBytes(cpu, buf); err != nil {
			return 0, nil, err
		}
	}
	// We always return node 0.
	if node != 0 {
		if _, err := t.MemoryManager().ZeroOut(t, node, 4, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, nil, err
		}
	}
	return 0, nil, nil
}

// Setpgid implements the linux syscall setpgid(2).
func Setpgid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// Note that throughout this function, pgid is interpreted with respect
	// to t's namespace, not with respect to the selected ThreadGroup's
	// namespace (which may be different).
	pid := kernel.ThreadID(args[0].Int())
	pgid := kernel.ProcessGroupID(args[1].Int())

	// "If pid is zero, then the process ID of the calling process is used."
	tg := t.ThreadGroup()
	if pid != 0 {
		ot := t.PIDNamespace().TaskWithID(pid)
		if ot == nil {
			return 0, nil, syserror.ESRCH
		}
		tg = ot.ThreadGroup()
		if tg.Leader() != ot {
			return 0, nil, syserror.EINVAL
		}

		// Setpgid only operates on child threadgroups.
		if tg != t.ThreadGroup() && (tg.Leader().Parent() == nil || tg.Leader().Parent().ThreadGroup() != t.ThreadGroup()) {
			return 0, nil, syserror.ESRCH
		}
	}

	// "If pgid is zero, then the PGID of the process specified by pid is made
	// the same as its process ID."
	defaultPGID := kernel.ProcessGroupID(t.PIDNamespace().IDOfThreadGroup(tg))
	if pgid == 0 {
		pgid = defaultPGID
	} else if pgid < 0 {
		return 0, nil, syserror.EINVAL
	}

	// If the pgid is the same as the group, then create a new one. Otherwise,
	// we attempt to join an existing process group.
	if pgid == defaultPGID {
		// For convenience, errors line up with Linux syscall API.
		if err := tg.CreateProcessGroup(); err != nil {
			// Is the process group already as expected? If so,
			// just return success. This is the same behavior as
			// Linux.
			if t.PIDNamespace().IDOfProcessGroup(tg.ProcessGroup()) == defaultPGID {
				return 0, nil, nil
			}
			return 0, nil, err
		}
	} else {
		// Same as CreateProcessGroup, above.
		if err := tg.JoinProcessGroup(t.PIDNamespace(), pgid, tg != t.ThreadGroup()); err != nil {
			// See above.
			if t.PIDNamespace().IDOfProcessGroup(tg.ProcessGroup()) == pgid {
				return 0, nil, nil
			}
			return 0, nil, err
		}
	}

	// Success.
	return 0, nil, nil
}

// Getpgrp implements the linux syscall getpgrp(2).
func Getpgrp(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return uintptr(t.PIDNamespace().IDOfProcessGroup(t.ThreadGroup().ProcessGroup())), nil, nil
}

// Getpgid implements the linux syscall getpgid(2).
func Getpgid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	tid := kernel.ThreadID(args[0].Int())
	if tid == 0 {
		return Getpgrp(t, args)
	}

	target := t.PIDNamespace().TaskWithID(tid)
	if target == nil {
		return 0, nil, syserror.ESRCH
	}

	return uintptr(t.PIDNamespace().IDOfProcessGroup(target.ThreadGroup().ProcessGroup())), nil, nil
}

// Setsid implements the linux syscall setsid(2).
func Setsid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, t.ThreadGroup().CreateSession()
}

// Getsid implements the linux syscall getsid(2).
func Getsid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	tid := kernel.ThreadID(args[0].Int())
	if tid == 0 {
		return uintptr(t.PIDNamespace().IDOfSession(t.ThreadGroup().Session())), nil, nil
	}

	target := t.PIDNamespace().TaskWithID(tid)
	if target == nil {
		return 0, nil, syserror.ESRCH
	}

	return uintptr(t.PIDNamespace().IDOfSession(target.ThreadGroup().Session())), nil, nil
}

// Getpriority pretends to implement the linux syscall getpriority(2).
//
// This is a stub; real priorities require a full scheduler.
func Getpriority(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	which := args[0].Int()
	who := kernel.ThreadID(args[1].Int())

	switch which {
	case linux.PRIO_PROCESS:
		// Look for who, return ESRCH if not found.
		var task *kernel.Task
		if who == 0 {
			task = t
		} else {
			task = t.PIDNamespace().TaskWithID(who)
		}

		if task == nil {
			return 0, nil, syserror.ESRCH
		}

		// From kernel/sys.c:getpriority:
		// "To avoid negative return values, 'getpriority()'
		// will not return the normal nice-value, but a negated
		// value that has been offset by 20"
		return uintptr(20 - task.Niceness()), nil, nil
	case linux.PRIO_USER:
		fallthrough
	case linux.PRIO_PGRP:
		// PRIO_USER and PRIO_PGRP have no further implementation yet.
		return 0, nil, nil
	default:
		return 0, nil, syserror.EINVAL
	}
}

// Setpriority pretends to implement the linux syscall setpriority(2).
//
// This is a stub; real priorities require a full scheduler.
func Setpriority(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	which := args[0].Int()
	who := kernel.ThreadID(args[1].Int())
	niceval := int(args[2].Int())

	// In the kernel's implementation, values outside the range
	// of [-20, 19] are truncated to these minimum and maximum
	// values.
	if niceval < -20 /* min niceval */ {
		niceval = -20
	} else if niceval > 19 /* max niceval */ {
		niceval = 19
	}

	switch which {
	case linux.PRIO_PROCESS:
		// Look for who, return ESRCH if not found.
		var task *kernel.Task
		if who == 0 {
			task = t
		} else {
			task = t.PIDNamespace().TaskWithID(who)
		}

		if task == nil {
			return 0, nil, syserror.ESRCH
		}

		task.SetNiceness(niceval)
	case linux.PRIO_USER:
		fallthrough
	case linux.PRIO_PGRP:
		// PRIO_USER and PRIO_PGRP have no further implementation yet.
		return 0, nil, nil
	default:
		return 0, nil, syserror.EINVAL
	}

	return 0, nil, nil
}

// Ptrace implements linux system call ptrace(2).
func Ptrace(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	req := args[0].Int64()
	pid := kernel.ThreadID(args[1].Int())
	addr := args[2].Pointer()
	data := args[3].Pointer()

	return 0, nil, t.Ptrace(req, pid, addr, data)
}
