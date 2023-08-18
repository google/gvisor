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

package kernel

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/nsfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Clone implements the clone(2) syscall and returns the thread ID of the new
// task in t's PID namespace. Clone may return both a non-zero thread ID and a
// non-nil error.
//
// Preconditions: The caller must be running Task.doSyscallInvoke on the task
// goroutine.
func (t *Task) Clone(args *linux.CloneArgs) (ThreadID, *SyscallControl, error) {
	// Since signal actions may refer to application signal handlers by virtual
	// address, any set of signal handlers must refer to the same address
	// space.
	if args.Flags&(linux.CLONE_SIGHAND|linux.CLONE_VM) == linux.CLONE_SIGHAND {
		return 0, nil, linuxerr.EINVAL
	}
	// In order for the behavior of thread-group-directed signals to be sane,
	// all tasks in a thread group must share signal handlers.
	if args.Flags&(linux.CLONE_THREAD|linux.CLONE_SIGHAND) == linux.CLONE_THREAD {
		return 0, nil, linuxerr.EINVAL
	}
	// All tasks in a thread group must be in the same PID namespace.
	if (args.Flags&linux.CLONE_THREAD != 0) && (args.Flags&linux.CLONE_NEWPID != 0 || t.childPIDNamespace != nil) {
		return 0, nil, linuxerr.EINVAL
	}
	// The two different ways of specifying a new PID namespace are
	// incompatible.
	if args.Flags&linux.CLONE_NEWPID != 0 && t.childPIDNamespace != nil {
		return 0, nil, linuxerr.EINVAL
	}
	// Thread groups and FS contexts cannot span user namespaces.
	if args.Flags&linux.CLONE_NEWUSER != 0 && args.Flags&(linux.CLONE_THREAD|linux.CLONE_FS) != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	// args.ExitSignal must be a valid signal.
	if args.ExitSignal != 0 && !linux.Signal(args.ExitSignal).IsValid() {
		return 0, nil, linuxerr.EINVAL
	}
	if args.Flags&(linux.CLONE_FS|linux.CLONE_NEWNS) == linux.CLONE_FS|linux.CLONE_NEWNS {
		return 0, nil, linuxerr.EINVAL
	}

	// Pull task registers and FPU state, a cloned task will inherit the
	// state of the current task.
	if err := t.p.PullFullState(t.MemoryManager().AddressSpace(), t.Arch()); err != nil {
		t.Warningf("Unable to pull a full state: %v", err)
		t.forceSignal(linux.SIGILL, true /* unconditional */)
		t.SendSignal(SignalInfoPriv(linux.SIGILL))
		return 0, nil, linuxerr.EFAULT
	}

	// "If CLONE_NEWUSER is specified along with other CLONE_NEW* flags in a
	// single clone(2) or unshare(2) call, the user namespace is guaranteed to
	// be created first, giving the child (clone(2)) or caller (unshare(2))
	// privileges over the remaining namespaces created by the call." -
	// user_namespaces(7)
	creds := t.Credentials()
	userns := creds.UserNamespace
	if args.Flags&linux.CLONE_NEWUSER != 0 {
		var err error
		// "EPERM (since Linux 3.9): CLONE_NEWUSER was specified in flags and
		// the caller is in a chroot environment (i.e., the caller's root
		// directory does not match the root directory of the mount namespace
		// in which it resides)." - clone(2). Neither chroot(2) nor
		// user_namespaces(7) document this.
		if t.IsChrooted() {
			return 0, nil, linuxerr.EPERM
		}
		userns, err = creds.NewChildUserNamespace()
		if err != nil {
			return 0, nil, err
		}
	}
	if args.Flags&(linux.CLONE_NEWPID|linux.CLONE_NEWNET|linux.CLONE_NEWUTS|linux.CLONE_NEWIPC) != 0 && !creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, userns) {
		return 0, nil, linuxerr.EPERM
	}

	cu := cleanup.Make(func() {})
	defer cu.Clean()

	utsns := t.utsns
	if args.Flags&linux.CLONE_NEWUTS != 0 {
		// Note that this must happen after NewUserNamespace so we get
		// the new userns if there is one.
		utsns = utsns.Clone(userns)
		utsns.SetInode(nsfs.NewInode(t, t.k.nsfsMount, utsns))
	} else {
		utsns.IncRef()
	}
	cu.Add(func() {
		utsns.DecRef(t)
	})

	ipcns := t.ipcns
	if args.Flags&linux.CLONE_NEWIPC != 0 {
		ipcns = NewIPCNamespace(userns)
		ipcns.InitPosixQueues(t, t.k.VFS(), creds)
		ipcns.SetInode(nsfs.NewInode(t, t.k.nsfsMount, ipcns))
	} else {
		ipcns.IncRef()
	}
	cu.Add(func() {
		ipcns.DecRef(t)
	})

	netns := t.netns
	if args.Flags&linux.CLONE_NEWNET != 0 {
		netns = inet.NewNamespace(netns, userns)
		inode := nsfs.NewInode(t, t.k.nsfsMount, netns)
		netns.SetInode(inode)
	} else {
		netns.IncRef()
	}
	cu.Add(func() {
		netns.DecRef(t)
	})

	// We must hold t.mu to access t.image, but we can't hold it during Fork(),
	// since TaskImage.Fork()=>mm.Fork() takes mm.addressSpaceMu, which is ordered
	// above Task.mu. So we copy t.image with t.mu held and call Fork() on the copy.
	t.mu.Lock()
	curImage := t.image
	t.mu.Unlock()
	image, err := curImage.Fork(t, t.k, args.Flags&linux.CLONE_VM != 0)
	if err != nil {
		return 0, nil, err
	}
	cu.Add(func() {
		image.release(t)
	})
	// clone() returns 0 in the child.
	image.Arch.SetReturn(0)
	if args.Stack != 0 {
		image.Arch.SetStack(uintptr(args.Stack))
	}
	if args.Flags&linux.CLONE_SETTLS != 0 {
		if !image.Arch.SetTLS(uintptr(args.TLS)) {
			return 0, nil, linuxerr.EPERM
		}
	}

	var fsContext *FSContext
	if args.Flags&linux.CLONE_FS == 0 || args.Flags&linux.CLONE_NEWNS != 0 {
		fsContext = t.fsContext.Fork()
	} else {
		fsContext = t.fsContext
		fsContext.IncRef()
	}

	mntns := t.mountNamespace
	if args.Flags&linux.CLONE_NEWNS != 0 {
		var err error
		mntns, err = t.k.vfs.CloneMountNamespace(t, creds, mntns, &fsContext.root, &fsContext.cwd, t.k)
		if err != nil {
			return 0, nil, err
		}
	} else {
		mntns.IncRef()
	}
	cu.Add(func() {
		mntns.DecRef(t)
	})

	var fdTable *FDTable
	if args.Flags&linux.CLONE_FILES == 0 {
		fdTable = t.fdTable.Fork(t, MaxFdLimit)
	} else {
		fdTable = t.fdTable
		fdTable.IncRef()
	}

	pidns := t.tg.pidns
	if t.childPIDNamespace != nil {
		pidns = t.childPIDNamespace
	} else if args.Flags&linux.CLONE_NEWPID != 0 {
		pidns = pidns.NewChild(userns)
	}

	tg := t.tg
	rseqAddr := hostarch.Addr(0)
	rseqSignature := uint32(0)
	if args.Flags&linux.CLONE_THREAD == 0 {
		sh := t.tg.signalHandlers
		if args.Flags&linux.CLONE_SIGHAND == 0 {
			sh = sh.Fork()
		}
		tg = t.k.NewThreadGroup(pidns, sh, linux.Signal(args.ExitSignal), tg.limits.GetCopy())
		tg.oomScoreAdj = atomicbitops.FromInt32(t.tg.oomScoreAdj.Load())
		rseqAddr = t.rseqAddr
		rseqSignature = t.rseqSignature
	}

	uc := t.userCounters
	if uc.uid != creds.RealKUID {
		uc = t.k.GetUserCounters(creds.RealKUID)
	}

	cfg := &TaskConfig{
		Kernel:                  t.k,
		ThreadGroup:             tg,
		SignalMask:              t.SignalMask(),
		TaskImage:               image,
		FSContext:               fsContext,
		FDTable:                 fdTable,
		Credentials:             creds,
		Niceness:                t.Niceness(),
		NetworkNamespace:        netns,
		AllowedCPUMask:          t.CPUMask(),
		UTSNamespace:            utsns,
		IPCNamespace:            ipcns,
		AbstractSocketNamespace: t.abstractSockets,
		MountNamespace:          mntns,
		RSeqAddr:                rseqAddr,
		RSeqSignature:           rseqSignature,
		ContainerID:             t.ContainerID(),
		UserCounters:            uc,
	}
	if args.Flags&linux.CLONE_THREAD == 0 {
		cfg.Parent = t
	} else {
		cfg.InheritParent = t
	}
	nt, err := t.tg.pidns.owner.NewTask(t, cfg)
	// If NewTask succeeds, we transfer references to nt. If NewTask fails, it does
	// the cleanup for us.
	cu.Release()
	if err != nil {
		return 0, nil, err
	}

	// "A child process created via fork(2) inherits a copy of its parent's
	// alternate signal stack settings" - sigaltstack(2).
	//
	// However kernel/fork.c:copy_process() adds a limitation to this:
	// "sigaltstack should be cleared when sharing the same VM".
	if args.Flags&linux.CLONE_VM == 0 || args.Flags&linux.CLONE_VFORK != 0 {
		nt.SetSignalStack(t.SignalStack())
	}

	if userns != creds.UserNamespace {
		if err := nt.SetUserNamespace(userns); err != nil {
			// This shouldn't be possible: userns was created from nt.creds, so
			// nt should have CAP_SYS_ADMIN in userns.
			panic("Task.Clone: SetUserNamespace failed: " + err.Error())
		}
	}

	// This has to happen last, because e.g. ptraceClone may send a SIGSTOP to
	// nt that it must receive before its task goroutine starts running.
	tid := nt.k.tasks.Root.IDOfTask(nt)
	defer nt.Start(tid)

	if seccheck.Global.Enabled(seccheck.PointClone) {
		mask, info := getCloneSeccheckInfo(t, nt, args.Flags)
		if err := seccheck.Global.SentToSinks(func(c seccheck.Sink) error {
			return c.Clone(t, mask, info)
		}); err != nil {
			// nt has been visible to the rest of the system since NewTask, so
			// it may be blocking execve or a group stop, have been notified
			// for group signal delivery, had children reparented to it, etc.
			// Thus we can't just drop it on the floor. Instead, instruct the
			// task goroutine to exit immediately, as quietly as possible.
			nt.exitTracerNotified = true
			nt.exitTracerAcked = true
			nt.exitParentNotified = true
			nt.exitParentAcked = true
			nt.runState = (*runExitMain)(nil)
			return 0, nil, err
		}
	}

	// "If fork/clone and execve are allowed by @prog, any child processes will
	// be constrained to the same filters and system call ABI as the parent." -
	// Documentation/prctl/seccomp_filter.txt
	if f := t.syscallFilters.Load(); f != nil {
		copiedFilters := append([]bpf.Program(nil), f.([]bpf.Program)...)
		nt.syscallFilters.Store(copiedFilters)
	}
	if args.Flags&linux.CLONE_VFORK != 0 {
		nt.vforkParent = t
	}

	if args.Flags&linux.CLONE_CHILD_CLEARTID != 0 {
		nt.SetClearTID(hostarch.Addr(args.ChildTID))
	}
	if args.Flags&linux.CLONE_CHILD_SETTID != 0 {
		ctid := nt.ThreadID()
		ctid.CopyOut(nt.CopyContext(t, usermem.IOOpts{AddressSpaceActive: false}), hostarch.Addr(args.ChildTID))
	}
	ntid := t.tg.pidns.IDOfTask(nt)
	if args.Flags&linux.CLONE_PARENT_SETTID != 0 {
		ntid.CopyOut(t, hostarch.Addr(args.ParentTID))
	}

	t.traceCloneEvent(tid)
	kind := ptraceCloneKindClone
	if args.Flags&linux.CLONE_VFORK != 0 {
		kind = ptraceCloneKindVfork
	} else if linux.Signal(args.ExitSignal) == linux.SIGCHLD {
		kind = ptraceCloneKindFork
	}
	if t.ptraceClone(kind, nt, args) {
		if args.Flags&linux.CLONE_VFORK != 0 {
			return ntid, &SyscallControl{next: &runSyscallAfterPtraceEventClone{vforkChild: nt, vforkChildTID: ntid}}, nil
		}
		return ntid, &SyscallControl{next: &runSyscallAfterPtraceEventClone{}}, nil
	}
	if args.Flags&linux.CLONE_VFORK != 0 {
		t.maybeBeginVforkStop(nt)
		return ntid, &SyscallControl{next: &runSyscallAfterVforkStop{childTID: ntid}}, nil
	}
	return ntid, nil, nil
}

func getCloneSeccheckInfo(t, nt *Task, flags uint64) (seccheck.FieldSet, *pb.CloneInfo) {
	fields := seccheck.Global.GetFieldSet(seccheck.PointClone)
	var cwd string
	if fields.Context.Contains(seccheck.FieldCtxtCwd) {
		cwd = getTaskCurrentWorkingDirectory(t)
	}
	t.k.tasks.mu.RLock()
	defer t.k.tasks.mu.RUnlock()
	info := &pb.CloneInfo{
		CreatedThreadId:          int32(nt.k.tasks.Root.tids[nt]),
		CreatedThreadGroupId:     int32(nt.k.tasks.Root.tgids[nt.tg]),
		CreatedThreadStartTimeNs: nt.startTime.Nanoseconds(),
		Flags:                    flags,
	}

	if !fields.Context.Empty() {
		info.ContextData = &pb.ContextData{}
		LoadSeccheckDataLocked(t, fields.Context, info.ContextData, cwd)
	}

	return fields, info
}

// maybeBeginVforkStop checks if a previously-started vfork child is still
// running and has not yet released its MM, such that its parent t should enter
// a vforkStop.
//
// Preconditions: The caller must be running on t's task goroutine.
func (t *Task) maybeBeginVforkStop(child *Task) {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	if t.killedLocked() {
		child.vforkParent = nil
		return
	}
	if child.vforkParent == t {
		t.beginInternalStopLocked((*vforkStop)(nil))
	}
}

func (t *Task) unstopVforkParent() {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	if p := t.vforkParent; p != nil {
		p.tg.signalHandlers.mu.Lock()
		defer p.tg.signalHandlers.mu.Unlock()
		if _, ok := p.stop.(*vforkStop); ok {
			p.endInternalStopLocked()
		}
		// Parent no longer needs to be unstopped.
		t.vforkParent = nil
	}
}

// +stateify savable
type runSyscallAfterPtraceEventClone struct {
	vforkChild *Task

	// If vforkChild is not nil, vforkChildTID is its thread ID in the parent's
	// PID namespace. vforkChildTID must be stored since the child may exit and
	// release its TID before the PTRACE_EVENT stop ends.
	vforkChildTID ThreadID
}

func (r *runSyscallAfterPtraceEventClone) execute(t *Task) taskRunState {
	if r.vforkChild != nil {
		t.maybeBeginVforkStop(r.vforkChild)
		return &runSyscallAfterVforkStop{r.vforkChildTID}
	}
	return (*runSyscallExit)(nil)
}

// +stateify savable
type runSyscallAfterVforkStop struct {
	// childTID has the same meaning as
	// runSyscallAfterPtraceEventClone.vforkChildTID.
	childTID ThreadID
}

func (r *runSyscallAfterVforkStop) execute(t *Task) taskRunState {
	t.ptraceVforkDone(r.childTID)
	return (*runSyscallExit)(nil)
}

// Setns reassociates thread with the specified namespace.
func (t *Task) Setns(fd *vfs.FileDescription, flags int32) error {
	d, ok := fd.Dentry().Impl().(*kernfs.Dentry)
	if !ok {
		return linuxerr.EINVAL
	}
	i, ok := d.Inode().(*nsfs.Inode)
	if !ok {
		return linuxerr.EINVAL
	}

	switch ns := i.Namespace().(type) {
	case *inet.Namespace:
		if flags != 0 && flags != linux.CLONE_NEWNET {
			return linuxerr.EINVAL
		}
		if !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, ns.UserNamespace()) ||
			!t.Credentials().HasCapability(linux.CAP_SYS_ADMIN) {
			return linuxerr.EPERM
		}
		oldNS := t.NetworkNamespace()
		ns.IncRef()
		t.mu.Lock()
		t.netns = ns
		t.mu.Unlock()
		oldNS.DecRef(t)
		return nil
	case *IPCNamespace:
		if flags != 0 && flags != linux.CLONE_NEWIPC {
			return linuxerr.EINVAL
		}
		if !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, ns.UserNamespace()) ||
			!t.Credentials().HasCapability(linux.CAP_SYS_ADMIN) {
			return linuxerr.EPERM
		}
		oldNS := t.IPCNamespace()
		ns.IncRef()
		t.mu.Lock()
		t.ipcns = ns
		t.mu.Unlock()
		oldNS.DecRef(t)
		return nil
	case *vfs.MountNamespace:
		if flags != 0 && flags != linux.CLONE_NEWNS {
			return linuxerr.EINVAL
		}
		if !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, ns.Owner) ||
			!t.Credentials().HasCapability(linux.CAP_SYS_CHROOT) ||
			!t.Credentials().HasCapability(linux.CAP_SYS_ADMIN) {
			return linuxerr.EPERM
		}
		oldFSContext := t.fsContext
		// The current task has to be an exclusive owner of its fs context.
		if oldFSContext.ReadRefs() != 1 {
			return linuxerr.EINVAL
		}
		fsContext := oldFSContext.Fork()
		fsContext.root.DecRef(t)
		fsContext.cwd.DecRef(t)
		vd := ns.Root(t)
		fsContext.root = vd
		vd.IncRef()
		fsContext.cwd = vd

		oldNS := t.mountNamespace
		ns.IncRef()
		t.mu.Lock()
		t.mountNamespace = ns
		t.fsContext = fsContext
		t.mu.Unlock()
		oldNS.DecRef(t)
		oldFSContext.DecRef(t)
		return nil
	case *UTSNamespace:
		if flags != 0 && flags != linux.CLONE_NEWUTS {
			return linuxerr.EINVAL
		}
		if !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, ns.UserNamespace()) ||
			!t.Credentials().HasCapability(linux.CAP_SYS_ADMIN) {
			return linuxerr.EPERM
		}
		oldNS := t.UTSNamespace()
		ns.IncRef()
		t.mu.Lock()
		t.utsns = ns
		t.mu.Unlock()
		oldNS.DecRef(t)
		return nil
	default:
		return linuxerr.EINVAL
	}
}

// Unshare changes the set of resources t shares with other tasks, as specified
// by flags.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) Unshare(flags int32) error {
	// "CLONE_THREAD, CLONE_SIGHAND, and CLONE_VM can be specified in flags if
	// the caller is single threaded (i.e., it is not sharing its address space
	// with another process or thread). In this case, these flags have no
	// effect. (Note also that specifying CLONE_THREAD automatically implies
	// CLONE_VM, and specifying CLONE_VM automatically implies CLONE_SIGHAND.)
	// If the process is multithreaded, then the use of these flags results in
	// an error." - unshare(2). This is incorrect (cf.
	// kernel/fork.c:ksys_unshare()):
	//
	//	- CLONE_THREAD does not imply CLONE_VM.
	//
	//	- CLONE_SIGHAND implies CLONE_THREAD.
	//
	//	- Only CLONE_VM requires that the caller is not sharing its address
	//		space with another thread. CLONE_SIGHAND requires that the caller is not
	//		sharing its signal handlers, and CLONE_THREAD requires that the caller
	//		is the only thread in its thread group.
	//
	// Since we don't count the number of tasks using each address space or set
	// of signal handlers, we reject CLONE_VM and CLONE_SIGHAND altogether.
	if flags&(linux.CLONE_VM|linux.CLONE_SIGHAND) != 0 {
		return linuxerr.EINVAL
	}
	creds := t.Credentials()
	if flags&linux.CLONE_THREAD != 0 {
		t.tg.signalHandlers.mu.Lock()
		if t.tg.tasksCount != 1 {
			t.tg.signalHandlers.mu.Unlock()
			return linuxerr.EINVAL
		}
		t.tg.signalHandlers.mu.Unlock()
		// This isn't racy because we're the only living task, and therefore
		// the only task capable of creating new ones, in our thread group.
	}
	if flags&linux.CLONE_NEWUSER != 0 {
		if t.IsChrooted() {
			return linuxerr.EPERM
		}
		newUserNS, err := creds.NewChildUserNamespace()
		if err != nil {
			return err
		}
		err = t.SetUserNamespace(newUserNS)
		if err != nil {
			return err
		}
		// Need to reload creds, because t.SetUserNamespace() changed task credentials.
		creds = t.Credentials()
	}
	haveCapSysAdmin := t.HasCapability(linux.CAP_SYS_ADMIN)
	if flags&linux.CLONE_NEWPID != 0 {
		if !haveCapSysAdmin {
			return linuxerr.EPERM
		}
		t.childPIDNamespace = t.tg.pidns.NewChild(t.UserNamespace())
	}
	if flags&linux.CLONE_NEWNET != 0 {
		if !haveCapSysAdmin {
			return linuxerr.EPERM
		}
		netns := t.NetworkNamespace()
		netns = inet.NewNamespace(netns, t.UserNamespace())
		netnsInode := nsfs.NewInode(t, t.k.nsfsMount, netns)
		netns.SetInode(netnsInode)
		t.mu.Lock()
		oldNetns := t.netns
		t.netns = netns
		t.mu.Unlock()
		oldNetns.DecRef(t)
	}

	cu := cleanup.Cleanup{}
	// All cu actions has to be executed after releasing t.mu.
	defer cu.Clean()
	t.mu.Lock()
	defer t.mu.Unlock()
	// Can't defer unlock: DecRefs must occur without holding t.mu.
	if flags&linux.CLONE_NEWUTS != 0 {
		if !haveCapSysAdmin {
			return linuxerr.EPERM
		}
		// Note that this must happen after NewUserNamespace, so the
		// new user namespace is used if there is one.
		oldUTSNS := t.utsns
		t.utsns = t.utsns.Clone(creds.UserNamespace)
		t.utsns.SetInode(nsfs.NewInode(t, t.k.nsfsMount, t.utsns))
		cu.Add(func() { oldUTSNS.DecRef(t) })
	}
	if flags&linux.CLONE_NEWIPC != 0 {
		if !haveCapSysAdmin {
			return linuxerr.EPERM
		}
		// Note that "If CLONE_NEWIPC is set, then create the process in a new IPC
		// namespace"
		oldIPCNS := t.ipcns
		t.ipcns = NewIPCNamespace(creds.UserNamespace)
		t.ipcns.InitPosixQueues(t, t.k.VFS(), creds)
		t.ipcns.SetInode(nsfs.NewInode(t, t.k.nsfsMount, t.ipcns))
		cu.Add(func() { oldIPCNS.DecRef(t) })
	}
	if flags&linux.CLONE_FILES != 0 {
		oldFDTable := t.fdTable
		t.fdTable = oldFDTable.Fork(t, MaxFdLimit)
		cu.Add(func() { oldFDTable.DecRef(t) })
	}
	if flags&linux.CLONE_FS != 0 || flags&linux.CLONE_NEWNS != 0 {
		oldFSContext := t.fsContext
		t.fsContext = oldFSContext.Fork()
		cu.Add(func() { oldFSContext.DecRef(t) })
	}
	if flags&linux.CLONE_NEWNS != 0 {
		if !haveCapSysAdmin {
			return linuxerr.EPERM
		}
		oldMountNS := t.mountNamespace
		mntns, err := t.k.vfs.CloneMountNamespace(t, creds, oldMountNS, &t.fsContext.root, &t.fsContext.cwd, t.k)
		if err != nil {
			return err
		}
		t.mountNamespace = mntns
		cu.Add(func() { oldMountNS.DecRef(t) })
	}
	return nil
}

// UnshareFdTable unshares the FdTable that task t shares with other tasks, upto
// the maxFd.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) UnshareFdTable(maxFd int32) {
	t.mu.Lock()
	oldFDTable := t.fdTable
	t.fdTable = oldFDTable.Fork(t, maxFd)
	t.mu.Unlock()

	oldFDTable.DecRef(t)
}

// vforkStop is a TaskStop imposed on a task that creates a child with
// CLONE_VFORK or vfork(2), that ends when the child task ceases to use its
// current MM. (Normally, CLONE_VFORK is used in conjunction with CLONE_VM, so
// that the child and parent share mappings until the child execve()s into a
// new process image or exits.)
//
// +stateify savable
type vforkStop struct{}

// StopIgnoresKill implements TaskStop.Killable.
func (*vforkStop) Killable() bool { return true }
