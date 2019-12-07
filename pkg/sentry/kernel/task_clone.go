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
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
)

// SharingOptions controls what resources are shared by a new task created by
// Task.Clone, or an existing task affected by Task.Unshare.
type SharingOptions struct {
	// If NewAddressSpace is true, the task should have an independent virtual
	// address space.
	NewAddressSpace bool

	// If NewSignalHandlers is true, the task should use an independent set of
	// signal handlers.
	NewSignalHandlers bool

	// If NewThreadGroup is true, the task should be the leader of its own
	// thread group. TerminationSignal is the signal that the thread group
	// will send to its parent when it exits. If NewThreadGroup is false,
	// TerminationSignal is ignored.
	NewThreadGroup    bool
	TerminationSignal linux.Signal

	// If NewPIDNamespace is true:
	//
	// - In the context of Task.Clone, the new task should be the init task
	// (TID 1) in a new PID namespace.
	//
	// - In the context of Task.Unshare, the task should create a new PID
	// namespace, and all subsequent clones of the task should be members of
	// the new PID namespace.
	NewPIDNamespace bool

	// If NewUserNamespace is true, the task should have an independent user
	// namespace.
	NewUserNamespace bool

	// If NewNetworkNamespace is true, the task should have an independent
	// network namespace. (Note that network namespaces are not really
	// implemented; see comment on Task.netns for details.)
	NewNetworkNamespace bool

	// If NewFiles is true, the task should use an independent file descriptor
	// table.
	NewFiles bool

	// If NewFSContext is true, the task should have an independent FSContext.
	NewFSContext bool

	// If NewUTSNamespace is true, the task should have an independent UTS
	// namespace.
	NewUTSNamespace bool

	// If NewIPCNamespace is true, the task should have an independent IPC
	// namespace.
	NewIPCNamespace bool
}

// CloneOptions controls the behavior of Task.Clone.
type CloneOptions struct {
	// SharingOptions defines the set of resources that the new task will share
	// with its parent.
	SharingOptions

	// Stack is the initial stack pointer of the new task. If Stack is 0, the
	// new task will start with the same stack pointer as its parent.
	Stack usermem.Addr

	// If SetTLS is true, set the new task's TLS (thread-local storage)
	// descriptor to TLS. If SetTLS is false, TLS is ignored.
	SetTLS bool
	TLS    usermem.Addr

	// If ChildClearTID is true, when the child exits, 0 is written to the
	// address ChildTID in the child's memory, and if the write is successful a
	// futex wake on the same address is performed.
	//
	// If ChildSetTID is true, the child's thread ID (in the child's PID
	// namespace) is written to address ChildTID in the child's memory. (As in
	// Linux, failed writes are silently ignored.)
	ChildClearTID bool
	ChildSetTID   bool
	ChildTID      usermem.Addr

	// If ParentSetTID is true, the child's thread ID (in the parent's PID
	// namespace) is written to address ParentTID in the parent's memory. (As
	// in Linux, failed writes are silently ignored.)
	//
	// Older versions of the clone(2) man page state that CLONE_PARENT_SETTID
	// causes the child's thread ID to be written to ptid in both the parent
	// and child's memory, but this is a documentation error fixed by
	// 87ab04792ced ("clone.2: Fix description of CLONE_PARENT_SETTID").
	ParentSetTID bool
	ParentTID    usermem.Addr

	// If Vfork is true, place the parent in vforkStop until the cloned task
	// releases its TaskContext.
	Vfork bool

	// If Untraced is true, do not report PTRACE_EVENT_CLONE/FORK/VFORK for
	// this clone(), and do not ptrace-attach the caller's tracer to the new
	// task. (PTRACE_EVENT_VFORK_DONE will still be reported if appropriate).
	Untraced bool

	// If InheritTracer is true, ptrace-attach the caller's tracer to the new
	// task, even if no PTRACE_EVENT_CLONE/FORK/VFORK event would be reported
	// for it. If both Untraced and InheritTracer are true, no event will be
	// reported, but tracer inheritance will still occur.
	InheritTracer bool
}

// Clone implements the clone(2) syscall and returns the thread ID of the new
// task in t's PID namespace. Clone may return both a non-zero thread ID and a
// non-nil error.
//
// Preconditions: The caller must be running Task.doSyscallInvoke on the task
// goroutine.
func (t *Task) Clone(opts *CloneOptions) (ThreadID, *SyscallControl, error) {
	// Since signal actions may refer to application signal handlers by virtual
	// address, any set of signal handlers must refer to the same address
	// space.
	if !opts.NewSignalHandlers && opts.NewAddressSpace {
		return 0, nil, syserror.EINVAL
	}
	// In order for the behavior of thread-group-directed signals to be sane,
	// all tasks in a thread group must share signal handlers.
	if !opts.NewThreadGroup && opts.NewSignalHandlers {
		return 0, nil, syserror.EINVAL
	}
	// All tasks in a thread group must be in the same PID namespace.
	if !opts.NewThreadGroup && (opts.NewPIDNamespace || t.childPIDNamespace != nil) {
		return 0, nil, syserror.EINVAL
	}
	// The two different ways of specifying a new PID namespace are
	// incompatible.
	if opts.NewPIDNamespace && t.childPIDNamespace != nil {
		return 0, nil, syserror.EINVAL
	}
	// Thread groups and FS contexts cannot span user namespaces.
	if opts.NewUserNamespace && (!opts.NewThreadGroup || !opts.NewFSContext) {
		return 0, nil, syserror.EINVAL
	}

	// "If CLONE_NEWUSER is specified along with other CLONE_NEW* flags in a
	// single clone(2) or unshare(2) call, the user namespace is guaranteed to
	// be created first, giving the child (clone(2)) or caller (unshare(2))
	// privileges over the remaining namespaces created by the call." -
	// user_namespaces(7)
	creds := t.Credentials()
	userns := creds.UserNamespace
	if opts.NewUserNamespace {
		var err error
		// "EPERM (since Linux 3.9): CLONE_NEWUSER was specified in flags and
		// the caller is in a chroot environment (i.e., the caller's root
		// directory does not match the root directory of the mount namespace
		// in which it resides)." - clone(2). Neither chroot(2) nor
		// user_namespaces(7) document this.
		if t.IsChrooted() {
			return 0, nil, syserror.EPERM
		}
		userns, err = creds.NewChildUserNamespace()
		if err != nil {
			return 0, nil, err
		}
	}
	if (opts.NewPIDNamespace || opts.NewNetworkNamespace || opts.NewUTSNamespace) && !creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, userns) {
		return 0, nil, syserror.EPERM
	}

	utsns := t.UTSNamespace()
	if opts.NewUTSNamespace {
		// Note that this must happen after NewUserNamespace so we get
		// the new userns if there is one.
		utsns = t.UTSNamespace().Clone(userns)
	}

	ipcns := t.IPCNamespace()
	if opts.NewIPCNamespace {
		// Note that "If CLONE_NEWIPC is set, then create the process in a new IPC
		// namespace"
		ipcns = NewIPCNamespace(userns)
	}

	tc, err := t.tc.Fork(t, t.k, !opts.NewAddressSpace)
	if err != nil {
		return 0, nil, err
	}
	// clone() returns 0 in the child.
	tc.Arch.SetReturn(0)
	if opts.Stack != 0 {
		tc.Arch.SetStack(uintptr(opts.Stack))
	}
	if opts.SetTLS {
		if !tc.Arch.SetTLS(uintptr(opts.TLS)) {
			return 0, nil, syserror.EPERM
		}
	}

	var fsContext *FSContext
	if opts.NewFSContext {
		fsContext = t.fsContext.Fork()
	} else {
		fsContext = t.fsContext
		fsContext.IncRef()
	}

	var fdTable *FDTable
	if opts.NewFiles {
		fdTable = t.fdTable.Fork()
	} else {
		fdTable = t.fdTable
		fdTable.IncRef()
	}

	pidns := t.tg.pidns
	if t.childPIDNamespace != nil {
		pidns = t.childPIDNamespace
	} else if opts.NewPIDNamespace {
		pidns = pidns.NewChild(userns)
	}
	tg := t.tg
	if opts.NewThreadGroup {
		tg.mounts.IncRef()
		sh := t.tg.signalHandlers
		if opts.NewSignalHandlers {
			sh = sh.Fork()
		}
		tg = t.k.newThreadGroup(tg.mounts, pidns, sh, opts.TerminationSignal, tg.limits.GetCopy(), t.k.monotonicClock)
	}

	cfg := &TaskConfig{
		Kernel:                  t.k,
		ThreadGroup:             tg,
		SignalMask:              t.SignalMask(),
		TaskContext:             tc,
		FSContext:               fsContext,
		FDTable:                 fdTable,
		Credentials:             creds,
		Niceness:                t.Niceness(),
		NetworkNamespaced:       t.netns,
		AllowedCPUMask:          t.CPUMask(),
		UTSNamespace:            utsns,
		IPCNamespace:            ipcns,
		AbstractSocketNamespace: t.abstractSockets,
		ContainerID:             t.ContainerID(),
	}
	if opts.NewThreadGroup {
		cfg.Parent = t
	} else {
		cfg.InheritParent = t
	}
	if opts.NewNetworkNamespace {
		cfg.NetworkNamespaced = true
	}
	nt, err := t.tg.pidns.owner.NewTask(cfg)
	if err != nil {
		if opts.NewThreadGroup {
			tg.release()
		}
		return 0, nil, err
	}

	// "A child process created via fork(2) inherits a copy of its parent's
	// alternate signal stack settings" - sigaltstack(2).
	//
	// However kernel/fork.c:copy_process() adds a limitation to this:
	// "sigaltstack should be cleared when sharing the same VM".
	if opts.NewAddressSpace || opts.Vfork {
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
	t.traceCloneEvent(tid)

	// "If fork/clone and execve are allowed by @prog, any child processes will
	// be constrained to the same filters and system call ABI as the parent." -
	// Documentation/prctl/seccomp_filter.txt
	if f := t.syscallFilters.Load(); f != nil {
		copiedFilters := append([]bpf.Program(nil), f.([]bpf.Program)...)
		nt.syscallFilters.Store(copiedFilters)
	}
	if opts.Vfork {
		nt.vforkParent = t
	}

	if opts.ChildClearTID {
		nt.SetClearTID(opts.ChildTID)
	}
	if opts.ChildSetTID {
		// Can't use Task.CopyOut, which assumes AddressSpaceActive.
		usermem.CopyObjectOut(t, nt.MemoryManager(), opts.ChildTID, nt.ThreadID(), usermem.IOOpts{})
	}
	ntid := t.tg.pidns.IDOfTask(nt)
	if opts.ParentSetTID {
		t.CopyOut(opts.ParentTID, ntid)
	}

	kind := ptraceCloneKindClone
	if opts.Vfork {
		kind = ptraceCloneKindVfork
	} else if opts.TerminationSignal == linux.SIGCHLD {
		kind = ptraceCloneKindFork
	}
	if t.ptraceClone(kind, nt, opts) {
		if opts.Vfork {
			return ntid, &SyscallControl{next: &runSyscallAfterPtraceEventClone{vforkChild: nt, vforkChildTID: ntid}}, nil
		}
		return ntid, &SyscallControl{next: &runSyscallAfterPtraceEventClone{}}, nil
	}
	if opts.Vfork {
		t.maybeBeginVforkStop(nt)
		return ntid, &SyscallControl{next: &runSyscallAfterVforkStop{childTID: ntid}}, nil
	}
	return ntid, nil, nil
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

// Unshare changes the set of resources t shares with other tasks, as specified
// by opts.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) Unshare(opts *SharingOptions) error {
	// In Linux unshare(2), NewThreadGroup implies NewSignalHandlers and
	// NewSignalHandlers implies NewAddressSpace. All three flags are no-ops if
	// t is the only task using its MM, which due to clone(2)'s rules imply
	// that it is also the only task using its signal handlers / in its thread
	// group, and cause EINVAL to be returned otherwise.
	//
	// Since we don't count the number of tasks using each address space or set
	// of signal handlers, we reject NewSignalHandlers and NewAddressSpace
	// altogether, and interpret NewThreadGroup as requiring that t be the only
	// member of its thread group. This seems to be logically coherent, in the
	// sense that clone(2) allows a task to share signal handlers and address
	// spaces with tasks in other thread groups.
	if opts.NewAddressSpace || opts.NewSignalHandlers {
		return syserror.EINVAL
	}
	creds := t.Credentials()
	if opts.NewThreadGroup {
		t.tg.signalHandlers.mu.Lock()
		if t.tg.tasksCount != 1 {
			t.tg.signalHandlers.mu.Unlock()
			return syserror.EINVAL
		}
		t.tg.signalHandlers.mu.Unlock()
		// This isn't racy because we're the only living task, and therefore
		// the only task capable of creating new ones, in our thread group.
	}
	if opts.NewUserNamespace {
		if t.IsChrooted() {
			return syserror.EPERM
		}
		newUserNS, err := creds.NewChildUserNamespace()
		if err != nil {
			return err
		}
		err = t.SetUserNamespace(newUserNS)
		if err != nil {
			return err
		}
		// Need to reload creds, becaue t.SetUserNamespace() changed task credentials.
		creds = t.Credentials()
	}
	haveCapSysAdmin := t.HasCapability(linux.CAP_SYS_ADMIN)
	if opts.NewPIDNamespace {
		if !haveCapSysAdmin {
			return syserror.EPERM
		}
		t.childPIDNamespace = t.tg.pidns.NewChild(t.UserNamespace())
	}
	t.mu.Lock()
	// Can't defer unlock: DecRefs must occur without holding t.mu.
	if opts.NewNetworkNamespace {
		if !haveCapSysAdmin {
			t.mu.Unlock()
			return syserror.EPERM
		}
		t.netns = true
	}
	if opts.NewUTSNamespace {
		if !haveCapSysAdmin {
			t.mu.Unlock()
			return syserror.EPERM
		}
		// Note that this must happen after NewUserNamespace, so the
		// new user namespace is used if there is one.
		t.utsns = t.utsns.Clone(creds.UserNamespace)
	}
	if opts.NewIPCNamespace {
		if !haveCapSysAdmin {
			t.mu.Unlock()
			return syserror.EPERM
		}
		// Note that "If CLONE_NEWIPC is set, then create the process in a new IPC
		// namespace"
		t.ipcns = NewIPCNamespace(creds.UserNamespace)
	}
	var oldFDTable *FDTable
	if opts.NewFiles {
		oldFDTable = t.fdTable
		t.fdTable = oldFDTable.Fork()
	}
	var oldFSContext *FSContext
	if opts.NewFSContext {
		oldFSContext = t.fsContext
		t.fsContext = oldFSContext.Fork()
	}
	t.mu.Unlock()
	if oldFDTable != nil {
		oldFDTable.DecRef()
	}
	if oldFSContext != nil {
		oldFSContext.DecRef()
	}
	return nil
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
