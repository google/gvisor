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
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/futex"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/unimpl"
	"gvisor.dev/gvisor/pkg/sentry/uniqueid"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syncutil"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Task represents a thread of execution in the untrusted app.  It
// includes registers and any thread-specific state that you would
// normally expect.
//
// Each task is associated with a goroutine, called the task goroutine, that
// executes code (application code, system calls, etc.) on behalf of that task.
// See Task.run (task_run.go).
//
// All fields that are "owned by the task goroutine" can only be mutated by the
// task goroutine while it is running. The task goroutine does not require
// synchronization to read these fields, although it still requires
// synchronization as described for those fields to mutate them.
//
// All fields that are "exclusive to the task goroutine" can only be accessed
// by the task goroutine while it is running. The task goroutine does not
// require synchronization to read or write these fields.
//
// +stateify savable
type Task struct {
	taskNode

	// runState is what the task goroutine is executing if it is not stopped.
	// If runState is nil, the task goroutine should exit or has exited.
	// runState is exclusive to the task goroutine.
	runState taskRunState

	// haveSyscallReturn is true if tc.Arch().Return() represents a value
	// returned by a syscall (or set by ptrace after a syscall).
	//
	// haveSyscallReturn is exclusive to the task goroutine.
	haveSyscallReturn bool

	// interruptChan is notified whenever the task goroutine is interrupted
	// (usually by a pending signal). interruptChan is effectively a condition
	// variable that can be used in select statements.
	//
	// interruptChan is not saved; because saving interrupts all tasks,
	// interruptChan is always notified after restore (see Task.run).
	interruptChan chan struct{} `state:"nosave"`

	// gosched contains the current scheduling state of the task goroutine.
	//
	// gosched is protected by goschedSeq. gosched is owned by the task
	// goroutine.
	goschedSeq syncutil.SeqCount `state:"nosave"`
	gosched    TaskGoroutineSchedInfo

	// yieldCount is the number of times the task goroutine has called
	// Task.InterruptibleSleepStart, Task.UninterruptibleSleepStart, or
	// Task.Yield(), voluntarily ceasing execution.
	//
	// yieldCount is accessed using atomic memory operations. yieldCount is
	// owned by the task goroutine.
	yieldCount uint64

	// pendingSignals is the set of pending signals that may be handled only by
	// this task.
	//
	// pendingSignals is protected by (taskNode.)tg.signalHandlers.mu
	// (hereafter "the signal mutex"); see comment on
	// ThreadGroup.signalHandlers.
	pendingSignals pendingSignals

	// signalMask is the set of signals whose delivery is currently blocked.
	//
	// signalMask is accessed using atomic memory operations, and is protected
	// by the signal mutex (such that reading signalMask is safe if either the
	// signal mutex is locked or if atomic memory operations are used, while
	// writing signalMask requires both). signalMask is owned by the task
	// goroutine.
	signalMask linux.SignalSet

	// If the task goroutine is currently executing Task.sigtimedwait,
	// realSignalMask is the previous value of signalMask, which has temporarily
	// been replaced by Task.sigtimedwait. Otherwise, realSignalMask is 0.
	//
	// realSignalMask is exclusive to the task goroutine.
	realSignalMask linux.SignalSet

	// If haveSavedSignalMask is true, savedSignalMask is the signal mask that
	// should be applied after the task has either delivered one signal to a
	// user handler or is about to resume execution in the untrusted
	// application.
	//
	// Both haveSavedSignalMask and savedSignalMask are exclusive to the task
	// goroutine.
	haveSavedSignalMask bool
	savedSignalMask     linux.SignalSet

	// signalStack is the alternate signal stack used by signal handlers for
	// which the SA_ONSTACK flag is set.
	//
	// signalStack is exclusive to the task goroutine.
	signalStack arch.SignalStack

	// signalQueue is a set of registered waiters for signal-related events.
	//
	// signalQueue is protected by the signalMutex. Note that the task does
	// not implement all queue methods, specifically the readiness checks.
	// The task only broadcast a notification on signal delivery.
	signalQueue waiter.Queue `state:"zerovalue"`

	// If groupStopPending is true, the task should participate in a group
	// stop in the interrupt path.
	//
	// groupStopPending is analogous to JOBCTL_STOP_PENDING in Linux.
	//
	// groupStopPending is protected by the signal mutex.
	groupStopPending bool

	// If groupStopAcknowledged is true, the task has already acknowledged that
	// it is entering the most recent group stop that has been initiated on its
	// thread group.
	//
	// groupStopAcknowledged is analogous to !JOBCTL_STOP_CONSUME in Linux.
	//
	// groupStopAcknowledged is protected by the signal mutex.
	groupStopAcknowledged bool

	// If trapStopPending is true, the task goroutine should enter a
	// PTRACE_INTERRUPT-induced stop from the interrupt path.
	//
	// trapStopPending is analogous to JOBCTL_TRAP_STOP in Linux, except that
	// Linux also sets JOBCTL_TRAP_STOP when a ptraced task detects
	// JOBCTL_STOP_PENDING.
	//
	// trapStopPending is protected by the signal mutex.
	trapStopPending bool

	// If trapNotifyPending is true, this task is PTRACE_SEIZEd, and a group
	// stop has begun or ended since the last time the task entered a
	// ptrace-stop from the group-stop path.
	//
	// trapNotifyPending is analogous to JOBCTL_TRAP_NOTIFY in Linux.
	//
	// trapNotifyPending is protected by the signal mutex.
	trapNotifyPending bool

	// If stop is not nil, it is the internally-initiated condition that
	// currently prevents the task goroutine from running.
	//
	// stop is protected by the signal mutex.
	stop TaskStop

	// stopCount is the number of active external stops (calls to
	// Task.BeginExternalStop that have not been paired with a call to
	// Task.EndExternalStop), plus 1 if stop is not nil. Hence stopCount is
	// non-zero if the task goroutine should stop.
	//
	// Mutating stopCount requires both locking the signal mutex and using
	// atomic memory operations. Reading stopCount requires either locking the
	// signal mutex or using atomic memory operations. This allows Task.doStop
	// to require only a single atomic read in the common case where stopCount
	// is 0.
	//
	// stopCount is not saved, because external stops cannot be retained across
	// a save/restore cycle. (Suppose a sentryctl command issues an external
	// stop; after a save/restore cycle, the restored sentry has no knowledge
	// of the pre-save sentryctl command, and the stopped task would remain
	// stopped forever.)
	stopCount int32 `state:"nosave"`

	// endStopCond is signaled when stopCount transitions to 0. The combination
	// of stopCount and endStopCond effectively form a sync.WaitGroup, but
	// WaitGroup provides no way to read its counter value.
	//
	// Invariant: endStopCond.L is the signal mutex. (This is not racy because
	// sync.Cond.Wait is the only user of sync.Cond.L; only the task goroutine
	// calls sync.Cond.Wait; and only the task goroutine can change the
	// identity of the signal mutex, in Task.finishExec.)
	endStopCond sync.Cond `state:"nosave"`

	// exitStatus is the task's exit status.
	//
	// exitStatus is protected by the signal mutex.
	exitStatus ExitStatus

	// syscallRestartBlock represents a custom restart function to run in
	// restart_syscall(2) to resume an interrupted syscall.
	//
	// syscallRestartBlock is exclusive to the task goroutine.
	syscallRestartBlock SyscallRestartBlock

	// p provides the mechanism by which the task runs code in userspace. The p
	// interface object is immutable.
	p platform.Context `state:"nosave"`

	// k is the Kernel that this task belongs to. The k pointer is immutable.
	k *Kernel

	// containerID has no equivalent in Linux; it's used by runsc to track all
	// tasks that belong to a given containers since cgroups aren't implemented.
	// It's inherited by the children, is immutable, and may be empty.
	//
	// NOTE: cgroups can be used to track this when implemented.
	containerID string

	// mu protects some of the following fields.
	mu sync.Mutex `state:"nosave"`

	// tc holds task data provided by the ELF loader.
	//
	// tc is protected by mu, and is owned by the task goroutine.
	tc TaskContext

	// fsContext is the task's filesystem context.
	//
	// fsContext is protected by mu, and is owned by the task goroutine.
	fsContext *FSContext

	// fdTable is the task's file descriptor table.
	//
	// fdTable is protected by mu, and is owned by the task goroutine.
	fdTable *FDTable

	// If vforkParent is not nil, it is the task that created this task with
	// vfork() or clone(CLONE_VFORK), and should have its vforkStop ended when
	// this TaskContext is released.
	//
	// vforkParent is protected by the TaskSet mutex.
	vforkParent *Task

	// exitState is the task's progress through the exit path.
	//
	// exitState is protected by the TaskSet mutex. exitState is owned by the
	// task goroutine.
	exitState TaskExitState

	// exitTracerNotified is true if the exit path has either signaled the
	// task's tracer to indicate the exit, or determined that no such signal is
	// needed. exitTracerNotified can only be true if exitState is
	// TaskExitZombie or TaskExitDead.
	//
	// exitTracerNotified is protected by the TaskSet mutex.
	exitTracerNotified bool

	// exitTracerAcked is true if exitTracerNotified is true and either the
	// task's tracer has acknowledged the exit notification, or the exit path
	// has determined that no such notification is needed.
	//
	// exitTracerAcked is protected by the TaskSet mutex.
	exitTracerAcked bool

	// exitParentNotified is true if the exit path has either signaled the
	// task's parent to indicate the exit, or determined that no such signal is
	// needed. exitParentNotified can only be true if exitState is
	// TaskExitZombie or TaskExitDead.
	//
	// exitParentNotified is protected by the TaskSet mutex.
	exitParentNotified bool

	// exitParentAcked is true if exitParentNotified is true and either the
	// task's parent has acknowledged the exit notification, or the exit path
	// has determined that no such acknowledgment is needed.
	//
	// exitParentAcked is protected by the TaskSet mutex.
	exitParentAcked bool

	// goroutineStopped is a WaitGroup whose counter value is 1 when the task
	// goroutine is running and 0 when the task goroutine is stopped or has
	// exited.
	goroutineStopped sync.WaitGroup `state:"nosave"`

	// ptraceTracer is the task that is ptrace-attached to this one. If
	// ptraceTracer is nil, this task is not being traced. Note that due to
	// atomic.Value limitations (atomic.Value.Store(nil) panics), a nil
	// ptraceTracer is always represented as a typed nil (i.e. (*Task)(nil)).
	//
	// ptraceTracer is protected by the TaskSet mutex, and accessed with atomic
	// operations. This allows paths that wouldn't otherwise lock the TaskSet
	// mutex, notably the syscall path, to check if ptraceTracer is nil without
	// additional synchronization.
	ptraceTracer atomic.Value `state:".(*Task)"`

	// ptraceTracees is the set of tasks that this task is ptrace-attached to.
	//
	// ptraceTracees is protected by the TaskSet mutex.
	ptraceTracees map[*Task]struct{}

	// ptraceSeized is true if ptraceTracer attached to this task with
	// PTRACE_SEIZE.
	//
	// ptraceSeized is protected by the TaskSet mutex.
	ptraceSeized bool

	// ptraceOpts contains ptrace options explicitly set by the tracer. If
	// ptraceTracer is nil, ptraceOpts is expected to be the zero value.
	//
	// ptraceOpts is protected by the TaskSet mutex.
	ptraceOpts ptraceOptions

	// ptraceSyscallMode controls ptrace behavior around syscall entry and
	// exit.
	//
	// ptraceSyscallMode is protected by the TaskSet mutex.
	ptraceSyscallMode ptraceSyscallMode

	// If ptraceSinglestep is true, the next time the task executes application
	// code, single-stepping should be enabled. ptraceSinglestep is stored
	// independently of the architecture-specific trap flag because tracer
	// detaching (which can happen concurrently with the tracee's execution if
	// the tracer exits) must disable single-stepping, and the task's
	// architectural state is implicitly exclusive to the task goroutine (no
	// synchronization occurs before passing registers to SwitchToApp).
	//
	// ptraceSinglestep is analogous to Linux's TIF_SINGLESTEP.
	//
	// ptraceSinglestep is protected by the TaskSet mutex.
	ptraceSinglestep bool

	// If t is ptrace-stopped, ptraceCode is a ptrace-defined value set at the
	// time that t entered the ptrace stop, reset to 0 when the tracer
	// acknowledges the stop with a wait*() syscall. Otherwise, it is the
	// signal number passed to the ptrace operation that ended the last ptrace
	// stop on this task. In the latter case, the effect of ptraceCode depends
	// on the nature of the ptrace stop; signal-delivery-stop uses it to
	// conditionally override ptraceSiginfo, syscall-entry/exit-stops send the
	// signal to the task after leaving the stop, and PTRACE_EVENT stops and
	// traced group stops ignore it entirely.
	//
	// Linux contextually stores the equivalent of ptraceCode in
	// task_struct::exit_code.
	//
	// ptraceCode is protected by the TaskSet mutex.
	ptraceCode int32

	// ptraceSiginfo is the value returned to the tracer by
	// ptrace(PTRACE_GETSIGINFO) and modified by ptrace(PTRACE_SETSIGINFO).
	// (Despite the name, PTRACE_PEEKSIGINFO is completely unrelated.)
	// ptraceSiginfo is nil if the task is in a ptraced group-stop (this is
	// required for PTRACE_GETSIGINFO to return EINVAL during such stops, which
	// is in turn required to distinguish group stops from other ptrace stops,
	// per subsection "Group-stop" in ptrace(2)).
	//
	// ptraceSiginfo is analogous to Linux's task_struct::last_siginfo.
	//
	// ptraceSiginfo is protected by the TaskSet mutex.
	ptraceSiginfo *arch.SignalInfo

	// ptraceEventMsg is the value set by PTRACE_EVENT stops and returned to
	// the tracer by ptrace(PTRACE_GETEVENTMSG).
	//
	// ptraceEventMsg is protected by the TaskSet mutex.
	ptraceEventMsg uint64

	// The struct that holds the IO-related usage. The ioUsage pointer is
	// immutable.
	ioUsage *usage.IO

	// logPrefix is a string containing the task's thread ID in the root PID
	// namespace, and is prepended to log messages emitted by Task.Infof etc.
	logPrefix atomic.Value `state:".(string)"`

	// creds is the task's credentials.
	//
	// creds.Load() may be called without synchronization. creds.Store() is
	// serialized by mu. creds is owned by the task goroutine. All
	// auth.Credentials objects that creds may point to, or have pointed to
	// in the past, must be treated as immutable.
	creds auth.AtomicPtrCredentials

	// utsns is the task's UTS namespace.
	//
	// utsns is protected by mu. utsns is owned by the task goroutine.
	utsns *UTSNamespace

	// ipcns is the task's IPC namespace.
	//
	// ipcns is protected by mu. ipcns is owned by the task goroutine.
	ipcns *IPCNamespace

	// abstractSockets tracks abstract sockets that are in use.
	//
	// abstractSockets is protected by mu.
	abstractSockets *AbstractSocketNamespace

	// parentDeathSignal is sent to this task's thread group when its parent exits.
	//
	// parentDeathSignal is protected by mu.
	parentDeathSignal linux.Signal

	// syscallFilters is all seccomp-bpf syscall filters applicable to the
	// task, in the order in which they were installed. The type of the atomic
	// is []bpf.Program. Writing needs to be protected by the signal mutex.
	//
	// syscallFilters is owned by the task goroutine.
	syscallFilters atomic.Value `state:".([]bpf.Program)"`

	// If cleartid is non-zero, treat it as a pointer to a ThreadID in the
	// task's virtual address space; when the task exits, set the pointed-to
	// ThreadID to 0, and wake any futex waiters.
	//
	// cleartid is exclusive to the task goroutine.
	cleartid usermem.Addr

	// This is mostly a fake cpumask just for sched_set/getaffinity as we
	// don't really control the affinity.
	//
	// Invariant: allowedCPUMask.Size() ==
	// sched.CPUMaskSize(Kernel.applicationCores).
	//
	// allowedCPUMask is protected by mu.
	allowedCPUMask sched.CPUSet

	// cpu is the fake cpu number returned by getcpu(2). cpu is ignored
	// entirely if Kernel.useHostCores is true.
	//
	// cpu is accessed using atomic memory operations.
	cpu int32

	// This is used to keep track of changes made to a process' priority/niceness.
	// It is mostly used to provide some reasonable return value from
	// getpriority(2) after a call to setpriority(2) has been made.
	// We currently do not actually modify a process' scheduling priority.
	// NOTE: This represents the userspace view of priority (nice).
	// This means that the value should be in the range [-20, 19].
	//
	// niceness is protected by mu.
	niceness int

	// This is used to track the numa policy for the current thread. This can be
	// modified through a set_mempolicy(2) syscall. Since we always report a
	// single numa node, all policies are no-ops. We only track this information
	// so that we can return reasonable values if the application calls
	// get_mempolicy(2) after setting a non-default policy. Note that in the
	// real syscall, nodemask can be longer than a single unsigned long, but we
	// always report a single node so never need to save more than a single
	// bit.
	//
	// numaPolicy and numaNodeMask are protected by mu.
	numaPolicy   int32
	numaNodeMask uint64

	// If netns is true, the task is in a non-root network namespace. Network
	// namespaces aren't currently implemented in full; being in a network
	// namespace simply prevents the task from observing any network devices
	// (including loopback) or using abstract socket addresses (see unix(7)).
	//
	// netns is protected by mu. netns is owned by the task goroutine.
	netns bool

	// If rseqPreempted is true, before the next call to p.Switch(), interrupt
	// RSEQ critical regions as defined by tg.rseq and write the task
	// goroutine's CPU number to rseqCPUAddr. rseqCPU is the last CPU number
	// written to rseqCPUAddr.
	//
	// If rseqCPUAddr is 0, rseqCPU is -1.
	//
	// rseqCPUAddr, rseqCPU, and rseqPreempted are exclusive to the task
	// goroutine.
	rseqPreempted bool `state:"nosave"`
	rseqCPUAddr   usermem.Addr
	rseqCPU       int32

	// copyScratchBuffer is a buffer available to CopyIn/CopyOut
	// implementations that require an intermediate buffer to copy data
	// into/out of. It prevents these buffers from being allocated/zeroed in
	// each syscall and eventually garbage collected.
	//
	// copyScratchBuffer is exclusive to the task goroutine.
	copyScratchBuffer [copyScratchBufferLen]byte `state:"nosave"`

	// blockingTimer is used for blocking timeouts. blockingTimerChan is the
	// channel that is sent to when blockingTimer fires.
	//
	// blockingTimer is exclusive to the task goroutine.
	blockingTimer     *ktime.Timer    `state:"nosave"`
	blockingTimerChan <-chan struct{} `state:"nosave"`

	// futexWaiter is used for futex(FUTEX_WAIT) syscalls.
	//
	// futexWaiter is exclusive to the task goroutine.
	futexWaiter *futex.Waiter `state:"nosave"`

	// startTime is the real time at which the task started. It is set when
	// a Task is created or invokes execve(2).
	//
	// startTime is protected by mu.
	startTime ktime.Time
}

func (t *Task) savePtraceTracer() *Task {
	return t.ptraceTracer.Load().(*Task)
}

func (t *Task) loadPtraceTracer(tracer *Task) {
	t.ptraceTracer.Store(tracer)
}

func (t *Task) saveLogPrefix() string {
	return t.logPrefix.Load().(string)
}

func (t *Task) loadLogPrefix(prefix string) {
	t.logPrefix.Store(prefix)
}

func (t *Task) saveSyscallFilters() []bpf.Program {
	if f := t.syscallFilters.Load(); f != nil {
		return f.([]bpf.Program)
	}
	return nil
}

func (t *Task) loadSyscallFilters(filters []bpf.Program) {
	t.syscallFilters.Store(filters)
}

// afterLoad is invoked by stateify.
func (t *Task) afterLoad() {
	t.interruptChan = make(chan struct{}, 1)
	t.gosched.State = TaskGoroutineNonexistent
	if t.stop != nil {
		t.stopCount = 1
	}
	t.endStopCond.L = &t.tg.signalHandlers.mu
	t.p = t.k.Platform.NewContext()
	t.rseqPreempted = true
	t.futexWaiter = futex.NewWaiter()
}

// copyScratchBufferLen is the length of Task.copyScratchBuffer.
const copyScratchBufferLen = 144 // sizeof(struct stat)

// CopyScratchBuffer returns a scratch buffer to be used in CopyIn/CopyOut
// functions. It must only be used within those functions and can only be used
// by the task goroutine; it exists to improve performance and thus
// intentionally lacks any synchronization.
//
// Callers should pass a constant value as an argument if possible, which will
// allow the compiler to inline and optimize out the if statement below.
func (t *Task) CopyScratchBuffer(size int) []byte {
	if size > copyScratchBufferLen {
		return make([]byte, size)
	}
	return t.copyScratchBuffer[:size]
}

// FutexWaiter returns the Task's futex.Waiter.
func (t *Task) FutexWaiter() *futex.Waiter {
	return t.futexWaiter
}

// Kernel returns the Kernel containing t.
func (t *Task) Kernel() *Kernel {
	return t.k
}

// Value implements context.Context.Value.
//
// Preconditions: The caller must be running on the task goroutine (as implied
// by the requirements of context.Context).
func (t *Task) Value(key interface{}) interface{} {
	switch key {
	case CtxCanTrace:
		return t.CanTrace
	case CtxKernel:
		return t.k
	case CtxPIDNamespace:
		return t.tg.pidns
	case CtxUTSNamespace:
		return t.utsns
	case CtxIPCNamespace:
		return t.ipcns
	case CtxTask:
		return t
	case auth.CtxCredentials:
		return t.Credentials()
	case context.CtxThreadGroupID:
		return int32(t.ThreadGroup().ID())
	case fs.CtxRoot:
		return t.fsContext.RootDirectory()
	case fs.CtxDirentCacheLimiter:
		return t.k.DirentCacheLimiter
	case inet.CtxStack:
		return t.NetworkContext()
	case ktime.CtxRealtimeClock:
		return t.k.RealtimeClock()
	case limits.CtxLimits:
		return t.tg.limits
	case pgalloc.CtxMemoryFile:
		return t.k.mf
	case pgalloc.CtxMemoryFileProvider:
		return t.k
	case platform.CtxPlatform:
		return t.k
	case uniqueid.CtxGlobalUniqueID:
		return t.k.UniqueID()
	case uniqueid.CtxGlobalUniqueIDProvider:
		return t.k
	case uniqueid.CtxInotifyCookie:
		return t.k.GenerateInotifyCookie()
	case unimpl.CtxEvents:
		return t.k
	default:
		return nil
	}
}

// SetClearTID sets t's cleartid.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) SetClearTID(addr usermem.Addr) {
	t.cleartid = addr
}

// SetSyscallRestartBlock sets the restart block for use in
// restart_syscall(2). After registering a restart block, a syscall should
// return ERESTART_RESTARTBLOCK to request a restart using the block.
//
// Precondition: The caller must be running on the task goroutine.
func (t *Task) SetSyscallRestartBlock(r SyscallRestartBlock) {
	t.syscallRestartBlock = r
}

// SyscallRestartBlock returns the currently registered restart block for use in
// restart_syscall(2). This function is *not* idempotent and may be called once
// per syscall. This function must not be called if a restart block has not been
// registered for the current syscall.
//
// Precondition: The caller must be running on the task goroutine.
func (t *Task) SyscallRestartBlock() SyscallRestartBlock {
	r := t.syscallRestartBlock
	// Explicitly set the restart block to nil so that a future syscall can't
	// accidentally reuse it.
	t.syscallRestartBlock = nil
	return r
}

// IsChrooted returns true if the root directory of t's FSContext is not the
// root directory of t's MountNamespace.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) IsChrooted() bool {
	realRoot := t.tg.mounts.Root()
	defer realRoot.DecRef()
	root := t.fsContext.RootDirectory()
	if root != nil {
		defer root.DecRef()
	}
	return root != realRoot
}

// TaskContext returns t's TaskContext.
//
// Precondition: The caller must be running on the task goroutine, or t.mu must
// be locked.
func (t *Task) TaskContext() *TaskContext {
	return &t.tc
}

// FSContext returns t's FSContext. FSContext does not take an additional
// reference on the returned FSContext.
//
// Precondition: The caller must be running on the task goroutine, or t.mu must
// be locked.
func (t *Task) FSContext() *FSContext {
	return t.fsContext
}

// FDTable returns t's FDTable. FDMTable does not take an additional reference
// on the returned FDMap.
//
// Precondition: The caller must be running on the task goroutine, or t.mu must
// be locked.
func (t *Task) FDTable() *FDTable {
	return t.fdTable
}

// GetFile is a convenience wrapper for t.FDTable().Get.
//
// Precondition: same as FDTable.Get.
func (t *Task) GetFile(fd int32) *fs.File {
	f, _ := t.fdTable.Get(fd)
	return f
}

// NewFDs is a convenience wrapper for t.FDTable().NewFDs.
//
// This automatically passes the task as the context.
//
// Precondition: same as FDTable.
func (t *Task) NewFDs(fd int32, files []*fs.File, flags FDFlags) ([]int32, error) {
	return t.fdTable.NewFDs(t, fd, files, flags)
}

// NewFDFrom is a convenience wrapper for t.FDTable().NewFDs with a single file.
//
// This automatically passes the task as the context.
//
// Precondition: same as FDTable.
func (t *Task) NewFDFrom(fd int32, file *fs.File, flags FDFlags) (int32, error) {
	fds, err := t.fdTable.NewFDs(t, fd, []*fs.File{file}, flags)
	if err != nil {
		return 0, err
	}
	return fds[0], nil
}

// NewFDAt is a convenience wrapper for t.FDTable().NewFDAt.
//
// This automatically passes the task as the context.
//
// Precondition: same as FDTable.
func (t *Task) NewFDAt(fd int32, file *fs.File, flags FDFlags) error {
	return t.fdTable.NewFDAt(t, fd, file, flags)
}

// WithMuLocked executes f with t.mu locked.
func (t *Task) WithMuLocked(f func(*Task)) {
	t.mu.Lock()
	f(t)
	t.mu.Unlock()
}

// MountNamespace returns t's MountNamespace. MountNamespace does not take an
// additional reference on the returned MountNamespace.
func (t *Task) MountNamespace() *fs.MountNamespace {
	return t.tg.mounts
}

// AbstractSockets returns t's AbstractSocketNamespace.
func (t *Task) AbstractSockets() *AbstractSocketNamespace {
	return t.abstractSockets
}

// ContainerID returns t's container ID.
func (t *Task) ContainerID() string {
	return t.containerID
}
