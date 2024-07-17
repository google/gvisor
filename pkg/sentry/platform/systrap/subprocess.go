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

package systrap

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/pool"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/usertrap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

var (
	// globalPool tracks all subprocesses in various state: active or available for
	// reuse.
	globalPool = subprocessPool{}

	// maximumUserAddress is the largest possible user address.
	maximumUserAddress = linux.TaskSize

	// stubInitAddress is the initial attempt link address for the stub.
	stubInitAddress = linux.TaskSize

	// maxRandomOffsetOfStubAddress is the maximum offset for randomizing a
	// stub address. It is set to the default value of mm.mmap_rnd_bits.
	//
	// Note: Tools like ThreadSanitizer don't like when the memory layout
	// is changed significantly.
	maxRandomOffsetOfStubAddress = (linux.TaskSize >> 7) & ^(uintptr(hostarch.PageSize) - 1)

	// maxStubUserAddress is the largest possible user address for
	// processes running inside gVisor. It is fixed because
	// * we don't want to reveal a stub address.
	// * it has to be the same across checkpoint/restore.
	maxStubUserAddress = maximumUserAddress - maxRandomOffsetOfStubAddress
)

// Linux kernel errnos which "should never be seen by user programs", but will
// be revealed to ptrace syscall exit tracing.
//
// These constants are only used in subprocess.go.
const (
	ERESTARTSYS    = unix.Errno(512)
	ERESTARTNOINTR = unix.Errno(513)
	ERESTARTNOHAND = unix.Errno(514)
)

// thread is a traced thread; it is a thread identifier.
//
// This is a convenience type for defining ptrace operations.
type thread struct {
	tgid int32
	tid  int32

	// sysmsgStackID is a stack ID in subprocess.sysmsgStackPool.
	sysmsgStackID uint64

	// initRegs are the initial registers for the first thread.
	//
	// These are used for the register set for system calls.
	initRegs arch.Registers

	logPrefix atomic.Pointer[string]
}

// requestThread is used to request a new sysmsg thread. A thread identifier will
// be sent into the thread channel.
type requestThread struct {
	thread chan *thread
}

// requestStub is used to request a new stub process.
type requestStub struct {
	done chan *thread
}

// maxSysmsgThreads is the maximum number of sysmsg threads that a subprocess
// can create. It is based on GOMAXPROCS and set once, so it must be set after
// GOMAXPROCS has been adjusted (see loader.go:Args.NumCPU).
var maxSysmsgThreads = 0

// maxChildThreads is the max number of all child system threads that a
// subprocess can create, including sysmsg threads.
var maxChildThreads = 0

const (
	// maxGuestContexts specifies the maximum number of task contexts that a
	// subprocess can handle.
	maxGuestContexts = 4095
	// invalidContextID specifies an invalid ID.
	invalidContextID uint32 = 0xfefefefe
	// invalidThreadID is used to indicate that a context is not being worked on by
	// any sysmsg thread.
	invalidThreadID uint32 = 0xfefefefe
)

// subprocess is a collection of threads being traced.
type subprocess struct {
	platform.NoAddressSpaceIO
	subprocessRefs

	// requests is used to signal creation of new threads.
	requests chan any

	// sysmsgInitRegs is used to reset sysemu regs.
	sysmsgInitRegs arch.Registers

	// mu protects the following fields.
	mu sync.Mutex

	// faultedContexts is the set of contexts for which it's possible that
	// platformContext.lastFaultSP == this subprocess.
	faultedContexts map[*platformContext]struct{}

	// sysmsgStackPool is a pool of available sysmsg stacks.
	sysmsgStackPool pool.Pool

	// threadContextPool is a pool of available sysmsg.ThreadContext IDs.
	threadContextPool pool.Pool

	// threadContextRegion defines the ThreadContext memory region start
	// within the sentry address space.
	threadContextRegion uintptr

	// memoryFile is used to allocate a sysmsg stack which is shared
	// between a stub process and the Sentry.
	memoryFile *pgalloc.MemoryFile

	// usertrap is the state of the usertrap table which contains syscall
	// trampolines.
	usertrap *usertrap.State

	syscallThreadMu sync.Mutex
	syscallThread   *syscallThread

	// sysmsgThreadsMu protects sysmsgThreads and numSysmsgThreads
	sysmsgThreadsMu sync.Mutex
	// sysmsgThreads is a collection of all active sysmsg threads in the
	// subprocess.
	sysmsgThreads map[uint32]*sysmsgThread
	// numSysmsgThreads counts the number of active sysmsg threads; we use a
	// counter instead of using len(sysmsgThreads) because we need to synchronize
	// how many threads get created _before_ the creation happens.
	numSysmsgThreads int

	// contextQueue is a queue of all contexts that are ready to switch back to
	// user mode.
	contextQueue *contextQueue

	// dead indicates whether the subprocess is alive or not.
	dead atomicbitops.Bool
}

var seccompNotifyIsSupported = false

func initSeccompNotify() {
	_, _, errno := unix.Syscall(seccomp.SYS_SECCOMP, linux.SECCOMP_SET_MODE_FILTER, linux.SECCOMP_FILTER_FLAG_NEW_LISTENER, 0)
	switch errno {
	case unix.EFAULT:
		// seccomp unotify is supported.
	case unix.EINVAL:
		log.Warningf("Seccomp user-space notification mechanism isn't " +
			"supported by the kernel (available since Linux 5.0).")
	default:
		panic(fmt.Sprintf("seccomp returns unexpected code: %d", errno))
	}
}

func (s *subprocess) initSyscallThread(ptraceThread *thread, seccompNotify bool) error {
	s.syscallThreadMu.Lock()
	defer s.syscallThreadMu.Unlock()

	id, ok := s.sysmsgStackPool.Get()
	if !ok {
		panic("unable to allocate a sysmsg stub thread")
	}

	ptraceThread.sysmsgStackID = id
	t := syscallThread{
		subproc: s,
		thread:  ptraceThread,
	}

	if err := t.init(seccompNotify); err != nil {
		panic(fmt.Sprintf("failed to create a syscall thread"))
	}
	s.syscallThread = &t

	s.syscallThread.detach()

	return nil
}

func handlePtraceSyscallRequestError(req any, format string, values ...any) {
	switch req.(type) {
	case requestThread:
		req.(requestThread).thread <- nil
	case requestStub:
		req.(requestStub).done <- nil
	}
	log.Warningf("handlePtraceSyscallRequest failed: "+format, values...)
}

// handlePtraceSyscallRequest executes system calls that can't be run via
// syscallThread without using ptrace. Look at the description of syscallThread
// to get more details about its limitations.
func (s *subprocess) handlePtraceSyscallRequest(req any) {
	s.syscallThreadMu.Lock()
	defer s.syscallThreadMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := s.syscallThread.attach(); err != nil {
		handlePtraceSyscallRequestError(req, err.Error())
		return
	}
	defer s.syscallThread.detach()

	ptraceThread := s.syscallThread.thread

	switch r := req.(type) {
	case requestThread:
		t, err := ptraceThread.clone()
		if err != nil {
			handlePtraceSyscallRequestError(req, "error initializing thread: %v", err)
			return
		}

		// Since the new thread was created with
		// clone(CLONE_PTRACE), it will begin execution with
		// SIGSTOP pending and with this thread as its tracer.
		// (Hopefully nobody tgkilled it with a signal <
		// SIGSTOP before the SIGSTOP was delivered, in which
		// case that signal would be delivered before SIGSTOP.)
		if sig := t.wait(stopped); sig != unix.SIGSTOP {
			handlePtraceSyscallRequestError(req, "error waiting for new clone: expected SIGSTOP, got %v", sig)
			return
		}

		t.initRegs = ptraceThread.initRegs
		// Set the parent death signal to SIGKILL.
		_, err = t.syscallIgnoreInterrupt(&t.initRegs, unix.SYS_PRCTL,
			arch.SyscallArgument{Value: linux.PR_SET_PDEATHSIG},
			arch.SyscallArgument{Value: uintptr(unix.SIGKILL)},
			arch.SyscallArgument{Value: 0},
			arch.SyscallArgument{Value: 0},
			arch.SyscallArgument{Value: 0},
			arch.SyscallArgument{Value: 0},
		)
		if err != nil {
			handlePtraceSyscallRequestError(req, "prctl: %v", err)
			return
		}

		id, ok := s.sysmsgStackPool.Get()
		if !ok {
			handlePtraceSyscallRequestError(req, "unable to allocate a sysmsg stub thread")
			return
		}
		t.sysmsgStackID = id

		if _, _, e := unix.RawSyscall(unix.SYS_TGKILL, uintptr(t.tgid), uintptr(t.tid), uintptr(unix.SIGSTOP)); e != 0 {
			handlePtraceSyscallRequestError(req, "tkill failed: %v", e)
			return
		}

		// Detach the thread.
		t.detach()

		// Return the thread.
		r.thread <- t
	case requestStub:
		t, err := ptraceThread.createStub()
		if err != nil {
			handlePtraceSyscallRequestError(req, "unable to create a stub process: %v", err)
			return
		}
		r.done <- t

	}
}

// newSubprocess returns a usable subprocess.
//
// This will either be a newly created subprocess, or one from the global pool.
// The create function will be called in the latter case, which is guaranteed
// to happen with the runtime thread locked.
//
// seccompNotify indicates a ways of comunications with syscall threads.
// If it is false, futex-s are used. Otherwise, seccomp-unotify is used.
// seccomp-unotify can't be used for the source pool process, because it is a
// parent of all other stub processes, but only one filter can be installed
// with SECCOMP_FILTER_FLAG_NEW_LISTENER.
func newSubprocess(create func() (*thread, error), memoryFile *pgalloc.MemoryFile, seccompNotify bool) (*subprocess, error) {
	if sp := globalPool.fetchAvailable(); sp != nil {
		sp.subprocessRefs.InitRefs()
		sp.usertrap = usertrap.New()
		return sp, nil
	}

	// The following goroutine is responsible for creating the first traced
	// thread, and responding to requests to make additional threads in the
	// traced process. The process will be killed and reaped when the
	// request channel is closed, which happens in Release below.
	requests := make(chan any)

	// Ready.
	sp := &subprocess{
		requests:          requests,
		faultedContexts:   make(map[*platformContext]struct{}),
		sysmsgStackPool:   pool.Pool{Start: 0, Limit: uint64(maxChildThreads)},
		threadContextPool: pool.Pool{Start: 0, Limit: maxGuestContexts},
		memoryFile:        memoryFile,
		sysmsgThreads:     make(map[uint32]*sysmsgThread),
	}
	sp.subprocessRefs.InitRefs()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Initialize the syscall thread.
	ptraceThread, err := create()
	if err != nil {
		return nil, err
	}
	sp.sysmsgInitRegs = ptraceThread.initRegs

	if err := sp.initSyscallThread(ptraceThread, seccompNotify); err != nil {
		return nil, err
	}

	go func() { // S/R-SAFE: Platform-related.

		// Wait for requests to create threads.
		for req := range requests {
			sp.handlePtraceSyscallRequest(req)
		}

		// Requests should never be closed.
		panic("unreachable")
	}()

	sp.unmap()
	sp.usertrap = usertrap.New()
	sp.mapSharedRegions()
	sp.mapPrivateRegions()

	// The main stub doesn't need sysmsg threads.
	if seccompNotify {
		// Create the initial sysmsg thread.
		atomic.AddUint32(&sp.contextQueue.numThreadsToWakeup, 1)
		if err := sp.createSysmsgThread(); err != nil {
			return nil, err
		}
		sp.numSysmsgThreads++
	}

	return sp, nil
}

// mapSharedRegions maps the shared regions that are used between the subprocess
// and ALL of the subsequently created sysmsg threads into both the sentry and
// the syscall thread.
//
// Should be called before any sysmsg threads are created.
// Initializes s.contextQueue and s.threadContextRegion.
func (s *subprocess) mapSharedRegions() {
	if s.contextQueue != nil || s.threadContextRegion != 0 {
		panic("contextQueue or threadContextRegion was already initialized")
	}

	opts := pgalloc.AllocOpts{
		Kind: usage.System,
		Dir:  pgalloc.TopDown,
	}

	// Map shared regions into the sentry.
	contextQueueFR, contextQueue := mmapContextQueueForSentry(s.memoryFile, opts)
	contextQueue.init()

	// Map thread context region into the syscall thread.
	_, err := s.syscallThread.syscall(
		unix.SYS_MMAP,
		arch.SyscallArgument{Value: uintptr(stubContextQueueRegion)},
		arch.SyscallArgument{Value: uintptr(contextQueueFR.Length())},
		arch.SyscallArgument{Value: uintptr(unix.PROT_READ | unix.PROT_WRITE)},
		arch.SyscallArgument{Value: uintptr(unix.MAP_SHARED | unix.MAP_FILE | unix.MAP_FIXED)},
		arch.SyscallArgument{Value: uintptr(s.memoryFile.FD())},
		arch.SyscallArgument{Value: uintptr(contextQueueFR.Start)})
	if err != nil {
		panic(fmt.Sprintf("failed to mmap context queue region into syscall thread: %v", err))
	}

	s.contextQueue = contextQueue

	// Map thread context region into the sentry.
	threadContextFR, err := s.memoryFile.Allocate(uint64(stubContextRegionLen), opts)
	if err != nil {
		panic(fmt.Sprintf("failed to allocate a new subprocess context memory region"))
	}
	sentryThreadContextRegionAddr, _, errno := unix.RawSyscall6(
		unix.SYS_MMAP,
		0,
		uintptr(threadContextFR.Length()),
		unix.PROT_WRITE|unix.PROT_READ,
		unix.MAP_SHARED|unix.MAP_FILE,
		uintptr(s.memoryFile.FD()), uintptr(threadContextFR.Start))
	if errno != 0 {
		panic(fmt.Sprintf("mmap failed for subprocess context memory region: %v", errno))
	}

	// Map thread context region into the syscall thread.
	if _, err := s.syscallThread.syscall(
		unix.SYS_MMAP,
		arch.SyscallArgument{Value: uintptr(stubContextRegion)},
		arch.SyscallArgument{Value: uintptr(threadContextFR.Length())},
		arch.SyscallArgument{Value: uintptr(unix.PROT_READ | unix.PROT_WRITE)},
		arch.SyscallArgument{Value: uintptr(unix.MAP_SHARED | unix.MAP_FILE | unix.MAP_FIXED)},
		arch.SyscallArgument{Value: uintptr(s.memoryFile.FD())},
		arch.SyscallArgument{Value: uintptr(threadContextFR.Start)}); err != nil {
		panic(fmt.Sprintf("failed to mmap context queue region into syscall thread: %v", err))
	}

	s.threadContextRegion = sentryThreadContextRegionAddr
}

func (s *subprocess) mapPrivateRegions() {
	_, err := s.syscallThread.syscall(
		unix.SYS_MMAP,
		arch.SyscallArgument{Value: uintptr(stubSpinningThreadQueueAddr)},
		arch.SyscallArgument{Value: uintptr(sysmsg.SpinningQueueMemSize)},
		arch.SyscallArgument{Value: uintptr(unix.PROT_READ | unix.PROT_WRITE)},
		arch.SyscallArgument{Value: uintptr(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS | unix.MAP_FIXED)},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: 0})
	if err != nil {
		panic(fmt.Sprintf("failed to mmap spinning queue region into syscall thread: %v", err))
	}
}

// unmap unmaps non-stub regions of the process.
//
// This will panic on failure (which should never happen).
func (s *subprocess) unmap() {
	s.Unmap(0, uint64(stubStart))
	if maximumUserAddress != stubEnd {
		s.Unmap(hostarch.Addr(stubEnd), uint64(maximumUserAddress-stubEnd))
	}
}

// Release kills the subprocess.
//
// Just kidding! We can't safely coordinate the detaching of all the
// tracees (since the tracers are random runtime threads, and the process
// won't exit until tracers have been notifier).
//
// Therefore we simply unmap everything in the subprocess and return it to the
// globalPool. This has the added benefit of reducing creation time for new
// subprocesses.
func (s *subprocess) Release() {
	if !s.alive() {
		return
	}
	s.unmap()
	s.DecRef(s.release)
}

// release returns the subprocess to the global pool.
func (s *subprocess) release() {
	if s.alive() {
		globalPool.markAvailable(s)
		return
	}
	if s.syscallThread != nil && s.syscallThread.seccompNotify != nil {
		s.syscallThread.seccompNotify.Close()
	}
}

// attach attaches to the thread.
func (t *thread) attach() error {
	if _, _, errno := unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_ATTACH, uintptr(t.tid), 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("unable to attach: %v", errno)
	}

	// PTRACE_ATTACH sends SIGSTOP, and wakes the tracee if it was already
	// stopped from the SIGSTOP queued by CLONE_PTRACE (see inner loop of
	// newSubprocess), so we always expect to see signal-delivery-stop with
	// SIGSTOP.
	if sig := t.wait(stopped); sig != unix.SIGSTOP {
		return fmt.Errorf("wait failed: expected SIGSTOP, got %v", sig)
	}

	// Initialize options.
	t.init()
	return nil
}

func (t *thread) grabInitRegs() {
	// Grab registers.
	//
	// Note that we adjust the current register RIP value to be just before
	// the current system call executed. This depends on the definition of
	// the stub itself.
	if err := t.getRegs(&t.initRegs); err != nil {
		panic(fmt.Sprintf("ptrace get regs failed: %v", err))
	}
	t.adjustInitRegsRip()
	t.initRegs.SetStackPointer(0)
}

// detach detaches from the thread.
//
// Because the SIGSTOP is not suppressed, the thread will enter group-stop.
func (t *thread) detach() {
	if _, _, errno := unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(t.tid), 0, uintptr(unix.SIGSTOP), 0, 0); errno != 0 {
		panic(fmt.Sprintf("can't detach new clone: %v", errno))
	}
}

// waitOutcome is used for wait below.
type waitOutcome int

const (
	// stopped indicates that the process was stopped.
	stopped waitOutcome = iota

	// killed indicates that the process was killed.
	killed
)

func (t *thread) loadLogPrefix() *string {
	p := t.logPrefix.Load()
	if p == nil {
		prefix := fmt.Sprintf("[% 4d:% 4d] ", t.tgid, t.tid)
		t.logPrefix.Store(&prefix)
		p = &prefix
	}
	return p
}

// Debugf logs with the debugging severity.
func (t *thread) Debugf(format string, v ...any) {
	if log.IsLogging(log.Debug) {
		log.DebugfAtDepth(1, *t.loadLogPrefix()+format, v...)
	}
}

// Warningf logs with the warning severity.
func (t *thread) Warningf(format string, v ...any) {
	if log.IsLogging(log.Warning) {
		log.WarningfAtDepth(1, *t.loadLogPrefix()+format, v...)
	}
}

func (t *thread) dumpAndPanic(message string) {
	var regs arch.Registers
	message += "\n"
	if err := t.getRegs(&regs); err == nil {
		message += dumpRegs(&regs)
	} else {
		log.Warningf("unable to get registers: %v", err)
	}
	message += fmt.Sprintf("stubStart\t = %016x\n", stubStart)
	panic(message)
}

func (t *thread) dumpRegs(message string) {
	var regs arch.Registers
	message += "\n"
	if err := t.getRegs(&regs); err == nil {
		message += dumpRegs(&regs)
	} else {
		log.Warningf("unable to get registers: %v", err)
	}
	log.Infof("%s", message)
}

func (t *thread) unexpectedStubExit() {
	msg, err := t.getEventMessage()
	status := unix.WaitStatus(msg)
	if status.Signaled() && status.Signal() == unix.SIGKILL {
		// SIGKILL can be only sent by a user or OOM-killer. In both
		// these cases, we don't need to panic. There is no reasons to
		// think that something wrong in gVisor.
		log.Warningf("The ptrace stub process %v has been killed by SIGKILL.", t.tgid)
		pid := os.Getpid()
		unix.Tgkill(pid, pid, unix.Signal(unix.SIGKILL))
	}
	t.dumpAndPanic(fmt.Sprintf("wait failed: the process %d:%d exited: %x (err %v)", t.tgid, t.tid, msg, err))
}

// wait waits for a stop event.
//
// Precondition: outcome is a valid waitOutcome.
func (t *thread) wait(outcome waitOutcome) unix.Signal {
	var status unix.WaitStatus

	for {
		r, err := unix.Wait4(int(t.tid), &status, unix.WALL|unix.WUNTRACED, nil)
		if err == unix.EINTR || err == unix.EAGAIN {
			// Wait was interrupted; wait again.
			continue
		} else if err != nil {
			panic(fmt.Sprintf("ptrace wait failed: %v", err))
		}
		if int(r) != int(t.tid) {
			panic(fmt.Sprintf("ptrace wait returned %v, expected %v", r, t.tid))
		}
		switch outcome {
		case stopped:
			if !status.Stopped() {
				t.dumpAndPanic(fmt.Sprintf("ptrace status unexpected: got %v, wanted stopped", status))
			}
			stopSig := status.StopSignal()
			if stopSig == 0 {
				continue // Spurious stop.
			}
			if stopSig == unix.SIGTRAP {
				if status.TrapCause() == unix.PTRACE_EVENT_EXIT {
					t.unexpectedStubExit()
				}
				// Re-encode the trap cause the way it's expected.
				return stopSig | unix.Signal(status.TrapCause()<<8)
			}
			// Not a trap signal.
			return stopSig
		case killed:
			if !status.Exited() && !status.Signaled() {
				t.dumpAndPanic(fmt.Sprintf("ptrace status unexpected: got %v, wanted exited", status))
			}
			return unix.Signal(status.ExitStatus())
		default:
			// Should not happen.
			t.dumpAndPanic(fmt.Sprintf("unknown outcome: %v", outcome))
		}
	}
}

// kill kills the thread;
func (t *thread) kill() {
	unix.Tgkill(int(t.tgid), int(t.tid), unix.Signal(unix.SIGKILL))
}

// destroy kills and waits on the thread.
//
// Note that this should not be used in the general case; the death of threads
// will typically cause the death of the parent. This is a utility method for
// manually created threads.
func (t *thread) destroy() {
	t.detach()
	unix.Tgkill(int(t.tgid), int(t.tid), unix.Signal(unix.SIGKILL))
	t.wait(killed)
}

// init initializes trace options.
func (t *thread) init() {
	// Set the TRACESYSGOOD option to differentiate real SIGTRAP.
	// set PTRACE_O_EXITKILL to ensure that the unexpected exit of the
	// sentry will immediately kill the associated stubs.
	_, _, errno := unix.RawSyscall6(
		unix.SYS_PTRACE,
		unix.PTRACE_SETOPTIONS,
		uintptr(t.tid),
		0,
		unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACEEXIT|unix.PTRACE_O_EXITKILL,
		0, 0)
	if errno != 0 {
		panic(fmt.Sprintf("ptrace set options failed: %v", errno))
	}
}

// syscall executes a system call cycle in the traced context.
//
// This is _not_ for use by application system calls, rather it is for use when
// a system call must be injected into the remote context (e.g. mmap, munmap).
// Note that clones are handled separately.
func (t *thread) syscall(regs *arch.Registers) (uintptr, error) {
	// Set registers.
	if err := t.setRegs(regs); err != nil {
		panic(fmt.Sprintf("ptrace set regs failed: %v", err))
	}

	for {
		// Execute the syscall instruction. The task has to stop on the
		// trap instruction which is right after the syscall
		// instruction.
		if _, _, errno := unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_CONT, uintptr(t.tid), 0, 0, 0, 0); errno != 0 {
			panic(fmt.Sprintf("ptrace syscall-enter failed: %v", errno))
		}

		sig := t.wait(stopped)
		if sig == unix.SIGTRAP {
			// Reached syscall-enter-stop.
			break
		} else {
			// Some other signal caused a thread stop; ignore.
			if sig != unix.SIGSTOP && sig != unix.SIGCHLD {
				log.Warningf("The thread %d:%d has been interrupted by %d", t.tgid, t.tid, sig)
			}
			continue
		}
	}

	// Grab registers.
	if err := t.getRegs(regs); err != nil {
		panic(fmt.Sprintf("ptrace get regs failed: %v", err))
	}
	return syscallReturnValue(regs)
}

// syscallIgnoreInterrupt ignores interrupts on the system call thread and
// restarts the syscall if the kernel indicates that should happen.
func (t *thread) syscallIgnoreInterrupt(
	initRegs *arch.Registers,
	sysno uintptr,
	args ...arch.SyscallArgument) (uintptr, error) {
	for {
		regs := createSyscallRegs(initRegs, sysno, args...)
		rval, err := t.syscall(&regs)
		switch err {
		case ERESTARTSYS:
			continue
		case ERESTARTNOINTR:
			continue
		case ERESTARTNOHAND:
			continue
		default:
			return rval, err
		}
	}
}

// NotifyInterrupt implements interrupt.Receiver.NotifyInterrupt.
func (t *thread) NotifyInterrupt() {
	unix.Tgkill(int(t.tgid), int(t.tid), unix.Signal(platform.SignalInterrupt))
}

func (s *subprocess) incAwakeContexts() {
	nr := atomic.AddUint32(&s.contextQueue.numAwakeContexts, 1)
	if nr > uint32(maxSysmsgThreads) {
		return
	}
	fastpath.nrMaxAwakeStubThreads.Add(1)
}

func (s *subprocess) decAwakeContexts() {
	nr := atomic.AddUint32(&s.contextQueue.numAwakeContexts, ^uint32(0))
	if nr >= uint32(maxSysmsgThreads) {
		return
	}
	fastpath.nrMaxAwakeStubThreads.Add(^uint32(0))
}

// switchToApp is called from the main SwitchToApp entrypoint.
//
// This function returns true on a system call, false on a signal.
// The second return value is true if a syscall instruction can be replaced on
// a function call.
func (s *subprocess) switchToApp(c *platformContext, ac *arch.Context64) (isSyscall bool, shouldPatchSyscall bool, err *platform.ContextError) {
	// Reset necessary registers.
	regs := &ac.StateData().Regs
	s.resetSysemuRegs(regs)
	ctx := c.sharedContext
	ctx.shared.Regs = regs.PtraceRegs
	restoreArchSpecificState(ctx.shared, ac)

	// Check for interrupts, and ensure that future interrupts signal the context.
	if !c.interrupt.Enable(c.sharedContext) {
		// Pending interrupt; simulate.
		ctx.clearInterrupt()
		c.signalInfo = linux.SignalInfo{Signo: int32(platform.SignalInterrupt)}
		return false, false, nil
	}
	defer func() {
		ctx.clearInterrupt()
		c.interrupt.Disable()
	}()

	restoreFPState(ctx, c, ac)

	// Place the context onto the context queue.
	if ctx.sleeping {
		ctx.sleeping = false
		s.incAwakeContexts()
	}
	ctx.setState(sysmsg.ContextStateNone)
	if err := s.contextQueue.add(ctx); err != nil {
		return false, false, err
	}

	if err := s.waitOnState(ctx); err != nil {
		return false, false, corruptedSharedMemoryErr(err.Error())
	}

	// Check if there's been an error.
	threadID := ctx.threadID()
	if threadID != invalidThreadID {
		if sysThread, ok := s.sysmsgThreads[threadID]; ok && sysThread.msg.Err != 0 {
			return false, false, sysThread.msg.ConvertSysmsgErr()
		}
		return false, false, corruptedSharedMemoryErr(fmt.Sprintf("found unexpected ThreadContext.ThreadID field, expected %d found %d", invalidThreadID, threadID))
	}

	// Copy register state locally.
	regs.PtraceRegs = ctx.shared.Regs
	retrieveArchSpecificState(ctx.shared, ac)
	c.needToPullFullState = true
	// We have a signal. We verify however, that the signal was
	// either delivered from the kernel or from this process. We
	// don't respect other signals.
	c.signalInfo = ctx.shared.SignalInfo
	ctxState := ctx.state()
	if ctxState == sysmsg.ContextStateSyscallCanBePatched {
		ctxState = sysmsg.ContextStateSyscall
		shouldPatchSyscall = true
	}

	if ctxState == sysmsg.ContextStateSyscall || ctxState == sysmsg.ContextStateSyscallTrap {
		if maybePatchSignalInfo(regs, &c.signalInfo) {
			return false, false, nil
		}
		updateSyscallRegs(regs)
		return true, shouldPatchSyscall, nil
	} else if ctxState != sysmsg.ContextStateFault {
		return false, false, corruptedSharedMemoryErr(fmt.Sprintf("unknown context state: %v", ctxState))
	}

	return false, false, nil
}

func (s *subprocess) waitOnState(ctx *sharedContext) error {
	ctx.kicked = false
	slowPath := false
	if !s.contextQueue.fastPathEnabled() || atomic.LoadUint32(&s.contextQueue.numActiveThreads) == 0 {
		ctx.kicked = s.kickSysmsgThread()
	}
	for curState := ctx.state(); curState == sysmsg.ContextStateNone; curState = ctx.state() {
		if !slowPath {
			events := dispatcher.waitFor(ctx)
			if events&sharedContextKicked != 0 {
				if ctx.kicked {
					continue
				}
				if ctx.isAcked() {
					ctx.kicked = true
					continue
				}
				s.kickSysmsgThread()
				ctx.kicked = true
				continue
			}
			if events&sharedContextSlowPath != 0 {
				ctx.disableSentryFastPath()
				slowPath = true
				continue
			}
		} else {
			// If the context already received a handshake then it knows it's being
			// worked on.
			if !ctx.kicked && !ctx.isAcked() {
				ctx.kicked = s.kickSysmsgThread()
			}

			if err := ctx.sleepOnState(curState); err != nil {
				return err
			}
		}
	}

	ctx.recordLatency()
	ctx.resetLatencyMeasures()
	ctx.enableSentryFastPath()

	return nil
}

// canKickSysmsgThread returns true if a new thread can be kicked.
// The second return value is the expected number of threads after kicking a
// new one.
func (s *subprocess) canKickSysmsgThread() (bool, uint32) {
	// numActiveContexts and numActiveThreads can be changed from stub
	// threads that handles the contextQueue without any locks. The idea
	// here is that any stub thread that gets CPU time can make some
	// progress. In stub threads, we can use only spinlock-like
	// synchronizations, but they don't work well because a thread that
	// holds a lock can be preempted by another thread that is waiting for
	// the same lock.
	nrActiveThreads := atomic.LoadUint32(&s.contextQueue.numActiveThreads)
	nrThreadsToWakeup := atomic.LoadUint32(&s.contextQueue.numThreadsToWakeup)
	nrActiveContexts := atomic.LoadUint32(&s.contextQueue.numActiveContexts)

	nrActiveThreads += nrThreadsToWakeup + 1
	if nrActiveThreads > nrActiveContexts {
		// This can happen when one or more stub threads are
		// waiting for cpu time. The host probably has more
		// running tasks than a number of cpu-s.
		return false, nrActiveThreads
	}
	return true, nrActiveThreads
}

// kickSysmsgThread returns true if it was able to wake up or create a new sysmsg
// stub thread.
func (s *subprocess) kickSysmsgThread() bool {
	kick, _ := s.canKickSysmsgThread()
	if !kick {
		return false
	}

	s.sysmsgThreadsMu.Lock()
	kick, nrThreads := s.canKickSysmsgThread()
	if !kick {
		s.sysmsgThreadsMu.Unlock()
		return false
	}
	numTimesStubKicked.Increment()
	atomic.AddUint32(&s.contextQueue.numThreadsToWakeup, 1)
	if s.numSysmsgThreads < maxSysmsgThreads && s.numSysmsgThreads < int(nrThreads) {
		s.numSysmsgThreads++
		s.sysmsgThreadsMu.Unlock()
		if err := s.createSysmsgThread(); err != nil {
			log.Warningf("Unable to create a new stub thread: %s", err)
			s.sysmsgThreadsMu.Lock()
			s.numSysmsgThreads--
			s.sysmsgThreadsMu.Unlock()
		}
	} else {
		s.sysmsgThreadsMu.Unlock()
	}
	s.contextQueue.wakeupSysmsgThread()

	return true
}

// syscall executes the given system call without handling interruptions.
func (s *subprocess) syscall(sysno uintptr, args ...arch.SyscallArgument) (uintptr, error) {
	s.syscallThreadMu.Lock()
	defer s.syscallThreadMu.Unlock()

	return s.syscallThread.syscall(sysno, args...)
}

// MapFile implements platform.AddressSpace.MapFile.
func (s *subprocess) MapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, precommit bool) error {
	var flags int
	if precommit {
		flags |= unix.MAP_POPULATE
	}
	_, err := s.syscall(
		unix.SYS_MMAP,
		arch.SyscallArgument{Value: uintptr(addr)},
		arch.SyscallArgument{Value: uintptr(fr.Length())},
		arch.SyscallArgument{Value: uintptr(at.Prot())},
		arch.SyscallArgument{Value: uintptr(flags | unix.MAP_SHARED | unix.MAP_FIXED)},
		arch.SyscallArgument{Value: uintptr(f.FD())},
		arch.SyscallArgument{Value: uintptr(fr.Start)})
	return err
}

// Unmap implements platform.AddressSpace.Unmap.
func (s *subprocess) Unmap(addr hostarch.Addr, length uint64) {
	ar, ok := addr.ToRange(length)
	if !ok {
		panic(fmt.Sprintf("addr %#x + length %#x overflows", addr, length))
	}
	s.mu.Lock()
	for c := range s.faultedContexts {
		c.mu.Lock()
		if c.lastFaultSP == s && ar.Contains(c.lastFaultAddr) {
			// Forget the last fault so that if c faults again, the fault isn't
			// incorrectly reported as a write fault. If this is being called
			// due to munmap() of the corresponding vma, handling of the second
			// fault will fail anyway.
			c.lastFaultSP = nil
			delete(s.faultedContexts, c)
		}
		c.mu.Unlock()
	}
	s.mu.Unlock()
	_, err := s.syscall(
		unix.SYS_MUNMAP,
		arch.SyscallArgument{Value: uintptr(addr)},
		arch.SyscallArgument{Value: uintptr(length)})
	if err != nil && err != errDeadSubprocess {
		// We never expect this to happen.
		panic(fmt.Sprintf("munmap(%x, %x)) failed: %v", addr, length, err))
	}
}

func (s *subprocess) PullFullState(c *platformContext, ac *arch.Context64) error {
	if !c.sharedContext.isActiveInSubprocess(s) {
		panic("Attempted to PullFullState for context that is not used in subprocess")
	}
	saveFPState(c.sharedContext, ac)
	return nil
}

var (
	sysmsgThreadPriorityOnce sync.Once
	sysmsgThreadPriority     int
)

// initSysmsgThreadPriority looks at the current priority of the process
// and updates `sysmsgThreadPriority` accordingly.
func initSysmsgThreadPriority() {
	sysmsgThreadPriorityOnce.Do(func() {
		prio, err := unix.Getpriority(unix.PRIO_PROCESS, 0)
		if err != nil {
			panic("unable to get current scheduling priority")
		}
		// Sysmsg threads are executed with a priority one lower than the Sentry.
		sysmsgThreadPriority = 20 - prio + 1
	})
}

// createSysmsgThread creates a new sysmsg thread.
// The thread starts processing any available context in the context queue.
func (s *subprocess) createSysmsgThread() error {
	// Create a new seccomp process.
	var r requestThread
	r.thread = make(chan *thread)
	s.requests <- r
	p := <-r.thread
	if p == nil {
		return fmt.Errorf("createSysmsgThread: failed to get clone")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := p.attach(); err != nil {
		return err
	}

	// Skip SIGSTOP.
	if _, _, errno := unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_CONT, uintptr(p.tid), 0, 0, 0, 0); errno != 0 {
		panic(fmt.Sprintf("ptrace cont failed: %v", errno))
	}
	sig := p.wait(stopped)
	if sig != unix.SIGSTOP {
		panic(fmt.Sprintf("error waiting for new clone: expected SIGSTOP, got %v", sig))
	}

	// Allocate a new stack for the BPF process.
	opts := pgalloc.AllocOpts{
		Kind: usage.System,
		Dir:  pgalloc.TopDown,
	}
	fr, err := s.memoryFile.Allocate(uint64(sysmsg.PerThreadSharedStackSize), opts)
	if err != nil {
		// TODO(b/144063246): Need to fail the clone system call.
		panic(fmt.Sprintf("failed to allocate a new stack: %v", err))
	}
	sysThread := &sysmsgThread{
		thread:     p,
		subproc:    s,
		stackRange: fr,
	}
	// Use the sysmsgStackID as a handle on this thread instead of host tid in
	// order to be able to reliably specify invalidThreadID.
	threadID := uint32(p.sysmsgStackID)

	// Map the stack into the sentry.
	sentryStackAddr, _, errno := unix.RawSyscall6(
		unix.SYS_MMAP,
		0,
		sysmsg.PerThreadSharedStackSize,
		unix.PROT_WRITE|unix.PROT_READ,
		unix.MAP_SHARED|unix.MAP_FILE,
		uintptr(s.memoryFile.FD()), uintptr(fr.Start))
	if errno != 0 {
		panic(fmt.Sprintf("mmap failed: %v", errno))
	}

	// Before installing the stub syscall filters, we need to call a few
	// system calls (e.g. sigaltstack, sigaction) which have in-memory
	// arguments.  We need to prevent changing these parameters by other
	// stub threads, so lets map the future BPF stack as read-only and
	// fill syscall arguments from the Sentry.
	sysmsgStackAddr := sysThread.sysmsgPerThreadMemAddr() + sysmsg.PerThreadSharedStackOffset
	err = sysThread.mapStack(sysmsgStackAddr, true)
	if err != nil {
		panic(fmt.Sprintf("mmap failed: %v", err))
	}

	sysThread.init(sentryStackAddr, sysmsgStackAddr)

	// Map the stack into the BPF process.
	err = sysThread.mapStack(sysmsgStackAddr, false)
	if err != nil {
		s.memoryFile.DecRef(fr)
		panic(fmt.Sprintf("mmap failed: %v", err))
	}

	// Map the stack into the BPF process.
	privateStackAddr := sysThread.sysmsgPerThreadMemAddr() + sysmsg.PerThreadPrivateStackOffset
	err = sysThread.mapPrivateStack(privateStackAddr, sysmsg.PerThreadPrivateStackSize)
	if err != nil {
		s.memoryFile.DecRef(fr)
		panic(fmt.Sprintf("mmap failed: %v", err))
	}

	sysThread.setMsg(sysmsg.StackAddrToMsg(sentryStackAddr))
	sysThread.msg.Init(threadID)
	sysThread.msg.Self = uint64(sysmsgStackAddr + sysmsg.MsgOffsetFromSharedStack)
	sysThread.msg.SyshandlerStack = uint64(sysmsg.StackAddrToSyshandlerStack(sysThread.sysmsgPerThreadMemAddr()))
	sysThread.msg.Syshandler = uint64(stubSysmsgStart + uintptr(sysmsg.Sighandler_blob_offset____export_syshandler))

	sysThread.msg.State.Set(sysmsg.ThreadStateInitializing)

	if err := unix.Setpriority(unix.PRIO_PROCESS, int(p.tid), sysmsgThreadPriority); err != nil {
		log.Warningf("Unable to change priority of a stub thread: %s", err)
	}

	// Install a pre-compiled seccomp rules for the BPF process.
	_, err = p.syscallIgnoreInterrupt(&p.initRegs, unix.SYS_PRCTL,
		arch.SyscallArgument{Value: uintptr(linux.PR_SET_NO_NEW_PRIVS)},
		arch.SyscallArgument{Value: uintptr(1)},
		arch.SyscallArgument{Value: uintptr(0)},
		arch.SyscallArgument{Value: uintptr(0)},
		arch.SyscallArgument{Value: uintptr(0)},
		arch.SyscallArgument{Value: uintptr(0)})
	if err != nil {
		panic(fmt.Sprintf("prctl(PR_SET_NO_NEW_PRIVS) failed: %v", err))
	}

	_, err = p.syscallIgnoreInterrupt(&p.initRegs, seccomp.SYS_SECCOMP,
		arch.SyscallArgument{Value: uintptr(linux.SECCOMP_SET_MODE_FILTER)},
		arch.SyscallArgument{Value: uintptr(0)},
		arch.SyscallArgument{Value: stubSysmsgRules})
	if err != nil {
		panic(fmt.Sprintf("seccomp failed: %v", err))
	}

	// Prepare to start the BPF process.
	tregs := &arch.Registers{}
	s.resetSysemuRegs(tregs)
	setArchSpecificRegs(sysThread, tregs)
	if err := p.setRegs(tregs); err != nil {
		panic(fmt.Sprintf("ptrace set regs failed: %v", err))
	}
	archSpecificSysmsgThreadInit(sysThread)
	// Skip SIGSTOP.
	if _, _, e := unix.RawSyscall(unix.SYS_TGKILL, uintptr(p.tgid), uintptr(p.tid), uintptr(unix.SIGCONT)); e != 0 {
		panic(fmt.Sprintf("tkill failed: %v", e))
	}
	// Resume the BPF process.
	if _, _, errno := unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(p.tid), 0, 0, 0, 0); errno != 0 {
		panic(fmt.Sprintf("can't detach new clone: %v", errno))
	}

	s.sysmsgThreadsMu.Lock()
	s.sysmsgThreads[threadID] = sysThread
	s.sysmsgThreadsMu.Unlock()

	return nil
}

// PreFork implements platform.AddressSpace.PreFork.
// We need to take the usertrap lock to be sure that fork() will not be in the
// middle of applying a binary patch.
func (s *subprocess) PreFork() {
	s.usertrap.PreFork()
}

// PostFork implements platform.AddressSpace.PostFork.
func (s *subprocess) PostFork() {
	s.usertrap.PostFork() // +checklocksforce: PreFork acquires, above.
}

// activateContext activates the context in this subprocess.
// No-op if the context is already active within the subprocess; if not,
// deactivates it from its last subprocess.
func (s *subprocess) activateContext(c *platformContext) error {
	if !c.sharedContext.isActiveInSubprocess(s) {
		c.sharedContext.release()
		c.sharedContext = nil

		shared, err := s.getSharedContext()
		if err != nil {
			return err
		}
		c.sharedContext = shared
	}
	return nil
}
