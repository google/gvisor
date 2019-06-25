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

package ptrace

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/procid"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// globalPool exists to solve two distinct problems:
//
// 1) Subprocesses can't always be killed properly (see Release).
//
// 2) Any seccomp filters that have been installed will apply to subprocesses
// created here. Therefore we use the intermediary (master), which is created
// on initialization of the platform.
var globalPool struct {
	mu        sync.Mutex
	master    *subprocess
	available []*subprocess
}

// thread is a traced thread; it is a thread identifier.
//
// This is a convenience type for defining ptrace operations.
type thread struct {
	tgid int32
	tid  int32
	cpu  uint32

	// initRegs are the initial registers for the first thread.
	//
	// These are used for the register set for system calls.
	initRegs syscall.PtraceRegs
}

// threadPool is a collection of threads.
type threadPool struct {
	// mu protects below.
	mu sync.Mutex

	// threads is the collection of threads.
	//
	// This map is indexed by system TID (the calling thread); which will
	// be the tracer for the given *thread, and therefore capable of using
	// relevant ptrace calls.
	threads map[int32]*thread
}

// lookupOrCreate looks up a given thread or creates one.
//
// newThread will generally be subprocess.newThread.
//
// Precondition: the runtime OS thread must be locked.
func (tp *threadPool) lookupOrCreate(currentTID int32, newThread func() *thread) *thread {
	tp.mu.Lock()
	t, ok := tp.threads[currentTID]
	if !ok {
		// Before creating a new thread, see if we can find a thread
		// whose system tid has disappeared.
		//
		// TODO(b/77216482): Other parts of this package depend on
		// threads never exiting.
		for origTID, t := range tp.threads {
			// Signal zero is an easy existence check.
			if err := syscall.Tgkill(syscall.Getpid(), int(origTID), 0); err != nil {
				// This thread has been abandoned; reuse it.
				delete(tp.threads, origTID)
				tp.threads[currentTID] = t
				tp.mu.Unlock()
				return t
			}
		}

		// Create a new thread.
		t = newThread()
		tp.threads[currentTID] = t
	}
	tp.mu.Unlock()
	return t
}

// subprocess is a collection of threads being traced.
type subprocess struct {
	platform.NoAddressSpaceIO

	// requests is used to signal creation of new threads.
	requests chan chan *thread

	// sysemuThreads are reserved for emulation.
	sysemuThreads threadPool

	// syscallThreads are reserved for syscalls (except clone, which is
	// handled in the dedicated goroutine corresponding to requests above).
	syscallThreads threadPool

	// mu protects the following fields.
	mu sync.Mutex

	// contexts is the set of contexts for which it's possible that
	// context.lastFaultSP == this subprocess.
	contexts map[*context]struct{}
}

// newSubprocess returns a useable subprocess.
//
// This will either be a newly created subprocess, or one from the global pool.
// The create function will be called in the latter case, which is guaranteed
// to happen with the runtime thread locked.
func newSubprocess(create func() (*thread, error)) (*subprocess, error) {
	// See Release.
	globalPool.mu.Lock()
	if len(globalPool.available) > 0 {
		sp := globalPool.available[len(globalPool.available)-1]
		globalPool.available = globalPool.available[:len(globalPool.available)-1]
		globalPool.mu.Unlock()
		return sp, nil
	}
	globalPool.mu.Unlock()

	// The following goroutine is responsible for creating the first traced
	// thread, and responding to requests to make additional threads in the
	// traced process. The process will be killed and reaped when the
	// request channel is closed, which happens in Release below.
	errChan := make(chan error)
	requests := make(chan chan *thread)
	go func() { // S/R-SAFE: Platform-related.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Initialize the first thread.
		firstThread, err := create()
		if err != nil {
			errChan <- err
			return
		}

		// Ready to handle requests.
		errChan <- nil

		// Wait for requests to create threads.
		for r := range requests {
			t, err := firstThread.clone()
			if err != nil {
				// Should not happen: not recoverable.
				panic(fmt.Sprintf("error initializing first thread: %v", err))
			}

			// Since the new thread was created with
			// clone(CLONE_PTRACE), it will begin execution with
			// SIGSTOP pending and with this thread as its tracer.
			// (Hopefully nobody tgkilled it with a signal <
			// SIGSTOP before the SIGSTOP was delivered, in which
			// case that signal would be delivered before SIGSTOP.)
			if sig := t.wait(stopped); sig != syscall.SIGSTOP {
				panic(fmt.Sprintf("error waiting for new clone: expected SIGSTOP, got %v", sig))
			}

			// Detach the thread.
			t.detach()

			// Return the thread.
			r <- t
		}

		// Requests should never be closed.
		panic("unreachable")
	}()

	// Wait until error or readiness.
	if err := <-errChan; err != nil {
		return nil, err
	}

	// Ready.
	sp := &subprocess{
		requests: requests,
		sysemuThreads: threadPool{
			threads: make(map[int32]*thread),
		},
		syscallThreads: threadPool{
			threads: make(map[int32]*thread),
		},
		contexts: make(map[*context]struct{}),
	}

	sp.unmap()
	return sp, nil
}

// unmap unmaps non-stub regions of the process.
//
// This will panic on failure (which should never happen).
func (s *subprocess) unmap() {
	s.Unmap(0, uint64(stubStart))
	if maximumUserAddress != stubEnd {
		s.Unmap(usermem.Addr(stubEnd), uint64(maximumUserAddress-stubEnd))
	}
}

// Release kills the subprocess.
//
// Just kidding! We can't safely co-ordinate the detaching of all the
// tracees (since the tracers are random runtime threads, and the process
// won't exit until tracers have been notifier).
//
// Therefore we simply unmap everything in the subprocess and return it to the
// globalPool. This has the added benefit of reducing creation time for new
// subprocesses.
func (s *subprocess) Release() {
	go func() { // S/R-SAFE: Platform.
		s.unmap()
		globalPool.mu.Lock()
		globalPool.available = append(globalPool.available, s)
		globalPool.mu.Unlock()
	}()
}

// newThread creates a new traced thread.
//
// Precondition: the OS thread must be locked.
func (s *subprocess) newThread() *thread {
	// Ask the first thread to create a new one.
	r := make(chan *thread)
	s.requests <- r
	t := <-r

	// Attach the subprocess to this one.
	t.attach()

	// Return the new thread, which is now bound.
	return t
}

// attach attachs to the thread.
func (t *thread) attach() {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PTRACE, syscall.PTRACE_ATTACH, uintptr(t.tid), 0); errno != 0 {
		panic(fmt.Sprintf("unable to attach: %v", errno))
	}

	// PTRACE_ATTACH sends SIGSTOP, and wakes the tracee if it was already
	// stopped from the SIGSTOP queued by CLONE_PTRACE (see inner loop of
	// newSubprocess), so we always expect to see signal-delivery-stop with
	// SIGSTOP.
	if sig := t.wait(stopped); sig != syscall.SIGSTOP {
		panic(fmt.Sprintf("wait failed: expected SIGSTOP, got %v", sig))
	}

	// Initialize options.
	t.init()

	// Grab registers.
	//
	// Note that we adjust the current register RIP value to be just before
	// the current system call executed. This depends on the definition of
	// the stub itself.
	if err := t.getRegs(&t.initRegs); err != nil {
		panic(fmt.Sprintf("ptrace get regs failed: %v", err))
	}
	t.initRegs.Rip -= initRegsRipAdjustment
}

// detach detachs from the thread.
//
// Because the SIGSTOP is not supressed, the thread will enter group-stop.
func (t *thread) detach() {
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PTRACE, syscall.PTRACE_DETACH, uintptr(t.tid), 0, uintptr(syscall.SIGSTOP), 0, 0); errno != 0 {
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

func (t *thread) dumpAndPanic(message string) {
	var regs syscall.PtraceRegs
	message += "\n"
	if err := t.getRegs(&regs); err == nil {
		message += dumpRegs(&regs)
	} else {
		log.Warningf("unable to get registers: %v", err)
	}
	message += fmt.Sprintf("stubStart\t = %016x\n", stubStart)
	panic(message)
}

// wait waits for a stop event.
//
// Precondition: outcome is a valid waitOutcome.
func (t *thread) wait(outcome waitOutcome) syscall.Signal {
	var status syscall.WaitStatus

	for {
		r, err := syscall.Wait4(int(t.tid), &status, syscall.WALL|syscall.WUNTRACED, nil)
		if err == syscall.EINTR || err == syscall.EAGAIN {
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
			if stopSig == syscall.SIGTRAP {
				// Re-encode the trap cause the way it's expected.
				return stopSig | syscall.Signal(status.TrapCause()<<8)
			}
			// Not a trap signal.
			return stopSig
		case killed:
			if !status.Exited() && !status.Signaled() {
				t.dumpAndPanic(fmt.Sprintf("ptrace status unexpected: got %v, wanted exited", status))
			}
			return syscall.Signal(status.ExitStatus())
		default:
			// Should not happen.
			t.dumpAndPanic(fmt.Sprintf("unknown outcome: %v", outcome))
		}
	}
}

// destroy kills the thread.
//
// Note that this should not be used in the general case; the death of threads
// will typically cause the death of the parent. This is a utility method for
// manually created threads.
func (t *thread) destroy() {
	t.detach()
	syscall.Tgkill(int(t.tgid), int(t.tid), syscall.Signal(syscall.SIGKILL))
	t.wait(killed)
}

// init initializes trace options.
func (t *thread) init() {
	// Set our TRACESYSGOOD option to differeniate real SIGTRAP. We also
	// set PTRACE_O_EXITKILL to ensure that the unexpected exit of the
	// sentry will immediately kill the associated stubs.
	const PTRACE_O_EXITKILL = 0x100000
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PTRACE,
		syscall.PTRACE_SETOPTIONS,
		uintptr(t.tid),
		0,
		syscall.PTRACE_O_TRACESYSGOOD|syscall.PTRACE_O_TRACEEXIT|PTRACE_O_EXITKILL,
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
func (t *thread) syscall(regs *syscall.PtraceRegs) (uintptr, error) {
	// Set registers.
	if err := t.setRegs(regs); err != nil {
		panic(fmt.Sprintf("ptrace set regs failed: %v", err))
	}

	for {
		// Execute the syscall instruction.
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PTRACE, syscall.PTRACE_SYSCALL, uintptr(t.tid), 0); errno != 0 {
			panic(fmt.Sprintf("ptrace syscall-enter failed: %v", errno))
		}

		sig := t.wait(stopped)
		if sig == (syscallEvent | syscall.SIGTRAP) {
			// Reached syscall-enter-stop.
			break
		} else {
			// Some other signal caused a thread stop; ignore.
			continue
		}
	}

	// Complete the actual system call.
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PTRACE, syscall.PTRACE_SYSCALL, uintptr(t.tid), 0); errno != 0 {
		panic(fmt.Sprintf("ptrace syscall-enter failed: %v", errno))
	}

	// Wait for syscall-exit-stop. "[Signal-delivery-stop] never happens
	// between syscall-enter-stop and syscall-exit-stop; it happens *after*
	// syscall-exit-stop.)" - ptrace(2), "Syscall-stops"
	if sig := t.wait(stopped); sig != (syscallEvent | syscall.SIGTRAP) {
		t.dumpAndPanic(fmt.Sprintf("wait failed: expected SIGTRAP, got %v [%d]", sig, sig))
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
	initRegs *syscall.PtraceRegs,
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
	syscall.Tgkill(int(t.tgid), int(t.tid), syscall.Signal(platform.SignalInterrupt))
}

// switchToApp is called from the main SwitchToApp entrypoint.
//
// This function returns true on a system call, false on a signal.
func (s *subprocess) switchToApp(c *context, ac arch.Context) bool {
	// Lock the thread for ptrace operations.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Extract floating point state.
	fpState := ac.FloatingPointData()
	fpLen, _ := ac.FeatureSet().ExtendedStateSize()
	useXsave := ac.FeatureSet().UseXsave()

	// Grab our thread from the pool.
	currentTID := int32(procid.Current())
	t := s.sysemuThreads.lookupOrCreate(currentTID, s.newThread)

	// Reset necessary registers.
	regs := &ac.StateData().Regs
	t.resetSysemuRegs(regs)

	// Check for interrupts, and ensure that future interrupts will signal t.
	if !c.interrupt.Enable(t) {
		// Pending interrupt; simulate.
		c.signalInfo = arch.SignalInfo{Signo: int32(platform.SignalInterrupt)}
		return false
	}
	defer c.interrupt.Disable()

	// Ensure that the CPU set is bound appropriately; this makes the
	// emulation below several times faster, presumably by avoiding
	// interprocessor wakeups and by simplifying the schedule.
	t.bind()

	// Set registers.
	if err := t.setRegs(regs); err != nil {
		panic(fmt.Sprintf("ptrace set regs (%+v) failed: %v", regs, err))
	}
	if err := t.setFPRegs(fpState, uint64(fpLen), useXsave); err != nil {
		panic(fmt.Sprintf("ptrace set fpregs (%+v) failed: %v", fpState, err))
	}

	for {
		// Start running until the next system call.
		if isSingleStepping(regs) {
			if _, _, errno := syscall.RawSyscall(
				syscall.SYS_PTRACE,
				syscall.PTRACE_SYSEMU_SINGLESTEP,
				uintptr(t.tid), 0); errno != 0 {
				panic(fmt.Sprintf("ptrace sysemu failed: %v", errno))
			}
		} else {
			if _, _, errno := syscall.RawSyscall(
				syscall.SYS_PTRACE,
				syscall.PTRACE_SYSEMU,
				uintptr(t.tid), 0); errno != 0 {
				panic(fmt.Sprintf("ptrace sysemu failed: %v", errno))
			}
		}

		// Wait for the syscall-enter stop.
		sig := t.wait(stopped)

		// Refresh all registers.
		if err := t.getRegs(regs); err != nil {
			panic(fmt.Sprintf("ptrace get regs failed: %v", err))
		}
		if err := t.getFPRegs(fpState, uint64(fpLen), useXsave); err != nil {
			panic(fmt.Sprintf("ptrace get fpregs failed: %v", err))
		}

		// Is it a system call?
		if sig == (syscallEvent | syscall.SIGTRAP) {
			// Ensure registers are sane.
			updateSyscallRegs(regs)
			return true
		} else if sig == syscall.SIGSTOP {
			// SIGSTOP was delivered to another thread in the same thread
			// group, which initiated another group stop. Just ignore it.
			continue
		}

		// Grab signal information.
		if err := t.getSignalInfo(&c.signalInfo); err != nil {
			// Should never happen.
			panic(fmt.Sprintf("ptrace get signal info failed: %v", err))
		}

		// We have a signal. We verify however, that the signal was
		// either delivered from the kernel or from this process. We
		// don't respect other signals.
		if c.signalInfo.Code > 0 {
			// The signal was generated by the kernel. We inspect
			// the signal information, and may patch it in order to
			// faciliate vsyscall emulation. See patchSignalInfo.
			patchSignalInfo(regs, &c.signalInfo)
			return false
		} else if c.signalInfo.Code <= 0 && c.signalInfo.Pid() == int32(os.Getpid()) {
			// The signal was generated by this process. That means
			// that it was an interrupt or something else that we
			// should bail for. Note that we ignore signals
			// generated by other processes.
			return false
		}
	}
}

// syscall executes the given system call without handling interruptions.
func (s *subprocess) syscall(sysno uintptr, args ...arch.SyscallArgument) (uintptr, error) {
	// Grab a thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	currentTID := int32(procid.Current())
	t := s.syscallThreads.lookupOrCreate(currentTID, s.newThread)

	return t.syscallIgnoreInterrupt(&t.initRegs, sysno, args...)
}

// MapFile implements platform.AddressSpace.MapFile.
func (s *subprocess) MapFile(addr usermem.Addr, f platform.File, fr platform.FileRange, at usermem.AccessType, precommit bool) error {
	var flags int
	if precommit {
		flags |= syscall.MAP_POPULATE
	}
	_, err := s.syscall(
		syscall.SYS_MMAP,
		arch.SyscallArgument{Value: uintptr(addr)},
		arch.SyscallArgument{Value: uintptr(fr.Length())},
		arch.SyscallArgument{Value: uintptr(at.Prot())},
		arch.SyscallArgument{Value: uintptr(flags | syscall.MAP_SHARED | syscall.MAP_FIXED)},
		arch.SyscallArgument{Value: uintptr(f.FD())},
		arch.SyscallArgument{Value: uintptr(fr.Start)})
	return err
}

// Unmap implements platform.AddressSpace.Unmap.
func (s *subprocess) Unmap(addr usermem.Addr, length uint64) {
	ar, ok := addr.ToRange(length)
	if !ok {
		panic(fmt.Sprintf("addr %#x + length %#x overflows", addr, length))
	}
	s.mu.Lock()
	for c := range s.contexts {
		c.mu.Lock()
		if c.lastFaultSP == s && ar.Contains(c.lastFaultAddr) {
			// Forget the last fault so that if c faults again, the fault isn't
			// incorrectly reported as a write fault. If this is being called
			// due to munmap() of the corresponding vma, handling of the second
			// fault will fail anyway.
			c.lastFaultSP = nil
			delete(s.contexts, c)
		}
		c.mu.Unlock()
	}
	s.mu.Unlock()
	_, err := s.syscall(
		syscall.SYS_MUNMAP,
		arch.SyscallArgument{Value: uintptr(addr)},
		arch.SyscallArgument{Value: uintptr(length)})
	if err != nil {
		// We never expect this to happen.
		panic(fmt.Sprintf("munmap(%x, %x)) failed: %v", addr, length, err))
	}
}
