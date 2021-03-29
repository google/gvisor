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
	"bytes"
	"fmt"
	"runtime"
	"runtime/trace"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/goid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/hostcpu"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/syserror"
)

// A taskRunState is a reified state in the task state machine. See README.md
// for details. The canonical list of all run states, as well as transitions
// between them, is given in run_states.dot.
//
// The set of possible states is enumerable and completely defined by the
// kernel package, so taskRunState would ideally be represented by a
// discriminated union. However, Go does not support sum types.
//
// Hence, as with TaskStop, data-free taskRunStates should be represented as
// typecast nils to avoid unnecessary allocation.
type taskRunState interface {
	// execute executes the code associated with this state over the given task
	// and returns the following state. If execute returns nil, the task
	// goroutine should exit.
	//
	// It is valid to tail-call a following state's execute to avoid the
	// overhead of converting the following state to an interface object and
	// checking for stops, provided that the tail-call cannot recurse.
	execute(*Task) taskRunState
}

// run runs the task goroutine.
//
// threadID a dummy value set to the task's TID in the root PID namespace to
// make it visible in stack dumps. A goroutine for a given task can be identified
// searching for Task.run()'s argument value.
func (t *Task) run(threadID uintptr) {
	atomic.StoreInt64(&t.goid, goid.Get())

	// Construct t.blockingTimer here. We do this here because we can't
	// reconstruct t.blockingTimer during restore in Task.afterLoad(), because
	// kernel.timekeeper.SetClocks() hasn't been called yet.
	blockingTimerNotifier, blockingTimerChan := ktime.NewChannelNotifier()
	t.blockingTimer = ktime.NewTimer(t.k.MonotonicClock(), blockingTimerNotifier)
	defer t.blockingTimer.Destroy()
	t.blockingTimerChan = blockingTimerChan

	// Activate our address space.
	t.Activate()
	// The corresponding t.Deactivate occurs in the exit path
	// (runExitMain.execute) so that when
	// Platform.CooperativelySharesAddressSpace() == true, we give up the
	// AddressSpace before the task goroutine finishes executing.

	// If this is a newly-started task, it should check for participation in
	// group stops. If this is a task resuming after restore, it was
	// interrupted by saving. In either case, the task is initially
	// interrupted.
	t.interruptSelf()

	for {
		// Explanation for this ordering:
		//
		// - A freshly-started task that is stopped should not do anything
		// before it enters the stop.
		//
		// - If taskRunState.execute returns nil, the task goroutine should
		// exit without checking for a stop.
		//
		// - Task.Start won't start Task.run if t.runState is nil, so this
		// ordering is safe.
		t.doStop()
		t.runState = t.runState.execute(t)
		if t.runState == nil {
			t.accountTaskGoroutineEnter(TaskGoroutineNonexistent)
			t.goroutineStopped.Done()
			t.tg.liveGoroutines.Done()
			t.tg.pidns.owner.liveGoroutines.Done()
			t.tg.pidns.owner.runningGoroutines.Done()
			t.p.Release()

			// Deferring this store triggers a false positive in the race
			// detector (https://github.com/golang/go/issues/42599).
			atomic.StoreInt64(&t.goid, 0)
			// Keep argument alive because stack trace for dead variables may not be correct.
			runtime.KeepAlive(threadID)
			return
		}
	}
}

// doStop is called by Task.run to block until the task is not stopped.
func (t *Task) doStop() {
	if atomic.LoadInt32(&t.stopCount) == 0 {
		return
	}
	t.Deactivate()
	// NOTE(b/30316266): t.Activate() must be called without any locks held, so
	// this defer must precede the defer for unlocking the signal mutex.
	defer t.Activate()
	t.accountTaskGoroutineEnter(TaskGoroutineStopped)
	defer t.accountTaskGoroutineLeave(TaskGoroutineStopped)
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	t.tg.pidns.owner.runningGoroutines.Add(-1)
	defer t.tg.pidns.owner.runningGoroutines.Add(1)
	t.goroutineStopped.Add(-1)
	defer t.goroutineStopped.Add(1)
	for t.stopCount > 0 {
		t.endStopCond.Wait()
	}
}

func (*runApp) handleCPUIDInstruction(t *Task) error {
	if len(arch.CPUIDInstruction) == 0 {
		// CPUID emulation isn't supported, but this code can be
		// executed, because the ptrace platform returns
		// ErrContextSignalCPUID on page faults too. Look at
		// pkg/sentry/platform/ptrace/ptrace.go:context.Switch for more
		// details.
		return platform.ErrContextSignal
	}
	// Is this a CPUID instruction?
	region := trace.StartRegion(t.traceContext, cpuidRegion)
	expected := arch.CPUIDInstruction[:]
	found := make([]byte, len(expected))
	_, err := t.CopyInBytes(hostarch.Addr(t.Arch().IP()), found)
	if err == nil && bytes.Equal(expected, found) {
		// Skip the cpuid instruction.
		t.Arch().CPUIDEmulate(t)
		t.Arch().SetIP(t.Arch().IP() + uintptr(len(expected)))
		region.End()

		return nil
	}
	region.End() // Not an actual CPUID, but required copy-in.
	return platform.ErrContextSignal
}

// The runApp state checks for interrupts before executing untrusted
// application code.
//
// +stateify savable
type runApp struct{}

func (app *runApp) execute(t *Task) taskRunState {
	if t.interrupted() {
		// Checkpointing instructs tasks to stop by sending an interrupt, so we
		// must check for stops before entering runInterrupt (instead of
		// tail-calling it).
		return (*runInterrupt)(nil)
	}

	// Execute any task work callbacks before returning to user space.
	if atomic.LoadInt32(&t.taskWorkCount) > 0 {
		t.taskWorkMu.Lock()
		queue := t.taskWork
		t.taskWork = nil
		atomic.StoreInt32(&t.taskWorkCount, 0)
		t.taskWorkMu.Unlock()

		// Do not hold taskWorkMu while executing task work, which may register
		// more work.
		for _, work := range queue {
			work.TaskWork(t)
		}
	}

	// We're about to switch to the application again. If there's still an
	// unhandled SyscallRestartErrno that wasn't translated to an EINTR,
	// restart the syscall that was interrupted. If there's a saved signal
	// mask, restore it. (Note that restoring the saved signal mask may unblock
	// a pending signal, causing another interruption, but that signal should
	// not interact with the interrupted syscall.)
	if t.haveSyscallReturn {
		if sre, ok := syserror.SyscallRestartErrnoFromReturn(t.Arch().Return()); ok {
			if sre == syserror.ERESTART_RESTARTBLOCK {
				t.Debugf("Restarting syscall %d with restart block after errno %d: not interrupted by handled signal", t.Arch().SyscallNo(), sre)
				t.Arch().RestartSyscallWithRestartBlock()
			} else {
				t.Debugf("Restarting syscall %d after errno %d: not interrupted by handled signal", t.Arch().SyscallNo(), sre)
				t.Arch().RestartSyscall()
			}
		}
		t.haveSyscallReturn = false
	}
	if t.haveSavedSignalMask {
		t.SetSignalMask(t.savedSignalMask)
		t.haveSavedSignalMask = false
		if t.interrupted() {
			return (*runInterrupt)(nil)
		}
	}

	// Apply restartable sequences.
	if t.rseqPreempted {
		t.rseqPreempted = false
		if t.rseqAddr != 0 || t.oldRSeqCPUAddr != 0 {
			// Linux writes the CPU on every preemption. We only do
			// so if it changed. Thus we may delay delivery of
			// SIGSEGV if rseqAddr/oldRSeqCPUAddr is invalid.
			cpu := int32(hostcpu.GetCPU())
			if t.rseqCPU != cpu {
				t.rseqCPU = cpu
				if err := t.rseqCopyOutCPU(); err != nil {
					t.Debugf("Failed to copy CPU to %#x for rseq: %v", t.rseqAddr, err)
					t.forceSignal(linux.SIGSEGV, false)
					t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
					// Re-enter the task run loop for signal delivery.
					return (*runApp)(nil)
				}
				if err := t.oldRSeqCopyOutCPU(); err != nil {
					t.Debugf("Failed to copy CPU to %#x for old rseq: %v", t.oldRSeqCPUAddr, err)
					t.forceSignal(linux.SIGSEGV, false)
					t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
					// Re-enter the task run loop for signal delivery.
					return (*runApp)(nil)
				}
			}
		}
		t.rseqInterrupt()
	}

	// Check if we need to enable single-stepping. Tracers expect that the
	// kernel preserves the value of the single-step flag set by PTRACE_SETREGS
	// whether or not PTRACE_SINGLESTEP/PTRACE_SYSEMU_SINGLESTEP is used (this
	// includes our ptrace platform, by the way), so we should only clear the
	// single-step flag if we're responsible for setting it. (clearSinglestep
	// is therefore analogous to Linux's TIF_FORCED_TF.)
	//
	// Strictly speaking, we should also not clear the single-step flag if we
	// single-step through an instruction that sets the single-step flag
	// (arch/x86/kernel/step.c:is_setting_trap_flag()). But nobody sets their
	// own TF. (Famous last words, I know.)
	clearSinglestep := false
	if t.hasTracer() {
		t.tg.pidns.owner.mu.RLock()
		if t.ptraceSinglestep {
			clearSinglestep = !t.Arch().SingleStep()
			t.Arch().SetSingleStep()
		}
		t.tg.pidns.owner.mu.RUnlock()
	}

	region := trace.StartRegion(t.traceContext, runRegion)
	t.accountTaskGoroutineEnter(TaskGoroutineRunningApp)
	info, at, err := t.p.Switch(t, t.MemoryManager(), t.Arch(), t.rseqCPU)
	t.accountTaskGoroutineLeave(TaskGoroutineRunningApp)
	region.End()

	if clearSinglestep {
		t.Arch().ClearSingleStep()
	}

	switch err {
	case nil:
		// Handle application system call.
		return t.doSyscall()

	case platform.ErrContextInterrupt:
		// Interrupted by platform.Context.Interrupt(). Re-enter the run
		// loop to figure out why.
		return (*runApp)(nil)

	case platform.ErrContextSignalCPUID:
		if err := app.handleCPUIDInstruction(t); err == nil {
			// Resume execution.
			return (*runApp)(nil)
		}

		// The instruction at the given RIP was not a CPUID, and we
		// fallthrough to the default signal deliver behavior below.
		fallthrough

	case platform.ErrContextSignal:
		// Looks like a signal has been delivered to us. If it's a synchronous
		// signal (SEGV, SIGBUS, etc.), it should be sent to the application
		// thread that received it.
		sig := linux.Signal(info.Signo)

		// Was it a fault that we should handle internally? If so, this wasn't
		// an application-generated signal and we should continue execution
		// normally.
		if at.Any() {
			region := trace.StartRegion(t.traceContext, faultRegion)
			addr := hostarch.Addr(info.Addr())
			err := t.MemoryManager().HandleUserFault(t, addr, at, hostarch.Addr(t.Arch().Stack()))
			region.End()
			if err == nil {
				// The fault was handled appropriately.
				// We can resume running the application.
				return (*runApp)(nil)
			}

			// Is this a vsyscall that we need emulate?
			//
			// Note that we don't track vsyscalls as part of a
			// specific trace region. This is because regions don't
			// stack, and the actual system call will count as a
			// region. We should be able to easily identify
			// vsyscalls by having a <fault><syscall> pair.
			if at.Execute {
				if sysno, ok := t.image.st.LookupEmulate(addr); ok {
					return t.doVsyscall(addr, sysno)
				}
			}

			// Faults are common, log only at debug level.
			t.Debugf("Unhandled user fault: addr=%x ip=%x access=%v err=%v", addr, t.Arch().IP(), at, err)
			t.DebugDumpState()

			// Continue to signal handling.
			//
			// Convert a BusError error to a SIGBUS from a SIGSEGV. All
			// other info bits stay the same (address, etc.).
			if _, ok := err.(*memmap.BusError); ok {
				sig = linux.SIGBUS
				info.Signo = int32(linux.SIGBUS)
			}
		}

		switch sig {
		case linux.SIGILL, linux.SIGSEGV, linux.SIGBUS, linux.SIGFPE, linux.SIGTRAP:
			// Synchronous signal. Send it to ourselves. Assume the signal is
			// legitimate and force it (work around the signal being ignored or
			// blocked) like Linux does. Conveniently, this is even the correct
			// behavior for SIGTRAP from single-stepping.
			t.forceSignal(linux.Signal(sig), false /* unconditional */)
			t.SendSignal(info)

		case platform.SignalInterrupt:
			// Assume that a call to platform.Context.Interrupt() misfired.

		case linux.SIGPROF:
			// It's a profiling interrupt: there's not much
			// we can do. We've already paid a decent cost
			// by intercepting the signal, at this point we
			// simply ignore it.

		default:
			// Asynchronous signal. Let the system deal with it.
			t.k.sendExternalSignal(info, "application")
		}

		return (*runApp)(nil)

	case platform.ErrContextCPUPreempted:
		// Ensure that rseq critical sections are interrupted and per-thread
		// CPU values are updated before the next platform.Context.Switch().
		t.rseqPreempted = true
		return (*runApp)(nil)

	default:
		// What happened? Can't continue.
		t.Warningf("Unexpected SwitchToApp error: %v", err)
		t.PrepareExit(ExitStatus{Code: ExtractErrno(err, -1)})
		return (*runExit)(nil)
	}
}

// assertTaskGoroutine panics if the caller is not running on t's task
// goroutine.
func (t *Task) assertTaskGoroutine() {
	if got, want := goid.Get(), atomic.LoadInt64(&t.goid); got != want {
		panic(fmt.Sprintf("running on goroutine %d (task goroutine for kernel.Task %p is %d)", got, t, want))
	}
}

// GoroutineID returns the ID of t's task goroutine.
func (t *Task) GoroutineID() int64 {
	return atomic.LoadInt64(&t.goid)
}

// waitGoroutineStoppedOrExited blocks until t's task goroutine stops or exits.
func (t *Task) waitGoroutineStoppedOrExited() {
	t.goroutineStopped.Wait()
}

// WaitExited blocks until all task goroutines in tg have exited.
//
// WaitExited does not correspond to anything in Linux; it's provided so that
// external callers of Kernel.CreateProcess can wait for the created thread
// group to terminate.
func (tg *ThreadGroup) WaitExited() {
	tg.liveGoroutines.Wait()
}

// Yield yields the processor for the calling task.
func (t *Task) Yield() {
	atomic.AddUint64(&t.yieldCount, 1)
	runtime.Gosched()
}
