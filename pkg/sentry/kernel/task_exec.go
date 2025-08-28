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

// This file implements the machinery behind the execve() syscall. In brief, a
// thread executes an execve() by killing all other threads in its thread
// group, assuming the leader's identity, and then switching process images.
//
// This design is effectively mandated by Linux. From ptrace(2):
//
// """
// execve(2) under ptrace
//     When one thread in a multithreaded process calls execve(2), the
//     kernel destroys all other threads in the process, and resets the
//     thread ID of the execing thread to the thread group ID (process ID).
//     (Or, to put things another way, when a multithreaded process does an
//     execve(2), at completion of the call, it appears as though the
//     execve(2) occurred in the thread group leader, regardless of which
//     thread did the execve(2).)  This resetting of the thread ID looks
//     very confusing to tracers:
//
//     *  All other threads stop in PTRACE_EVENT_EXIT stop, if the
//        PTRACE_O_TRACEEXIT option was turned on.  Then all other threads
//        except the thread group leader report death as if they exited via
//        _exit(2) with exit code 0.
//
//     *  The execing tracee changes its thread ID while it is in the
//        execve(2).  (Remember, under ptrace, the "pid" returned from
//        waitpid(2), or fed into ptrace calls, is the tracee's thread ID.)
//        That is, the tracee's thread ID is reset to be the same as its
//        process ID, which is the same as the thread group leader's thread
//        ID.
//
//     *  Then a PTRACE_EVENT_EXEC stop happens, if the PTRACE_O_TRACEEXEC
//        option was turned on.
//
//     *  If the thread group leader has reported its PTRACE_EVENT_EXIT stop
//        by this time, it appears to the tracer that the dead thread leader
//        "reappears from nowhere".  (Note: the thread group leader does not
//        report death via WIFEXITED(status) until there is at least one
//        other live thread.  This eliminates the possibility that the
//        tracer will see it dying and then reappearing.)  If the thread
//        group leader was still alive, for the tracer this may look as if
//        thread group leader returns from a different system call than it
//        entered, or even "returned from a system call even though it was
//        not in any system call".  If the thread group leader was not
//        traced (or was traced by a different tracer), then during
//        execve(2) it will appear as if it has become a tracee of the
//        tracer of the execing tracee.
//
//     All of the above effects are the artifacts of the thread ID change in
//     the tracee.
// """

import (
	"crypto/sha256"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/loader"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// Execve implements the execve(2) syscall by first doing these two potentially stop-requiring tasks:
//
//  1. Acquiring a lock that serializes execve with a concurrent PTRACE_ATTACH or seccomp tsync for
//     correct creds computation.
//     * The next taskRunState is runExecveAfterExecveCredsLock
//     * The task will wait in the execveCredsMutexStop stop till it can acquire the lock.
//  2. Killing all other tasks in its thread group and switching to the new TaskImage.
//     * The next run state is runExecveAfterSiblingExitStop
//     * The task will wait in the siblingExitStop stop till it its siblings have exited.
//
// Execve takes ownership of `executable`.
//
// Preconditions: The caller must be running Task.doSyscallInvoke on the task goroutine.
func (t *Task) Execve(argv, envv []string, flags int32, pathname string, executable *vfs.FileDescription, closeOnExec bool) *SyscallControl {
	// Serialize with PTRACE_ATTACH to ensure correct creds computation,
	// see Task.shouldStopPrivGainDueToPtracer().
	t.execveCredsMutexStartLock(t.tg)

	// We cannot load the TaskImage before we serialize with PTRACE_ATTACH because loading the image
	// involves setting up aux vectors that reflect the task's new creds, which can only be correctly
	// computed after we freeze the identity (or the absence of) a ptracer.
	//
	// So we save the execve args for the next run state "runSyscallAfterPtraceExecveMutexLocked" that
	// will load the new task image.
	r := runExecveAfterExecveCredsLock{
		argv:        argv,
		envv:        envv,
		pathname:    pathname,
		flags:       flags,
		executable:  executable,
		closeOnExec: closeOnExec,
	}
	return &SyscallControl{next: &r, ignoreReturn: true}
}

// The runExecveAfterExecveCredsLock state continues execve(2) after the lock serializing
// PTRACE_ATTACH and execve has been acquired.
//
// +stateify savable
type runExecveAfterExecveCredsLock struct {
	argv, envv  []string
	pathname    string
	flags       int32
	executable  *vfs.FileDescription
	closeOnExec bool
}

func (r *runExecveAfterExecveCredsLock) execute(t *Task) taskRunState {
	defer func() {
		if r.executable != nil {
			r.executable.DecRef(t)
		}
	}()
	if t.killed() {
		// execveCredsMutexUnlock() will not pass us the lock after we were killed, so there is no
		// race in loading the execveCredsMutexOwner value without a lock.
		if t.execveCredsMutexOwner != nil {
			t.execveCredsMutexUnlock()
		}
		return (*runInterrupt)(nil)
	}

	fsContext := t.FSContext()
	root := fsContext.RootDirectory()
	defer root.DecRef(t)
	wd := fsContext.WorkingDirectory()
	defer wd.DecRef(t)

	// Cannot gain privileges if the ptracer's capabilities prevent it.
	stopPrivGain := t.shouldStopPrivGainDueToPtracerLocked()
	// Cannot gain privileges if the FSContext is shared outside of our thread group.
	if fsContext.checkAndPreventSharingOutsideTG(t.tg) {
		stopPrivGain = true
	}

	remainingTraversals := uint(linux.MaxSymlinkTraversals)
	loadArgs := loader.LoadArgs{
		Root:                root,
		WorkingDir:          wd,
		RemainingTraversals: &remainingTraversals,
		ResolveFinal:        r.flags&linux.AT_SYMLINK_NOFOLLOW == 0,
		Filename:            r.pathname,
		File:                r.executable,
		CloseOnExec:         r.closeOnExec,
		Argv:                r.argv,
		Envv:                r.envv,
		Features:            t.Kernel().FeatureSet(),
		NoNewPrivs:          t.GetNoNewPrivs(),
		StopPrivGain:        stopPrivGain,
		AllowSUID:           t.Kernel().AllowSUID,
	}

	if seccheck.Global.Enabled(seccheck.PointExecve) {
		// Retain the first executable file that is opened (which may open
		// multiple executable files while resolving interpreter scripts).
		if r.executable == nil {
			loadArgs.AfterOpen = func(f *vfs.FileDescription) {
				if r.executable == nil {
					f.IncRef()
					r.executable = f
					r.pathname = r.executable.MappedName(t)
				}
			}
		}
	}

	image, newCreds, secureExec, se := t.Kernel().LoadTaskImage(t, loadArgs)
	if se != nil {
		t.releaseExecveCredsLocks()
		return t.doSyscallError(se.ToError())
	}

	return r.execveWithImage(t, image, newCreds, secureExec)
}

// siblingExitStop is a TaskStop that a task sets on itself when it wants to execve
// and is waiting for the other tasks in its thread group to exit first.
//
// +stateify savable
type siblingExitStop struct{}

// Killable implements TaskStop.Killable.
func (*siblingExitStop) Killable() bool { return true }

// execveWithImage continues the implementation of execve(2) now that the PTRACE_ATTACH lock has been
// acquired and the new TaskImage has been loaded.
//
// Enters the execStop state to wait for other tasks in the thread group to exit.
func (r *runExecveAfterExecveCredsLock) execveWithImage(t *Task, newImage *TaskImage, newCreds *auth.Credentials, secureExec bool) taskRunState {
	cu := cleanup.Make(func() {
		newImage.release(t)
	})
	cu.Add(func() {
		t.releaseExecveCredsLocks()
	})
	defer cu.Clean()
	// We can't clearly hold kernel package locks while stat'ing executable.
	if seccheck.Global.Enabled(seccheck.PointExecve) {
		mask, info := getExecveSeccheckInfo(t, r.argv, r.envv, r.executable, r.pathname)
		if err := seccheck.Global.SentToSinks(func(c seccheck.Sink) error {
			return c.Execve(t, mask, info)
		}); err != nil {
			return t.doSyscallError(err)
		}
	}

	t.tg.pidns.owner.mu.Lock()
	defer t.tg.pidns.owner.mu.Unlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()

	if t.tg.exiting || t.tg.execing != nil {
		// We lost to a racing group-exit, kill, or exec from another thread
		// and should just exit.
		return t.doSyscallError(linuxerr.EINTR)
	}

	// Cancel any racing group stops.
	t.tg.endGroupStopLocked(false)

	// If the task has any siblings, they have to exit before the exec can
	// continue.
	t.tg.execing = t
	if t.tg.tasks.Front() != t.tg.tasks.Back() {
		// "[All] other threads except the thread group leader report death as
		// if they exited via _exit(2) with exit code 0." - ptrace(2)
		for sibling := t.tg.tasks.Front(); sibling != nil; sibling = sibling.Next() {
			if t != sibling {
				sibling.killLocked()
			}
		}
		// The last sibling to exit will wake t.
		t.beginInternalStopLocked((*siblingExitStop)(nil))
	}

	cu.Release()
	return &runExecveAfterSiblingExitStop{newImage, newCreds, secureExec}
}

// The runExecveAfterSiblingExitStop state continues execve(2) after all siblings of
// a thread in the execve syscall have exited.
//
// +stateify savable
type runExecveAfterSiblingExitStop struct {
	image      *TaskImage
	newCreds   *auth.Credentials
	secureExec bool
}

func (r *runExecveAfterSiblingExitStop) execute(t *Task) taskRunState {
	defer t.releaseExecveCredsLocks()
	t.traceExecEvent(r.image)
	t.tg.pidns.owner.mu.Lock()
	t.tg.execing = nil
	if t.killed() {
		t.tg.pidns.owner.mu.Unlock()
		r.image.release(t)
		return (*runInterrupt)(nil)
	}
	// We are the thread group leader now. Save our old thread ID for
	// PTRACE_EVENT_EXEC. This is racy in that if a tracer attaches after this
	// point it will get a PID of 0, but this is consistent with Linux.
	oldTID := ThreadID(0)
	if tracer := t.Tracer(); tracer != nil {
		oldTID = tracer.tg.pidns.tids[t]
	}
	t.promoteLocked()
	// "POSIX timers are not preserved (timer_create(2))." - execve(2). Handle
	// this first since POSIX timers are protected by the signal mutex, which
	// we're about to change. Note that we have to stop and destroy timers
	// without holding any mutexes to avoid circular lock ordering.
	var its []*IntervalTimer
	oldSignalHandlers := t.tg.signalHandlers
	oldSignalHandlers.mu.Lock()
	for _, it := range t.tg.timers {
		its = append(its, it)
	}
	clear(t.tg.timers)
	oldSignalHandlers.mu.Unlock()
	t.tg.pidns.owner.mu.Unlock()
	for _, it := range its {
		it.DestroyTimer()
	}
	t.tg.pidns.owner.mu.Lock()
	// "During an execve(2), the dispositions of handled signals are reset to
	// the default; the dispositions of ignored signals are left unchanged. ...
	// [The] signal mask is preserved across execve(2). ... [The] pending
	// signal set is preserved across an execve(2)." - signal(7)
	//
	// Details:
	//
	//	- If the thread group is sharing its signal handlers with another thread
	//		group via CLONE_SIGHAND, execve forces the signal handlers to be copied
	//		(see Linux's fs/exec.c:de_thread). We're not reference-counting signal
	//		handlers, so we always make a copy.
	//
	//	- "Disposition" only means sigaction::sa_handler/sa_sigaction; flags,
	//		restorer (if present), and mask are always reset. (See Linux's
	//		fs/exec.c:setup_new_exec => kernel/signal.c:flush_signal_handlers.)
	oldSignalHandlers.mu.Lock() // to ensure ThreadGroup.signalLock()'s correctness
	t.tg.setSignalHandlersLocked(oldSignalHandlers.copyForExecLocked())
	t.endStopCond.L = &t.tg.signalHandlers.mu
	oldSignalHandlers.mu.Unlock()
	// "Any alternate signal stack is not preserved (sigaltstack(2))." - execve(2)
	t.signalStack = linux.SignalStack{Flags: linux.SS_DISABLE}
	// "The termination signal is reset to SIGCHLD (see clone(2))."
	t.tg.terminationSignal = linux.SIGCHLD
	// execed indicates that the process's pgid cannot be changed
	// in some scenarios (namely, the parent call setpgid(2) on the child).
	// See the Setpgid function in sys_thread.go for more context.
	t.tg.execed = true
	// Maximum RSS is preserved across execve(2).
	t.updateRSSLocked()
	// Restartable sequence state is discarded.
	t.rseqPreempted = false
	t.rseqCPU = -1
	t.rseqAddr = 0
	t.rseqSignature = 0
	t.oldRSeqCPUAddr = 0
	t.tg.oldRSeqCritical.Store(&OldRSeqCriticalRegion{})
	t.tg.pidns.owner.mu.Unlock()

	oldFDTable := t.fdTable
	t.fdTable = t.fdTable.Fork(t, int32(t.fdTable.CurrentMaxFDs()))
	oldFDTable.DecRef(t)

	// Remove FDs with the CloseOnExec flag set.
	t.fdTable.RemoveIf(t, func(_ *vfs.FileDescription, flags FDFlags) bool {
		return flags.CloseOnExec
	})

	// Handle the robust futex list.
	t.exitRobustList()

	// Parent should not signal the now privileged task, undocumented Linux behavior.
	if r.secureExec {
		t.parentDeathSignal = 0
	}

	// Update dumpability using just the old creds, see fs/exec.c:begin_new_exec().
	// FIXME: Account for executables that may not be read when setting dumpability below.
	oldCreds := t.creds.Load()
	if oldCreds.EffectiveKUID != oldCreds.RealKUID ||
		oldCreds.EffectiveKGID != oldCreds.RealKGID {
		r.image.MemoryManager.SetDumpability(mm.NotDumpable) // suid_dumpable is not implemented
	} else {
		r.image.MemoryManager.SetDumpability(mm.UserDumpable)
	}

	// Lower dumpability based on cred delta, see kernel/cred.c:commit_creds().
	if r.newCreds.EffectiveKUID != oldCreds.EffectiveKUID ||
		r.newCreds.EffectiveKGID != oldCreds.EffectiveKGID ||
		!r.newCreds.PermittedCaps.IsSubsetOf(oldCreds.PermittedCaps) {
		r.image.MemoryManager.SetDumpability(mm.NotDumpable) // suid_dumpable is not implemented
		t.parentDeathSignal = 0
	}

	// Switch to the new process.
	t.MemoryManager().Deactivate()
	// Update credentials to reflect the execve. This should precede switching
	// MMs to ensure that dumpability has been reset first, if needed.
	t.creds.Store(r.newCreds)
	t.mu.Lock()
	oldImage := t.image
	t.image = *r.image
	t.mu.Unlock()

	// Don't hold t.mu while calling t.image.release(), that may
	// attempt to acquire TaskImage.MemoryManager.mappingMu, a lock order
	// violation.
	oldImage.release(t)

	t.unstopVforkParent()
	t.p.FullStateChanged()
	// NOTE(b/30316266): All locks must be dropped prior to calling Activate.
	if err := t.MemoryManager().Activate(t); err != nil {
		panic("unable to activate mm: " + err.Error())
	}

	t.ptraceExec(oldTID)
	return (*runSyscallExit)(nil)
}

// promoteLocked makes t the leader of its thread group. If t is already the
// thread group leader, promoteLocked is a no-op.
//
// Preconditions:
//   - All other tasks in t's thread group, including the existing leader (if it
//     is not t), have reached TaskExitZombie.
//   - The TaskSet mutex must be locked for writing.
func (t *Task) promoteLocked() {
	oldLeader := t.tg.leader
	if t == oldLeader {
		return
	}
	// Swap the leader's TIDs with the execing task's. The latter will be
	// released when the old leader is reaped below.
	for ns := t.tg.pidns; ns != nil; ns = ns.parent {
		oldTID, leaderTID := ns.tids[t], ns.tids[oldLeader]
		ns.tids[oldLeader] = oldTID
		ns.tids[t] = leaderTID
		ns.tasks[oldTID] = oldLeader
		ns.tasks[leaderTID] = t
		// Neither the ThreadGroup nor TGID change, so no need to
		// update ns.tgids.
	}

	// Inherit the old leader's start time.
	oldStartTime := oldLeader.StartTime()
	t.mu.Lock()
	t.startTime = oldStartTime
	t.mu.Unlock()

	t.tg.leader = t
	t.Infof("Becoming TID %d (in root PID namespace)", t.tg.pidns.owner.Root.tids[t])
	t.updateInfoLocked()
	// Reap the original leader. If it has a tracer, detach it instead of
	// waiting for it to acknowledge the original leader's death.
	oldLeader.exitParentNotified = true
	oldLeader.exitParentAcked = true
	if tracer := oldLeader.Tracer(); tracer != nil {
		delete(tracer.ptraceTracees, oldLeader)
		oldLeader.forgetTracerLocked()
		// Notify the tracer that it will no longer be receiving these events
		// from the tracee.
		tracer.tg.eventQueue.Notify(EventExit | EventTraceeStop | EventGroupContinue)
	}
	oldLeader.exitNotifyLocked(false)
}

func getExecveSeccheckInfo(t *Task, argv, env []string, executable *vfs.FileDescription, pathname string) (seccheck.FieldSet, *pb.ExecveInfo) {
	fields := seccheck.Global.GetFieldSet(seccheck.PointExecve)
	info := &pb.ExecveInfo{
		Argv: argv,
		Env:  env,
	}
	if executable != nil {
		info.BinaryPath = pathname
		if fields.Local.Contains(seccheck.FieldSentryExecveBinaryInfo) {
			statOpts := vfs.StatOptions{
				Mask: linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID,
			}
			if stat, err := executable.Stat(t, statOpts); err == nil {
				if stat.Mask&(linux.STATX_TYPE|linux.STATX_MODE) == (linux.STATX_TYPE | linux.STATX_MODE) {
					info.BinaryMode = uint32(stat.Mode)
				}
				if stat.Mask&linux.STATX_UID != 0 {
					info.BinaryUid = stat.UID
				}
				if stat.Mask&linux.STATX_GID != 0 {
					info.BinaryGid = stat.GID
				}
			}
		}

		if fields.Local.Contains(seccheck.FieldSentryExecveBinarySha256) {
			hash := sha256.New()
			buf := make([]byte, 1024*1024) // Read 1MB at a time.
			dest := usermem.BytesIOSequence(buf)
			offset := int64(0)

			for {
				if read, err := executable.PRead(t, dest, offset, vfs.ReadOptions{}); err == nil {
					hash.Write(buf[0:read])
					offset += read

				} else if err == io.EOF {
					hash.Write(buf[0:read])
					info.BinarySha256 = hash.Sum(nil)
					break

				} else {
					log.Warningf("Failed to read executable for SHA-256 hash: %v", err)
					break
				}
			}
		}
	}

	if !fields.Context.Empty() {
		info.ContextData = &pb.ContextData{}
		LoadSeccheckData(t, fields.Context, info.ContextData)
	}
	return fields, info
}

// execveCredsMutexStop is a TaskStop that a task enters if it fails to acquire the execveCredsMutex
// lock immediately. The task exits the stop when the lock owner eventually calls endInternalStop on
// it in Task.execveCredsMutexUnlock, or if it is killed before that happens.
//
// +stateify savable
type execveCredsMutexStop struct{}

// Killable implements TaskStop.Killable.
func (*execveCredsMutexStop) Killable() bool { return true }

// execveCredsMutexStartLock attempts to acquire the lock that serializes an execve(2) with a
// concurrent PTRACE_ATTACH or seccomp tsync. Such an exclusion is required to ensure correct creds
// computation in execve(2).
//
// Will push the calling Task into the execveCredsMutexStop stop if the lock is busy.
// The owner of the lock will then call endInternalStop on the waiting Task to pass on the lock.
// Since the caller cannot determine if the lock was acquired or the stop entered, it must
// have a distinct taskRunState where it would perform the work protected by the lock.
//
// Preconditions: Must be called from the task goroutine.
func (t *Task) execveCredsMutexStartLock(tg *ThreadGroup) {
	tg.execveCredsMutexMu.Lock()
	defer tg.execveCredsMutexMu.Unlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	if t.execveCredsMutexOwner != nil {
		panic("Task already holds a execveCredsMutex lock")
	}
	if t.killedLocked() {
		return // No point in taking the lock when we'd give it up first thing come the next runState.
	}
	if !tg.execveCredsMutexLocked {
		tg.execveCredsMutexLocked = true
		t.execveCredsMutexOwner = tg
		return
	}
	t.beginInternalStopLocked((*execveCredsMutexStop)(nil))
	tg.execveCredsMutexWaiters[t] = struct{}{}
}

// execveCredsMutexUnlock releases the mutex that serializes an execve(2) with a PTRACE_ATTACH or
// seccomp tsync. If there are other tasks waiting on the lock, one will be pulled out of the
// execveCredsMutexStop stop it is in and handed the lock.
//
// Preconditions: Must be called from the task goroutine. The caller must have called
// execveCredsMutexStartLock() earlier.
func (t *Task) execveCredsMutexUnlock() {
	if t.execveCredsMutexOwner == nil {
		panic("calling Task does not hold hold any execveCredsMutex lock")
	}
	tg := t.execveCredsMutexOwner

	tg.execveCredsMutexMu.Lock()
	defer tg.execveCredsMutexMu.Unlock()
	if !tg.execveCredsMutexLocked {
		panic("unlock of unlocked ThreadGroup execveCredsMutex")
	}
	tg.execveCredsMutexLocked = false
	t.execveCredsMutexOwner = nil

	// Find a waiting task whose execveCredsMutexStop hasn't been killed and pass on the lock.
	for t2 := range tg.execveCredsMutexWaiters {
		delete(tg.execveCredsMutexWaiters, t2)
		if t.execveCredsMutexStartLocked(tg, t2) {
			break
		}
	}
}

// Tries to pass the execveCredsMutex lock in tg to t2. Returns true if the lock was passed.
//
// preconditions: tg.execveCredsMutexMu must be locked.
func (t *Task) execveCredsMutexStartLocked(tg *ThreadGroup, t2 *Task) bool {
	t2.tg.signalHandlers.mu.Lock()
	defer t2.tg.signalHandlers.mu.Unlock()
	// This check achieves the invariant "A Task cannot be passed the lock after being killed",
	// allowing the post-kill taskRunState::execute() to access Task.execveCredsMutexOwner
	// without anything racing with it.
	if _, ok := t2.stop.(*execveCredsMutexStop); ok {
		tg.execveCredsMutexLocked = true // tg.execveCredsMutexMu being locked is a precondition
		if t2.execveCredsMutexOwner != nil {
			panic("Task already holds a execveCredsMutex lock")
		}
		// The write to t2.execveCredsMutexOwner is safe because we know t2 is in a stop and we hold
		// the signalHandlers.mu lock, so it cannot exit the stop from under us.
		t2.execveCredsMutexOwner = tg
		t2.endInternalStopLocked()
		return true
	}
	return false
}

// shouldStopPrivGainDueToPtracerLocked returns true if the task has a tracer and the tracer's
// capabilities prevent us from elevating the current task's (the tracee's) privileges.
// Preconditions: The caller must have called execveCredsMutexStartLock() earlier.
func (t *Task) shouldStopPrivGainDueToPtracerLocked() bool {
	if !t.hasTracer() {
		return false
	}
	tracerCreds := t.Tracer().Credentials()
	return !tracerCreds.HasCapabilityIn(linux.CAP_SYS_PTRACE, t.Credentials().UserNamespace)
}

// Releases the mutex that serializes an execve(2) with a PTRACE_ATTACH and allows t.fsContext to
// be shared again via clone(2). The caller must have called execveCredsMutexStartLock() and
// fsContext.checkAndPreventSharingOutsideTG() earlier.
func (t *Task) releaseExecveCredsLocks() {
	t.execveCredsMutexUnlock()
	t.FSContext().allowSharing()
}
