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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/futex"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// pidFDMode is an enum that clone3 uses to support CLONE_PIDFD.
type pidFDMode int

const (
	dontMakePIDFD pidFDMode = iota
	makePIDFD
	makeThreadedPIDFD
)

// TaskConfig defines the configuration of a new Task (see below).
type TaskConfig struct {
	// Kernel is the owning Kernel.
	Kernel *Kernel

	// Parent is the new task's parent. Parent may be nil.
	Parent *Task

	// If InheritParent is not nil, use InheritParent's parent as the new
	// task's parent.
	InheritParent *Task

	// ThreadGroup is the ThreadGroup the new task belongs to.
	ThreadGroup *ThreadGroup

	// SignalMask is the new task's initial signal mask.
	SignalMask linux.SignalSet

	// TaskImage is the TaskImage of the new task. Ownership of the
	// TaskImage is transferred to TaskSet.NewTask, whether or not it
	// succeeds.
	TaskImage *TaskImage

	// FSContext is the FSContext of the new task. A reference must be held on
	// FSContext, which is transferred to TaskSet.NewTask whether or not it
	// succeeds.
	FSContext *FSContext

	// FDTable is the FDTableof the new task. A reference must be held on
	// FDMap, which is transferred to TaskSet.NewTask whether or not it
	// succeeds.
	FDTable *FDTable

	// Credentials is the Credentials of the new task. A reference must be held
	// on Credentials.UserNamespace, which is transferred to TaskSet.NewTask
	// whether or not it succeeds.
	Credentials *auth.Credentials

	// NoNewPrivs determines if the task can gain new privileges.
	NoNewPrivs bool

	// Niceness is the niceness of the new task.
	Niceness int

	// NetworkNamespace is the network namespace to be used for the new task.
	NetworkNamespace *inet.Namespace

	// AllowedCPUMask contains the cpus that this task can run on.
	AllowedCPUMask sched.CPUSet

	// UTSNamespace is the UTSNamespace of the new task.
	UTSNamespace *UTSNamespace

	// IPCNamespace is the IPCNamespace of the new task.
	IPCNamespace *IPCNamespace

	// MountNamespace is the MountNamespace of the new task.
	MountNamespace *vfs.MountNamespace

	// RSeqAddr is a pointer to the userspace linux.RSeq structure.
	RSeqAddr hostarch.Addr

	// RSeqSignature is the signature that the rseq abort IP must be signed
	// with.
	RSeqSignature uint32

	// ContainerID is the container the new task belongs to.
	ContainerID string

	// InitialCgroups are the cgroups the container is initialised to.
	InitialCgroups map[Cgroup]struct{}

	// UserCounters is user resource counters.
	UserCounters *UserCounters

	// SessionKeyring is the session keyring associated with the parent task.
	// It may be nil.
	SessionKeyring *auth.Key

	// Personality is the personality of the parent task.
	Personality uint32

	// Origin indicates the origins of the new task.
	Origin TaskOrigin

	// Used by clone3 to support CLONE_PIDFD.
	pidFDMode pidFDMode
	pidFDAddr hostarch.Addr

	// cgroupFD is the CLONE_INTO_CGROUP file descriptor. Valid only if
	// cloneIntoCgroup is true.
	cgroupFD uint64
	// Set only if CLONE_INTO_CGROUP is passed to clone.
	cloneIntoCgroup bool
}

// NewTask creates a new task defined by cfg.
//
// NewTask does not start the returned task; the caller must call Task.Start.
//
// If successful, NewTask transfers references held by cfg to the new task.
// Otherwise, NewTask releases them.
func (ts *TaskSet) NewTask(ctx context.Context, cfg *TaskConfig) (*Task, error) {
	t, _, err := ts.cloneNewTask(ctx, cfg)
	return t, err
}

// cloneNewTask is a version of NewTask that the clone() syscall uses.
// Unlike NewTask, cloneNewTask will create and return a pidFD if requested.
func (ts *TaskSet) cloneNewTask(ctx context.Context, cfg *TaskConfig) (*Task, int32, error) {
	var err error
	cleanup := func() {
		cfg.TaskImage.release(ctx)
		cfg.Credentials.UserNamespace.DecRef(ctx)
		cfg.FSContext.DecRef(ctx)
		cfg.FDTable.DecRef(ctx)
		cfg.UTSNamespace.DecRef(ctx)
		cfg.IPCNamespace.DecRef(ctx)
		cfg.NetworkNamespace.DecRef(ctx)
		if cfg.MountNamespace != nil {
			cfg.MountNamespace.DecRef(ctx)
		}
	}
	if err := cfg.UserCounters.incRLimitNProc(ctx); err != nil {
		cleanup()
		return nil, -1, err
	}
	t, fd, err := ts.newTask(ctx, cfg)
	if err != nil {
		cfg.UserCounters.decRLimitNProc()
		cleanup()
		return nil, -1, err
	}
	return t, fd, nil
}

// newTask is a helper for TaskSet.NewTask that only takes ownership of parts
// of cfg if it succeeds.
func (ts *TaskSet) newTask(ctx context.Context, cfg *TaskConfig) (*Task, int32, error) {
	srcT := TaskFromContext(ctx)
	tg := cfg.ThreadGroup
	image := cfg.TaskImage

	var cu cleanup.Cleanup
	defer cu.Clean()

	var cgroup2 Cgroup2      // The destination cgroup2 node.
	var cachedKillSeq uint64 // To avoid racing with cgroup.kill.

	if cfg.cloneIntoCgroup {
		c, err := srcT.getCgroup2NodeFromFD(cfg.cgroupFD)
		if err != nil {
			return nil, -1, err
		}
		// We must lock the cgroup2 tree down to avoid racing with another
		// thread that might destroy the destination cgroup. Note that we
		// only lock this after we have extracted the destination cgroup to
		// respect the prevailing lock order between the kernfs's filesystem
		// mutex and the cgroup2 tree mutex.
		srcT.k.Cgroup2FS().RLockTree()
		cu.Add(func() {
			// Note how the unlock is not deferred but added to cu.
			// This means in the happy path, when cu is Release'd, we
			// must unlock further down in this function, just after
			// committing the entry of the new task into the cgroup.
			srcT.k.Cgroup2FS().RUnlockTree()
		})
		if err := c.CanCloneInto(ctx, srcT.Credentials()); err != nil {
			return nil, -1, err
		}
		cgroup2 = c
		cachedKillSeq = cgroup2.KillSeq()
	}

	t := &Task{
		taskNode: taskNode{
			tg:       tg,
			parent:   cfg.Parent,
			children: make(map[*Task]struct{}),
		},
		runState:        (*runApp)(nil),
		interruptChan:   make(chan struct{}, 1),
		signalMask:      atomicbitops.FromUint64(uint64(cfg.SignalMask)),
		signalStack:     linux.SignalStack{Flags: linux.SS_DISABLE},
		image:           *image,
		fdTable:         cfg.FDTable,
		k:               cfg.Kernel,
		ptraceTracees:   make(map[*Task]struct{}),
		allowedCPUMask:  cfg.AllowedCPUMask.Copy(),
		ioUsage:         &usage.IO{},
		niceness:        cfg.Niceness,
		utsns:           cfg.UTSNamespace,
		ipcns:           cfg.IPCNamespace,
		mountNamespace:  cfg.MountNamespace,
		rseqCPU:         -1,
		rseqAddr:        cfg.RSeqAddr,
		rseqSignature:   cfg.RSeqSignature,
		futexWaiter:     futex.NewWaiter(),
		containerID:     cfg.ContainerID,
		cgroups:         make(map[Cgroup]struct{}),
		userCounters:    cfg.UserCounters,
		sessionKeyring:  cfg.SessionKeyring,
		personality:     atomicbitops.FromUint32(cfg.Personality),
		Origin:          cfg.Origin,
		onDestroyAction: make(map[TaskDestroyAction]struct{}),
		noNewPrivs:      cfg.NoNewPrivs,
		cgroup2:         cgroup2,
	}
	t.netns = cfg.NetworkNamespace
	t.creds.Store(cfg.Credentials)
	t.fsContext.Store(cfg.FSContext)
	t.endStopCond.L = &t.tg.signalHandlers.mu
	// We don't construct t.blockingTimer until Task.run(); see that function
	// for justification.

	pidFD := int32(-1)
	if cfg.pidFDMode != dontMakePIDFD {
		isThread := cfg.pidFDMode == makeThreadedPIDFD
		t.pid = &pid{}
		t.pid.t.Store(t)

		vfsfd, err := srcT.pidFDOpen(t.pid, isThread, false /*nonblock*/)
		if err != nil {
			return nil, -1, err
		}
		defer vfsfd.DecRef(t)

		fd, err := srcT.NewFDFrom(0, vfsfd, FDFlags{CloseOnExec: true})
		if err != nil {
			return nil, -1, err
		}
		pidFD = fd
		cu.Add(func() {
			if oldFile := srcT.FDTable().Remove(ctx, fd); oldFile != nil {
				oldFile.DecRef(t)
			}
		})

		if _, err := primitive.CopyUint32Out(srcT, cfg.pidFDAddr, uint32(fd)); err != nil {
			return nil, -1, err
		}
	}

	// Reserve cgroup PIDs controller charge. This is either committed when the
	// new task enters the cgroup below, or rolled back on failure.
	// We may also get here from a non-task context (for example, when
	// creating the init task, or from the exec control command). In these cases
	// we skip charging the pids controller, as non-userspace task creation
	// bypasses pid limits.
	var (
		cg                 Cgroup
		charged, committed bool
	)
	if srcT != nil {
		var err error
		if charged, cg, err = srcT.ChargeFor(t, CgroupControllerPIDs, CgroupResourcePID, 1); err != nil {
			return nil, -1, err
		}
		if charged {
			defer func() {
				if !committed {
					if err := cg.Charge(t, cg.Dentry, CgroupControllerPIDs, CgroupResourcePID, -1); err != nil {
						panic(fmt.Sprintf("Failed to clean up PIDs charge on task creation failure: %v", err))
					}
				}
				// Ref from ChargeFor. Note that we need to drop this outside of
				// TaskSet.mu critical sections.
				cg.DecRef(ctx)
			}()
		}
	}

	// If the task was the first to be added to the thread group, check if
	// it needs to be notified of CPU limits being exceeded.
	// We use a defer here because we need to do this without holding the
	// TaskSet or signalHandlers lock.
	var isFirstTask bool
	defer func() {
		if isFirstTask {
			tg.notifyRlimitCPUUpdated(t)
		}
	}()

	// Make the new task (and possibly thread group) visible to the rest of
	// the system atomically.
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// For the standard, non-cloneIntoCgroup fork case, we have to do this
	// after acquiring the TaskSet mutex to guard against a racing cgroup.procs
	// write that might migrate the parent to a different cgroup. Note that
	// task migration locks the taskset mutex for reading, and hence is mutually
	// excluded from clone here.
	if !cfg.cloneIntoCgroup {
		if srcT != nil {
			cgroup2 = srcT.Cgroup2()
		} else {
			// Direct exec into the sandbox.
			cgroup2 = cfg.Kernel.Cgroup2FS().RootCgroup()
		}
		t.cgroup2 = cgroup2 // +checklocksignore: task not visible to anything yet

		// This new task should not escape from a racing cgroup.kill.
		// If here we cache the pre-kill seq no, we will either:
		//  - Get killed naturally when the kill finds us in the cgroup task list.
		//  - We kill ourselves when we find an augmented seq no later in this function.
		// If instead we see the post-kill seq no, then we will find the parent
		// to have been killed() below.
		cachedKillSeq = cgroup2.KillSeq()
		if srcT != nil && srcT.killed() {
			return nil, -1, linuxerr.EINTR
		}
	}

	abort, commitCgroupV2, err := cgroup2.CanEnter(ctx, t)
	if err != nil {
		return nil, -1, err
	}
	cu.Add(abort)

	tg.signalHandlers.mu.Lock()
	// N.B. unlock is not deferred for the happy path because calling
	// commitCgroupV2() with the signals mutex held would violate lock order.
	cu.Add(func() { tg.signalHandlers.mu.Unlock() })

	if tg.exiting || tg.execing != nil {
		// If the caller is in the same thread group, then what we return
		// doesn't matter too much since the caller will exit before it returns
		// to userspace. If the caller isn't in the same thread group, then
		// we're in uncharted territory and can return whatever we want.
		return nil, -1, linuxerr.EINTR
	}
	if ts.liveTasks == 0 && ts.noNewTasksIfZeroLive {
		// Since liveTasks == 0, our caller cannot be a task goroutine invoking
		// a syscall, so it's safe to return a non-errno error that is more
		// explanatory.
		return nil, -1, fmt.Errorf("task creation disabled after Kernel.WaitExited() may have returned")
	}

	if err := ts.assignTIDsLocked(t); err != nil {
		return nil, -1, err
	}

	// Below this point, newTask is expected not to fail (there is no rollback
	// of assignTIDsLocked or any of the following).
	cu.Release()

	ts.liveTasks++

	// Logging on t's behalf will panic if t.logPrefix hasn't been
	// initialized. This is the earliest point at which we can do so
	// (since t now has thread IDs).
	t.updateInfoLocked()

	if cfg.InheritParent != nil {
		t.parent = cfg.InheritParent.parent
	}
	if t.parent != nil {
		t.parent.children[t] = struct{}{}
	}

	// If InitialCgroups is not nil, the new task will be placed in the
	// specified cgroups. Otherwise, if srcT is not nil, the new task will
	// be placed in the srcT's cgroups. If neither is specified, the new task
	// will be in the root cgroups.
	t.EnterInitialV1Cgroups(srcT, cfg.InitialCgroups)
	committed = true

	if isFirstTask = tg.leader == nil; isFirstTask {
		// New thread group.
		tg.leader = t
		if parentPG := tg.parentPG(); parentPG == nil {
			tg.createSession()
		} else {
			// Inherit the process group and terminal.
			parentPG.incRefWithParent(parentPG)
			tg.processGroup = parentPG
			tg.tty = t.parent.tg.tty
		}

		// If our parent is a child subreaper, or if it has a child
		// subreaper, then this new thread group does as well.
		if t.parent != nil {
			tg.hasChildSubreaper = t.parent.tg.isChildSubreaper || t.parent.tg.hasChildSubreaper
		}
	}
	tg.tasks.PushBack(t)
	tg.tasksCount++
	tg.liveTasks++
	tg.activeTasks++

	// Propagate external TaskSet stops to the new task.
	t.stopCount = atomicbitops.FromInt32(ts.stopCount)

	t.mu.Lock()
	t.cpu = atomicbitops.FromInt32(assignCPU(t.allowedCPUMask, ts.Root.tids[t]))

	t.startTime = t.k.RealtimeClock().Now()

	// As a final step, initialize the platform context. This may require
	// other pieces to be initialized as the task is used the context.
	t.p = cfg.Kernel.Platform.NewContext(t.AsyncContext())
	t.mu.Unlock()
	tg.signalHandlers.mu.Unlock()

	if commitCgroupV2 != nil {
		// We can call this only after releasing the signals mutex due to lock
		// order reasons.
		commitCgroupV2()
	}
	if cfg.cloneIntoCgroup {
		// Unlock the cgroup v2 tree mutex now that the task is in the desired cgroup.
		t.k.Cgroup2FS().RUnlockTree()
	}
	// We raced with a cgroup.kill write.
	// Kills occurring after this check will find t in the cgroup's task
	// list and will kill the task naturally.
	if t.Cgroup2().KillSeq() != cachedKillSeq {
		t.SendSignal(SignalInfoPriv(linux.SIGKILL))
	}

	return t, pidFD, nil
}

// assignTIDsLocked ensures that new task t is visible in all PID namespaces in
// which it should be visible.
//
// Preconditions: ts.mu must be locked for writing.
func (ts *TaskSet) assignTIDsLocked(t *Task) error {
	type allocatedTID struct {
		ns  *PIDNamespace
		tid ThreadID
	}
	var allocatedTIDs []allocatedTID
	var tid ThreadID
	var err error
	for ns := t.tg.pidns; ns != nil; ns = ns.parent {
		if tid, err = ns.allocateTID(); err != nil {
			break
		}
		if err = ns.addTask(t, tid); err != nil {
			break
		}
		allocatedTIDs = append(allocatedTIDs, allocatedTID{ns, tid})
	}
	if err != nil {
		// Failure. Remove the tids we already allocated in descendant
		// namespaces.
		for _, a := range allocatedTIDs {
			a.ns.deleteTask(t)
		}
		return err
	}
	t.tg.pidWithinNS.Store(int32(t.tg.pidns.tgids[t.tg]))
	return nil
}

// allocateTID returns an unused ThreadID from ns.
//
// Preconditions: ns.owner.mu must be locked for writing.
func (ns *PIDNamespace) allocateTID() (ThreadID, error) {
	if ns.exiting {
		// "In this case, a subsequent fork(2) into this PID namespace will
		// fail with the error ENOMEM; it is not possible to create a new
		// processes [sic] in a PID namespace whose init process has
		// terminated." - pid_namespaces(7)
		return 0, linuxerr.ENOMEM
	}
	tid := ns.last
	for {
		// Next.
		tid++
		if tid > TasksLimit {
			tid = initTID + 1
		}

		// Is it available?
		tidInUse := func() bool {
			if _, ok := ns.tasks[tid]; ok {
				return true
			}
			if _, ok := ns.processGroups[ProcessGroupID(tid)]; ok {
				return true
			}
			if _, ok := ns.sessions[SessionID(tid)]; ok {
				return true
			}
			return false
		}()

		if !tidInUse {
			ns.last = tid
			return tid, nil
		}

		// Did we do a full cycle?
		if tid == ns.last {
			// No tid available.
			return 0, linuxerr.EAGAIN
		}
	}
}

// Start starts the task goroutine. Start must be called exactly once for each
// task returned by NewTask.
//
// 'tid' must be the task's TID in the root PID namespace and it's used for
// debugging purposes only (set as parameter to Task.run to make it visible
// in stack dumps).
func (t *Task) Start(tid ThreadID) {
	// If the task was restored, it may be "starting" after having already exited.
	if t.runState == nil {
		return
	}
	t.goroutineStopped.Add(1)
	t.tg.liveGoroutines.Add(1)
	t.tg.pidns.owner.runningGoroutines.Add(1)

	// Task is now running in system mode.
	t.accountTaskGoroutineLeave(TaskGoroutineNonexistent)

	// Use the task's TID in the root PID namespace to make it visible in stack dumps.
	go t.run(uintptr(tid)) // S/R-SAFE: synchronizes with saving through stops
}
