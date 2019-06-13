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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/futex"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/syserror"
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

	// TaskContext is the TaskContext of the new task. Ownership of the
	// TaskContext is transferred to TaskSet.NewTask, whether or not it
	// succeeds.
	TaskContext *TaskContext

	// FSContext is the FSContext of the new task. A reference must be held on
	// FSContext, which is transferred to TaskSet.NewTask whether or not it
	// succeeds.
	FSContext *FSContext

	// FDMap is the FDMap of the new task. A reference must be held on FDMap,
	// which is transferred to TaskSet.NewTask whether or not it succeeds.
	FDMap *FDMap

	// Credentials is the Credentials of the new task.
	Credentials *auth.Credentials

	// Niceness is the niceness of the new task.
	Niceness int

	// If NetworkNamespaced is true, the new task should observe a non-root
	// network namespace.
	NetworkNamespaced bool

	// AllowedCPUMask contains the cpus that this task can run on.
	AllowedCPUMask sched.CPUSet

	// UTSNamespace is the UTSNamespace of the new task.
	UTSNamespace *UTSNamespace

	// IPCNamespace is the IPCNamespace of the new task.
	IPCNamespace *IPCNamespace

	// AbstractSocketNamespace is the AbstractSocketNamespace of the new task.
	AbstractSocketNamespace *AbstractSocketNamespace

	// ContainerID is the container the new task belongs to.
	ContainerID string
}

// NewTask creates a new task defined by cfg.
//
// NewTask does not start the returned task; the caller must call Task.Start.
func (ts *TaskSet) NewTask(cfg *TaskConfig) (*Task, error) {
	t, err := ts.newTask(cfg)
	if err != nil {
		cfg.TaskContext.release()
		cfg.FSContext.DecRef()
		cfg.FDMap.DecRef()
		return nil, err
	}
	return t, nil
}

// newTask is a helper for TaskSet.NewTask that only takes ownership of parts
// of cfg if it succeeds.
func (ts *TaskSet) newTask(cfg *TaskConfig) (*Task, error) {
	tg := cfg.ThreadGroup
	tc := cfg.TaskContext
	t := &Task{
		taskNode: taskNode{
			tg:       tg,
			parent:   cfg.Parent,
			children: make(map[*Task]struct{}),
		},
		runState:        (*runApp)(nil),
		interruptChan:   make(chan struct{}, 1),
		signalMask:      cfg.SignalMask,
		signalStack:     arch.SignalStack{Flags: arch.SignalStackFlagDisable},
		tc:              *tc,
		fsc:             cfg.FSContext,
		fds:             cfg.FDMap,
		p:               cfg.Kernel.Platform.NewContext(),
		k:               cfg.Kernel,
		ptraceTracees:   make(map[*Task]struct{}),
		allowedCPUMask:  cfg.AllowedCPUMask.Copy(),
		ioUsage:         &usage.IO{},
		creds:           cfg.Credentials,
		niceness:        cfg.Niceness,
		netns:           cfg.NetworkNamespaced,
		utsns:           cfg.UTSNamespace,
		ipcns:           cfg.IPCNamespace,
		abstractSockets: cfg.AbstractSocketNamespace,
		rseqCPU:         -1,
		futexWaiter:     futex.NewWaiter(),
		containerID:     cfg.ContainerID,
	}
	t.endStopCond.L = &t.tg.signalHandlers.mu
	t.ptraceTracer.Store((*Task)(nil))
	// We don't construct t.blockingTimer until Task.run(); see that function
	// for justification.

	// Make the new task (and possibly thread group) visible to the rest of
	// the system atomically.
	ts.mu.Lock()
	defer ts.mu.Unlock()
	tg.signalHandlers.mu.Lock()
	defer tg.signalHandlers.mu.Unlock()
	if tg.exiting || tg.execing != nil {
		// If the caller is in the same thread group, then what we return
		// doesn't matter too much since the caller will exit before it returns
		// to userspace. If the caller isn't in the same thread group, then
		// we're in uncharted territory and can return whatever we want.
		return nil, syserror.EINTR
	}
	if err := ts.assignTIDsLocked(t); err != nil {
		return nil, err
	}
	// Below this point, newTask is expected not to fail (there is no rollback
	// of assignTIDsLocked or any of the following).

	// Logging on t's behalf will panic if t.logPrefix hasn't been initialized.
	// This is the earliest point at which we can do so (since t now has thread
	// IDs).
	t.updateLogPrefixLocked()

	if cfg.InheritParent != nil {
		t.parent = cfg.InheritParent.parent
	}
	if t.parent != nil {
		t.parent.children[t] = struct{}{}
	}

	if tg.leader == nil {
		// New thread group.
		tg.leader = t
		if parentPG := tg.parentPG(); parentPG == nil {
			tg.createSession()
		} else {
			// Inherit the process group.
			parentPG.incRefWithParent(parentPG)
			tg.processGroup = parentPG
		}
	}
	tg.tasks.PushBack(t)
	tg.tasksCount++
	tg.liveTasks++
	tg.activeTasks++

	// Propagate external TaskSet stops to the new task.
	t.stopCount = ts.stopCount

	t.mu.Lock()
	defer t.mu.Unlock()

	t.cpu = assignCPU(t.allowedCPUMask, ts.Root.tids[t])

	t.startTime = t.k.RealtimeClock().Now()

	return t, nil
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
	for ns := t.tg.pidns; ns != nil; ns = ns.parent {
		tid, err := ns.allocateTID()
		if err != nil {
			// Failure. Remove the tids we already allocated in descendant
			// namespaces.
			for _, a := range allocatedTIDs {
				delete(a.ns.tasks, a.tid)
				delete(a.ns.tids, t)
				if t.tg.leader == nil {
					delete(a.ns.tgids, t.tg)
				}
			}
			return err
		}
		ns.tasks[tid] = t
		ns.tids[t] = tid
		if t.tg.leader == nil {
			// New thread group.
			ns.tgids[t.tg] = tid
		}
		allocatedTIDs = append(allocatedTIDs, allocatedTID{ns, tid})
	}
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
		return 0, syserror.ENOMEM
	}
	tid := ns.last
	for {
		// Next.
		tid++
		if tid > TasksLimit {
			tid = InitTID + 1
		}

		// Is it available?
		_, ok := ns.tasks[tid]
		if !ok {
			ns.last = tid
			return tid, nil
		}

		// Did we do a full cycle?
		if tid == ns.last {
			// No tid available.
			return 0, syserror.EAGAIN
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
	t.tg.pidns.owner.liveGoroutines.Add(1)
	t.tg.pidns.owner.runningGoroutines.Add(1)

	// Task is now running in system mode.
	t.accountTaskGoroutineLeave(TaskGoroutineNonexistent)

	// Use the task's TID in the root PID namespace to make it visible in stack dumps.
	go t.run(uintptr(tid)) // S/R-SAFE: synchronizes with saving through stops
}
