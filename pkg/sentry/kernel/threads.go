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

	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TasksLimit is the maximum number of threads for untrusted application.
// Linux doesn't really limit this directly, rather it is limited by total
// memory size, stacks allocated and a global maximum. There's no real reason
// for us to limit it either, (esp. since threads are backed by go routines),
// and we would expect to hit resource limits long before hitting this number.
// However, for correctness, we still check that the user doesn't exceed this
// number.
//
// Note that because of the way futexes are implemented, there *are* in fact
// serious restrictions on valid thread IDs. They are limited to 2^30 - 1
// (kernel/fork.c:MAX_THREADS).
const TasksLimit = (1 << 16)

// ThreadID is a generic thread identifier.
//
// +marshal
type ThreadID int32

// String returns a decimal representation of the ThreadID.
func (tid ThreadID) String() string {
	return fmt.Sprintf("%d", tid)
}

// InitTID is the TID given to the first task added to each PID namespace. The
// thread group led by InitTID is called the namespace's init process. The
// death of a PID namespace's init process causes all tasks visible in that
// namespace to be killed.
const InitTID ThreadID = 1

// A TaskSet comprises all tasks in a system.
//
// +stateify savable
type TaskSet struct {
	// mu protects all relationships betweens tasks and thread groups in the
	// TaskSet. (mu is approximately equivalent to Linux's tasklist_lock.)
	mu sync.RWMutex `state:"nosave"`

	// Root is the root PID namespace, in which all tasks in the TaskSet are
	// visible. The Root pointer is immutable.
	Root *PIDNamespace

	// sessions is the set of all sessions.
	sessions sessionList

	// stopCount is the number of active external stops applicable to all tasks
	// in the TaskSet (calls to TaskSet.BeginExternalStop that have not been
	// paired with a call to TaskSet.EndExternalStop). stopCount is protected
	// by mu.
	//
	// stopCount is not saved for the same reason as Task.stopCount; it is
	// always reset to zero after restore.
	stopCount int32 `state:"nosave"`

	// liveGoroutines is the number of non-exited task goroutines in the
	// TaskSet.
	//
	// liveGoroutines is not saved; it is reset as task goroutines are
	// restarted by Task.Start.
	liveGoroutines sync.WaitGroup `state:"nosave"`

	// runningGoroutines is the number of running task goroutines in the
	// TaskSet.
	//
	// runningGoroutines is not saved; its counter value is required to be zero
	// at time of save (but note that this is not necessarily the same thing as
	// sync.WaitGroup's zero value).
	runningGoroutines sync.WaitGroup `state:"nosave"`

	// aioGoroutines is the number of goroutines running async I/O
	// callbacks.
	//
	// aioGoroutines is not saved but is required to be zero at the time of
	// save.
	aioGoroutines sync.WaitGroup `state:"nosave"`
}

// newTaskSet returns a new, empty TaskSet.
func newTaskSet(pidns *PIDNamespace) *TaskSet {
	ts := &TaskSet{Root: pidns}
	pidns.owner = ts
	return ts
}

// forEachThreadGroupLocked applies f to each thread group in ts.
//
// Preconditions: ts.mu must be locked (for reading or writing).
func (ts *TaskSet) forEachThreadGroupLocked(f func(tg *ThreadGroup)) {
	for tg := range ts.Root.tgids {
		f(tg)
	}
}

// A PIDNamespace represents a PID namespace, a bimap between thread IDs and
// tasks. See the pid_namespaces(7) man page for further details.
//
// N.B. A task is said to be visible in a PID namespace if the PID namespace
// contains a thread ID that maps to that task.
//
// +stateify savable
type PIDNamespace struct {
	// owner is the TaskSet that this PID namespace belongs to. The owner
	// pointer is immutable.
	owner *TaskSet

	// parent is the PID namespace of the process that created this one. If
	// this is the root PID namespace, parent is nil. The parent pointer is
	// immutable.
	//
	// Invariant: All tasks that are visible in this namespace are also visible
	// in all ancestor namespaces.
	parent *PIDNamespace

	// userns is the user namespace with which this PID namespace is
	// associated. Privileged operations on this PID namespace must have
	// appropriate capabilities in userns. The userns pointer is immutable.
	userns *auth.UserNamespace

	// The following fields are protected by owner.mu.

	// last is the last ThreadID to be allocated in this namespace.
	last ThreadID

	// tasks is a mapping from ThreadIDs in this namespace to tasks visible in
	// the namespace.
	tasks map[ThreadID]*Task

	// tids is a mapping from tasks visible in this namespace to their
	// identifiers in this namespace.
	tids map[*Task]ThreadID

	// tgids is a mapping from thread groups visible in this namespace to
	// their identifiers in this namespace.
	//
	// The content of tgids is equivalent to tids[tg.leader]. This exists
	// primarily as an optimization to quickly find all thread groups.
	tgids map[*ThreadGroup]ThreadID

	// sessions is a mapping from SessionIDs in this namespace to sessions
	// visible in the namespace.
	sessions map[SessionID]*Session

	// sids is a mapping from sessions visible in this namespace to their
	// identifiers in this namespace.
	sids map[*Session]SessionID

	// processGroups is a mapping from ProcessGroupIDs in this namespace to
	// process groups visible in the namespace.
	processGroups map[ProcessGroupID]*ProcessGroup

	// pgids is a mapping from process groups visible in this namespace to
	// their identifiers in this namespace.
	pgids map[*ProcessGroup]ProcessGroupID

	// exiting indicates that the namespace's init process is exiting or has
	// exited.
	exiting bool
}

func newPIDNamespace(ts *TaskSet, parent *PIDNamespace, userns *auth.UserNamespace) *PIDNamespace {
	return &PIDNamespace{
		owner:         ts,
		parent:        parent,
		userns:        userns,
		tasks:         make(map[ThreadID]*Task),
		tids:          make(map[*Task]ThreadID),
		tgids:         make(map[*ThreadGroup]ThreadID),
		sessions:      make(map[SessionID]*Session),
		sids:          make(map[*Session]SessionID),
		processGroups: make(map[ProcessGroupID]*ProcessGroup),
		pgids:         make(map[*ProcessGroup]ProcessGroupID),
	}
}

// NewRootPIDNamespace creates the root PID namespace. 'owner' is not available
// yet when root namespace is created and must be set by caller.
func NewRootPIDNamespace(userns *auth.UserNamespace) *PIDNamespace {
	return newPIDNamespace(nil, nil, userns)
}

// NewChild returns a new, empty PID namespace that is a child of ns. Authority
// over the new PID namespace is controlled by userns.
func (ns *PIDNamespace) NewChild(userns *auth.UserNamespace) *PIDNamespace {
	return newPIDNamespace(ns.owner, ns, userns)
}

// TaskWithID returns the task with thread ID tid in PID namespace ns. If no
// task has that TID, TaskWithID returns nil.
func (ns *PIDNamespace) TaskWithID(tid ThreadID) *Task {
	ns.owner.mu.RLock()
	t := ns.tasks[tid]
	ns.owner.mu.RUnlock()
	return t
}

// ThreadGroupWithID returns the thread group lead by the task with thread ID
// tid in PID namespace ns. If no task has that TID, or if the task with that
// TID is not a thread group leader, ThreadGroupWithID returns nil.
func (ns *PIDNamespace) ThreadGroupWithID(tid ThreadID) *ThreadGroup {
	ns.owner.mu.RLock()
	defer ns.owner.mu.RUnlock()
	t := ns.tasks[tid]
	if t == nil {
		return nil
	}
	if t != t.tg.leader {
		return nil
	}
	return t.tg
}

// IDOfTask returns the TID assigned to the given task in PID namespace ns. If
// the task is not visible in that namespace, IDOfTask returns 0. (This return
// value is significant in some cases, e.g. getppid() is documented as
// returning 0 if the caller's parent is in an ancestor namespace and
// consequently not visible to the caller.) If the task is nil, IDOfTask returns
// 0.
func (ns *PIDNamespace) IDOfTask(t *Task) ThreadID {
	ns.owner.mu.RLock()
	id := ns.tids[t]
	ns.owner.mu.RUnlock()
	return id
}

// IDOfThreadGroup returns the TID assigned to tg's leader in PID namespace ns.
// If the task is not visible in that namespace, IDOfThreadGroup returns 0.
func (ns *PIDNamespace) IDOfThreadGroup(tg *ThreadGroup) ThreadID {
	ns.owner.mu.RLock()
	id := ns.tgids[tg]
	ns.owner.mu.RUnlock()
	return id
}

// Tasks returns a snapshot of the tasks in ns.
func (ns *PIDNamespace) Tasks() []*Task {
	ns.owner.mu.RLock()
	defer ns.owner.mu.RUnlock()
	tasks := make([]*Task, 0, len(ns.tasks))
	for t := range ns.tids {
		tasks = append(tasks, t)
	}
	return tasks
}

// ThreadGroups returns a snapshot of the thread groups in ns.
func (ns *PIDNamespace) ThreadGroups() []*ThreadGroup {
	return ns.ThreadGroupsAppend(nil)
}

// ThreadGroupsAppend appends a snapshot of the thread groups in ns to tgs.
func (ns *PIDNamespace) ThreadGroupsAppend(tgs []*ThreadGroup) []*ThreadGroup {
	ns.owner.mu.RLock()
	defer ns.owner.mu.RUnlock()
	for tg := range ns.tgids {
		tgs = append(tgs, tg)
	}
	return tgs
}

// UserNamespace returns the user namespace associated with PID namespace ns.
func (ns *PIDNamespace) UserNamespace() *auth.UserNamespace {
	return ns.userns
}

// A threadGroupNode defines the relationship between a thread group and the
// rest of the system. Conceptually, threadGroupNode is data belonging to the
// owning TaskSet, as if TaskSet contained a field `nodes
// map[*ThreadGroup]*threadGroupNode`. However, for practical reasons,
// threadGroupNode is embedded in the ThreadGroup it represents.
// (threadGroupNode is an anonymous field in ThreadGroup; this is to expose
// threadGroupEntry's methods on ThreadGroup to make it implement
// threadGroupLinker.)
//
// +stateify savable
type threadGroupNode struct {
	// pidns is the PID namespace containing the thread group and all of its
	// member tasks. The pidns pointer is immutable.
	pidns *PIDNamespace

	// eventQueue is notified whenever a event of interest to Task.Wait occurs
	// in a child of this thread group, or a ptrace tracee of a task in this
	// thread group. Events are defined in task_exit.go.
	//
	// Note that we cannot check and save this wait queue similarly to other
	// wait queues, as the queue will not be empty by the time of saving, due
	// to the wait sourced from Exec().
	eventQueue waiter.Queue `state:"nosave"`

	// leader is the thread group's leader, which is the oldest task in the
	// thread group; usually the last task in the thread group to call
	// execve(), or if no such task exists then the first task in the thread
	// group, which was created by a call to fork() or clone() without
	// CLONE_THREAD. Once a thread group has been made visible to the rest of
	// the system by TaskSet.newTask, leader is never nil.
	//
	// Note that it's possible for the leader to exit without causing the rest
	// of the thread group to exit; in such a case, leader will still be valid
	// and non-nil, but leader will not be in tasks.
	//
	// leader is protected by the TaskSet mutex.
	leader *Task

	// If execing is not nil, it is a task in the thread group that has killed
	// all other tasks so that it can become the thread group leader and
	// perform an execve. (execing may already be the thread group leader.)
	//
	// execing is analogous to Linux's signal_struct::group_exit_task.
	//
	// execing is protected by the TaskSet mutex.
	execing *Task

	// tasks is all tasks in the thread group that have not yet been reaped.
	//
	// tasks is protected by both the TaskSet mutex and the signal mutex:
	// Mutating tasks requires locking the TaskSet mutex for writing *and*
	// locking the signal mutex. Reading tasks requires locking the TaskSet
	// mutex *or* locking the signal mutex.
	tasks taskList

	// tasksCount is the number of tasks in the thread group that have not yet
	// been reaped; equivalently, tasksCount is the number of tasks in tasks.
	//
	// tasksCount is protected by both the TaskSet mutex and the signal mutex,
	// as with tasks.
	tasksCount int

	// liveTasks is the number of tasks in the thread group that have not yet
	// reached TaskExitZombie.
	//
	// liveTasks is protected by the TaskSet mutex (NOT the signal mutex).
	liveTasks int

	// activeTasks is the number of tasks in the thread group that have not yet
	// reached TaskExitInitiated.
	//
	// activeTasks is protected by both the TaskSet mutex and the signal mutex,
	// as with tasks.
	activeTasks int
}

// PIDNamespace returns the PID namespace containing tg.
func (tg *ThreadGroup) PIDNamespace() *PIDNamespace {
	return tg.pidns
}

// TaskSet returns the TaskSet containing tg.
func (tg *ThreadGroup) TaskSet() *TaskSet {
	return tg.pidns.owner
}

// Leader returns tg's leader.
func (tg *ThreadGroup) Leader() *Task {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()
	return tg.leader
}

// Count returns the number of non-exited threads in the group.
func (tg *ThreadGroup) Count() int {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()
	var count int
	for t := tg.tasks.Front(); t != nil; t = t.Next() {
		count++
	}
	return count
}

// MemberIDs returns a snapshot of the ThreadIDs (in PID namespace pidns) for
// all tasks in tg.
func (tg *ThreadGroup) MemberIDs(pidns *PIDNamespace) []ThreadID {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()

	var tasks []ThreadID
	for t := tg.tasks.Front(); t != nil; t = t.Next() {
		if id, ok := pidns.tids[t]; ok {
			tasks = append(tasks, id)
		}
	}
	return tasks
}

// ID returns tg's leader's thread ID in its own PID namespace. If tg's leader
// is dead, ID returns 0.
func (tg *ThreadGroup) ID() ThreadID {
	tg.pidns.owner.mu.RLock()
	id := tg.pidns.tgids[tg]
	tg.pidns.owner.mu.RUnlock()
	return id
}

// A taskNode defines the relationship between a task and the rest of the
// system. The comments on threadGroupNode also apply to taskNode.
//
// +stateify savable
type taskNode struct {
	// tg is the thread group that this task belongs to. The tg pointer is
	// immutable.
	tg *ThreadGroup `state:"wait"`

	// taskEntry links into tg.tasks. Note that this means that
	// Task.Next/Prev/SetNext/SetPrev refer to sibling tasks in the same thread
	// group. See threadGroupNode.tasks for synchronization info.
	taskEntry

	// parent is the task's parent. parent may be nil.
	//
	// parent is protected by the TaskSet mutex.
	parent *Task

	// children is this task's children.
	//
	// children is protected by the TaskSet mutex.
	children map[*Task]struct{}

	// If childPIDNamespace is not nil, all new tasks created by this task will
	// be members of childPIDNamespace rather than this one. (As a corollary,
	// this task becomes unable to create sibling tasks in the same thread
	// group.)
	//
	// childPIDNamespace is exclusive to the task goroutine.
	childPIDNamespace *PIDNamespace
}

// ThreadGroup returns the thread group containing t.
func (t *Task) ThreadGroup() *ThreadGroup {
	return t.tg
}

// PIDNamespace returns the PID namespace containing t.
func (t *Task) PIDNamespace() *PIDNamespace {
	return t.tg.pidns
}

// TaskSet returns the TaskSet containing t.
func (t *Task) TaskSet() *TaskSet {
	return t.tg.pidns.owner
}

// Timekeeper returns the system Timekeeper.
func (t *Task) Timekeeper() *Timekeeper {
	return t.k.timekeeper
}

// Parent returns t's parent.
func (t *Task) Parent() *Task {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	return t.parent
}

// ThreadID returns t's thread ID in its own PID namespace. If the task is
// dead, ThreadID returns 0.
func (t *Task) ThreadID() ThreadID {
	return t.tg.pidns.IDOfTask(t)
}
