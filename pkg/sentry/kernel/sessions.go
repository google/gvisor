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
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/syserror"
)

// SessionID is the public identifier.
type SessionID ThreadID

// ProcessGroupID is the public identifier.
type ProcessGroupID ThreadID

// Session contains a leader threadgroup and a list of ProcessGroups.
//
// +stateify savable
type Session struct {
	refs refs.AtomicRefCount

	// leader is the originator of the Session.
	//
	// Note that this may no longer be running (and may be reaped), so the
	// ID is cached upon initial creation. The leader is still required
	// however, since its PIDNamespace defines the scope of the Session.
	//
	// The leader is immutable.
	leader *ThreadGroup

	// id is the cached identifier in the leader's namespace.
	//
	// The id is immutable.
	id SessionID

	// ProcessGroups is a list of process groups in this Session. This is
	// protected by TaskSet.mu.
	processGroups processGroupList

	// sessionEntry is the embed for TaskSet.sessions. This is protected by
	// TaskSet.mu.
	sessionEntry
}

// incRef grabs a reference.
func (s *Session) incRef() {
	s.refs.IncRef()
}

// decRef drops a reference.
//
// Precondition: callers must hold TaskSet.mu for writing.
func (s *Session) decRef() {
	s.refs.DecRefWithDestructor(func() {
		// Remove translations from the leader.
		for ns := s.leader.pidns; ns != nil; ns = ns.parent {
			id := ns.sids[s]
			delete(ns.sids, s)
			delete(ns.sessions, id)
		}

		// Remove from the list of global Sessions.
		s.leader.pidns.owner.sessions.Remove(s)
	})
}

// ProcessGroup contains an originator threadgroup and a parent Session.
//
// +stateify savable
type ProcessGroup struct {
	refs refs.AtomicRefCount // not exported.

	// originator is the originator of the group.
	//
	// See note re: leader in Session. The same applies here.
	//
	// The originator is immutable.
	originator *ThreadGroup

	// id is the cached identifier in the originator's namespace.
	//
	// The id is immutable.
	id ProcessGroupID

	// Session is the parent Session.
	//
	// The session is immutable.
	session *Session

	// ancestors is the number of thread groups in this process group whose
	// parent is in a different process group in the same session.
	//
	// The name is derived from the fact that process groups where
	// ancestors is zero are considered "orphans".
	//
	// ancestors is protected by TaskSet.mu.
	ancestors uint32

	// processGroupEntry is the embedded entry for Sessions.groups. This is
	// protected by TaskSet.mu.
	processGroupEntry
}

// Originator retuns the originator of the process group.
func (pg *ProcessGroup) Originator() *ThreadGroup {
	return pg.originator
}

// IsOrphan returns true if this process group is an orphan.
func (pg *ProcessGroup) IsOrphan() bool {
	pg.originator.TaskSet().mu.RLock()
	defer pg.originator.TaskSet().mu.RUnlock()
	return pg.ancestors == 0
}

// incRefWithParent grabs a reference.
//
// This function is called when this ProcessGroup is being associated with some
// new ThreadGroup, tg. parentPG is the ProcessGroup of tg's parent
// ThreadGroup. If tg is init, then parentPG may be nil.
//
// Precondition: callers must hold TaskSet.mu for writing.
func (pg *ProcessGroup) incRefWithParent(parentPG *ProcessGroup) {
	// We acquire an "ancestor" reference in the case of a nil parent.
	// This is because the process being associated is init, and init can
	// never be orphaned (we count it as always having an ancestor).
	if pg != parentPG && (parentPG == nil || pg.session == parentPG.session) {
		pg.ancestors++
	}

	pg.refs.IncRef()
}

// decRefWithParent drops a reference.
//
// parentPG is per incRefWithParent.
//
// Precondition: callers must hold TaskSet.mu for writing.
func (pg *ProcessGroup) decRefWithParent(parentPG *ProcessGroup) {
	// See incRefWithParent regarding parent == nil.
	if pg != parentPG && (parentPG == nil || pg.session == parentPG.session) {
		pg.ancestors--
	}

	alive := true
	pg.refs.DecRefWithDestructor(func() {
		alive = false // don't bother with handleOrphan.

		// Remove translations from the originator.
		for ns := pg.originator.pidns; ns != nil; ns = ns.parent {
			id := ns.pgids[pg]
			delete(ns.pgids, pg)
			delete(ns.processGroups, id)
		}

		// Remove the list of process groups.
		pg.session.processGroups.Remove(pg)
		pg.session.decRef()
	})
	if alive {
		pg.handleOrphan()
	}
}

// parentPG returns the parent process group.
//
// Precondition: callers must hold TaskSet.mu.
func (tg *ThreadGroup) parentPG() *ProcessGroup {
	if tg.leader.parent != nil {
		return tg.leader.parent.tg.processGroup
	}
	return nil
}

// handleOrphan checks whether the process group is an orphan and has any
// stopped jobs. If yes, then appropriate signals are delivered to each thread
// group within the process group.
//
// Precondition: callers must hold TaskSet.mu for writing.
func (pg *ProcessGroup) handleOrphan() {
	// Check if this process is an orphan.
	if pg.ancestors != 0 {
		return
	}

	// See if there are any stopped jobs.
	hasStopped := false
	pg.originator.pidns.owner.forEachThreadGroupLocked(func(tg *ThreadGroup) {
		if tg.processGroup != pg {
			return
		}
		tg.signalHandlers.mu.Lock()
		if tg.groupStopComplete {
			hasStopped = true
		}
		tg.signalHandlers.mu.Unlock()
	})
	if !hasStopped {
		return
	}

	// Deliver appropriate signals to all thread groups.
	pg.originator.pidns.owner.forEachThreadGroupLocked(func(tg *ThreadGroup) {
		if tg.processGroup != pg {
			return
		}
		tg.signalHandlers.mu.Lock()
		tg.leader.sendSignalLocked(SignalInfoPriv(linux.SIGHUP), true /* group */)
		tg.leader.sendSignalLocked(SignalInfoPriv(linux.SIGCONT), true /* group */)
		tg.signalHandlers.mu.Unlock()
	})

	return
}

// Session returns the process group's session without taking a reference.
func (pg *ProcessGroup) Session() *Session {
	return pg.session
}

// SendSignal sends a signal to all processes inside the process group. It is
// analagous to kernel/signal.c:kill_pgrp.
func (pg *ProcessGroup) SendSignal(info *arch.SignalInfo) error {
	tasks := pg.originator.TaskSet()
	tasks.mu.RLock()
	defer tasks.mu.RUnlock()

	var lastErr error
	for tg := range tasks.Root.tgids {
		if tg.ProcessGroup() == pg {
			tg.signalHandlers.mu.Lock()
			infoCopy := *info
			if err := tg.leader.sendSignalLocked(&infoCopy, true /*group*/); err != nil {
				lastErr = err
			}
			tg.signalHandlers.mu.Unlock()
		}
	}
	return lastErr
}

// CreateSession creates a new Session, with the ThreadGroup as the leader.
//
// EPERM may be returned if either the given ThreadGroup is already a Session
// leader, or a ProcessGroup already exists for the ThreadGroup's ID.
func (tg *ThreadGroup) CreateSession() error {
	tg.pidns.owner.mu.Lock()
	defer tg.pidns.owner.mu.Unlock()
	return tg.createSession()
}

// createSession creates a new session for a threadgroup.
//
// Precondition: callers must hold TaskSet.mu for writing.
func (tg *ThreadGroup) createSession() error {
	// Get the ID for this thread in the current namespace.
	id := tg.pidns.tgids[tg]

	// Check if this ThreadGroup already leads a Session, or
	// if the proposed group is already taken.
	for s := tg.pidns.owner.sessions.Front(); s != nil; s = s.Next() {
		if s.leader.pidns != tg.pidns {
			continue
		}
		if s.leader == tg {
			return syserror.EPERM
		}
		if s.id == SessionID(id) {
			return syserror.EPERM
		}
		for pg := s.processGroups.Front(); pg != nil; pg = pg.Next() {
			if pg.id == ProcessGroupID(id) {
				return syserror.EPERM
			}
		}
	}

	// Create a new Session, with a single reference.
	s := &Session{
		id:     SessionID(id),
		leader: tg,
	}

	// Create a new ProcessGroup, belonging to that Session.
	// This also has a single reference (assigned below).
	//
	// Note that since this is a new session and a new process group, there
	// will be zero ancestors for this process group. (It is an orphan at
	// this point.)
	pg := &ProcessGroup{
		id:         ProcessGroupID(id),
		originator: tg,
		session:    s,
		ancestors:  0,
	}

	// Tie them and return the result.
	s.processGroups.PushBack(pg)
	tg.pidns.owner.sessions.PushBack(s)

	// Leave the current group, and assign the new one.
	if tg.processGroup != nil {
		oldParentPG := tg.parentPG()
		tg.forEachChildThreadGroupLocked(func(childTG *ThreadGroup) {
			childTG.processGroup.incRefWithParent(pg)
			childTG.processGroup.decRefWithParent(oldParentPG)
		})
		tg.processGroup.decRefWithParent(oldParentPG)
		tg.processGroup = pg
	} else {
		// The current process group may be nil only in the case of an
		// unparented thread group (i.e. the init process). This would
		// not normally occur, but we allow it for the convenience of
		// CreateSession working from that point. There will be no
		// child processes. We always say that the very first group
		// created has ancestors (avoids checks elsewhere).
		//
		// Note that this mirrors the parent == nil logic in
		// incRef/decRef/reparent, which counts nil as an ancestor.
		tg.processGroup = pg
		tg.processGroup.ancestors++
	}

	// Ensure a translation is added to all namespaces.
	for ns := tg.pidns; ns != nil; ns = ns.parent {
		local := ns.tgids[tg]
		ns.sids[s] = SessionID(local)
		ns.sessions[SessionID(local)] = s
		ns.pgids[pg] = ProcessGroupID(local)
		ns.processGroups[ProcessGroupID(local)] = pg
	}

	return nil
}

// CreateProcessGroup creates a new process group.
//
// An EPERM error will be returned if the ThreadGroup belongs to a different
// Session, is a Session leader or the group already exists.
func (tg *ThreadGroup) CreateProcessGroup() error {
	tg.pidns.owner.mu.Lock()
	defer tg.pidns.owner.mu.Unlock()

	// Get the ID for this thread in the current namespace.
	id := tg.pidns.tgids[tg]

	// Per above, check for a Session leader or existing group.
	for s := tg.pidns.owner.sessions.Front(); s != nil; s = s.Next() {
		if s.leader.pidns != tg.pidns {
			continue
		}
		if s.leader == tg {
			return syserror.EPERM
		}
		for pg := s.processGroups.Front(); pg != nil; pg = pg.Next() {
			if pg.id == ProcessGroupID(id) {
				return syserror.EPERM
			}
		}
	}

	// Create a new ProcessGroup, belonging to the current Session.
	//
	// We manually adjust the ancestors if the parent is in the same
	// session.
	tg.processGroup.session.incRef()
	pg := &ProcessGroup{
		id:         ProcessGroupID(id),
		originator: tg,
		session:    tg.processGroup.session,
	}
	if tg.leader.parent != nil && tg.leader.parent.tg.processGroup.session == pg.session {
		pg.ancestors++
	}

	// Assign the new process group; adjust children.
	oldParentPG := tg.parentPG()
	tg.forEachChildThreadGroupLocked(func(childTG *ThreadGroup) {
		childTG.processGroup.incRefWithParent(pg)
		childTG.processGroup.decRefWithParent(oldParentPG)
	})
	tg.processGroup.decRefWithParent(oldParentPG)
	tg.processGroup = pg

	// Add the new process group to the session.
	pg.session.processGroups.PushBack(pg)

	// Ensure this translation is added to all namespaces.
	for ns := tg.pidns; ns != nil; ns = ns.parent {
		local := ns.tgids[tg]
		ns.pgids[pg] = ProcessGroupID(local)
		ns.processGroups[ProcessGroupID(local)] = pg
	}

	return nil
}

// JoinProcessGroup joins an existing process group.
//
// This function will return EACCES if an exec has been performed since fork
// by the given ThreadGroup, and EPERM if the Sessions are not the same or the
// group does not exist.
//
// If checkExec is set, then the join is not permitted after the process has
// executed exec at least once.
func (tg *ThreadGroup) JoinProcessGroup(pidns *PIDNamespace, pgid ProcessGroupID, checkExec bool) error {
	pidns.owner.mu.Lock()
	defer pidns.owner.mu.Unlock()

	// Lookup the ProcessGroup.
	pg := pidns.processGroups[pgid]
	if pg == nil {
		return syserror.EPERM
	}

	// Disallow the join if an execve has performed, per POSIX.
	if checkExec && tg.execed {
		return syserror.EACCES
	}

	// See if it's in the same session as ours.
	if pg.session != tg.processGroup.session {
		return syserror.EPERM
	}

	// Join the group; adjust children.
	parentPG := tg.parentPG()
	pg.incRefWithParent(parentPG)
	tg.forEachChildThreadGroupLocked(func(childTG *ThreadGroup) {
		childTG.processGroup.incRefWithParent(pg)
		childTG.processGroup.decRefWithParent(tg.processGroup)
	})
	tg.processGroup.decRefWithParent(parentPG)
	tg.processGroup = pg

	return nil
}

// Session returns the ThreadGroup's Session.
//
// A reference is not taken on the session.
func (tg *ThreadGroup) Session() *Session {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()
	return tg.processGroup.session
}

// IDOfSession returns the Session assigned to s in PID namespace ns.
//
// If this group isn't visible in this namespace, zero will be returned. It is
// the callers responsibility to check that before using this function.
func (pidns *PIDNamespace) IDOfSession(s *Session) SessionID {
	pidns.owner.mu.RLock()
	defer pidns.owner.mu.RUnlock()
	return pidns.sids[s]
}

// SessionWithID returns the Session with the given ID in the PID namespace ns,
// or nil if that given ID is not defined in this namespace.
//
// A reference is not taken on the session.
func (pidns *PIDNamespace) SessionWithID(id SessionID) *Session {
	pidns.owner.mu.RLock()
	defer pidns.owner.mu.RUnlock()
	return pidns.sessions[id]
}

// ProcessGroup returns the ThreadGroup's ProcessGroup.
//
// A reference is not taken on the process group.
func (tg *ThreadGroup) ProcessGroup() *ProcessGroup {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()
	return tg.processGroup
}

// IDOfProcessGroup returns the process group assigned to pg in PID namespace ns.
//
// The same constraints apply as IDOfSession.
func (pidns *PIDNamespace) IDOfProcessGroup(pg *ProcessGroup) ProcessGroupID {
	pidns.owner.mu.RLock()
	defer pidns.owner.mu.RUnlock()
	return pidns.pgids[pg]
}

// ProcessGroupWithID returns the ProcessGroup with the given ID in the PID
// namespace ns, or nil if that given ID is not defined in this namespace.
//
// A reference is not taken on the process group.
func (pidns *PIDNamespace) ProcessGroupWithID(id ProcessGroupID) *ProcessGroup {
	pidns.owner.mu.RLock()
	defer pidns.owner.mu.RUnlock()
	return pidns.processGroups[id]
}
