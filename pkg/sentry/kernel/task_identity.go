// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Credentials returns t's credentials.
//
// This value must be considered immutable.
func (t *Task) Credentials() *auth.Credentials {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.creds
}

// UserNamespace returns the user namespace associated with the task.
func (t *Task) UserNamespace() *auth.UserNamespace {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.creds.UserNamespace
}

// HasCapabilityIn checks if the task has capability cp in user namespace ns.
func (t *Task) HasCapabilityIn(cp linux.Capability, ns *auth.UserNamespace) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.creds.HasCapabilityIn(cp, ns)
}

// HasCapability checks if the task has capability cp in its user namespace.
func (t *Task) HasCapability(cp linux.Capability) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.creds.HasCapability(cp)
}

// SetUID implements the semantics of setuid(2).
func (t *Task) SetUID(uid auth.UID) error {
	// setuid considers -1 to be invalid.
	if !uid.Ok() {
		return syserror.EINVAL
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	kuid := t.creds.UserNamespace.MapToKUID(uid)
	if !kuid.Ok() {
		return syserror.EINVAL
	}
	// "setuid() sets the effective user ID of the calling process. If the
	// effective UID of the caller is root (more precisely: if the caller has
	// the CAP_SETUID capability), the real UID and saved set-user-ID are also
	// set." - setuid(2)
	if t.creds.HasCapability(linux.CAP_SETUID) {
		t.setKUIDsUncheckedLocked(kuid, kuid, kuid)
		return nil
	}
	// "EPERM: The user is not privileged (Linux: does not have the CAP_SETUID
	// capability) and uid does not match the real UID or saved set-user-ID of
	// the calling process."
	if kuid != t.creds.RealKUID && kuid != t.creds.SavedKUID {
		return syserror.EPERM
	}
	t.setKUIDsUncheckedLocked(t.creds.RealKUID, kuid, t.creds.SavedKUID)
	return nil
}

// SetREUID implements the semantics of setreuid(2).
func (t *Task) SetREUID(r, e auth.UID) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	// "Supplying a value of -1 for either the real or effective user ID forces
	// the system to leave that ID unchanged." - setreuid(2)
	newR := t.creds.RealKUID
	if r.Ok() {
		newR = t.creds.UserNamespace.MapToKUID(r)
		if !newR.Ok() {
			return syserror.EINVAL
		}
	}
	newE := t.creds.EffectiveKUID
	if e.Ok() {
		newE = t.creds.UserNamespace.MapToKUID(e)
		if !newE.Ok() {
			return syserror.EINVAL
		}
	}
	if !t.creds.HasCapability(linux.CAP_SETUID) {
		// "Unprivileged processes may only set the effective user ID to the
		// real user ID, the effective user ID, or the saved set-user-ID."
		if newE != t.creds.RealKUID && newE != t.creds.EffectiveKUID && newE != t.creds.SavedKUID {
			return syserror.EPERM
		}
		// "Unprivileged users may only set the real user ID to the real user
		// ID or the effective user ID."
		if newR != t.creds.RealKUID && newR != t.creds.EffectiveKUID {
			return syserror.EPERM
		}
	}
	// "If the real user ID is set (i.e., ruid is not -1) or the effective user
	// ID is set to a value not equal to the previous real user ID, the saved
	// set-user-ID will be set to the new effective user ID."
	newS := t.creds.SavedKUID
	if r.Ok() || (e.Ok() && newE != t.creds.EffectiveKUID) {
		newS = newE
	}
	t.setKUIDsUncheckedLocked(newR, newE, newS)
	return nil
}

// SetRESUID implements the semantics of the setresuid(2) syscall.
func (t *Task) SetRESUID(r, e, s auth.UID) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	// "Unprivileged user processes may change the real UID, effective UID, and
	// saved set-user-ID, each to one of: the current real UID, the current
	// effective UID or the current saved set-user-ID. Privileged processes (on
	// Linux, those having the CAP_SETUID capability) may set the real UID,
	// effective UID, and saved set-user-ID to arbitrary values. If one of the
	// arguments equals -1, the corresponding value is not changed." -
	// setresuid(2)
	var err error
	newR := t.creds.RealKUID
	if r.Ok() {
		newR, err = t.creds.UseUID(r)
		if err != nil {
			return err
		}
	}
	newE := t.creds.EffectiveKUID
	if e.Ok() {
		newE, err = t.creds.UseUID(e)
		if err != nil {
			return err
		}
	}
	newS := t.creds.SavedKUID
	if s.Ok() {
		newS, err = t.creds.UseUID(s)
		if err != nil {
			return err
		}
	}
	t.setKUIDsUncheckedLocked(newR, newE, newS)
	return nil
}

// Preconditions: t.mu must be locked.
func (t *Task) setKUIDsUncheckedLocked(newR, newE, newS auth.KUID) {
	root := t.creds.UserNamespace.MapToKUID(auth.RootUID)
	oldR, oldE, oldS := t.creds.RealKUID, t.creds.EffectiveKUID, t.creds.SavedKUID
	t.creds = t.creds.Fork() // See doc for creds.
	t.creds.RealKUID, t.creds.EffectiveKUID, t.creds.SavedKUID = newR, newE, newS

	// "1. If one or more of the real, effective or saved set user IDs was
	// previously 0, and as a result of the UID changes all of these IDs have a
	// nonzero value, then all capabilities are cleared from the permitted and
	// effective capability sets." - capabilities(7)
	if (oldR == root || oldE == root || oldS == root) && (newR != root && newE != root && newS != root) {
		// prctl(2): "PR_SET_KEEPCAP: Set the state of the calling thread's
		// "keep capabilities" flag, which determines whether the thread's permitted
		// capability set is cleared when a change is made to the
		// thread's user IDs such that the thread's real UID, effective
		// UID, and saved set-user-ID all become nonzero when at least
		// one of them previously had the value 0.  By default, the
		// permitted capability set is cleared when such a change is
		// made; setting the "keep capabilities" flag prevents it from
		// being cleared." (A thread's effective capability set is always
		// cleared when such a credential change is made,
		// regardless of the setting of the "keep capabilities" flag.)
		if !t.creds.KeepCaps {
			t.creds.PermittedCaps = 0
			t.creds.EffectiveCaps = 0
		}
	}
	// """
	// 2. If the effective user ID is changed from 0 to nonzero, then all
	// capabilities are cleared from the effective set.
	//
	// 3. If the effective user ID is changed from nonzero to 0, then the
	// permitted set is copied to the effective set.
	// """
	if oldE == root && newE != root {
		t.creds.EffectiveCaps = 0
	} else if oldE != root && newE == root {
		t.creds.EffectiveCaps = t.creds.PermittedCaps
	}
	// "4. If the filesystem user ID is changed from 0 to nonzero (see
	// setfsuid(2)), then the following capabilities are cleared from the
	// effective set: ..."
	// (filesystem UIDs aren't implemented, nor are any of the capabilities in
	// question)

	// Not documented, but compare Linux's kernel/cred.c:commit_creds().
	if oldE != newE {
		t.parentDeathSignal = 0
	}
}

// SetGID implements the semantics of setgid(2).
func (t *Task) SetGID(gid auth.GID) error {
	if !gid.Ok() {
		return syserror.EINVAL
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	kgid := t.creds.UserNamespace.MapToKGID(gid)
	if !kgid.Ok() {
		return syserror.EINVAL
	}
	if t.creds.HasCapability(linux.CAP_SETGID) {
		t.setKGIDsUncheckedLocked(kgid, kgid, kgid)
		return nil
	}
	if kgid != t.creds.RealKGID && kgid != t.creds.SavedKGID {
		return syserror.EPERM
	}
	t.setKGIDsUncheckedLocked(t.creds.RealKGID, kgid, t.creds.SavedKGID)
	return nil
}

// SetREGID implements the semantics of setregid(2).
func (t *Task) SetREGID(r, e auth.GID) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	newR := t.creds.RealKGID
	if r.Ok() {
		newR = t.creds.UserNamespace.MapToKGID(r)
		if !newR.Ok() {
			return syserror.EINVAL
		}
	}
	newE := t.creds.EffectiveKGID
	if e.Ok() {
		newE = t.creds.UserNamespace.MapToKGID(e)
		if !newE.Ok() {
			return syserror.EINVAL
		}
	}
	if !t.creds.HasCapability(linux.CAP_SETGID) {
		if newE != t.creds.RealKGID && newE != t.creds.EffectiveKGID && newE != t.creds.SavedKGID {
			return syserror.EPERM
		}
		if newR != t.creds.RealKGID && newR != t.creds.EffectiveKGID {
			return syserror.EPERM
		}
	}
	newS := t.creds.SavedKGID
	if r.Ok() || (e.Ok() && newE != t.creds.EffectiveKGID) {
		newS = newE
	}
	t.setKGIDsUncheckedLocked(newR, newE, newS)
	return nil
}

// SetRESGID implements the semantics of the setresgid(2) syscall.
func (t *Task) SetRESGID(r, e, s auth.GID) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	var err error
	newR := t.creds.RealKGID
	if r.Ok() {
		newR, err = t.creds.UseGID(r)
		if err != nil {
			return err
		}
	}
	newE := t.creds.EffectiveKGID
	if e.Ok() {
		newE, err = t.creds.UseGID(e)
		if err != nil {
			return err
		}
	}
	newS := t.creds.SavedKGID
	if s.Ok() {
		newS, err = t.creds.UseGID(s)
		if err != nil {
			return err
		}
	}
	t.setKGIDsUncheckedLocked(newR, newE, newS)
	return nil
}

func (t *Task) setKGIDsUncheckedLocked(newR, newE, newS auth.KGID) {
	oldE := t.creds.EffectiveKGID
	t.creds = t.creds.Fork() // See doc for creds.
	t.creds.RealKGID, t.creds.EffectiveKGID, t.creds.SavedKGID = newR, newE, newS

	// Not documented, but compare Linux's kernel/cred.c:commit_creds().
	if oldE != newE {
		t.parentDeathSignal = 0
	}
}

// SetExtraGIDs attempts to change t's supplemental groups. All IDs are
// interpreted as being in t's user namespace.
func (t *Task) SetExtraGIDs(gids []auth.GID) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.creds.HasCapability(linux.CAP_SETGID) {
		return syserror.EPERM
	}
	kgids := make([]auth.KGID, len(gids))
	for i, gid := range gids {
		kgid := t.creds.UserNamespace.MapToKGID(gid)
		if !kgid.Ok() {
			return syserror.EINVAL
		}
		kgids[i] = kgid
	}
	t.creds = t.creds.Fork() // See doc for creds.
	t.creds.ExtraKGIDs = kgids
	return nil
}

// SetCapabilitySets attempts to change t's permitted, inheritable, and
// effective capability sets.
func (t *Task) SetCapabilitySets(permitted, inheritable, effective auth.CapabilitySet) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	// "Permitted: This is a limiting superset for the effective capabilities
	// that the thread may assume." - capabilities(7)
	if effective & ^permitted != 0 {
		return syserror.EPERM
	}
	// "It is also a limiting superset for the capabilities that may be added
	// to the inheritable set by a thread that does not have the CAP_SETPCAP
	// capability in its effective set."
	if !t.creds.HasCapability(linux.CAP_SETPCAP) && (inheritable & ^(t.creds.InheritableCaps|t.creds.PermittedCaps) != 0) {
		return syserror.EPERM
	}
	// "If a thread drops a capability from its permitted set, it can never
	// reacquire that capability (unless it execve(2)s ..."
	if permitted & ^t.creds.PermittedCaps != 0 {
		return syserror.EPERM
	}
	// "... if a capability is not in the bounding set, then a thread can't add
	// this capability to its inheritable set, even if it was in its permitted
	// capabilities ..."
	if inheritable & ^(t.creds.InheritableCaps|t.creds.BoundingCaps) != 0 {
		return syserror.EPERM
	}
	t.creds = t.creds.Fork() // See doc for creds.
	t.creds.PermittedCaps = permitted
	t.creds.InheritableCaps = inheritable
	t.creds.EffectiveCaps = effective
	return nil
}

// DropBoundingCapability attempts to drop capability cp from t's capability
// bounding set.
func (t *Task) DropBoundingCapability(cp linux.Capability) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.creds.HasCapability(linux.CAP_SETPCAP) {
		return syserror.EPERM
	}
	t.creds = t.creds.Fork() // See doc for creds.
	t.creds.BoundingCaps &^= auth.CapabilitySetOf(cp)
	return nil
}

// SetUserNamespace attempts to move c into ns.
func (t *Task) SetUserNamespace(ns *auth.UserNamespace) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// "A process reassociating itself with a user namespace must have the
	// CAP_SYS_ADMIN capability in the target user namespace." - setns(2)
	//
	// If t just created ns, then t.creds is guaranteed to have CAP_SYS_ADMIN
	// in ns (by rule 3 in auth.Credentials.HasCapability).
	if !t.creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, ns) {
		return syserror.EPERM
	}

	t.creds = t.creds.Fork() // See doc for creds.
	t.creds.UserNamespace = ns
	// "The child process created by clone(2) with the CLONE_NEWUSER flag
	// starts out with a complete set of capabilities in the new user
	// namespace. Likewise, a process that creates a new user namespace using
	// unshare(2) or joins an existing user namespace using setns(2) gains a
	// full set of capabilities in that namespace."
	t.creds.PermittedCaps = auth.AllCapabilities
	t.creds.InheritableCaps = 0
	t.creds.EffectiveCaps = auth.AllCapabilities
	t.creds.BoundingCaps = auth.AllCapabilities
	// "A call to clone(2), unshare(2), or setns(2) using the CLONE_NEWUSER
	// flag sets the "securebits" flags (see capabilities(7)) to their default
	// values (all flags disabled) in the child (for clone(2)) or caller (for
	// unshare(2), or setns(2)." - user_namespaces(7)
	t.creds.KeepCaps = false

	return nil
}

// SetKeepCaps will set the keep capabilities flag PR_SET_KEEPCAPS.
func (t *Task) SetKeepCaps(k bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.creds = t.creds.Fork() // See doc for creds.
	t.creds.KeepCaps = k
}

// updateCredsForExec updates t.creds to reflect an execve().
//
// NOTE(b/30815691): We currently do not implement privileged executables
// (set-user/group-ID bits and file capabilities). This allows us to make a lot
// of simplifying assumptions:
//
// - We assume the no_new_privs bit (set by prctl(SET_NO_NEW_PRIVS)), which
// disables the features we don't support anyway, is always set. This
// drastically simplifies this function.
//
// - We don't implement AT_SECURE, because no_new_privs always being set means
// that the conditions that require AT_SECURE never arise. (Compare Linux's
// security/commoncap.c:cap_bprm_set_creds() and cap_bprm_secureexec().)
//
// - We don't check for CAP_SYS_ADMIN in prctl(PR_SET_SECCOMP), since
// seccomp-bpf is also allowed if the task has no_new_privs set.
//
// - Task.ptraceAttach does not serialize with execve as it does in Linux,
// since no_new_privs being set has the same effect as the presence of an
// unprivileged tracer.
//
// Preconditions: t.mu must be locked.
func (t *Task) updateCredsForExecLocked() {
	// """
	// During an execve(2), the kernel calculates the new capabilities of
	// the process using the following algorithm:
	//
	//     P'(permitted) = (P(inheritable) & F(inheritable)) |
	//                     (F(permitted) & cap_bset)
	//
	//     P'(effective) = F(effective) ? P'(permitted) : 0
	//
	//     P'(inheritable) = P(inheritable)    [i.e., unchanged]
	//
	// where:
	//
	//     P         denotes the value of a thread capability set before the
	//               execve(2)
	//
	//     P'        denotes the value of a thread capability set after the
	//               execve(2)
	//
	//     F         denotes a file capability set
	//
	//     cap_bset  is the value of the capability bounding set
	//
	// ...
	//
	// In order to provide an all-powerful root using capability sets, during
	// an execve(2):
	//
	// 1. If a set-user-ID-root program is being executed, or the real user ID
	// of the process is 0 (root) then the file inheritable and permitted sets
	// are defined to be all ones (i.e. all capabilities enabled).
	//
	// 2. If a set-user-ID-root program is being executed, then the file
	// effective bit is defined to be one (enabled).
	//
	// The upshot of the above rules, combined with the capabilities
	// transformations described above, is that when a process execve(2)s a
	// set-user-ID-root program, or when a process with an effective UID of 0
	// execve(2)s a program, it gains all capabilities in its permitted and
	// effective capability sets, except those masked out by the capability
	// bounding set.
	// """ - capabilities(7)
	// (ambient capability sets omitted)
	//
	// As the last paragraph implies, the case of "a set-user-ID root program
	// is being executed" also includes the case where (namespace) root is
	// executing a non-set-user-ID program; the actual check is just based on
	// the effective user ID.
	var newPermitted auth.CapabilitySet // since F(inheritable) == F(permitted) == 0
	fileEffective := false
	root := t.creds.UserNamespace.MapToKUID(auth.RootUID)
	if t.creds.EffectiveKUID == root || t.creds.RealKUID == root {
		newPermitted = t.creds.InheritableCaps | t.creds.BoundingCaps
		if t.creds.EffectiveKUID == root {
			fileEffective = true
		}
	}

	t.creds = t.creds.Fork() // See doc for creds.

	// Now we enter poorly-documented, somewhat confusing territory. (The
	// accompanying comment in Linux's security/commoncap.c:cap_bprm_set_creds
	// is not very helpful.) My reading of it is:
	//
	// If at least one of the following is true:
	//
	// A1. The execing task is ptraced, and the tracer did not have
	// CAP_SYS_PTRACE in the execing task's user namespace at the time of
	// PTRACE_ATTACH.
	//
	// A2. The execing task shares its FS context with at least one task in
	// another thread group.
	//
	// A3. The execing task has no_new_privs set.
	//
	// AND at least one of the following is true:
	//
	// B1. The new effective user ID (which may come from set-user-ID, or be the
	// execing task's existing effective user ID) is not equal to the task's
	// real UID.
	//
	// B2. The new effective group ID (which may come from set-group-ID, or be
	// the execing task's existing effective group ID) is not equal to the
	// task's real GID.
	//
	// B3. The new permitted capability set contains capabilities not in the
	// task's permitted capability set.
	//
	// Then:
	//
	// C1. Limit the new permitted capability set to the task's permitted
	// capability set.
	//
	// C2. If either the task does not have CAP_SETUID in its user namespace, or
	// the task has no_new_privs set, force the new effective UID and GID to
	// the task's real UID and GID.
	//
	// But since no_new_privs is always set (A3 is always true), this becomes
	// much simpler. If B1 and B2 are false, C2 is a no-op. If B3 is false, C1
	// is a no-op. So we can just do C1 and C2 unconditionally.
	if t.creds.EffectiveKUID != t.creds.RealKUID || t.creds.EffectiveKGID != t.creds.RealKGID {
		t.creds.EffectiveKUID = t.creds.RealKUID
		t.creds.EffectiveKGID = t.creds.RealKGID
		t.parentDeathSignal = 0
	}
	// (Saved set-user-ID is always set to the new effective user ID, and saved
	// set-group-ID is always set to the new effective group ID, regardless of
	// the above.)
	t.creds.SavedKUID = t.creds.RealKUID
	t.creds.SavedKGID = t.creds.RealKGID
	t.creds.PermittedCaps &= newPermitted
	if fileEffective {
		t.creds.EffectiveCaps = t.creds.PermittedCaps
	} else {
		t.creds.EffectiveCaps = 0
	}

	// prctl(2): The "keep capabilities" value will be reset to 0 on subsequent
	// calls to execve(2).
	t.creds.KeepCaps = false

	// "The bounding set is inherited at fork(2) from the thread's parent, and
	// is preserved across an execve(2)". So we're done.
}
