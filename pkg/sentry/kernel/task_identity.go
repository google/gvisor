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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/mm"
)

// Credentials returns t's credentials.
//
// This value must be considered immutable.
func (t *Task) Credentials() *auth.Credentials {
	return t.creds.Load()
}

// UserNamespace returns the user namespace associated with the task.
func (t *Task) UserNamespace() *auth.UserNamespace {
	return t.Credentials().UserNamespace
}

// HasCapabilityIn checks if the task has capability cp in user namespace ns.
func (t *Task) HasCapabilityIn(cp linux.Capability, ns *auth.UserNamespace) bool {
	return t.Credentials().HasCapabilityIn(cp, ns)
}

// HasCapability checks if the task has capability cp in its user namespace.
func (t *Task) HasCapability(cp linux.Capability) bool {
	return t.Credentials().HasCapability(cp)
}

// SetUID implements the semantics of setuid(2).
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) SetUID(uid auth.UID) error {
	// setuid considers -1 to be invalid.
	if !uid.Ok() {
		return linuxerr.EINVAL
	}

	creds := t.Credentials()
	kuid := creds.UserNamespace.MapToKUID(uid)
	if !kuid.Ok() {
		return linuxerr.EINVAL
	}
	// "setuid() sets the effective user ID of the calling process. If the
	// effective UID of the caller is root (more precisely: if the caller has
	// the CAP_SETUID capability), the real UID and saved set-user-ID are also
	// set." - setuid(2)
	if creds.HasCapability(linux.CAP_SETUID) {
		t.setKUIDsUnchecked(kuid, kuid, kuid)
		return nil
	}
	// "EPERM: The user is not privileged (Linux: does not have the CAP_SETUID
	// capability) and uid does not match the real UID or saved set-user-ID of
	// the calling process."
	if kuid != creds.RealKUID && kuid != creds.SavedKUID {
		return linuxerr.EPERM
	}
	t.setKUIDsUnchecked(creds.RealKUID, kuid, creds.SavedKUID)
	return nil
}

// SetREUID implements the semantics of setreuid(2).
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) SetREUID(r, e auth.UID) error {
	// "Supplying a value of -1 for either the real or effective user ID forces
	// the system to leave that ID unchanged." - setreuid(2)
	creds := t.Credentials()
	newR := creds.RealKUID
	if r.Ok() {
		newR = creds.UserNamespace.MapToKUID(r)
		if !newR.Ok() {
			return linuxerr.EINVAL
		}
	}
	newE := creds.EffectiveKUID
	if e.Ok() {
		newE = creds.UserNamespace.MapToKUID(e)
		if !newE.Ok() {
			return linuxerr.EINVAL
		}
	}
	if !creds.HasCapability(linux.CAP_SETUID) {
		// "Unprivileged processes may only set the effective user ID to the
		// real user ID, the effective user ID, or the saved set-user-ID."
		if newE != creds.RealKUID && newE != creds.EffectiveKUID && newE != creds.SavedKUID {
			return linuxerr.EPERM
		}
		// "Unprivileged users may only set the real user ID to the real user
		// ID or the effective user ID."
		if newR != creds.RealKUID && newR != creds.EffectiveKUID {
			return linuxerr.EPERM
		}
	}
	// "If the real user ID is set (i.e., ruid is not -1) or the effective user
	// ID is set to a value not equal to the previous real user ID, the saved
	// set-user-ID will be set to the new effective user ID."
	newS := creds.SavedKUID
	if r.Ok() || (e.Ok() && newE != creds.EffectiveKUID) {
		newS = newE
	}
	t.setKUIDsUnchecked(newR, newE, newS)
	return nil
}

// SetRESUID implements the semantics of the setresuid(2) syscall.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) SetRESUID(r, e, s auth.UID) error {
	// "Unprivileged user processes may change the real UID, effective UID, and
	// saved set-user-ID, each to one of: the current real UID, the current
	// effective UID or the current saved set-user-ID. Privileged processes (on
	// Linux, those having the CAP_SETUID capability) may set the real UID,
	// effective UID, and saved set-user-ID to arbitrary values. If one of the
	// arguments equals -1, the corresponding value is not changed." -
	// setresuid(2)
	var err error
	creds := t.Credentials()
	newR := creds.RealKUID
	if r.Ok() {
		newR, err = creds.UseUID(r)
		if err != nil {
			return err
		}
	}
	newE := creds.EffectiveKUID
	if e.Ok() {
		newE, err = creds.UseUID(e)
		if err != nil {
			return err
		}
	}
	newS := creds.SavedKUID
	if s.Ok() {
		newS, err = creds.UseUID(s)
		if err != nil {
			return err
		}
	}
	t.setKUIDsUnchecked(newR, newE, newS)
	return nil
}

// Preconditions: The caller must be running on the task goroutine.
func (t *Task) setKUIDsUnchecked(newR, newE, newS auth.KUID) {
	creds := t.Credentials().Fork() // The credentials object is immutable. See doc for creds.
	root := creds.UserNamespace.MapToKUID(auth.RootUID)
	oldR, oldE, oldS := creds.RealKUID, creds.EffectiveKUID, creds.SavedKUID
	creds.RealKUID, creds.EffectiveKUID, creds.SavedKUID = newR, newE, newS

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
		if !creds.KeepCaps {
			creds.PermittedCaps = 0
			creds.EffectiveCaps = 0
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
		creds.EffectiveCaps = 0
	} else if oldE != root && newE == root {
		creds.EffectiveCaps = creds.PermittedCaps
	}
	// "4. If the filesystem user ID is changed from 0 to nonzero (see
	// setfsuid(2)), then the following capabilities are cleared from the
	// effective set: ..."
	// (filesystem UIDs aren't implemented, nor are any of the capabilities in
	// question)

	if oldE != newE {
		// "[dumpability] is reset to the current value contained in
		// the file /proc/sys/fs/suid_dumpable (which by default has
		// the value 0), in the following circumstances: The process's
		// effective user or group ID is changed." - prctl(2)
		//
		// (suid_dumpable isn't implemented, so we just use the
		// default.
		t.MemoryManager().SetDumpability(mm.NotDumpable)

		// Not documented, but compare Linux's kernel/cred.c:commit_creds().
		t.parentDeathSignal = 0
	}
	t.creds.Store(creds)
}

// SetGID implements the semantics of setgid(2).
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) SetGID(gid auth.GID) error {
	if !gid.Ok() {
		return linuxerr.EINVAL
	}

	creds := t.Credentials()
	kgid := creds.UserNamespace.MapToKGID(gid)
	if !kgid.Ok() {
		return linuxerr.EINVAL
	}
	if creds.HasCapability(linux.CAP_SETGID) {
		t.setKGIDsUnchecked(kgid, kgid, kgid)
		return nil
	}
	if kgid != creds.RealKGID && kgid != creds.SavedKGID {
		return linuxerr.EPERM
	}
	t.setKGIDsUnchecked(creds.RealKGID, kgid, creds.SavedKGID)
	return nil
}

// SetREGID implements the semantics of setregid(2).
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) SetREGID(r, e auth.GID) error {
	creds := t.Credentials()
	newR := creds.RealKGID
	if r.Ok() {
		newR = creds.UserNamespace.MapToKGID(r)
		if !newR.Ok() {
			return linuxerr.EINVAL
		}
	}
	newE := creds.EffectiveKGID
	if e.Ok() {
		newE = creds.UserNamespace.MapToKGID(e)
		if !newE.Ok() {
			return linuxerr.EINVAL
		}
	}
	if !creds.HasCapability(linux.CAP_SETGID) {
		if newE != creds.RealKGID && newE != creds.EffectiveKGID && newE != creds.SavedKGID {
			return linuxerr.EPERM
		}
		if newR != creds.RealKGID && newR != creds.EffectiveKGID {
			return linuxerr.EPERM
		}
	}
	newS := creds.SavedKGID
	if r.Ok() || (e.Ok() && newE != creds.EffectiveKGID) {
		newS = newE
	}
	t.setKGIDsUnchecked(newR, newE, newS)
	return nil
}

// SetRESGID implements the semantics of the setresgid(2) syscall.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) SetRESGID(r, e, s auth.GID) error {
	var err error

	creds := t.Credentials()
	newR := creds.RealKGID
	if r.Ok() {
		newR, err = creds.UseGID(r)
		if err != nil {
			return err
		}
	}
	newE := creds.EffectiveKGID
	if e.Ok() {
		newE, err = creds.UseGID(e)
		if err != nil {
			return err
		}
	}
	newS := creds.SavedKGID
	if s.Ok() {
		newS, err = creds.UseGID(s)
		if err != nil {
			return err
		}
	}
	t.setKGIDsUnchecked(newR, newE, newS)
	return nil
}

// Preconditions: The caller must be running on the task goroutine.
func (t *Task) setKGIDsUnchecked(newR, newE, newS auth.KGID) {
	creds := t.Credentials().Fork() // The credentials object is immutable. See doc for creds.
	oldE := creds.EffectiveKGID
	creds.RealKGID, creds.EffectiveKGID, creds.SavedKGID = newR, newE, newS

	if oldE != newE {
		// "[dumpability] is reset to the current value contained in
		// the file /proc/sys/fs/suid_dumpable (which by default has
		// the value 0), in the following circumstances: The process's
		// effective user or group ID is changed." - prctl(2)
		//
		// (suid_dumpable isn't implemented, so we just use the
		// default.
		t.MemoryManager().SetDumpability(mm.NotDumpable)

		// Not documented, but compare Linux's
		// kernel/cred.c:commit_creds().
		t.parentDeathSignal = 0
	}
	t.creds.Store(creds)
}

// SetExtraGIDs attempts to change t's supplemental groups. All IDs are
// interpreted as being in t's user namespace.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) SetExtraGIDs(gids []auth.GID) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	creds := t.Credentials()
	if !creds.HasCapability(linux.CAP_SETGID) {
		return linuxerr.EPERM
	}
	kgids := make([]auth.KGID, len(gids))
	for i, gid := range gids {
		kgid := creds.UserNamespace.MapToKGID(gid)
		if !kgid.Ok() {
			return linuxerr.EINVAL
		}
		kgids[i] = kgid
	}
	creds = creds.Fork() // The credentials object is immutable. See doc for creds.
	creds.ExtraKGIDs = kgids
	t.creds.Store(creds)
	return nil
}

// weakCaps is a set of capabilities that can be disabled externally.
var weakCaps = auth.CapabilitySetOf(linux.CAP_NET_RAW)

// SetCapabilitySets attempts to change t's permitted, inheritable, and
// effective capability sets.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) SetCapabilitySets(permitted, inheritable, effective auth.CapabilitySet) error {
	// "Permitted: This is a limiting superset for the effective capabilities
	// that the thread may assume." - capabilities(7)
	if effective & ^permitted != 0 {
		return linuxerr.EPERM
	}
	creds := t.Credentials()

	// Don't fail if one or more weak capabilities can't be set, just drop them.
	mask := (weakCaps & creds.BoundingCaps) | (auth.AllCapabilities &^ weakCaps)
	permitted &= mask
	inheritable &= mask
	effective &= mask

	// "It is also a limiting superset for the capabilities that may be added
	// to the inheritable set by a thread that does not have the CAP_SETPCAP
	// capability in its effective set."
	if !creds.HasCapability(linux.CAP_SETPCAP) && (inheritable & ^(creds.InheritableCaps|creds.PermittedCaps) != 0) {
		return linuxerr.EPERM
	}
	// "If a thread drops a capability from its permitted set, it can never
	// reacquire that capability (unless it execve(2)s ..."
	if permitted & ^creds.PermittedCaps != 0 {
		return linuxerr.EPERM
	}
	// "... if a capability is not in the bounding set, then a thread can't add
	// this capability to its inheritable set, even if it was in its permitted
	// capabilities ..."
	if inheritable & ^(creds.InheritableCaps|creds.BoundingCaps) != 0 {
		return linuxerr.EPERM
	}
	creds = creds.Fork() // The credentials object is immutable. See doc for creds.
	creds.PermittedCaps = permitted
	creds.InheritableCaps = inheritable
	creds.EffectiveCaps = effective
	t.creds.Store(creds)
	return nil
}

// DropBoundingCapability attempts to drop capability cp from t's capability
// bounding set.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) DropBoundingCapability(cp linux.Capability) error {
	creds := t.Credentials()
	if !creds.HasCapability(linux.CAP_SETPCAP) {
		return linuxerr.EPERM
	}
	creds = creds.Fork() // The credentials object is immutable. See doc for creds.
	creds.BoundingCaps &^= auth.CapabilitySetOf(cp)
	t.creds.Store(creds)
	return nil
}

// SetKeepCaps will set the keep capabilities flag PR_SET_KEEPCAPS.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) SetKeepCaps(k bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	creds := t.Credentials().Fork() // The credentials object is immutable. See doc for creds.
	creds.KeepCaps = k
	t.creds.Store(creds)
}

// SetNoNewPrivs will set the no new privileges flag PR_SET_NO_NEW_PRIVS.
func (t *Task) SetNoNewPrivs() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.noNewPrivs = true
}

// GetNoNewPrivs returns true if the prctl flag NO_NEW_PRIVS is set.
func (t *Task) GetNoNewPrivs() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.noNewPrivs
}
