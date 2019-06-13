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

package auth

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/syserror"
)

// MapFromKUID translates kuid, a UID in the root namespace, to a UID in ns.
func (ns *UserNamespace) MapFromKUID(kuid KUID) UID {
	if ns.parent == nil {
		return UID(kuid)
	}
	return UID(ns.mapID(&ns.uidMapFromParent, uint32(ns.parent.MapFromKUID(kuid))))
}

// MapFromKGID translates kgid, a GID in the root namespace, to a GID in ns.
func (ns *UserNamespace) MapFromKGID(kgid KGID) GID {
	if ns.parent == nil {
		return GID(kgid)
	}
	return GID(ns.mapID(&ns.gidMapFromParent, uint32(ns.parent.MapFromKGID(kgid))))
}

// MapToKUID translates uid, a UID in ns, to a UID in the root namespace.
func (ns *UserNamespace) MapToKUID(uid UID) KUID {
	if ns.parent == nil {
		return KUID(uid)
	}
	return ns.parent.MapToKUID(UID(ns.mapID(&ns.uidMapToParent, uint32(uid))))
}

// MapToKGID translates gid, a GID in ns, to a GID in the root namespace.
func (ns *UserNamespace) MapToKGID(gid GID) KGID {
	if ns.parent == nil {
		return KGID(gid)
	}
	return ns.parent.MapToKGID(GID(ns.mapID(&ns.gidMapToParent, uint32(gid))))
}

func (ns *UserNamespace) mapID(m *idMapSet, id uint32) uint32 {
	if id == NoID {
		return NoID
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if it := m.FindSegment(id); it.Ok() {
		return it.Value() + (id - it.Start())
	}
	return NoID
}

// allIDsMapped returns true if all IDs in the range [start, end) are mapped in
// m.
//
// Preconditions: end >= start.
func (ns *UserNamespace) allIDsMapped(m *idMapSet, start, end uint32) bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return m.SpanRange(idMapRange{start, end}) == end-start
}

// An IDMapEntry represents a mapping from a range of contiguous IDs in a user
// namespace to an equally-sized range of contiguous IDs in the namespace's
// parent.
//
// +stateify savable
type IDMapEntry struct {
	// FirstID is the first ID in the range in the namespace.
	FirstID uint32

	// FirstParentID is the first ID in the range in the parent namespace.
	FirstParentID uint32

	// Length is the number of IDs in the range.
	Length uint32
}

// SetUIDMap instructs ns to translate UIDs as specified by entries.
//
// Note: SetUIDMap does not place an upper bound on the number of entries, but
// Linux does. This restriction is implemented in SetUIDMap's caller, the
// implementation of /proc/[pid]/uid_map.
func (ns *UserNamespace) SetUIDMap(ctx context.Context, entries []IDMapEntry) error {
	c := CredentialsFromContext(ctx)

	ns.mu.Lock()
	defer ns.mu.Unlock()
	// "After the creation of a new user namespace, the uid_map file of *one*
	// of the processes in the namespace may be written to *once* to define the
	// mapping of user IDs in the new user namespace. An attempt to write more
	// than once to a uid_map file in a user namespace fails with the error
	// EPERM. Similar rules apply for gid_map files." - user_namespaces(7)
	if !ns.uidMapFromParent.IsEmpty() {
		return syserror.EPERM
	}
	// "At least one line must be written to the file."
	if len(entries) == 0 {
		return syserror.EINVAL
	}
	// """
	// In order for a process to write to the /proc/[pid]/uid_map
	// (/proc/[pid]/gid_map) file, all of the following requirements must be
	// met:
	//
	// 1. The writing process must have the CAP_SETUID (CAP_SETGID) capability
	// in the user namespace of the process pid.
	// """
	if !c.HasCapabilityIn(linux.CAP_SETUID, ns) {
		return syserror.EPERM
	}
	// "2. The writing process must either be in the user namespace of the process
	// pid or be in the parent user namespace of the process pid."
	if c.UserNamespace != ns && c.UserNamespace != ns.parent {
		return syserror.EPERM
	}
	// """
	// 3. (see trySetUIDMap)
	//
	// 4. One of the following two cases applies:
	//
	// * Either the writing process has the CAP_SETUID (CAP_SETGID) capability
	// in the parent user namespace.
	// """
	if !c.HasCapabilityIn(linux.CAP_SETUID, ns.parent) {
		// """
		// * Or otherwise all of the following restrictions apply:
		//
		//   + The data written to uid_map (gid_map) must consist of a single line
		//   that maps the writing process' effective user ID (group ID) in the
		//   parent user namespace to a user ID (group ID) in the user namespace.
		// """
		if len(entries) != 1 || ns.parent.MapToKUID(UID(entries[0].FirstParentID)) != c.EffectiveKUID || entries[0].Length != 1 {
			return syserror.EPERM
		}
		// """
		//   + The writing process must have the same effective user ID as the
		//   process that created the user namespace.
		// """
		if c.EffectiveKUID != ns.owner {
			return syserror.EPERM
		}
	}
	// trySetUIDMap leaves data in maps if it fails.
	if err := ns.trySetUIDMap(entries); err != nil {
		ns.uidMapFromParent.RemoveAll()
		ns.uidMapToParent.RemoveAll()
		return err
	}
	return nil
}

func (ns *UserNamespace) trySetUIDMap(entries []IDMapEntry) error {
	for _, e := range entries {
		// Determine upper bounds and check for overflow. This implicitly
		// checks for NoID.
		lastID := e.FirstID + e.Length
		if lastID <= e.FirstID {
			return syserror.EINVAL
		}
		lastParentID := e.FirstParentID + e.Length
		if lastParentID <= e.FirstParentID {
			return syserror.EINVAL
		}
		// "3. The mapped user IDs (group IDs) must in turn have a mapping in
		// the parent user namespace."
		// Only the root namespace has a nil parent, and root is assigned
		// mappings when it's created, so SetUIDMap would have returned EPERM
		// without reaching this point if ns is root.
		if !ns.parent.allIDsMapped(&ns.parent.uidMapToParent, e.FirstParentID, lastParentID) {
			return syserror.EPERM
		}
		// If either of these Adds fail, we have an overlapping range.
		if !ns.uidMapFromParent.Add(idMapRange{e.FirstParentID, lastParentID}, e.FirstID) {
			return syserror.EINVAL
		}
		if !ns.uidMapToParent.Add(idMapRange{e.FirstID, lastID}, e.FirstParentID) {
			return syserror.EINVAL
		}
	}
	return nil
}

// SetGIDMap instructs ns to translate GIDs as specified by entries.
func (ns *UserNamespace) SetGIDMap(ctx context.Context, entries []IDMapEntry) error {
	c := CredentialsFromContext(ctx)

	ns.mu.Lock()
	defer ns.mu.Unlock()
	if !ns.gidMapFromParent.IsEmpty() {
		return syserror.EPERM
	}
	if len(entries) == 0 {
		return syserror.EINVAL
	}
	if !c.HasCapabilityIn(linux.CAP_SETGID, ns) {
		return syserror.EPERM
	}
	if c.UserNamespace != ns && c.UserNamespace != ns.parent {
		return syserror.EPERM
	}
	if !c.HasCapabilityIn(linux.CAP_SETGID, ns.parent) {
		if len(entries) != 1 || ns.parent.MapToKGID(GID(entries[0].FirstParentID)) != c.EffectiveKGID || entries[0].Length != 1 {
			return syserror.EPERM
		}
		// It's correct for this to still be UID.
		if c.EffectiveKUID != ns.owner {
			return syserror.EPERM
		}
		// "In the case of gid_map, use of the setgroups(2) system call must
		// first be denied by writing "deny" to the /proc/[pid]/setgroups file
		// (see below) before writing to gid_map." (This file isn't implemented
		// in the version of Linux we're emulating; see comment in
		// UserNamespace.)
	}
	if err := ns.trySetGIDMap(entries); err != nil {
		ns.gidMapFromParent.RemoveAll()
		ns.gidMapToParent.RemoveAll()
		return err
	}
	return nil
}

func (ns *UserNamespace) trySetGIDMap(entries []IDMapEntry) error {
	for _, e := range entries {
		lastID := e.FirstID + e.Length
		if lastID <= e.FirstID {
			return syserror.EINVAL
		}
		lastParentID := e.FirstParentID + e.Length
		if lastParentID <= e.FirstParentID {
			return syserror.EINVAL
		}
		if !ns.parent.allIDsMapped(&ns.parent.gidMapToParent, e.FirstParentID, lastParentID) {
			return syserror.EPERM
		}
		if !ns.gidMapFromParent.Add(idMapRange{e.FirstParentID, lastParentID}, e.FirstID) {
			return syserror.EINVAL
		}
		if !ns.gidMapToParent.Add(idMapRange{e.FirstID, lastID}, e.FirstParentID) {
			return syserror.EINVAL
		}
	}
	return nil
}

// UIDMap returns the user ID mappings configured for ns. If no mappings
// have been configured, UIDMap returns nil.
func (ns *UserNamespace) UIDMap() []IDMapEntry {
	return ns.getIDMap(&ns.uidMapToParent)
}

// GIDMap returns the group ID mappings configured for ns. If no mappings
// have been configured, GIDMap returns nil.
func (ns *UserNamespace) GIDMap() []IDMapEntry {
	return ns.getIDMap(&ns.gidMapToParent)
}

func (ns *UserNamespace) getIDMap(m *idMapSet) []IDMapEntry {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	var entries []IDMapEntry
	for it := m.FirstSegment(); it.Ok(); it = it.NextSegment() {
		entries = append(entries, IDMapEntry{
			FirstID:       it.Start(),
			FirstParentID: it.Value(),
			Length:        it.Range().Length(),
		})
	}
	return entries
}
