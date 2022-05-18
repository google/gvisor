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
	"math"
)

// UID is a user ID in an unspecified user namespace.
//
// +marshal
type UID uint32

// GID is a group ID in an unspecified user namespace.
//
// +marshal slice:GIDSlice
type GID uint32

// In the root user namespace, user/group IDs have a 1-to-1 relationship with
// the users/groups they represent. In other user namespaces, this is not the
// case; for example, two different unmapped users may both "have" the overflow
// UID. This means that it is generally only valid to compare user and group
// IDs in the root user namespace. We assign distinct types, KUID/KGID, to such
// IDs to emphasize this distinction. ("k" is for "key", as in "unique key".
// Linux also uses the prefix "k", but I think they mean "kernel".)

// KUID is a user ID in the root user namespace.
type KUID uint32

// KGID is a group ID in the root user namespace.
type KGID uint32

const (
	// NoID is uint32(-1). -1 is consistently used as a special value, in Linux
	// and by extension in the auth package, to mean "no ID":
	//
	//	- ID mapping returns -1 if the ID is not mapped.
	//
	//	- Most set*id() syscalls accept -1 to mean "do not change this ID".
	NoID = math.MaxUint32

	// OverflowUID is the default value of /proc/sys/kernel/overflowuid. The
	// "overflow UID" is usually [1] used when translating a user ID between
	// namespaces fails because the ID is not mapped. (We don't implement this
	// file, so the overflow UID is constant.)
	//
	// [1] "There is one notable case where unmapped user and group IDs are not
	// converted to the corresponding overflow ID value. When viewing a uid_map
	// or gid_map file in which there is no mapping for the second field, that
	// field is displayed as 4294967295 (-1 as an unsigned integer);" -
	// user_namespaces(7)
	OverflowUID = UID(65534)

	// OverflowGID is the group equivalent to OverflowUID.
	OverflowGID = GID(65534)

	// NobodyKUID is the user ID usually reserved for the least privileged user
	// "nobody".
	NobodyKUID = KUID(65534)

	// NobodyKGID is the group equivalent to NobodyKUID.
	NobodyKGID = KGID(65534)

	// RootKUID is the user ID usually used for the most privileged user "root".
	RootKUID = KUID(0)

	// RootKGID is the group equivalent to RootKUID.
	RootKGID = KGID(0)

	// RootUID is the root user.
	RootUID = UID(0)

	// RootGID is the root group.
	RootGID = GID(0)
)

// Ok returns true if uid is not -1.
func (uid UID) Ok() bool {
	return uid != NoID
}

// Ok returns true if gid is not -1.
func (gid GID) Ok() bool {
	return gid != NoID
}

// Ok returns true if kuid is not -1.
func (kuid KUID) Ok() bool {
	return kuid != NoID
}

// Ok returns true if kgid is not -1.
func (kgid KGID) Ok() bool {
	return kgid != NoID
}

// OrOverflow returns uid if it is valid and the overflow UID otherwise.
func (uid UID) OrOverflow() UID {
	if uid.Ok() {
		return uid
	}
	return OverflowUID
}

// OrOverflow returns gid if it is valid and the overflow GID otherwise.
func (gid GID) OrOverflow() GID {
	if gid.Ok() {
		return gid
	}
	return OverflowGID
}

// In translates kuid into user namespace ns. If kuid is not mapped in ns, In
// returns NoID.
func (kuid KUID) In(ns *UserNamespace) UID {
	return ns.MapFromKUID(kuid)
}

// In translates kgid into user namespace ns. If kgid is not mapped in ns, In
// returns NoID.
func (kgid KGID) In(ns *UserNamespace) GID {
	return ns.MapFromKGID(kgid)
}
