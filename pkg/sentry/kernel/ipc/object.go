// Copyright 2021 The gVisor Authors.
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

// Package ipc defines functionality and utilities common to sysvipc mechanisms.
//
// Lock ordering: [shm/semaphore/msgqueue].Registry.mu -> Mechanism
package ipc

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// Key is a user-provided identifier for IPC objects.
type Key int32

// ID is a kernel identifier for IPC objects.
type ID int32

// Object represents an abstract IPC object with fields common to all IPC
// mechanisms.
//
// +stateify savable
type Object struct {
	// User namespace which owns the IPC namespace which owns the IPC object.
	// Immutable.
	UserNS *auth.UserNamespace

	// ID is a kernel identifier for the IPC object. Immutable.
	ID ID

	// Key is a user-provided identifier for the IPC object. Immutable.
	Key Key

	// Creator is the user who created the IPC object. Immutable.
	Creator fs.FileOwner

	// Owner is the current owner of the IPC object.
	Owner fs.FileOwner

	// Perms is the access permissions the IPC object.
	Perms fs.FilePermissions
}

// Mechanism represents a SysV mechanism that holds an IPC object. It can also
// be looked at as a container for an ipc.Object, which is by definition a fully
// functional SysV object.
type Mechanism interface {
	// Lock behaves the same as Mutex.Lock on the mechanism.
	Lock()

	// Unlock behaves the same as Mutex.Unlock on the mechanism.
	Unlock()

	// Object returns a pointer to the mechanism's ipc.Object. Mechanism.Lock,
	// and Mechanism.Unlock should be used when the object is used.
	Object() *Object

	// Destroy destroys the mechanism.
	Destroy()
}

// NewObject returns a new, initialized ipc.Object. The newly returned object
// doesn't have a valid ID. When the object is registered, the registry assigns
// it a new unique ID.
func NewObject(un *auth.UserNamespace, key Key, creator, owner fs.FileOwner, perms fs.FilePermissions) *Object {
	return &Object{
		UserNS:  un,
		Key:     key,
		Creator: creator,
		Owner:   owner,
		Perms:   perms,
	}
}

// CheckOwnership verifies whether an IPC object may be accessed using creds as
// an owner. See ipc/util.c:ipcctl_obtain_check() in Linux.
func (o *Object) CheckOwnership(creds *auth.Credentials) bool {
	if o.Owner.UID == creds.EffectiveKUID || o.Creator.UID == creds.EffectiveKUID {
		return true
	}

	// Tasks with CAP_SYS_ADMIN may bypass ownership checks. Strangely, Linux
	// doesn't use CAP_IPC_OWNER for this despite CAP_IPC_OWNER being documented
	// for use to "override IPC ownership checks".
	return creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, o.UserNS)
}

// CheckPermissions verifies whether an IPC object is accessible using creds for
// access described by req. See ipc/util.c:ipcperms() in Linux.
func (o *Object) CheckPermissions(creds *auth.Credentials, req fs.PermMask) bool {
	p := o.Perms.Other
	if o.Owner.UID == creds.EffectiveKUID {
		p = o.Perms.User
	} else if creds.InGroup(o.Owner.GID) {
		p = o.Perms.Group
	}

	if p.SupersetOf(req) {
		return true
	}
	return creds.HasCapabilityIn(linux.CAP_IPC_OWNER, o.UserNS)
}

// Set modifies attributes for an IPC object. See *ctl(IPC_SET).
//
// Precondition: Mechanism.mu must be held.
func (o *Object) Set(ctx context.Context, perm *linux.IPCPerm) error {
	creds := auth.CredentialsFromContext(ctx)
	uid := creds.UserNamespace.MapToKUID(auth.UID(perm.UID))
	gid := creds.UserNamespace.MapToKGID(auth.GID(perm.GID))
	if !uid.Ok() || !gid.Ok() {
		// The man pages don't specify an errno for invalid uid/gid, but EINVAL
		// is generally used for invalid arguments.
		return linuxerr.EINVAL
	}

	if !o.CheckOwnership(creds) {
		// "The argument cmd has the value IPC_SET or IPC_RMID, but the
		//  effective user ID of the calling process is not the creator (as
		//  found in msg_perm.cuid) or the owner (as found in msg_perm.uid)
		//  of the message queue, and the caller is not privileged (Linux:
		//  does not have the CAP_SYS_ADMIN capability)."
		return linuxerr.EPERM
	}

	// User may only modify the lower 9 bits of the mode. All the other bits are
	// always 0 for the underlying inode.
	mode := linux.FileMode(perm.Mode & 0x1ff)

	o.Perms = fs.FilePermsFromMode(mode)
	o.Owner.UID = uid
	o.Owner.GID = gid

	return nil
}
