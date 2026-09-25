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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/refs"
)

// A UserNamespace represents a user namespace. See user_namespaces(7) for
// details.
//
// +stateify savable
type UserNamespace struct {
	// parent is this namespace's parent. If this is the root namespace, parent
	// is nil. The parent pointer is immutable.
	parent *UserNamespace

	// owner is the effective UID of the namespace's creator in the root
	// namespace. owner is immutable.
	owner KUID

	// Keys is the set of keys in this namespace.
	Keys KeySet

	// maxUserNamespaces is this namespace's /proc/sys/user/max_user_namespaces:
	// the most descendant user namespaces that may be charged to it.
	// **Not** protected by mu.
	maxUserNamespaces atomicbitops.Int32

	// numUserNamespaces is the number of descendant user namespaces currently
	// charged to this namespace. **Not** protected by mu.
	numUserNamespaces atomicbitops.Int32

	// mu protects the ID maps, setgroupsAllowed, and inode.
	//
	// If mu will be locked in multiple UserNamespaces, it must be locked in
	// descendant namespaces before ancestors.
	mu userNamespaceMutex `state:"nosave"`

	// Mappings of user/group IDs between this namespace and its parent.
	//
	// All ID maps, once set, cannot be changed. This means that successful
	// UID/GID translations cannot be racy.
	//
	// +checklocks:mu
	uidMapFromParent idMapSet

	// +checklocks:mu
	uidMapToParent idMapSet

	// +checklocks:mu
	gidMapFromParent idMapSet

	// +checklocks:mu
	gidMapToParent idMapSet

	// parentHadSetfcap is true if the creator had CAP_SETFCAP in the parent
	// namespace when this namespace was created. It is immutable, like
	// user_namespace.parent_could_setfcap in Linux.
	parentHadSetfcap bool

	// setgroupsAllowed mirrors USERNS_SETGROUPS_ALLOWED in Linux.
	//
	// +checklocks:mu
	setgroupsAllowed bool

	// inode is the nsfs inode associated with this namespace. This is stored as
	// refs.TryRefCounter instead of *nsfs.Inode because nsfs imports auth.
	//
	// +checklocks:mu
	inode refs.TryRefCounter
}

// NewRootUserNamespace returns a UserNamespace that is appropriate for a
// system's root user namespace. Note that namespaces returned by separate calls
// to this function are *distinct* namespaces. Once a root namespace is created
// by this function, the returned value must be reused to refer to the same
// namespace.
func NewRootUserNamespace() *UserNamespace {
	var ns UserNamespace
	ns.setgroupsAllowed = true
	ns.maxUserNamespaces.Store(defaultMaxUserNamespaces)
	// """
	// The initial user namespace has no parent namespace, but, for
	// consistency, the kernel provides dummy user and group ID mapping files
	// for this namespace. Looking at the uid_map file (gid_map is the same)
	// from a shell in the initial namespace shows:
	//
	// $ cat /proc/$$/uid_map
	// 0          0 4294967295
	// """ - user_namespaces(7)
	for _, m := range []*idMapSet{
		&ns.uidMapFromParent,
		&ns.uidMapToParent,
		&ns.gidMapFromParent,
		&ns.gidMapToParent,
	} {
		// Insertion into an empty map shouldn't fail.
		m.InsertRange(idMapRange{0, math.MaxUint32}, 0)
	}
	return &ns
}

// Root returns the root of the user namespace tree containing ns.
func (ns *UserNamespace) Root() *UserNamespace {
	for ns.parent != nil {
		ns = ns.parent
	}
	return ns
}

// Type implements vfs.Namespace.Type.
func (ns *UserNamespace) Type() string {
	return "user"
}

// Destroy implements vfs.Namespace.Destroy.
// Releases ns's charge on its ancestors.
func (ns *UserNamespace) Destroy(ctx context.Context) {
	uncharge(ns.parent, nil)
}

// MaxUserNamespaces returns ns's max_user_namespaces limit.
func (ns *UserNamespace) MaxUserNamespaces() int32 {
	return ns.maxUserNamespaces.Load()
}

// SetMaxUserNamespaces sets ns's max_user_namespaces limit.
func (ns *UserNamespace) SetMaxUserNamespaces(max int32) {
	ns.maxUserNamespaces.Store(max)
}

// UserNamespace implements vfs.Namespace.UserNamespace.
func (ns *UserNamespace) UserNamespace() *UserNamespace {
	return ns
}

// SetInode sets the nsfs inode associated with ns. The initial ref on inode is
// the task or kernel ref for a newly-created user namespace, so those callers
// don't need a separate IncRef.
//
// +checklocksexclude:ns.mu
func (ns *UserNamespace) SetInode(inode refs.TryRefCounter) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.inode = inode
}

// IncRef increments ns's inode refcount.
//
// +checklocksexclude:ns.mu
func (ns *UserNamespace) IncRef() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.inode != nil {
		ns.inode.IncRef()
	}
}

// TryGetInode returns ns's inode with an incremented refcount.
//
// +checklocksexclude:ns.mu
func (ns *UserNamespace) TryGetInode() refs.TryRefCounter {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.inode == nil || !ns.inode.TryIncRef() {
		return nil
	}
	return ns.inode
}

// DecRef decrements ns's inode refcount.
//
// +checklocksexclude:ns.mu
func (ns *UserNamespace) DecRef(ctx context.Context) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.inode != nil {
		ns.inode.DecRef(ctx)
	}
}

// "The kernel imposes (since version 3.11) a limit of 32 nested levels of user
// namespaces." - user_namespaces(7)
const maxUserNamespaceDepth = 32

// defaultMaxUserNamespaces is a new namespace's max_user_namespaces.
// Effectively unlimited until lowered through
// /proc/sys/user/max_user_namespaces.
const defaultMaxUserNamespaces = math.MaxInt32

func (ns *UserNamespace) depth() int {
	var i int
	for ns != nil {
		i++
		ns = ns.parent
	}
	return i
}

// NewChildUserNamespace returns a new user namespace created by a caller with
// credentials c.
//
// +checklocksexclude:c.UserNamespace.mu
func (c *Credentials) NewChildUserNamespace() (*UserNamespace, error) {
	if c.UserNamespace.depth() >= maxUserNamespaceDepth {
		// "... Calls to unshare(2) or clone(2) that would cause this limit to
		// be exceeded fail with the error EUSERS." - user_namespaces(7)
		return nil, linuxerr.EUSERS
	}
	// "EPERM: CLONE_NEWUSER was specified in flags, but either the effective
	// user ID or the effective group ID of the caller does not have a mapping
	// in the parent namespace (see user_namespaces(7))." - clone(2)
	// "CLONE_NEWUSER requires that the user ID and group ID of the calling
	// process are mapped to user IDs and group IDs in the user namespace of
	// the calling process at the time of the call." - unshare(2)
	if !c.EffectiveKUID.In(c.UserNamespace).Ok() {
		return nil, linuxerr.EPERM
	}
	if !c.EffectiveKGID.In(c.UserNamespace).Ok() {
		return nil, linuxerr.EPERM
	}
	c.UserNamespace.mu.Lock()
	parentSetgroupsAllowed := c.UserNamespace.setgroupsAllowed
	c.UserNamespace.mu.Unlock()
	if err := c.UserNamespace.chargeChild(); err != nil {
		return nil, err
	}
	return &UserNamespace{
		parent:            c.UserNamespace,
		owner:             c.EffectiveKUID,
		parentHadSetfcap:  c.HasSelfCapability(linux.CAP_SETFCAP),
		setgroupsAllowed:  parentSetgroupsAllowed,
		maxUserNamespaces: atomicbitops.FromInt32(defaultMaxUserNamespaces),
		// "When a user namespace is created, it starts without a mapping of
		// user IDs (group IDs) to the parent user namespace." -
		// user_namespaces(7)
	}, nil
}

// chargeChild charges a new child namespace to ns and each of its ancestors.
// If any is already at its max_user_namespaces, it undoes the charges already
// taken and returns ENOSPC. This mirrors inc_ucount() in Linux.
func (ns *UserNamespace) chargeChild() error {
	for cur := ns; cur != nil; cur = cur.parent {
		if !cur.tryCharge() {
			uncharge(ns, cur)
			return linuxerr.ENOSPC
		}
	}
	return nil
}

// tryCharge increments ns's descendant count if it is below ns's limit, and
// reports whether it did. This mirrors atomic_long_inc_below() in Linux.
func (ns *UserNamespace) tryCharge() bool {
	for {
		n := ns.numUserNamespaces.Load()
		if n >= ns.maxUserNamespaces.Load() {
			return false
		}
		if ns.numUserNamespaces.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// uncharge decrements the descendant count of from and each of its ancestors,
// stopping before end (which may be nil to go all the way to the root).
func uncharge(from, end *UserNamespace) {
	for cur := from; cur != end; cur = cur.parent {
		cur.numUserNamespaces.Add(-1)
	}
}

// SetgroupsAllowed returns ns's USERNS_SETGROUPS_ALLOWED bit.
//
// +checklocksexclude:ns.mu
func (ns *UserNamespace) SetgroupsAllowed() bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return ns.setgroupsAllowed
}

// MaySetgroups mirrors userns_may_setgroups in Linux.
//
// +checklocksexclude:ns.mu
func (ns *UserNamespace) MaySetgroups() bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return !ns.gidMapFromParent.IsEmpty() && ns.setgroupsAllowed
}

// SetSetgroupsAllowed mirrors proc_setgroups_write in Linux.
//
// +checklocksexclude:ns.mu
func (ns *UserNamespace) SetSetgroupsAllowed(ctx context.Context, allow bool) error {
	c := CredentialsFromContext(ctx)
	if !c.HasCapabilityIn(linux.CAP_SYS_ADMIN, ns) {
		return linuxerr.EPERM
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if allow {
		if !ns.setgroupsAllowed {
			return linuxerr.EPERM
		}
		return nil
	}
	if !ns.gidMapFromParent.IsEmpty() {
		return linuxerr.EPERM
	}
	ns.setgroupsAllowed = false
	return nil
}
