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
	"sync"

	"gvisor.dev/gvisor/pkg/syserror"
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

	// mu protects the following fields.
	//
	// If mu will be locked in multiple UserNamespaces, it must be locked in
	// descendant namespaces before ancestors.
	mu sync.Mutex `state:"nosave"`

	// Mappings of user/group IDs between this namespace and its parent.
	//
	// All ID maps, once set, cannot be changed. This means that successful
	// UID/GID translations cannot be racy.
	uidMapFromParent idMapSet
	uidMapToParent   idMapSet
	gidMapFromParent idMapSet
	gidMapToParent   idMapSet

	// TODO(b/27454212): Support disabling setgroups(2).
}

// NewRootUserNamespace returns a UserNamespace that is appropriate for a
// system's root user namespace.
func NewRootUserNamespace() *UserNamespace {
	var ns UserNamespace
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
		if !m.Add(idMapRange{0, math.MaxUint32}, 0) {
			panic("Failed to insert into empty ID map")
		}
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

// "The kernel imposes (since version 3.11) a limit of 32 nested levels of user
// namespaces." - user_namespaces(7)
const maxUserNamespaceDepth = 32

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
func (c *Credentials) NewChildUserNamespace() (*UserNamespace, error) {
	if c.UserNamespace.depth() >= maxUserNamespaceDepth {
		// "... Calls to unshare(2) or clone(2) that would cause this limit to
		// be exceeded fail with the error EUSERS." - user_namespaces(7)
		return nil, syserror.EUSERS
	}
	// "EPERM: CLONE_NEWUSER was specified in flags, but either the effective
	// user ID or the effective group ID of the caller does not have a mapping
	// in the parent namespace (see user_namespaces(7))." - clone(2)
	// "CLONE_NEWUSER requires that the user ID and group ID of the calling
	// process are mapped to user IDs and group IDs in the user namespace of
	// the calling process at the time of the call." - unshare(2)
	if !c.EffectiveKUID.In(c.UserNamespace).Ok() {
		return nil, syserror.EPERM
	}
	if !c.EffectiveKGID.In(c.UserNamespace).Ok() {
		return nil, syserror.EPERM
	}
	return &UserNamespace{
		parent: c.UserNamespace,
		owner:  c.EffectiveKUID,
		// "When a user namespace is created, it starts without a mapping of
		// user IDs (group IDs) to the parent user namespace." -
		// user_namespaces(7)
	}, nil
}
