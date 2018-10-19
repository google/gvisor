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

package auth

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Credentials contains information required to authorize privileged operations
// in a user namespace.
//
// +stateify savable
type Credentials struct {
	// Real/effective/saved user/group IDs in the root user namespace. None of
	// these should ever be NoID.
	RealKUID      KUID
	EffectiveKUID KUID
	SavedKUID     KUID
	RealKGID      KGID
	EffectiveKGID KGID
	SavedKGID     KGID

	// Filesystem user/group IDs are not implemented. "... setfsuid() is
	// nowadays unneeded and should be avoided in new applications (likewise
	// for setfsgid(2))." - setfsuid(2)

	// Supplementary groups used by set/getgroups.
	//
	// ExtraKGIDs slices are immutable, allowing multiple Credentials with the
	// same ExtraKGIDs to share the same slice.
	ExtraKGIDs []KGID

	// The capability sets applicable to this set of credentials.
	PermittedCaps   CapabilitySet
	InheritableCaps CapabilitySet
	EffectiveCaps   CapabilitySet
	BoundingCaps    CapabilitySet
	// Ambient capabilities are not introduced until Linux 4.3.

	// KeepCaps is the flag for PR_SET_KEEPCAPS which allow capabilities to be
	// maintained after a switch from root user to non-root user via setuid().
	KeepCaps bool

	// The user namespace associated with the owner of the credentials.
	UserNamespace *UserNamespace
}

// NewAnonymousCredentials returns a set of credentials with no capabilities in
// any user namespace.
func NewAnonymousCredentials() *Credentials {
	// Create a new root user namespace. Since the new namespace's owner is
	// KUID 0 and the returned credentials have non-zero KUID/KGID, the
	// returned credentials do not have any capabilities in the new namespace.
	// Since the new namespace is not part of any existing user namespace
	// hierarchy, the returned credentials do not have any capabilities in any
	// other namespace.
	return &Credentials{
		RealKUID:      NobodyKUID,
		EffectiveKUID: NobodyKUID,
		SavedKUID:     NobodyKUID,
		RealKGID:      NobodyKGID,
		EffectiveKGID: NobodyKGID,
		SavedKGID:     NobodyKGID,
		UserNamespace: NewRootUserNamespace(),
	}
}

// NewRootCredentials returns a set of credentials with KUID and KGID 0 (i.e.
// global root) in user namespace ns.
func NewRootCredentials(ns *UserNamespace) *Credentials {
	// I can't find documentation for this anywhere, but it's correct for the
	// inheritable capability set to be initially empty (the capabilities test
	// checks for this property).
	return &Credentials{
		RealKUID:      RootKUID,
		EffectiveKUID: RootKUID,
		SavedKUID:     RootKUID,
		RealKGID:      RootKGID,
		EffectiveKGID: RootKGID,
		SavedKGID:     RootKGID,
		PermittedCaps: AllCapabilities,
		EffectiveCaps: AllCapabilities,
		BoundingCaps:  AllCapabilities,
		UserNamespace: ns,
	}
}

// NewUserCredentials returns a set of credentials based on the given UID, GIDs,
// and capabilities in a given namespace. If all arguments are their zero
// values, this returns the same credentials as NewRootCredentials.
func NewUserCredentials(kuid KUID, kgid KGID, extraKGIDs []KGID, capabilities *TaskCapabilities, ns *UserNamespace) *Credentials {
	creds := NewRootCredentials(ns)

	// Set the UID.
	uid := kuid
	creds.RealKUID = uid
	creds.EffectiveKUID = uid
	creds.SavedKUID = uid

	// Set GID.
	gid := kgid
	creds.RealKGID = gid
	creds.EffectiveKGID = gid
	creds.SavedKGID = gid

	// Set additional GIDs.
	creds.ExtraKGIDs = append(creds.ExtraKGIDs, extraKGIDs...)

	// Set capabilities. If capabilities aren't specified, we default to
	// all capabilities.
	if capabilities != nil {
		creds.PermittedCaps = capabilities.PermittedCaps
		creds.EffectiveCaps = capabilities.EffectiveCaps
		creds.BoundingCaps = capabilities.BoundingCaps
		creds.InheritableCaps = capabilities.InheritableCaps
		// // TODO: Support ambient capabilities.
	} else {
		// If no capabilities are specified, grant the same capabilities
		// that NewRootCredentials does.
		creds.PermittedCaps = AllCapabilities
		creds.EffectiveCaps = AllCapabilities
		creds.BoundingCaps = AllCapabilities
	}

	return creds
}

// Fork generates an identical copy of a set of credentials.
func (c *Credentials) Fork() *Credentials {
	nc := new(Credentials)
	*nc = *c // Copy-by-value; this is legal for all fields.
	return nc
}

// InGroup returns true if c is in group kgid. Compare Linux's
// kernel/groups.c:in_group_p().
func (c *Credentials) InGroup(kgid KGID) bool {
	if c.EffectiveKGID == kgid {
		return true
	}
	for _, extraKGID := range c.ExtraKGIDs {
		if extraKGID == kgid {
			return true
		}
	}
	return false
}

// HasCapabilityIn returns true if c has capability cp in ns.
func (c *Credentials) HasCapabilityIn(cp linux.Capability, ns *UserNamespace) bool {
	for {
		// "1. A process has a capability inside a user namespace if it is a member
		// of that namespace and it has the capability in its effective capability
		// set." - user_namespaces(7)
		if c.UserNamespace == ns {
			return CapabilitySetOf(cp)&c.EffectiveCaps != 0
		}
		// "3. ... A process that resides in the parent of the user namespace and
		// whose effective user ID matches the owner of the namespace has all
		// capabilities in the namespace."
		if c.UserNamespace == ns.parent && c.EffectiveKUID == ns.owner {
			return true
		}
		// "2. If a process has a capability in a user namespace, then it has that
		// capability in all child (and further removed descendant) namespaces as
		// well."
		if ns.parent == nil {
			return false
		}
		ns = ns.parent
	}
}

// HasCapability returns true if c has capability cp in its user namespace.
func (c *Credentials) HasCapability(cp linux.Capability) bool {
	return c.HasCapabilityIn(cp, c.UserNamespace)
}

// UseUID checks that c can use uid in its user namespace, then translates it
// to the root user namespace.
//
// The checks UseUID does are common, but you should verify that it's doing
// exactly what you want.
func (c *Credentials) UseUID(uid UID) (KUID, error) {
	// uid must be mapped.
	kuid := c.UserNamespace.MapToKUID(uid)
	if !kuid.Ok() {
		return NoID, syserror.EINVAL
	}
	// If c has CAP_SETUID, then it can use any UID in its user namespace.
	if c.HasCapability(linux.CAP_SETUID) {
		return kuid, nil
	}
	// Otherwise, c must already have the UID as its real, effective, or saved
	// set-user-ID.
	if kuid == c.RealKUID || kuid == c.EffectiveKUID || kuid == c.SavedKUID {
		return kuid, nil
	}
	return NoID, syserror.EPERM
}

// UseGID checks that c can use gid in its user namespace, then translates it
// to the root user namespace.
func (c *Credentials) UseGID(gid GID) (KGID, error) {
	kgid := c.UserNamespace.MapToKGID(gid)
	if !kgid.Ok() {
		return NoID, syserror.EINVAL
	}
	if c.HasCapability(linux.CAP_SETGID) {
		return kgid, nil
	}
	if kgid == c.RealKGID || kgid == c.EffectiveKGID || kgid == c.SavedKGID {
		return kgid, nil
	}
	return NoID, syserror.EPERM
}
