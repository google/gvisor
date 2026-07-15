// Copyright 2026 The gVisor Authors.
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

package vfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// ACLType is an ACL's type.
type ACLType uint

const (
	// AccessACL is an ACL used to determine file permissions.
	AccessACL ACLType = iota

	// DefaultACL is an ACL inherited by objects created in directories.
	DefaultACL
)

// ACLUser represents a named ACL user.
//
// +stateify savable
type ACLUser struct {
	// UID is the named user.
	UID auth.KUID

	// Perms is the permissions granted to the named user.
	Perms AccessTypes
}

// ACLGroup represents a named ACL group.
//
// +stateify savable
type ACLGroup struct {
	// GID is the named group.
	GID auth.KGID

	// Perms is the permissions granted to the named group.
	Perms AccessTypes
}

// PosixACL represents a POSIX ACL, analogous to Linux's struct posix_acl.
//
// *All* fields in PosixACL are immutable.
//
// +stateify savable
type PosixACL struct {
	// UGOPerms represent the ACL_USER_OBJ, ACL_GROUP_OBJ, and ACL_OTHER permissions
	// as specified in the ACL (all of which are required).
	UGOPerms uint16

	// Mask contains the ACL_MASK field as specified in the ACL (or nil if not present).
	Mask *AccessTypes

	// Users is a list of named users in the ACL.
	Users []ACLUser

	// Groups is a list of named groups in the ACL.
	Groups []ACLGroup
}

func (a *PosixACL) masked(perms AccessTypes) AccessTypes {
	if a.Mask == nil {
		return perms
	}
	return perms & *a.Mask
}

// UserPerms returns the permissions granted to the owning user by the ACL.
func (a *PosixACL) UserPerms() AccessTypes {
	return AccessTypes((a.UGOPerms & linux.ModeUserAll) >> 6)
}

// GroupPerms returns the permissions granted to the owning group (without
// consideration for the mask) by the ACL.
func (a *PosixACL) GroupPerms() AccessTypes {
	return AccessTypes((a.UGOPerms & linux.ModeGroupAll) >> 3)
}

// OtherPerms returns the permissions granted to "other" by the ACL.
func (a *PosixACL) OtherPerms() AccessTypes {
	return AccessTypes(a.UGOPerms & linux.ModeOtherAll)
}

// Chmod returns a new PosixACL updated based on the new mode's permission bits.
//
// It is roughly analogous to Linux's fs/posix_acl.c:posix_acl_chmod().
func (a *PosixACL) Chmod(mode uint16) PosixACL {
	new := *a

	// User/Other come directly from the new mode
	new.UGOPerms = (new.UGOPerms &^ linux.ModeUserAll) | (mode & linux.ModeUserAll)
	new.UGOPerms = (new.UGOPerms &^ linux.ModeOtherAll) | (mode & linux.ModeOtherAll)

	// Group updates the mask if present
	if new.Mask != nil {
		newMask := AccessTypes((mode & linux.ModeGroupAll) >> 3)
		new.Mask = &newMask
	} else {
		new.UGOPerms = (new.UGOPerms &^ linux.ModeGroupAll) | (mode & linux.ModeGroupAll)
	}

	return new
}

// MaskNewFileMode returns a PosixACL adjusted with the open mode when creating a new file.
//
// It is roughly analogous to Linux's fs/posix_acl.c:posix_acl_create().
func (a *PosixACL) MaskNewFileMode(mode uint16) PosixACL {
	newACL := *a

	// User
	newACL.UGOPerms &= (mode & linux.ModeUserAll) | (newACL.UGOPerms &^ linux.ModeUserAll)
	// Other
	newACL.UGOPerms &= (mode & linux.ModeOtherAll) | (newACL.UGOPerms &^ linux.ModeOtherAll)

	if a.Mask != nil {
		// Mask
		newMask := *newACL.Mask
		newMask &= AccessTypes((mode & linux.ModeGroupAll) >> 3)
		newACL.Mask = &newMask
	} else {
		// Group
		newACL.UGOPerms &= (mode & linux.ModeGroupAll) | (newACL.UGOPerms &^ linux.ModeGroupAll)
	}

	return newACL
}

// Mode returns the userspace-facing permission bits of the mode from the ACL,
// along with a bool indicating whether the ACL is fully equivalent to the mode
// (in other words, storing the ACL is not necessary).
//
// It is analogous to fs/posix_acl.c:posix_acl_equiv_mode() in Linux.
func (a *PosixACL) Mode() (uint16, bool) {
	mode := a.UGOPerms
	if a.Mask != nil {
		// The mask, if present, appears to userspace as the group bits
		mode = (mode &^ linux.ModeGroupAll) | (uint16(*a.Mask) << 3)
	}

	equiv := len(a.Users) == 0 && len(a.Groups) == 0 && a.Mask == nil

	return mode, equiv
}

// checkUserWithMask is used to check named users as part of the ACL access check algorithm.
//
// found indicates whether a named user determines the permissions for this check.
// passes indicates whether the permission check succeeds.
func (a *PosixACL) checkUserWithMask(creds *auth.Credentials, ats AccessTypes) (found bool, passes bool) {
	for _, user := range a.Users {
		if user.UID == creds.EffectiveKUID {
			found = true
			if ats.checkPerms(a.masked(user.Perms)) {
				passes = true
			}
			break
		}
	}
	return
}

// checkGroupsWithMask is used to check named groups as part of the ACL access check algorithm.
//
// found indicates whether a named group determines the permissions for this check.
// passes indicates whether the permission check succeeds.
func (a *PosixACL) checkGroupsWithMask(creds *auth.Credentials, ats AccessTypes) (found bool, passes bool) {
	for _, group := range a.Groups {
		if creds.InGroup(group.GID) {
			found = true
			if ats.checkPerms(a.masked(group.Perms)) {
				passes = true
				break
			}
		}
	}
	return
}

// checkPermissions implements the ACL portion of the access check algorithm as described in acl(5).
func (a *PosixACL) checkPermissions(creds *auth.Credentials, ats AccessTypes, kuid auth.KUID, kgid auth.KGID) bool {
	// [From acl(5):]
	if creds.EffectiveKUID == kuid {
		// 1. if the effective user ID of the process matches
		//    the user ID of the file object owner, then
		if ats.checkPerms(a.UserPerms()) {
			// if the ACL_USER_OBJ entry contains the requested permissions,
			// access is granted,
			return true
		}
		// else access is denied.
	} else if found, passes := a.checkUserWithMask(creds, ats); found {
		// 2. else if the effective user ID of the process matches
		//    the qualifier of any entry of type ACL_USER, then
		if passes {
			// if the matching ACL_USER entry and the ACL_MASK entry
			// contain the requested permissions, access is granted,
			return true
		}
		// else access is denied.
	} else if found, passes := a.checkGroupsWithMask(creds, ats); creds.InGroup(kgid) || found {
		// 3. else if the effective group ID or any of the supplementary group IDs
		//    of the process match the file group or the qualifier of any entry of
		//    type ACL_GROUP, then
		if creds.InGroup(kgid) && ats.checkPerms(a.masked(a.GroupPerms())) {
			// if the ACL_MASK entry and any of the matching [...] ACL_GROUP
			// entries contain the requested permissions, access is granted,
			return true
		}
		if found && passes {
			// [...] or ACL_GROUP entries
			return true
		}

		// [note that the above implicitly handles both present and missing ACL_MASK]
	} else if ats.checkPerms(a.OtherPerms()) {
		// 4. else if the ACL_OTHER entry contains the requested permissions,
		//    access is granted.
		return true
	}

	// 5. else access is denied.
	return false
}

// Serialize returns the userspace xattr representation of the specified PosixACL.
// Specifying a user namespace is required since UIDs and GIDs for named users in
// the ACL's xattr representation are transformed into the process's user namespace.
func (a *PosixACL) Serialize(userns *auth.UserNamespace) []byte {
	// Version header
	ret := linux.PosixACLXattr{
		Version: linux.POSIX_ACL_XATTR_VERSION,
		Entries: make([]linux.PosixACLXattrEntry, 0),
	}

	// Owning user's permissions
	ret.Entries = append(ret.Entries, linux.PosixACLXattrEntry{
		Tag:  linux.ACL_USER_OBJ,
		Perm: uint16(a.UserPerms()),
		ID:   linux.ACL_UNDEFINED_ID,
	})

	// Named users
	for _, user := range a.Users {
		ret.Entries = append(ret.Entries, linux.PosixACLXattrEntry{
			Tag:  linux.ACL_USER,
			Perm: uint16(user.Perms),
			ID:   uint32(userns.MapFromKUID(user.UID)),
		})
	}

	// Owning group's permissions
	ret.Entries = append(ret.Entries, linux.PosixACLXattrEntry{
		Tag:  linux.ACL_GROUP_OBJ,
		Perm: uint16(a.GroupPerms()),
		ID:   linux.ACL_UNDEFINED_ID,
	})

	// Named groups
	for _, group := range a.Groups {
		ret.Entries = append(ret.Entries, linux.PosixACLXattrEntry{
			Tag:  linux.ACL_GROUP,
			Perm: uint16(group.Perms),
			ID:   uint32(userns.MapFromKGID(group.GID)),
		})
	}

	// Mask
	if a.Mask != nil {
		ret.Entries = append(ret.Entries, linux.PosixACLXattrEntry{
			Tag:  linux.ACL_MASK,
			Perm: uint16(*a.Mask),
			ID:   linux.ACL_UNDEFINED_ID,
		})
	}

	// Other permissions
	ret.Entries = append(ret.Entries, linux.PosixACLXattrEntry{
		Tag:  linux.ACL_OTHER,
		Perm: uint16(a.OtherPerms()),
		ID:   linux.ACL_UNDEFINED_ID,
	})

	buf := make([]byte, ret.SizeBytes())
	ret.MarshalBytes(buf)

	return buf
}

// ParsePosixACL parses a userspace-specified xattr into a Posix ACL.
func ParsePosixACL(src []byte, userns *auth.UserNamespace) (*PosixACL, error) {
	if len(src) == 0 {
		// Empty string counts as empty ACL.
		return nil, nil
	}

	// First, parse into a Linux.PosixACLXattr (the uabi type).
	if len(src) < (&linux.PosixACLXattr{}).SizeBytes() {
		// Header missing
		return &PosixACL{}, linuxerr.EINVAL
	}
	acl := &linux.PosixACLXattr{}
	if remaining := acl.UnmarshalBytes(src); len(remaining) != 0 {
		// Should contain a whole number of entries
		return &PosixACL{}, linuxerr.EINVAL
	}

	if acl.Version != linux.POSIX_ACL_XATTR_VERSION {
		// Version was incorrect
		return &PosixACL{}, linuxerr.EOPNOTSUPP
	}

	if len(acl.Entries) == 0 {
		// ACL with no entries counts as empty ACL.
		return nil, nil
	}

	// Now, take a look at the entries.
	var userObj, groupObj, other, mask *uint16
	users := make([]ACLUser, 0)
	groups := make([]ACLGroup, 0)
	for _, entry := range acl.Entries {
		if entry.Perm&^(linux.ACL_READ|linux.ACL_WRITE|linux.ACL_EXECUTE) != 0 {
			// Perm must always be a valid set of permission bits
			return &PosixACL{}, linuxerr.EINVAL
		}

		switch entry.Tag {
		case linux.ACL_USER_OBJ:
			if userObj != nil {
				// Only one ACL_USER_OBJ allowed
				return &PosixACL{}, linuxerr.EINVAL
			}
			userObj = &entry.Perm
		case linux.ACL_GROUP_OBJ:
			if groupObj != nil {
				// Only one ACL_GROUP_OBJ allowed
				return &PosixACL{}, linuxerr.EINVAL
			}
			groupObj = &entry.Perm
		case linux.ACL_OTHER:
			if other != nil {
				// Only one ACL_OTHER allowed
				return &PosixACL{}, linuxerr.EINVAL
			}
			other = &entry.Perm
		case linux.ACL_USER:
			kuid := userns.MapToKUID(auth.UID(entry.ID))
			if !kuid.Ok() {
				return &PosixACL{}, linuxerr.EINVAL
			}

			aclUser := ACLUser{
				UID:   kuid,
				Perms: AccessTypes(entry.Perm),
			}
			users = append(users, aclUser)
		case linux.ACL_GROUP:
			kgid := userns.MapToKGID(auth.GID(entry.ID))
			if !kgid.Ok() {
				return &PosixACL{}, linuxerr.EINVAL
			}

			aclGroup := ACLGroup{
				GID:   kgid,
				Perms: AccessTypes(entry.Perm),
			}
			groups = append(groups, aclGroup)
		case linux.ACL_MASK:
			if mask != nil {
				// Only one ACL_MASK allowed
				return &PosixACL{}, linuxerr.EINVAL
			}
			mask = &entry.Perm
		default:
			// Unknown tag
			return &PosixACL{}, linuxerr.EINVAL
		}
	}

	// According to acl(5), a valid ACL:
	// (a) must contain no *fewer* than one entry each of ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_OTHER
	if userObj == nil || groupObj == nil || other == nil {
		return &PosixACL{}, linuxerr.EINVAL
	}
	// (b) must contain no *more* than one entry each of ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_OTHER
	//     (checked in the loop)
	// (c) if named users or groups are present, no *fewer* than one ACL_MASK must be present
	if (len(users) > 0 || len(groups) > 0) && mask == nil {
		return &PosixACL{}, linuxerr.EINVAL
	}
	// (d) no *more* than one ACL_MASK must be present
	//     (checked in the loop)
	// (e) must have unique UIDs and GIDs for named users and groups
	//     (not enforced by Linux, so we ignore as well)

	ret := PosixACL{
		UGOPerms: (*userObj << 6) | (*groupObj << 3) | *other,
		Mask:     (*AccessTypes)(mask),
		Users:    users,
		Groups:   groups,
	}
	return &ret, nil
}

// String represents a POSIX ACL as a human-readable string.
func (a PosixACL) String() string {
	mask := "nil"
	if a.Mask != nil {
		mask = fmt.Sprintf("%O", *a.Mask)
	}

	return fmt.Sprintf("PosixACL { UGOPerms: %O, Mask: %s, Users: %v, Groups: %v }", a.UGOPerms, mask, a.Users, a.Groups)
}
