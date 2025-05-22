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
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
)

// A CapabilitySet is a set of capabilities implemented as a bitset. The zero
// value of CapabilitySet is a set containing no capabilities.
type CapabilitySet uint64

// AllCapabilities is a CapabilitySet containing all valid capabilities.
var AllCapabilities = CapabilitySetOf(linux.CAP_LAST_CAP+1) - 1

// CapabilitySetOf returns a CapabilitySet containing only the given
// capability.
func CapabilitySetOf(cp linux.Capability) CapabilitySet {
	return CapabilitySet(bits.MaskOf64(int(cp)))
}

// CapabilitySetOfMany returns a CapabilitySet containing the given capabilities.
func CapabilitySetOfMany(cps []linux.Capability) CapabilitySet {
	var cs uint64
	for _, cp := range cps {
		cs |= bits.MaskOf64(int(cp))
	}
	return CapabilitySet(cs)
}

// Add adds the given capability to the CapabilitySet.
func (cs *CapabilitySet) Add(cp linux.Capability) {
	*cs |= CapabilitySetOf(cp)
}

// Clear removes the given capability from the CapabilitySet.
func (cs *CapabilitySet) Clear(cp linux.Capability) {
	*cs &= ^CapabilitySetOf(cp)
}

// VfsCapDataOf returns a VfsCapData containing the file capabilities for the given slice of bytes.
// For each field of the cap data, which are in the structure of either vfs_cap_data or vfs_ns_cap_data,
// the bytes are ordered in little endian.
func VfsCapDataOf(data []byte) (linux.VfsNsCapData, error) {
	size := len(data)
	if size != linux.XATTR_CAPS_SZ_2 && size != linux.XATTR_CAPS_SZ_3 {
		log.Warningf("the size of security.capability is invalid: size=%d", size)
		return linux.VfsNsCapData{}, linuxerr.EINVAL
	}
	var capData linux.VfsNsCapData
	if size == linux.XATTR_CAPS_SZ_3 {
		capData.UnmarshalUnsafe(data)
	} else {
		capData.VfsCapData.UnmarshalUnsafe(data)
		// rootid = 0 is correct for version 2 file capabilities.
	}
	// See security/commoncap.c:validheader().
	if sansflags := capData.MagicEtc & ^uint32(linux.VFS_CAP_FLAGS_EFFECTIVE); (size == linux.XATTR_CAPS_SZ_2 && sansflags != linux.VFS_CAP_REVISION_2) ||
		(size == linux.XATTR_CAPS_SZ_3 && sansflags != linux.VFS_CAP_REVISION_3) {
		log.Warningf("the magic header of security.capability is invalid: magic=%#x, size=%d", capData.MagicEtc, size)
		return linux.VfsNsCapData{}, linuxerr.EINVAL
	}
	return capData, nil
}

// HandleVfsCaps updates creds based on the given vfsCaps. It returns two
// booleans; the first indicates whether the effective flag is set, and the second
// second indicates whether the file capability is applied.
func HandleVfsCaps(vfsCaps linux.VfsNsCapData, creds *Credentials) (bool, bool, error) {
	// gVisor does not support ID-mapped mounts and all filesystems are owned by
	// the initial user namespace. So we an directly cast the root ID to KUID.
	rootID := KUID(vfsCaps.RootID)
	if !rootIDOwnsCurrentUserns(creds, rootID) {
		// Linux skips vfs caps in this situation.
		return false, false, nil
	}
	// Note that ambient capabilities are not yet supported in gVisor.
	// P'(permitted) = (P(inheritable) & F(inheritable)) | (F(permitted) & P(bounding)) | P'(ambient)
	creds.PermittedCaps = (CapabilitySet(vfsCaps.Permitted()) & creds.BoundingCaps) |
		(CapabilitySet(vfsCaps.Inheritable()) & creds.InheritableCaps)
	effective := (vfsCaps.MagicEtc & linux.VFS_CAP_FLAGS_EFFECTIVE) > 0
	// Insufficient to execute correctly. Linux only returns EPERM when effective
	// flag is set.
	if effective && (CapabilitySet(vfsCaps.Permitted()) & ^creds.PermittedCaps) != 0 {
		return effective, true, linuxerr.EPERM
	}
	return effective, true, nil
}

// FixupVfsCapDataOnSet may convert the given value to v3 file capabilities. It
// is analogous to security/commoncap.c:cap_convert_nscap().
func FixupVfsCapDataOnSet(creds *Credentials, value string, kuid KUID, kgid KGID) (string, error) {
	vfsCaps, err := VfsCapDataOf([]byte(value))
	if err != nil {
		return "", err
	}
	if !creds.HasCapabilityOnFile(linux.CAP_SETFCAP, kuid, kgid) {
		return "", linuxerr.EPERM
	}
	if vfsCaps.IsRevision2() && creds.HasCapabilityIn(linux.CAP_SETFCAP, creds.UserNamespace.Root()) {
		// The user is privileged, allow the v2 write.
		return value, nil
	}
	// Linux does the following UID gymnastics:
	//   1. The userspace-provided rootID is relative to the caller's user
	//      namespace. So vfsCaps.RootID is mapped down to KUID first.
	//   2. If this is an ID-mapped mount, the result is mapped up using the
	//      ID-map and then down again using the filesystem's owning user
	//      namespace (inode->i_sb->s_user_ns). We again have a KUID result.
	//   3. The result is mapped up using the filesystem's owning user namespace.
	//
	// The final result is saved in the xattr value at vfs_ns_cap_data->rootid.
	// Since gVisor does not support ID-mapped mounts and all filesystems are
	// owned by the initial user namespace, we can skip steps 2 and 3.
	rootID := creds.UserNamespace.MapToKUID(UID(vfsCaps.RootID))
	if !rootID.Ok() {
		return "", linuxerr.EINVAL
	}
	vfsCaps.ConvertToV3(uint32(rootID))
	return vfsCaps.ToString(), nil
}

// FixupVfsCapDataOnGet may convert the given value to v2 file capabilities. It
// is analogous to security/commoncap.c:cap_inode_getsecurity().
func FixupVfsCapDataOnGet(creds *Credentials, value string) (string, error) {
	vfsCaps, err := VfsCapDataOf([]byte(value))
	if err != nil {
		return "", err
	}
	// Linux does the steps mentioned in FixupVfsCapDataOnSet in reverse. But
	// since gVisor does not support ID-mapped mounts and all filesystems are
	// owned by the initial user namespace, we only need to reverse step 1 here.
	rootID := KUID(vfsCaps.RootID)
	mappedRoot := creds.UserNamespace.MapFromKUID(rootID)
	if mappedRoot.Ok() && mappedRoot != RootUID {
		// Return this as v3.
		vfsCaps.ConvertToV3(uint32(mappedRoot))
		return vfsCaps.ToString(), nil
	}
	if !rootIDOwnsCurrentUserns(creds, rootID) {
		return "", linuxerr.EOVERFLOW
	}
	// Return this as v2.
	vfsCaps.ConvertToV2()
	return vfsCaps.ToString(), nil
}

// Analogous to security/commoncap.c:rootid_owns_currentns().
func rootIDOwnsCurrentUserns(creds *Credentials, rootID KUID) bool {
	if !rootID.Ok() {
		return false
	}
	for ns := creds.UserNamespace; ns != nil; ns = ns.parent {
		if ns.MapFromKUID(rootID) == RootUID {
			return true
		}
	}
	return false
}

// HandlePrivilegedRoot updates creds for a privileged root user as per
// `Capabilities and execution of programs by root` in capabilities(7).
// It returns true if the file effective bit should be considered set.
func HandlePrivilegedRoot(creds *Credentials, hasVFSCaps bool, filename string) bool {
	// gVisor currently does not support SECURE_NOROOT secure bit since
	// PR_SET_SECUREBITS is not supported. So no need to check here.
	root := creds.UserNamespace.MapToKUID(RootUID)
	if hasVFSCaps && creds.RealKUID != root && creds.EffectiveKUID == root {
		log.Warningf("File %q has both SUID bit and file capabilities set, not raising all capabilities.", filename)
		return false
	}
	if creds.RealKUID == root || creds.EffectiveKUID == root {
		// P'(permitted) = P(inheritable) | P(bounding)
		creds.PermittedCaps = creds.BoundingCaps | creds.InheritableCaps
	}
	// Linux only sets the effective bit if the effective KUID is root.
	return creds.EffectiveKUID == root
}

// UpdateCredsForNewTask updates creds for a new task as per capabilities(7).
func UpdateCredsForNewTask(creds *Credentials, fileCaps string, filename string) error {
	// Clear the permitted capability set. It is initialized below via
	// HandleVfsCaps() and HandlePrivilegedRoot().
	creds.PermittedCaps = 0
	hasVFSCaps := false
	setEffective := false
	if len(fileCaps) != 0 {
		vfsCaps, err := VfsCapDataOf([]byte(fileCaps))
		if err != nil {
			return err
		}
		setEffective, hasVFSCaps, err = HandleVfsCaps(vfsCaps, creds)
		if err != nil {
			return err
		}
	}
	setEffective = HandlePrivilegedRoot(creds, hasVFSCaps, filename) || setEffective
	// P'(effective) = effective ? P'(permitted) : P'(ambient).
	creds.EffectiveCaps = 0
	if setEffective {
		creds.EffectiveCaps = creds.PermittedCaps
	}
	return nil
}

// TaskCapabilities represents all the capability sets for a task. Each of these
// sets is explained in greater detail in capabilities(7).
type TaskCapabilities struct {
	// Permitted is a limiting superset for the effective capabilities that
	// the thread may assume.
	PermittedCaps CapabilitySet
	// Inheritable is a set of capabilities preserved across an execve(2).
	InheritableCaps CapabilitySet
	// Effective is the set of capabilities used by the kernel to perform
	// permission checks for the thread.
	EffectiveCaps CapabilitySet
	// Bounding is a limiting superset for the capabilities that a thread
	// can add to its inheritable set using capset(2).
	BoundingCaps CapabilitySet
	// Ambient is a set of capabilities that are preserved across an
	// execve(2) of a program that is not privileged.
	AmbientCaps CapabilitySet
}
