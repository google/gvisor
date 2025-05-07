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

// CapsFromVfsCaps returns a copy of the given creds with new capability sets
// by applying the file capability that is specified by capData.
func CapsFromVfsCaps(capData linux.VfsNsCapData, creds *Credentials) (*Credentials, error) {
	// If the real or effective user ID of the process is root,
	// the file inheritable and permitted sets are ignored from
	// `Capabilities and execution of programs by root` at capabilities(7).
	if root := creds.UserNamespace.MapToKUID(RootUID); creds.EffectiveKUID == root || creds.RealKUID == root {
		return creds, nil
	}
	effective := (capData.MagicEtc & linux.VFS_CAP_FLAGS_EFFECTIVE) > 0
	permittedCaps := (CapabilitySet(capData.Permitted()) & creds.BoundingCaps) |
		(CapabilitySet(capData.Inheritable()) & creds.InheritableCaps)
	// P'(effective) = effective ? P'(permitted) : P'(ambient).
	// The ambient capabilities has not supported yet in gVisor,
	// set effective capabilities to 0 when effective bit is false.
	effectiveCaps := CapabilitySet(0)
	if effective {
		effectiveCaps = permittedCaps
	}
	// Insufficient to execute correctly.
	if (CapabilitySet(capData.Permitted()) & ^permittedCaps) != 0 {
		return nil, linuxerr.EPERM
	}
	// If the capabilities don't change, it will return the creds'
	// original copy.
	if creds.PermittedCaps == permittedCaps && creds.EffectiveCaps == effectiveCaps {
		return creds, nil
	}
	// The credentials object is immutable.
	newCreds := creds.Fork()
	newCreds.PermittedCaps = permittedCaps
	newCreds.EffectiveCaps = effectiveCaps
	return newCreds, nil
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
