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
	return bits.MaskOf[CapabilitySet](int(cp))
}

// CapabilitySetOfMany returns a CapabilitySet containing the given capabilities.
func CapabilitySetOfMany(cps []linux.Capability) CapabilitySet {
	var cs CapabilitySet
	for _, cp := range cps {
		cs |= bits.MaskOf[CapabilitySet](int(cp))
	}
	return cs
}

// Add adds the given capability to the CapabilitySet.
func (cs *CapabilitySet) Add(cp linux.Capability) {
	*cs |= CapabilitySetOf(cp)
}

// Clear removes the given capability from the CapabilitySet.
func (cs *CapabilitySet) Clear(cp linux.Capability) {
	*cs &= ^CapabilitySetOf(cp)
}

// IsSubsetOf returns true if the given capability set is a subset of "super".
func (cs *CapabilitySet) IsSubsetOf(super CapabilitySet) bool {
	return *cs&super == *cs
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
	if vfsCaps.IsRevision2() && creds.HasRootCapability(linux.CAP_SETFCAP) {
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

// FilePrivileges contains the file privileges for a file.
type FilePrivileges struct {
	// SetUserID, when not NoID, indicates that the file has the setuid bit set. It is the KUID of the
	// owner of the file.
	SetUserID KUID

	// SetGroupID, when not NoID, indicates that the file has the setgid bit set. It is the KGID of
	// the owning group of the file.
	SetGroupID KGID

	// HasCaps indicates whether the file has capabilities attached.
	HasCaps bool

	// CapRootID is the KUID of the namespace root of the Task that created the file caps.
	CapRootID KUID

	// "These capabilities are automatically permitted to the thread, regardless of the thread's
	// inheritable capabilities." - capabilities(7).
	PermittedCaps CapabilitySet

	// "This set is ANDed with the thread's inheritable set to determine which inheritable capabilities
	// are enabled in the permitted set of the thread after the execve(2)." - capabilities(7).
	InheritableCaps CapabilitySet

	// "Determines if all of the new permitted capabilities for the thread are also raised in the
	// effective set." - capabilities(7).
	Effective bool
}

// handlePrivilegedRoot updates creds for a privileged root user as per
// "Capabilities and execution of programs by root" in capabilities(7).
func handlePrivilegedRoot(c *Credentials, f *FilePrivileges, filename string) {
	// gVisor currently does not support SECURE_NOROOT secure bit since
	// PR_SET_SECUREBITS is not supported. So no need to check here.
	root := c.UserNamespace.MapToKUID(RootUID)

	// "If (a) the binary that is being executed has capabilities attached and (b) the real user ID of
	// the process is not 0 (root) and (c) the effective user ID of the process is 0 (root), then the
	// file capability bits are honored.  (i.e., they are not notionally considered to be all ones)."
	// - capabilities(7)
	if f.HasCaps && c.RealKUID != root && c.EffectiveKUID == root {
		log.Warningf("File %q has both SUID bit and file capabilities set, not raising all capabilities.", filename)
		return
	}

	// "If the real or effective user ID of the process is 0 (root), then the file inheritable and
	// permitted sets are ignored; instead they are notionally considered to be all ones (i.e., all
	// capabilities enabled)." - capabilities(7)
	if c.RealKUID == root || c.EffectiveKUID == root {
		// P'(permitted) = P(inheritable) | P(bounding)
		c.PermittedCaps = c.BoundingCaps | c.InheritableCaps
	}

	// "If the effective user ID of the process is 0 (root) or the file effective bit is in fact
	// enabled, then the file effective bit is notionally defined to be one (enabled)." - capabilities(7)
	f.Effective = c.EffectiveKUID == root || f.Effective
}

// ComputeCredsForExec computes the new credentials given the file privileges.
// It returns the new creds and a bool indicating if the task is executing with
// elevated privileges. A few words about the arguments:
//   - c: The current credentials of the task.
//   - f: The file privileges of the executable.
//   - filename: The name of the executable, used for logging.
//   - noNewPrivs: The current state of the prctl NO_NEW_PRIVS.
//   - stopPrivGain: Determines if privilege gain should be stopped for reasons beyond NO_NEW_PRIVS.
//     Both noNewPrivs and stopPrivGain prevent cap gain, but stopPrivGain does not by itself
//     prevent ID gain.
//   - allowSUID: If true, the task will be allowed to setuid.
//     Both noNewPrivs and allowSUID prevent ID gain, but allowSUID does not by itself prevent cap
//     gain. Note also that while noNewPrivs brings down the effective IDs down to the real IDs,
//     allowSUID at most prevents further ID gain due the SUID/GID bits.
//
// Note that gVisor does not support Ambient capabilities.
func ComputeCredsForExec(c *Credentials, f FilePrivileges, filename string,
	noNewPrivs bool, stopPrivGain bool, allowSUID bool) (*Credentials, bool, error) {
	if noNewPrivs || !allowSUID {
		f.SetUserID = NoID
		f.SetGroupID = NoID
	}
	// "...if either the user or the group ID of the file has no mapping inside the namespace, the
	// set-user-ID (set-group-ID) bit is silently ignored: the new program is executed, but the
	// process's effective user (group) ID is left unchanged." - user_namespaces(7).
	if !f.SetUserID.In(c.UserNamespace).Ok() {
		f.SetUserID = NoID
	}
	if !f.SetGroupID.In(c.UserNamespace).Ok() {
		f.SetGroupID = NoID
	}
	// "...capabilities are conferred only if the binary is executed by a process that resides in a
	// user namespace whose UID 0 maps to the root user ID that is saved in the extended attribute,
	// or when executed by a process that resides in a descendant of such a namespace."
	// - capabilities(7).
	if !rootIDOwnsCurrentUserns(c, f.CapRootID) {
		f.HasCaps = false
		f.Effective = false
	}

	newC := c.Fork()
	if f.SetUserID.Ok() {
		newC.EffectiveKUID = f.SetUserID
	}
	if f.SetGroupID.Ok() {
		newC.EffectiveKGID = f.SetGroupID
	}

	newC.PermittedCaps = CapabilitySet(0)
	if f.HasCaps {
		// P'(permitted) = (P(inheritable) & F(inheritable)) | (F(permitted) & P(bounding))
		newC.PermittedCaps = (c.InheritableCaps & f.InheritableCaps) | (f.PermittedCaps & c.BoundingCaps)

		// The "Safety checking for capability-dumb binaries" section of capabilities(7) says:
		// "...For such applications, the effective capability bit is set on the file...
		// ...If the process did not obtain the full set of file permitted capabilities,
		// then execve(2) fails with the error EPERM."
		if f.Effective && (newC.PermittedCaps&f.PermittedCaps != f.PermittedCaps) {
			return nil, false, linuxerr.EPERM
		}
	}
	// newC.PermittedCaps and f.Effective are set differently for namespace root.
	handlePrivilegedRoot(newC, &f, filename)

	// Deny privilege elevation if we have to, see commoncap.c:cap_bprm_creds_from_file().
	gainedID := (newC.EffectiveKUID != c.RealKUID) || (newC.EffectiveKGID != c.RealKGID)
	gainedCaps := !newC.PermittedCaps.IsSubsetOf(c.PermittedCaps)
	if (gainedID || gainedCaps) && (noNewPrivs || stopPrivGain) {
		if noNewPrivs || !c.HasSelfCapability(linux.CAP_SETUID) {
			newC.EffectiveKUID = c.RealKUID
			newC.EffectiveKGID = c.RealKGID
		}
		newC.PermittedCaps &= c.PermittedCaps
	}
	newC.SavedKUID = newC.EffectiveKUID
	newC.SavedKGID = newC.EffectiveKGID

	// P'(effective) = effective ? P'(permitted) : P'(ambient).
	newC.EffectiveCaps = 0
	if f.Effective {
		newC.EffectiveCaps = newC.PermittedCaps
	}

	// prctl(2): The "keep capabilities" value will be reset to 0 on subsequent calls to execve(2).
	newC.KeepCaps = false

	root := c.UserNamespace.MapToKUID(RootUID)
	// See commoncap.c:cap_bprm_secureexec() in Linux 4.2 (before the introduction of ambient caps).
	secureExec := gainedID || (newC.RealKUID != root && (f.Effective || newC.PermittedCaps != CapabilitySet(0)))
	return newC, secureExec, nil
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
