// Copyright 2019 The gVisor Authors.
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
	"math"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/syserror"
)

// AccessTypes is a bitmask of Unix file permissions.
//
// +stateify savable
type AccessTypes uint16

// Bits in AccessTypes.
const (
	MayExec  AccessTypes = 1
	MayWrite AccessTypes = 2
	MayRead  AccessTypes = 4
)

// OnlyRead returns true if access _only_ allows read.
func (a AccessTypes) OnlyRead() bool {
	return a == MayRead
}

// MayRead returns true if access allows read.
func (a AccessTypes) MayRead() bool {
	return a&MayRead != 0
}

// MayWrite returns true if access allows write.
func (a AccessTypes) MayWrite() bool {
	return a&MayWrite != 0
}

// MayExec returns true if access allows exec.
func (a AccessTypes) MayExec() bool {
	return a&MayExec != 0
}

// GenericCheckPermissions checks that creds has the given access rights on a
// file with the given permissions, UID, and GID, subject to the rules of
// fs/namei.c:generic_permission().
func GenericCheckPermissions(creds *auth.Credentials, ats AccessTypes, mode linux.FileMode, kuid auth.KUID, kgid auth.KGID) error {
	// Check permission bits.
	perms := uint16(mode.Permissions())
	if creds.EffectiveKUID == kuid {
		perms >>= 6
	} else if creds.InGroup(kgid) {
		perms >>= 3
	}
	if uint16(ats)&perms == uint16(ats) {
		// All permission bits match, access granted.
		return nil
	}

	// Caller capabilities require that the file's KUID and KGID are mapped in
	// the caller's user namespace; compare
	// kernel/capability.c:privileged_wrt_inode_uidgid().
	if !kuid.In(creds.UserNamespace).Ok() || !kgid.In(creds.UserNamespace).Ok() {
		return syserror.EACCES
	}
	// CAP_DAC_READ_SEARCH allows the caller to read and search arbitrary
	// directories, and read arbitrary non-directory files.
	if (mode.IsDir() && !ats.MayWrite()) || ats.OnlyRead() {
		if creds.HasCapability(linux.CAP_DAC_READ_SEARCH) {
			return nil
		}
	}
	// CAP_DAC_OVERRIDE allows arbitrary access to directories, read/write
	// access to non-directory files, and execute access to non-directory files
	// for which at least one execute bit is set.
	if mode.IsDir() || !ats.MayExec() || (mode.Permissions()&0111 != 0) {
		if creds.HasCapability(linux.CAP_DAC_OVERRIDE) {
			return nil
		}
	}
	return syserror.EACCES
}

// MayLink determines whether creating a hard link to a file with the given
// mode, kuid, and kgid is permitted.
//
// This corresponds to Linux's fs/namei.c:may_linkat.
func MayLink(creds *auth.Credentials, mode linux.FileMode, kuid auth.KUID, kgid auth.KGID) error {
	// Source inode owner can hardlink all they like; otherwise, it must be a
	// safe source.
	if CanActAsOwner(creds, kuid) {
		return nil
	}

	// Only regular files can be hard linked.
	if mode.FileType() != linux.S_IFREG {
		return syserror.EPERM
	}

	// Setuid files should not get pinned to the filesystem.
	if mode&linux.S_ISUID != 0 {
		return syserror.EPERM
	}

	// Executable setgid files should not get pinned to the filesystem, but we
	// don't support S_IXGRP anyway.

	// Hardlinking to unreadable or unwritable sources is dangerous.
	if err := GenericCheckPermissions(creds, MayRead|MayWrite, mode, kuid, kgid); err != nil {
		return syserror.EPERM
	}
	return nil
}

// AccessTypesForOpenFlags returns the access types required to open a file
// with the given OpenOptions.Flags. Note that this is NOT the same thing as
// the set of accesses permitted for the opened file:
//
// - O_TRUNC causes MayWrite to be set in the returned AccessTypes (since it
// mutates the file), but does not permit writing to the open file description
// thereafter.
//
// - "Linux reserves the special, nonstandard access mode 3 (binary 11) in
// flags to mean: check for read and write permission on the file and return a
// file descriptor that can't be used for reading or writing." - open(2). Thus
// AccessTypesForOpenFlags returns MayRead|MayWrite in this case.
//
// Use May{Read,Write}FileWithOpenFlags() for these checks instead.
func AccessTypesForOpenFlags(opts *OpenOptions) AccessTypes {
	ats := AccessTypes(0)
	if opts.FileExec {
		ats |= MayExec
	}

	switch opts.Flags & linux.O_ACCMODE {
	case linux.O_RDONLY:
		if opts.Flags&linux.O_TRUNC != 0 {
			return ats | MayRead | MayWrite
		}
		return ats | MayRead
	case linux.O_WRONLY:
		return ats | MayWrite
	default:
		return ats | MayRead | MayWrite
	}
}

// MayReadFileWithOpenFlags returns true if a file with the given open flags
// should be readable.
func MayReadFileWithOpenFlags(flags uint32) bool {
	switch flags & linux.O_ACCMODE {
	case linux.O_RDONLY, linux.O_RDWR:
		return true
	default:
		return false
	}
}

// MayWriteFileWithOpenFlags returns true if a file with the given open flags
// should be writable.
func MayWriteFileWithOpenFlags(flags uint32) bool {
	switch flags & linux.O_ACCMODE {
	case linux.O_WRONLY, linux.O_RDWR:
		return true
	default:
		return false
	}
}

// CheckSetStat checks that creds has permission to change the metadata of a
// file with the given permissions, UID, and GID as specified by stat, subject
// to the rules of Linux's fs/attr.c:setattr_prepare().
func CheckSetStat(ctx context.Context, creds *auth.Credentials, opts *SetStatOptions, mode linux.FileMode, kuid auth.KUID, kgid auth.KGID) error {
	stat := &opts.Stat
	if stat.Mask&linux.STATX_SIZE != 0 {
		limit, err := CheckLimit(ctx, 0, int64(stat.Size))
		if err != nil {
			return err
		}
		if limit < int64(stat.Size) {
			return syserror.ErrExceedsFileSizeLimit
		}
	}
	if stat.Mask&linux.STATX_MODE != 0 {
		if !CanActAsOwner(creds, kuid) {
			return syserror.EPERM
		}
		// TODO(b/30815691): "If the calling process is not privileged (Linux:
		// does not have the CAP_FSETID capability), and the group of the file
		// does not match the effective group ID of the process or one of its
		// supplementary group IDs, the S_ISGID bit will be turned off, but
		// this will not cause an error to be returned." - chmod(2)
	}
	if stat.Mask&linux.STATX_UID != 0 {
		if !((creds.EffectiveKUID == kuid && auth.KUID(stat.UID) == kuid) ||
			HasCapabilityOnFile(creds, linux.CAP_CHOWN, kuid, kgid)) {
			return syserror.EPERM
		}
	}
	if stat.Mask&linux.STATX_GID != 0 {
		if !((creds.EffectiveKUID == kuid && creds.InGroup(auth.KGID(stat.GID))) ||
			HasCapabilityOnFile(creds, linux.CAP_CHOWN, kuid, kgid)) {
			return syserror.EPERM
		}
	}
	if opts.NeedWritePerm && !creds.HasCapability(linux.CAP_DAC_OVERRIDE) {
		if err := GenericCheckPermissions(creds, MayWrite, mode, kuid, kgid); err != nil {
			return err
		}
	}
	if stat.Mask&(linux.STATX_ATIME|linux.STATX_MTIME|linux.STATX_CTIME) != 0 {
		if !CanActAsOwner(creds, kuid) {
			if (stat.Mask&linux.STATX_ATIME != 0 && stat.Atime.Nsec != linux.UTIME_NOW) ||
				(stat.Mask&linux.STATX_MTIME != 0 && stat.Mtime.Nsec != linux.UTIME_NOW) ||
				(stat.Mask&linux.STATX_CTIME != 0 && stat.Ctime.Nsec != linux.UTIME_NOW) {
				return syserror.EPERM
			}
			if err := GenericCheckPermissions(creds, MayWrite, mode, kuid, kgid); err != nil {
				return err
			}
		}
	}
	return nil
}

// CheckDeleteSticky checks whether the sticky bit is set on a directory with
// the given file mode, and if so, checks whether creds has permission to
// remove a file owned by childKUID from a directory with the given mode.
// CheckDeleteSticky is consistent with fs/linux.h:check_sticky().
func CheckDeleteSticky(creds *auth.Credentials, parentMode linux.FileMode, parentKUID auth.KUID, childKUID auth.KUID, childKGID auth.KGID) error {
	if parentMode&linux.ModeSticky == 0 {
		return nil
	}
	if creds.EffectiveKUID == childKUID ||
		creds.EffectiveKUID == parentKUID ||
		HasCapabilityOnFile(creds, linux.CAP_FOWNER, childKUID, childKGID) {
		return nil
	}
	return syserror.EPERM
}

// CanActAsOwner returns true if creds can act as the owner of a file with the
// given owning UID, consistent with Linux's
// fs/inode.c:inode_owner_or_capable().
func CanActAsOwner(creds *auth.Credentials, kuid auth.KUID) bool {
	if creds.EffectiveKUID == kuid {
		return true
	}
	return creds.HasCapability(linux.CAP_FOWNER) && creds.UserNamespace.MapFromKUID(kuid).Ok()
}

// HasCapabilityOnFile returns true if creds has the given capability with
// respect to a file with the given owning UID and GID, consistent with Linux's
// kernel/capability.c:capable_wrt_inode_uidgid().
func HasCapabilityOnFile(creds *auth.Credentials, cp linux.Capability, kuid auth.KUID, kgid auth.KGID) bool {
	return creds.HasCapability(cp) && creds.UserNamespace.MapFromKUID(kuid).Ok() && creds.UserNamespace.MapFromKGID(kgid).Ok()
}

// CheckLimit enforces file size rlimits. It returns error if the write
// operation must not proceed. Otherwise it returns the max length allowed to
// without violating the limit.
func CheckLimit(ctx context.Context, offset, size int64) (int64, error) {
	fileSizeLimit := limits.FromContextOrDie(ctx).Get(limits.FileSize).Cur
	if fileSizeLimit > math.MaxInt64 {
		return size, nil
	}
	if offset >= int64(fileSizeLimit) {
		return 0, syserror.ErrExceedsFileSizeLimit
	}
	remaining := int64(fileSizeLimit) - offset
	if remaining < size {
		return remaining, nil
	}
	return size, nil
}

// CheckXattrPermissions checks permissions for extended attribute access.
// This is analogous to fs/xattr.c:xattr_permission(). Some key differences:
// * Does not check for read-only filesystem property.
// * Does not check inode immutability or append only mode. In both cases EPERM
//   must be returned by filesystem implementations.
// * Does not do inode permission checks. Filesystem implementations should
//   handle inode permission checks as they may differ across implementations.
func CheckXattrPermissions(creds *auth.Credentials, ats AccessTypes, mode linux.FileMode, kuid auth.KUID, name string) error {
	switch {
	case strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX):
		// The trusted.* namespace can only be accessed by privileged
		// users.
		if creds.HasCapability(linux.CAP_SYS_ADMIN) {
			return nil
		}
		if ats.MayWrite() {
			return syserror.EPERM
		}
		return syserror.ENODATA
	case strings.HasPrefix(name, linux.XATTR_USER_PREFIX):
		// In the user.* namespace, only regular files and directories can have
		// extended attributes. For sticky directories, only the owner and
		// privileged users can write attributes.
		filetype := mode.FileType()
		if filetype != linux.ModeRegular && filetype != linux.ModeDirectory {
			if ats.MayWrite() {
				return syserror.EPERM
			}
			return syserror.ENODATA
		}
		if filetype == linux.ModeDirectory && mode&linux.ModeSticky != 0 && ats.MayWrite() && !CanActAsOwner(creds, kuid) {
			return syserror.EPERM
		}
	}
	return nil
}

// ClearSUIDAndSGID clears the setuid and/or setgid bits after a chown or write.
// Depending on the mode, neither bit, only the setuid bit, or both are cleared.
func ClearSUIDAndSGID(mode uint32) uint32 {
	// Directories don't have their bits changed.
	if mode&linux.ModeDirectory == linux.ModeDirectory {
		return mode
	}

	// Changing owners always disables the setuid bit. It disables
	// the setgid bit when the file is executable.
	mode &= ^uint32(linux.ModeSetUID)
	if sgid := uint32(linux.ModeSetGID | linux.ModeGroupExec); mode&sgid == sgid {
		mode &= ^uint32(linux.ModeSetGID)
	}
	return mode
}
