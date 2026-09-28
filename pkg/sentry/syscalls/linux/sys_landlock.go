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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	// landlockABIVersion is the highest supported Landlock ABI version, as
	// reported for LANDLOCK_CREATE_RULESET_VERSION. Like Linux's
	// landlock_abi_version, it is not part of the UAPI.
	landlockABIVersion = 1

	// landlockErrata is the bitmask of fixed errata (erratum N is bit N-1), as
	// reported for LANDLOCK_CREATE_RULESET_ERRATA. Only erratum 3
	// (disconnected directories) applies to ABI 1.
	//
	// See https://docs.kernel.org/userspace-api/landlock.html#landlock-errata.
	//
	// Matches Linux [security/landlock/errata/abi-1.h] and
	// [security/landlock/setup.c]:compute_errata()
	landlockErrata = 1 << (3 - 1)

	// landlockAccessFile is the set of access rights a PATH_BENEATH rule on a
	// non-directory may grant. It mirrors ACCESS_FILE as of Linux 7.3; the
	// post-v1 bits are unreachable, since rulesets only handle v1 rights.
	//
	// Matches Linux [security/landlock/fs.c]:ACCESS_FILE
	landlockAccessFile = linux.LANDLOCK_ACCESS_FS_EXECUTE |
		linux.LANDLOCK_ACCESS_FS_WRITE_FILE |
		linux.LANDLOCK_ACCESS_FS_READ_FILE |
		linux.LANDLOCK_ACCESS_FS_TRUNCATE |
		linux.LANDLOCK_ACCESS_FS_IOCTL_DEV |
		linux.LANDLOCK_ACCESS_FS_RESOLVE_UNIX
)

// LandlockCreateRuleset implements Linux syscall landlock_create_ruleset(2).
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_create_ruleset()
func LandlockCreateRuleset(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	attrAddr := args[0].Pointer()
	size := args[1].SizeT()
	flags := args[2].Uint()

	if flags != 0 {
		if attrAddr != 0 || size != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if flags == linux.LANDLOCK_CREATE_RULESET_VERSION {
			return uintptr(landlockABIVersion), nil, nil
		}
		if flags == linux.LANDLOCK_CREATE_RULESET_ERRATA {
			return uintptr(landlockErrata), nil, nil
		}
		return 0, nil, linuxerr.EINVAL
	}

	// The v1 landlock_ruleset_attr is 8 bytes (handled_access_fs). A NULL attr
	// is EFAULT before size checks, which precede reading the buffer.
	//
	// Matches Linux [security/landlock/syscalls.c]:copy_min_struct_from_user()
	const v1AttrSize = 8
	if attrAddr == 0 {
		return 0, nil, linuxerr.EFAULT
	}
	if size < v1AttrSize {
		return 0, nil, linuxerr.EINVAL
	}
	if size > hostarch.PageSize {
		return 0, nil, linuxerr.E2BIG
	}

	// A longer struct is accepted only if its tail is zero; otherwise E2BIG
	// (e.g. a nonzero handled_access_net), as on a v1-era kernel. The tail is
	// checked before the head is copied.
	//
	// Matches Linux [lib/usercopy.c]:copy_struct_from_user()
	if size > v1AttrSize {
		extraBuf := make([]byte, size-v1AttrSize)
		if _, err := t.CopyInBytes(attrAddr+v1AttrSize, extraBuf); err != nil {
			return 0, nil, linuxerr.EFAULT
		}
		for _, b := range extraBuf {
			if b != 0 {
				return 0, nil, linuxerr.E2BIG
			}
		}
	}

	var handledAccessFS primitive.Uint64
	if _, err := handledAccessFS.CopyIn(t, attrAddr); err != nil {
		return 0, nil, linuxerr.EFAULT
	}

	if (uint64(handledAccessFS) &^ linux.LANDLOCK_ACCESS_FS_V1) != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if handledAccessFS == 0 {
		return 0, nil, linuxerr.ENOMSG
	}

	ruleset := vfs.NewLandlockRuleset(uint64(handledAccessFS))
	file, err := vfs.NewLandlockRulesetFD(t, t.Kernel().VFS(), ruleset)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)

	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(fd), nil, nil
}

// LandlockAddRule implements Linux syscall landlock_add_rule(2).
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_add_rule()
func LandlockAddRule(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// Matches Linux [security/landlock/syscalls.c]:add_rule_path_beneath()
	rulesetFD := args[0].Int()
	ruleType := args[1].Uint()
	ruleAttrAddr := args[2].Pointer()
	flags := args[3].Uint()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	rulesetFile := t.GetFile(rulesetFD)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)
	ruleset, err := vfs.LandlockRulesetFromFD(rulesetFile, linux.O_WRONLY)
	if err != nil {
		return 0, nil, err
	}

	// Validate the ruleset fd before the rule type, so a bad fd's error wins,
	// as in sys_landlock_add_rule().
	if ruleType != linux.LANDLOCK_RULE_PATH_BENEATH {
		return 0, nil, linuxerr.EINVAL
	}

	if ruleAttrAddr == 0 {
		return 0, nil, linuxerr.EFAULT
	}

	var attr linux.LandlockPathBeneathAttr
	if _, err := attr.CopyIn(t, ruleAttrAddr); err != nil {
		return 0, nil, linuxerr.EFAULT
	}

	if attr.AllowedAccess == 0 {
		return 0, nil, linuxerr.ENOMSG
	}
	if (attr.AllowedAccess &^ ruleset.HandledAccessFS()) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	parentFile := t.GetFile(attr.ParentFD)
	if parentFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer parentFile.DecRef(t)

	if _, isRuleset := parentFile.Impl().(*vfs.LandlockRulesetFileDescription); isRuleset {
		return 0, nil, linuxerr.EBADFD
	}

	vd := parentFile.VirtualDentry()
	// Reject files on internal mounts (e.g. pipefs, sockfs, memfd), which no
	// path reaches, rather than adding a rule that never matches.
	//
	// Matches Linux [security/landlock/syscalls.c]:get_path_from_fd() checking MNT_INTERNAL / SB_NOUSER
	if mnt := vd.Mount(); mnt == nil || mnt.Internal() {
		return 0, nil, linuxerr.EBADFD
	}

	stat, err := parentFile.Stat(t, vfs.StatOptions{})
	if err != nil {
		return 0, nil, err
	}

	isDir := linux.FileMode(stat.Mode).IsDir()
	if !isDir && (attr.AllowedAccess&^landlockAccessFile) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// The rule is keyed by the file's Landlock object, so it follows the file,
	// not its name. A file with no Landlock object is EBADFD, like
	// get_path_from_fd().
	object, err := vfs.GetLandlockObject(vd)
	if err != nil {
		return 0, nil, err
	}

	ruleset.InsertRule(t, object, attr.AllowedAccess)
	return 0, nil, nil
}

// LandlockRestrictSelf implements Linux syscall landlock_restrict_self(2).
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_restrict_self()
func LandlockRestrictSelf(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFD := args[0].Int()
	flags := args[1].Uint()

	// The no_new_privs check precedes argument checks, so its EPERM wins.
	// Matches Linux commit eba39ca4b155 ("landlock: Change
	// landlock_restrict_self(2) check ordering").
	if !t.GetNoNewPrivs() && !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.UserNamespace()) {
		return 0, nil, linuxerr.EPERM
	}

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	rulesetFile := t.GetFile(rulesetFD)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)
	ruleset, err := vfs.LandlockRulesetFromFD(rulesetFile, linux.O_RDONLY)
	if err != nil {
		return 0, nil, err
	}

	currentDomain := t.LandlockDomain()
	newDomain, err := currentDomain.Merge(ruleset)
	if err != nil {
		return 0, nil, err
	}

	t.SetLandlockDomain(newDomain)
	return 0, nil, nil
}
