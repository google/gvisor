// Copyright 2020 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Mount implements Linux syscall mount(2).
func Mount(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	sourceAddr := args[0].Pointer()
	targetAddr := args[1].Pointer()
	typeAddr := args[2].Pointer()
	flags := args[3].Uint64()
	dataAddr := args[4].Pointer()

	// Must have CAP_SYS_ADMIN in the current mount namespace's associated user
	// namespace.
	creds := t.Credentials()
	if !creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.MountNamespace().Owner) {
		return 0, nil, linuxerr.EPERM
	}

	// Ignore magic value that was required before Linux 2.4.
	if flags&linux.MS_MGC_MSK == linux.MS_MGC_VAL {
		flags = flags &^ linux.MS_MGC_MSK
	}

	// Silently allow MS_NOSUID, since we don't implement set-id bits anyway.
	const unsupported = linux.MS_UNBINDABLE | linux.MS_MOVE | linux.MS_NODIRATIME

	// Linux just allows passing any flags to mount(2) - it won't fail when
	// unknown or unsupported flags are passed. Since we don't implement
	// everything, we fail explicitly on flags that are unimplemented.
	if flags&(unsupported) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// For null-terminated strings related to mount(2), Linux copies in at most
	// a page worth of data. See fs/namespace.c:copy_mount_string().
	targetPath, err := copyInPath(t, targetAddr)
	if err != nil {
		return 0, nil, err
	}
	target, err := getTaskPathOperation(t, linux.AT_FDCWD, targetPath, disallowEmptyPath, followFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer target.Release(t)
	var opts vfs.MountOptions
	if flags&(linux.MS_NOATIME|linux.MS_STRICTATIME) == linux.MS_NOATIME {
		opts.Flags.NoATime = true
	}
	if flags&linux.MS_NOEXEC == linux.MS_NOEXEC {
		opts.Flags.NoExec = true
	}
	if flags&linux.MS_NODEV == linux.MS_NODEV {
		opts.Flags.NoDev = true
	}
	if flags&linux.MS_NOSUID == linux.MS_NOSUID {
		opts.Flags.NoSUID = true
	}
	if flags&linux.MS_RDONLY == linux.MS_RDONLY {
		opts.ReadOnly = true
	}
	data := ""
	if dataAddr != 0 {
		// In Linux, a full page is always copied in regardless of null
		// character placement, and the address is passed to each file system.
		// Most file systems always treat this data as a string, though, and so
		// do all of the ones we implement.
		data, err = t.CopyInString(dataAddr, hostarch.PageSize)
		if err != nil {
			return 0, nil, err
		}
	}
	opts.GetFilesystemOptions.Data = data
	switch {
	case flags&linux.MS_REMOUNT != 0:
		// When MS_REMOUNT is specified, the flags and data should match the values used in the original mount() call,
		// except for those parameters that are being changed.
		//
		// The src and filesystem type are ignored for MS_REMOUNT.
		return 0, nil, t.Kernel().VFS().RemountAt(t, creds, &target.pop, &opts)
	case flags&linux.MS_BIND != 0:
		sourcePath, err := copyInPath(t, sourceAddr)
		if err != nil {
			return 0, nil, err
		}
		var sourceTpop taskPathOperation
		sourceTpop, err = getTaskPathOperation(t, linux.AT_FDCWD, sourcePath, disallowEmptyPath, followFinalSymlink)
		if err != nil {
			return 0, nil, err
		}
		defer sourceTpop.Release(t)
		return 0, nil, t.Kernel().VFS().BindAt(t, creds, &sourceTpop.pop, &target.pop, flags&linux.MS_REC != 0)
	case flags&(linux.MS_SHARED|linux.MS_PRIVATE|linux.MS_SLAVE|linux.MS_UNBINDABLE) != 0:
		return 0, nil, t.Kernel().VFS().SetMountPropagationAt(t, creds, &target.pop, uint32(flags))
	}

	// Only copy in source, fstype, and data if we are doing a normal mount.
	source, err := t.CopyInString(sourceAddr, hostarch.PageSize)
	if err != nil {
		return 0, nil, err
	}
	fsType, err := t.CopyInString(typeAddr, hostarch.PageSize)
	if err != nil {
		return 0, nil, err
	}
	_, err = t.Kernel().VFS().MountAt(t, creds, source, &target.pop, fsType, &opts)
	return 0, nil, err
}

// Umount2 implements Linux syscall umount2(2).
func Umount2(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	flags := args[1].Int()

	// Must have CAP_SYS_ADMIN in the mount namespace's associated user
	// namespace.
	//
	// Currently, this is always the init task's user namespace.
	creds := t.Credentials()
	if !creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.MountNamespace().Owner) {
		return 0, nil, linuxerr.EPERM
	}

	const unsupported = linux.MNT_FORCE | linux.MNT_EXPIRE
	if flags&unsupported != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	path, err := copyInPath(t, addr)
	if err != nil {
		return 0, nil, err
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, shouldFollowFinalSymlink(flags&linux.UMOUNT_NOFOLLOW == 0))
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	opts := vfs.UmountOptions{
		Flags: uint32(flags &^ linux.UMOUNT_NOFOLLOW),
	}

	return 0, nil, t.Kernel().VFS().UmountAt(t, creds, &tpop.pop, &opts)
}
