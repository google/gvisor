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

package vfs2

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// Mount implements Linux syscall mount(2).
func Mount(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	sourceAddr := args[0].Pointer()
	targetAddr := args[1].Pointer()
	typeAddr := args[2].Pointer()
	flags := args[3].Uint64()
	dataAddr := args[4].Pointer()

	// For null-terminated strings related to mount(2), Linux copies in at most
	// a page worth of data. See fs/namespace.c:copy_mount_string().
	fsType, err := t.CopyInString(typeAddr, hostarch.PageSize)
	if err != nil {
		return 0, nil, err
	}
	source, err := t.CopyInString(sourceAddr, hostarch.PageSize)
	if err != nil {
		return 0, nil, err
	}

	targetPath, err := copyInPath(t, targetAddr)
	if err != nil {
		return 0, nil, err
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

	// Ignore magic value that was required before Linux 2.4.
	if flags&linux.MS_MGC_MSK == linux.MS_MGC_VAL {
		flags = flags &^ linux.MS_MGC_MSK
	}

	// Must have CAP_SYS_ADMIN in the current mount namespace's associated user
	// namespace.
	creds := t.Credentials()
	if !creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.MountNamespaceVFS2().Owner) {
		return 0, nil, syserror.EPERM
	}

	const unsupportedOps = linux.MS_REMOUNT | linux.MS_BIND |
		linux.MS_SHARED | linux.MS_PRIVATE | linux.MS_SLAVE |
		linux.MS_UNBINDABLE | linux.MS_MOVE

	// Silently allow MS_NOSUID, since we don't implement set-id bits
	// anyway.
	const unsupportedFlags = linux.MS_NODIRATIME | linux.MS_STRICTATIME

	// Linux just allows passing any flags to mount(2) - it won't fail when
	// unknown or unsupported flags are passed. Since we don't implement
	// everything, we fail explicitly on flags that are unimplemented.
	if flags&(unsupportedOps|unsupportedFlags) != 0 {
		return 0, nil, syserror.EINVAL
	}

	var opts vfs.MountOptions
	if flags&linux.MS_NOATIME == linux.MS_NOATIME {
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
	opts.GetFilesystemOptions.Data = data

	target, err := getTaskPathOperation(t, linux.AT_FDCWD, targetPath, disallowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer target.Release(t)
	_, err = t.Kernel().VFS().MountAt(t, creds, source, &target.pop, fsType, &opts)
	return 0, nil, err
}

// Umount2 implements Linux syscall umount2(2).
func Umount2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	flags := args[1].Int()

	// Must have CAP_SYS_ADMIN in the mount namespace's associated user
	// namespace.
	//
	// Currently, this is always the init task's user namespace.
	creds := t.Credentials()
	if !creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.MountNamespaceVFS2().Owner) {
		return 0, nil, syserror.EPERM
	}

	const unsupported = linux.MNT_FORCE | linux.MNT_EXPIRE
	if flags&unsupported != 0 {
		return 0, nil, syserror.EINVAL
	}

	path, err := copyInPath(t, addr)
	if err != nil {
		return 0, nil, err
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	opts := vfs.UmountOptions{
		Flags: uint32(flags),
	}

	return 0, nil, t.Kernel().VFS().UmountAt(t, creds, &tpop.pop, &opts)
}
