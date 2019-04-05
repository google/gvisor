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

package linux

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Mount implements Linux syscall mount(2).
func Mount(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	sourceAddr := args[0].Pointer()
	targetAddr := args[1].Pointer()
	typeAddr := args[2].Pointer()
	flags := args[3].Uint64()
	dataAddr := args[4].Pointer()

	fsType, err := t.CopyInString(typeAddr, usermem.PageSize)
	if err != nil {
		return 0, nil, err
	}

	sourcePath, _, err := copyInPath(t, sourceAddr, true /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	targetPath, _, err := copyInPath(t, targetAddr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	data := ""
	if dataAddr != 0 {
		// In Linux, a full page is always copied in regardless of null
		// character placement, and the address is passed to each file system.
		// Most file systems always treat this data as a string, though, and so
		// do all of the ones we implement.
		data, err = t.CopyInString(dataAddr, usermem.PageSize)
		if err != nil {
			return 0, nil, err
		}
	}

	// Ignore magic value that was required before Linux 2.4.
	if flags&linux.MS_MGC_MSK == linux.MS_MGC_VAL {
		flags = flags &^ linux.MS_MGC_MSK
	}

	// Must have CAP_SYS_ADMIN in the mount namespace's associated user
	// namespace.
	if !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.MountNamespace().UserNamespace()) {
		return 0, nil, syserror.EPERM
	}

	const unsupportedOps = linux.MS_REMOUNT | linux.MS_BIND |
		linux.MS_SHARED | linux.MS_PRIVATE | linux.MS_SLAVE |
		linux.MS_UNBINDABLE | linux.MS_MOVE

	// Silently allow MS_NOSUID, since we don't implement set-id bits
	// anyway.
	const unsupportedFlags = linux.MS_NODEV |
		linux.MS_NODIRATIME | linux.MS_STRICTATIME

	// Linux just allows passing any flags to mount(2) - it won't fail when
	// unknown or unsupported flags are passed. Since we don't implement
	// everything, we fail explicitly on flags that are unimplemented.
	if flags&(unsupportedOps|unsupportedFlags) != 0 {
		return 0, nil, syserror.EINVAL
	}

	rsys, ok := fs.FindFilesystem(fsType)
	if !ok {
		return 0, nil, syserror.ENODEV
	}
	if !rsys.AllowUserMount() {
		return 0, nil, syserror.EPERM
	}

	var superFlags fs.MountSourceFlags
	if flags&linux.MS_NOATIME == linux.MS_NOATIME {
		superFlags.NoAtime = true
	}
	if flags&linux.MS_RDONLY == linux.MS_RDONLY {
		superFlags.ReadOnly = true
	}
	if flags&linux.MS_NOEXEC == linux.MS_NOEXEC {
		superFlags.NoExec = true
	}

	rootInode, err := rsys.Mount(t, sourcePath, superFlags, data, nil)
	if err != nil {
		return 0, nil, syserror.EINVAL
	}

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, targetPath, true /* resolve */, func(root *fs.Dirent, d *fs.Dirent) error {
		return t.MountNamespace().Mount(t, d, rootInode)
	})
}

// Umount2 implements Linux syscall umount2(2).
func Umount2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	flags := args[1].Int()

	const unsupported = linux.MNT_FORCE | linux.MNT_EXPIRE
	if flags&unsupported != 0 {
		return 0, nil, syserror.EINVAL
	}

	path, _, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	// Must have CAP_SYS_ADMIN in the mount namespace's associated user
	// namespace.
	//
	// Currently, this is always the init task's user namespace.
	if !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.MountNamespace().UserNamespace()) {
		return 0, nil, syserror.EPERM
	}

	resolve := flags&linux.UMOUNT_NOFOLLOW != linux.UMOUNT_NOFOLLOW
	detachOnly := flags&linux.MNT_DETACH == linux.MNT_DETACH

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, path, resolve, func(root *fs.Dirent, d *fs.Dirent) error {
		return t.MountNamespace().Unmount(t, d, detachOnly)
	})
}
