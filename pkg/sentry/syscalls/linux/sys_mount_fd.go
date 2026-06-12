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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/fsconfigfd"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/mountfd"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// FSOpen implements Linux syscall fsopen(2).
func FSOpen(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fsnameAddr := args[0].Pointer()
	flags := args[1].Uint()

	if flags&^linux.FSOPEN_CLOEXEC != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Must have CAP_SYS_ADMIN in the current mount namespace's associated user
	// namespace.
	creds := t.Credentials()
	if !creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.MountNamespace().Owner) {
		return 0, nil, linuxerr.EPERM
	}

	fsname, err := t.CopyInString(fsnameAddr, hostarch.PageSize)
	if err != nil {
		return 0, nil, err
	}

	vfsObj := t.Kernel().VFS()
	fileFlags := uint32(linux.O_RDWR)
	file, err := fsconfigfd.New(t, vfsObj, fsname, fileFlags)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)
	fsfd, err := t.NewFDFrom(0, file, kernel.FDFlags{
		CloseOnExec: flags&linux.FSOPEN_CLOEXEC == linux.FSOPEN_CLOEXEC,
	})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(fsfd), nil, nil
}

func paramFromFSConfigArgs(t *kernel.Task, cmd uint32, valueAddr hostarch.Addr, aux int32) (*fsconfigfd.FSParameter, error) {
	var value fsconfigfd.FSValue
	switch cmd {
	case linux.FSCONFIG_SET_FLAG:
		if valueAddr != 0 || aux != 0 {
			return nil, linuxerr.EINVAL
		}

		value = fsconfigfd.FSValueFlag{}
	case linux.FSCONFIG_SET_STRING:
		if aux != 0 {
			return nil, linuxerr.EINVAL
		}
		str, err := t.CopyInString(valueAddr, hostarch.PageSize)
		if err != nil {
			return nil, err
		}

		value = fsconfigfd.FSValueString(str)
	case linux.FSCONFIG_SET_BINARY:
		fallthrough
	case linux.FSCONFIG_SET_FD:
		fallthrough
	case linux.FSCONFIG_SET_PATH:
		fallthrough
	case linux.FSCONFIG_SET_PATH_EMPTY:
		return nil, linuxerr.EINVAL
	case linux.FSCONFIG_CMD_CREATE:
		fallthrough
	case linux.FSCONFIG_CMD_CREATE_EXCL:
		fallthrough
	case linux.FSCONFIG_CMD_RECONFIGURE:
		return nil, nil
	default:
		return nil, linuxerr.EINVAL
	}

	param := fsconfigfd.FSParameter{
		Value: value,
		// TODO(b/513024543): support non-flag/non-string parameters, which will include using DirFd
		DirFd: -1,
	}

	return &param, nil
}

// FSConfig implements Linux syscall fsconfig(2).
func FSConfig(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	cmd := args[1].Uint()
	keyAddr := args[2].Pointer()
	valueAddr := args[3].Pointer()
	aux := args[4].Int()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	fsfd, ok := file.Impl().(*fsconfigfd.Fd)
	if !ok {
		return 0, nil, linuxerr.EINVAL
	}

	// First, is this a request to set a parameter (FSCONFIG_SET_*)?
	param, err := paramFromFSConfigArgs(t, cmd, valueAddr, aux)
	if err != nil {
		return 0, nil, err
	}

	if param != nil {
		// FSCONFIG_SET_*: copy in the key and set the parameter
		key, err := t.CopyInString(keyAddr, hostarch.PageSize)
		if err != nil {
			return 0, nil, err
		}
		err = fsfd.SetParam(key, *param)
		return 0, nil, err
	}

	if cmd == linux.FSCONFIG_CMD_CREATE {
		// FSCONFIG_CMD_CREATE: create a detached mount

		// CAP_SYS_ADMIN check performed in fsfd.DoCmdCreate().
		vfsObj := t.Kernel().VFS()
		err := fsfd.DoCmdCreate(t, vfsObj)
		return 0, nil, err
	}

	// TODO(b/513024543): support FSCONFIG_CMD_CREATE_EXCL and FSCONFIG_CMD_RECONFIGURE

	return 0, nil, linuxerr.EINVAL
}

var fsmountValidAttrFlags = uint32(linux.MOUNT_ATTR_RDONLY | linux.MOUNT_ATTR_NOSUID | linux.MOUNT_ATTR_NODEV | linux.MOUNT_ATTR_NOEXEC | linux.MOUNT_ATTR__ATIME)

func parseAttrFlagsIntoMountOpts(attrFlags uint32, opts *vfs.MountOptions) {
	if attrFlags&linux.MOUNT_ATTR_RDONLY == linux.MOUNT_ATTR_RDONLY {
		opts.ReadOnly = true
	}
	if attrFlags&linux.MOUNT_ATTR_NOSUID == linux.MOUNT_ATTR_NOSUID {
		opts.Flags.NoSUID = true
	}
	if attrFlags&linux.MOUNT_ATTR_NODEV == linux.MOUNT_ATTR_NODEV {
		opts.Flags.NoDev = true
	}
	if attrFlags&linux.MOUNT_ATTR_NOEXEC == linux.MOUNT_ATTR_NOEXEC {
		opts.Flags.NoExec = true
	}
	if attrFlags&linux.MOUNT_ATTR__ATIME == linux.MOUNT_ATTR_NOATIME {
		opts.Flags.NoATime = true
	}
}

// FSMount implements Linux syscall fsmount(2).
func FSMount(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	flags := args[1].Uint()
	attrFlags := args[2].Uint()

	if flags&^linux.FSMOUNT_CLOEXEC != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	if attrFlags&^fsmountValidAttrFlags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Must have CAP_SYS_ADMIN in the current mount namespace's associated user
	// namespace.
	creds := t.Credentials()
	if !creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.MountNamespace().Owner) {
		return 0, nil, linuxerr.EPERM
	}

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	fsfd, ok := file.Impl().(*fsconfigfd.Fd)
	if !ok {
		return 0, nil, linuxerr.EINVAL
	}

	// Fetch the previously-instantiated filesystem
	fs, root, opts, err := fsfd.GetFilesystem()
	if err != nil {
		return 0, nil, err
	}

	// Parse mount options specified in attrFlags
	parseAttrFlagsIntoMountOpts(attrFlags, opts)

	// Create the mount, which we will place at the root of a new anonymous mount namespace
	mountNs := t.Kernel().VFS().NewMountNamespaceFrom(t, creds, fs, root, opts, t.Kernel(), true /* anon */)

	// Create the mount object fd
	mountFile, err := mountfd.New(t, mountNs, linux.O_RDONLY)
	if err != nil {
		return 0, nil, err
	}
	defer mountFile.DecRef(t)
	mountFd, err := t.NewFDFrom(0, mountFile, kernel.FDFlags{
		CloseOnExec: flags&linux.FSMOUNT_CLOEXEC == linux.FSMOUNT_CLOEXEC,
	})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(mountFd), nil, nil
}

const supportedMoveMountFlags = linux.MOVE_MOUNT_F_EMPTY_PATH | linux.MOVE_MOUNT_T_EMPTY_PATH | linux.MOVE_MOUNT_F_SYMLINKS | linux.MOVE_MOUNT_T_SYMLINKS

// MoveMount implements Linux syscall move_mount(2).
func MoveMount(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fromDirfd := args[0].Int()
	fromAddr := args[1].Pointer()
	toDirfd := args[2].Int()
	toAddr := args[3].Pointer()
	flags := args[4].Uint()

	// TODO(b/270247637): gVisor does not yet support automount, so
	// MOVE_MOUNT_*_AUTOMOUNTS flags are a no-op.
	flags &= ^(uint32(linux.MOVE_MOUNT_F_AUTOMOUNTS | linux.MOVE_MOUNT_T_AUTOMOUNTS))

	if flags&^supportedMoveMountFlags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Must have CAP_SYS_ADMIN in the current mount namespace's associated user
	// namespace.
	creds := t.Credentials()
	if !creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.MountNamespace().Owner) {
		return 0, nil, linuxerr.EPERM
	}

	fromPath, err := copyInPath(t, fromAddr)
	if err != nil {
		return 0, nil, err
	}
	from, err := getTaskPathOperation(t, fromDirfd, fromPath, shouldAllowEmptyPath(flags&linux.MOVE_MOUNT_F_EMPTY_PATH != 0), shouldFollowFinalSymlink(flags&linux.MOVE_MOUNT_F_SYMLINKS != 0))
	if err != nil {
		return 0, nil, err
	}
	defer from.Release(t)
	toPath, err := copyInPath(t, toAddr)
	if err != nil {
		return 0, nil, err
	}
	to, err := getTaskPathOperation(t, toDirfd, toPath, shouldAllowEmptyPath(flags&linux.MOVE_MOUNT_T_EMPTY_PATH != 0), shouldFollowFinalSymlink(flags&linux.MOVE_MOUNT_T_SYMLINKS != 0))
	if err != nil {
		return 0, nil, err
	}
	defer to.Release(t)

	// Re-attach the mount to the destination mountpoint
	vfsObj := t.Kernel().VFS()
	err = vfsObj.MoveMountAt(t, creds, &from.pop, &to.pop)
	if err != nil {
		return 0, nil, err
	}

	return 0, nil, nil
}
