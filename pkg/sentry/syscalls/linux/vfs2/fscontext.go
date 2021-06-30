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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Getcwd implements Linux syscall getcwd(2).
func Getcwd(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	size := args[1].SizeT()

	root := t.FSContext().RootDirectoryVFS2()
	wd := t.FSContext().WorkingDirectoryVFS2()
	s, err := t.Kernel().VFS().PathnameForGetcwd(t, root, wd)
	root.DecRef(t)
	wd.DecRef(t)
	if err != nil {
		return 0, nil, err
	}

	// Note this is >= because we need a terminator.
	if uint(len(s)) >= size {
		return 0, nil, syserror.ERANGE
	}

	// Construct a byte slice containing a NUL terminator.
	buf := t.CopyScratchBuffer(len(s) + 1)
	copy(buf, s)
	buf[len(buf)-1] = 0

	// Write the pathname slice.
	n, err := t.CopyOutBytes(addr, buf)
	if err != nil {
		return 0, nil, err
	}
	return uintptr(n), nil, nil
}

// Chdir implements Linux syscall chdir(2).
func Chdir(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	path, err := copyInPath(t, addr)
	if err != nil {
		return 0, nil, err
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, followFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	vd, err := t.Kernel().VFS().GetDentryAt(t, t.Credentials(), &tpop.pop, &vfs.GetDentryOptions{
		CheckSearchable: true,
	})
	if err != nil {
		return 0, nil, err
	}
	t.FSContext().SetWorkingDirectoryVFS2(t, vd)
	vd.DecRef(t)
	return 0, nil, nil
}

// Fchdir implements Linux syscall fchdir(2).
func Fchdir(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	tpop, err := getTaskPathOperation(t, fd, fspath.Path{}, allowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	vd, err := t.Kernel().VFS().GetDentryAt(t, t.Credentials(), &tpop.pop, &vfs.GetDentryOptions{
		CheckSearchable: true,
	})
	if err != nil {
		return 0, nil, err
	}
	t.FSContext().SetWorkingDirectoryVFS2(t, vd)
	vd.DecRef(t)
	return 0, nil, nil
}

// Chroot implements Linux syscall chroot(2).
func Chroot(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	if !t.HasCapability(linux.CAP_SYS_CHROOT) {
		return 0, nil, linuxerr.EPERM
	}

	path, err := copyInPath(t, addr)
	if err != nil {
		return 0, nil, err
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, followFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)

	vd, err := t.Kernel().VFS().GetDentryAt(t, t.Credentials(), &tpop.pop, &vfs.GetDentryOptions{
		CheckSearchable: true,
	})
	if err != nil {
		return 0, nil, err
	}
	t.FSContext().SetRootDirectoryVFS2(t, vd)
	vd.DecRef(t)
	return 0, nil, nil
}
