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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const allFlags = linux.IN_NONBLOCK | linux.IN_CLOEXEC

// InotifyInit1 implements the inotify_init1() syscalls.
func InotifyInit1(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	flags := args[0].Int()
	if flags&^allFlags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	ino, err := vfs.NewInotifyFD(t, t.Kernel().VFS(), uint32(flags))
	if err != nil {
		return 0, nil, err
	}
	defer ino.DecRef(t)

	fd, err := t.NewFDFrom(0, ino, kernel.FDFlags{
		CloseOnExec: flags&linux.IN_CLOEXEC != 0,
	})

	if err != nil {
		return 0, nil, err
	}

	return uintptr(fd), nil, nil
}

// InotifyInit implements the inotify_init() syscalls.
func InotifyInit(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	args[0].Value = 0
	return InotifyInit1(t, args)
}

// fdToInotify resolves an fd to an inotify object. If successful, the file will
// have an extra ref and the caller is responsible for releasing the ref.
func fdToInotify(t *kernel.Task, fd int32) (*vfs.Inotify, *vfs.FileDescription, error) {
	f := t.GetFile(fd)
	if f == nil {
		// Invalid fd.
		return nil, nil, linuxerr.EBADF
	}

	ino, ok := f.Impl().(*vfs.Inotify)
	if !ok {
		// Not an inotify fd.
		f.DecRef(t)
		return nil, nil, linuxerr.EINVAL
	}

	return ino, f, nil
}

// InotifyAddWatch implements the inotify_add_watch() syscall.
func InotifyAddWatch(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	mask := args[2].Uint()

	// "EINVAL: The given event mask contains no valid events."
	//	-- inotify_add_watch(2)
	if mask&linux.ALL_INOTIFY_BITS == 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// "IN_DONT_FOLLOW: Don't dereference pathname if it is a symbolic link."
	//  -- inotify(7)
	follow := followFinalSymlink
	if mask&linux.IN_DONT_FOLLOW != 0 {
		follow = nofollowFinalSymlink
	}

	ino, f, err := fdToInotify(t, fd)
	if err != nil {
		return 0, nil, err
	}
	defer f.DecRef(t)

	path, err := copyInPath(t, addr)
	if err != nil {
		return 0, nil, err
	}
	if mask&linux.IN_ONLYDIR != 0 {
		path.Dir = true
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, follow)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)
	d, err := t.Kernel().VFS().GetDentryAt(t, t.Credentials(), &tpop.pop, &vfs.GetDentryOptions{})
	if err != nil {
		return 0, nil, err
	}
	defer d.DecRef(t)

	return uintptr(ino.AddWatch(d.Dentry(), mask)), nil, nil
}

// InotifyRmWatch implements the inotify_rm_watch() syscall.
func InotifyRmWatch(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	wd := args[1].Int()

	ino, f, err := fdToInotify(t, fd)
	if err != nil {
		return 0, nil, err
	}
	defer f.DecRef(t)
	return 0, nil, ino.RmWatch(t, wd)
}
