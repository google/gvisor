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
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/anon"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

const allFlags = int(linux.IN_NONBLOCK | linux.IN_CLOEXEC)

// InotifyInit1 implements the inotify_init1() syscalls.
func InotifyInit1(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	flags := int(args[0].Int())

	if flags&^allFlags != 0 {
		return 0, nil, syscall.EINVAL
	}

	dirent := fs.NewDirent(t, anon.NewInode(t), "inotify")
	fileFlags := fs.FileFlags{
		Read:        true,
		Write:       true,
		NonBlocking: flags&linux.IN_NONBLOCK != 0,
	}
	n := fs.NewFile(t, dirent, fileFlags, fs.NewInotify(t))
	defer n.DecRef()

	fd, err := t.NewFDFrom(0, n, kernel.FDFlags{
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
func fdToInotify(t *kernel.Task, fd int32) (*fs.Inotify, *fs.File, error) {
	file := t.GetFile(fd)
	if file == nil {
		// Invalid fd.
		return nil, nil, syscall.EBADF
	}

	ino, ok := file.FileOperations.(*fs.Inotify)
	if !ok {
		// Not an inotify fd.
		file.DecRef()
		return nil, nil, syscall.EINVAL
	}

	return ino, file, nil
}

// InotifyAddWatch implements the inotify_add_watch() syscall.
func InotifyAddWatch(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	mask := args[2].Uint()

	// "IN_DONT_FOLLOW: Don't dereference pathname if it is a symbolic link."
	//  -- inotify(7)
	resolve := mask&linux.IN_DONT_FOLLOW == 0

	// "EINVAL: The given event mask contains no valid events."
	// -- inotify_add_watch(2)
	if validBits := mask & linux.ALL_INOTIFY_BITS; validBits == 0 {
		return 0, nil, syscall.EINVAL
	}

	ino, file, err := fdToInotify(t, fd)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef()

	path, _, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	err = fileOpOn(t, linux.AT_FDCWD, path, resolve, func(root *fs.Dirent, dirent *fs.Dirent, _ uint) error {
		// "IN_ONLYDIR: Only watch pathname if it is a directory." -- inotify(7)
		if onlyDir := mask&linux.IN_ONLYDIR != 0; onlyDir && !fs.IsDir(dirent.Inode.StableAttr) {
			return syscall.ENOTDIR
		}

		// Copy out to the return frame.
		fd = ino.AddWatch(dirent, mask)

		return nil
	})
	return uintptr(fd), nil, err // Return from the existing value.
}

// InotifyRmWatch implements the inotify_rm_watch() syscall.
func InotifyRmWatch(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	wd := args[1].Int()

	ino, file, err := fdToInotify(t, fd)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef()
	return 0, nil, ino.RmWatch(wd)
}
