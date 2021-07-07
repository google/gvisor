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
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsbridge"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/loader"
	slinux "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Execve implements linux syscall execve(2).
func Execve(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	pathnameAddr := args[0].Pointer()
	argvAddr := args[1].Pointer()
	envvAddr := args[2].Pointer()
	return execveat(t, linux.AT_FDCWD, pathnameAddr, argvAddr, envvAddr, 0 /* flags */)
}

// Execveat implements linux syscall execveat(2).
func Execveat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirfd := args[0].Int()
	pathnameAddr := args[1].Pointer()
	argvAddr := args[2].Pointer()
	envvAddr := args[3].Pointer()
	flags := args[4].Int()
	return execveat(t, dirfd, pathnameAddr, argvAddr, envvAddr, flags)
}

func execveat(t *kernel.Task, dirfd int32, pathnameAddr, argvAddr, envvAddr hostarch.Addr, flags int32) (uintptr, *kernel.SyscallControl, error) {
	if flags&^(linux.AT_EMPTY_PATH|linux.AT_SYMLINK_NOFOLLOW) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	pathname, err := t.CopyInString(pathnameAddr, linux.PATH_MAX)
	if err != nil {
		return 0, nil, err
	}
	var argv, envv []string
	if argvAddr != 0 {
		var err error
		argv, err = t.CopyInVector(argvAddr, slinux.ExecMaxElemSize, slinux.ExecMaxTotalSize)
		if err != nil {
			return 0, nil, err
		}
	}
	if envvAddr != 0 {
		var err error
		envv, err = t.CopyInVector(envvAddr, slinux.ExecMaxElemSize, slinux.ExecMaxTotalSize)
		if err != nil {
			return 0, nil, err
		}
	}

	root := t.FSContext().RootDirectoryVFS2()
	defer root.DecRef(t)
	var executable fsbridge.File
	closeOnExec := false
	if path := fspath.Parse(pathname); dirfd != linux.AT_FDCWD && !path.Absolute {
		// We must open the executable ourselves since dirfd is used as the
		// starting point while resolving path, but the task working directory
		// is used as the starting point while resolving interpreters (Linux:
		// fs/binfmt_script.c:load_script() => fs/exec.c:open_exec() =>
		// do_open_execat(fd=AT_FDCWD)), and the loader package is currently
		// incapable of handling this correctly.
		if !path.HasComponents() && flags&linux.AT_EMPTY_PATH == 0 {
			return 0, nil, linuxerr.ENOENT
		}
		dirfile, dirfileFlags := t.FDTable().GetVFS2(dirfd)
		if dirfile == nil {
			return 0, nil, linuxerr.EBADF
		}
		start := dirfile.VirtualDentry()
		start.IncRef()
		dirfile.DecRef(t)
		closeOnExec = dirfileFlags.CloseOnExec
		file, err := t.Kernel().VFS().OpenAt(t, t.Credentials(), &vfs.PathOperation{
			Root:               root,
			Start:              start,
			Path:               path,
			FollowFinalSymlink: flags&linux.AT_SYMLINK_NOFOLLOW == 0,
		}, &vfs.OpenOptions{
			Flags:    linux.O_RDONLY,
			FileExec: true,
		})
		start.DecRef(t)
		if err != nil {
			return 0, nil, err
		}
		defer file.DecRef(t)
		executable = fsbridge.NewVFSFile(file)
	}

	// Load the new TaskImage.
	mntns := t.MountNamespaceVFS2()
	wd := t.FSContext().WorkingDirectoryVFS2()
	defer wd.DecRef(t)
	remainingTraversals := uint(linux.MaxSymlinkTraversals)
	loadArgs := loader.LoadArgs{
		Opener:              fsbridge.NewVFSLookup(mntns, root, wd),
		RemainingTraversals: &remainingTraversals,
		ResolveFinal:        flags&linux.AT_SYMLINK_NOFOLLOW == 0,
		Filename:            pathname,
		File:                executable,
		CloseOnExec:         closeOnExec,
		Argv:                argv,
		Envv:                envv,
		Features:            t.Arch().FeatureSet(),
	}

	image, se := t.Kernel().LoadTaskImage(t, loadArgs)
	if se != nil {
		return 0, nil, se.ToError()
	}

	ctrl, err := t.Execve(image)
	return 0, ctrl, err
}
