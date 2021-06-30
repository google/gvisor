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

package vfs2

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/signalfd"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	slinux "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
)

// sharedSignalfd is shared between the two calls.
func sharedSignalfd(t *kernel.Task, fd int32, sigset hostarch.Addr, sigsetsize uint, flags int32) (uintptr, *kernel.SyscallControl, error) {
	// Copy in the signal mask.
	mask, err := slinux.CopyInSigSet(t, sigset, sigsetsize)
	if err != nil {
		return 0, nil, err
	}

	// Always check for valid flags, even if not creating.
	if flags&^(linux.SFD_NONBLOCK|linux.SFD_CLOEXEC) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Is this a change to an existing signalfd?
	//
	// The spec indicates that this should adjust the mask.
	if fd != -1 {
		file := t.GetFileVFS2(fd)
		if file == nil {
			return 0, nil, linuxerr.EBADF
		}
		defer file.DecRef(t)

		// Is this a signalfd?
		if sfd, ok := file.Impl().(*signalfd.SignalFileDescription); ok {
			sfd.SetMask(mask)
			return 0, nil, nil
		}

		// Not a signalfd.
		return 0, nil, linuxerr.EINVAL
	}

	fileFlags := uint32(linux.O_RDWR)
	if flags&linux.SFD_NONBLOCK != 0 {
		fileFlags |= linux.O_NONBLOCK
	}

	// Create a new file.
	vfsObj := t.Kernel().VFS()
	file, err := signalfd.New(vfsObj, t, mask, fileFlags)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)

	// Create a new descriptor.
	fd, err = t.NewFDFromVFS2(0, file, kernel.FDFlags{
		CloseOnExec: flags&linux.SFD_CLOEXEC != 0,
	})
	if err != nil {
		return 0, nil, err
	}

	// Done.
	return uintptr(fd), nil, nil
}

// Signalfd implements the linux syscall signalfd(2).
func Signalfd(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	sigset := args[1].Pointer()
	sigsetsize := args[2].SizeT()
	return sharedSignalfd(t, fd, sigset, sigsetsize, 0)
}

// Signalfd4 implements the linux syscall signalfd4(2).
func Signalfd4(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	sigset := args[1].Pointer()
	sigsetsize := args[2].SizeT()
	flags := args[3].Int()
	return sharedSignalfd(t, fd, sigset, sigsetsize, flags)
}
