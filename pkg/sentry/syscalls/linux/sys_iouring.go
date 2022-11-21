// Copyright 2022 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/iouringfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// IOUringSetup implements linux syscall io_uring_setup(2).
func IOUringSetup(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	entries := uint32(args[0].Uint())
	paramsAddr := args[1].Pointer()
	var params linux.IOUringParams

	if entries == 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if _, err := params.CopyIn(t, paramsAddr); err != nil {
		return 0, nil, err
	}

	for i := int(0); i < len(params.Resv); i++ {
		if params.Resv[i] != 0 {
			return 0, nil, linuxerr.EINVAL
		}
	}

	// List of currently supported flags in our IO_URING implementation.
	const supportedFlags = 0 // Currently support none

	// Since we don't implement everything, we fail explicitly on flags that are unimplemented.
	if params.Flags|supportedFlags != supportedFlags {
		return 0, nil, linuxerr.EINVAL
	}

	vfsObj := t.Kernel().VFS()
	iouringfd, err := iouringfs.New(t, vfsObj, entries, &params)

	if err != nil {
		// return 0, nil, err
		return 0, nil, linuxerr.EPERM
	}
	defer iouringfd.DecRef(t)

	fd, err := t.NewFDFrom(0, iouringfd, kernel.FDFlags{
		// O_CLOEXEC is always set up. See io_uring/io_uring.c:io_uring_install_fd().
		CloseOnExec: true,
	})

	if err != nil {
		return 0, nil, err
	}

	if _, err := params.CopyOut(t, paramsAddr); err != nil {
		return 0, nil, err
	}

	return uintptr(fd), nil, nil
}

// IOUringEnter implements linux syscall io_uring_enter(2).
func IOUringEnter(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := int32(args[0].Int())
	toSubmit := uint32(args[1].Uint())
	minComplete := uint32(args[2].Uint())
	flags := uint32(args[3].Uint())
	sigSet := args[4].Pointer()

	ret := -1

	// List of currently supported flags for io_uring_enter(2).
	const supportedFlags = linux.IORING_ENTER_GETEVENTS

	// Since we don't implement everything, we fail explicitly on flags that are unimplemented.
	if flags|supportedFlags != supportedFlags {
		return uintptr(ret), nil, linuxerr.EINVAL
	}

	// Currently don't support replacing an existing signal mask.
	if sigSet != hostarch.Addr(0) {
		return uintptr(ret), nil, linuxerr.EFAULT
	}

	// If a user requested to submit zero SQEs, then we don't process any and return right away.
	if toSubmit == 0 {
		return uintptr(ret), nil, nil
	}

	file := t.GetFile(fd)
	if file == nil {
		return uintptr(ret), nil, linuxerr.EBADF
	}
	defer file.DecRef(t)
	iouringfd, ok := file.Impl().(*iouringfs.FileDescription)
	if !ok {
		return uintptr(ret), nil, linuxerr.EBADF
	}
	ret, err := iouringfd.ProcessSubmissions(t, toSubmit, minComplete, flags)
	if err != nil {
		return uintptr(ret), nil, err
	}

	return uintptr(ret), nil, nil
}
