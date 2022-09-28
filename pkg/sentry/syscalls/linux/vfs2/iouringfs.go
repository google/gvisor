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

package vfs2

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
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
	const supportedFlags = linux.IORING_SETUP_IOPOLL

	// Since we don't implement everything, we fail explicitly on flags that are unimplemented.
	if params.Flags|supportedFlags != supportedFlags {
		return 0, nil, linuxerr.EINVAL
	}

	vfsObj := t.Kernel().VFS()
	iouringfd, err := iouringfs.New(t, vfsObj, entries, &params)

	if err != nil {
		return 0, nil, err
	}
	defer iouringfd.DecRef(t)

	fd, err := t.NewFDFromVFS2(0, iouringfd, kernel.FDFlags{
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
