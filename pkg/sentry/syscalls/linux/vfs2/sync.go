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
	"gvisor.dev/gvisor/pkg/syserror"
)

// Sync implements Linux syscall sync(2).
func Sync(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, t.Kernel().VFS().SyncAllFilesystems(t)
}

// Syncfs implements Linux syscall syncfs(2).
func Syncfs(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	return 0, nil, file.SyncFS(t)
}

// Fsync implements Linux syscall fsync(2).
func Fsync(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	return 0, nil, file.Sync(t)
}

// Fdatasync implements Linux syscall fdatasync(2).
func Fdatasync(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// TODO(gvisor.dev/issue/1897): Avoid writeback of unnecessary metadata.
	return Fsync(t, args)
}

// SyncFileRange implements Linux syscall sync_file_range(2).
func SyncFileRange(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	offset := args[1].Int64()
	nbytes := args[2].Int64()
	flags := args[3].Uint()

	if offset < 0 {
		return 0, nil, syserror.EINVAL
	}
	if nbytes < 0 {
		return 0, nil, syserror.EINVAL
	}
	if flags&^(linux.SYNC_FILE_RANGE_WAIT_BEFORE|linux.SYNC_FILE_RANGE_WRITE|linux.SYNC_FILE_RANGE_WAIT_AFTER) != 0 {
		return 0, nil, syserror.EINVAL
	}

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// TODO(gvisor.dev/issue/1897): Avoid writeback of data ranges outside of
	// [offset, offset+nbytes).
	return 0, nil, file.Sync(t)
}
