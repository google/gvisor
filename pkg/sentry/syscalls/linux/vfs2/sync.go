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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserr"
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
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	if file.StatusFlags()&linux.O_PATH != 0 {
		return 0, nil, linuxerr.EBADF
	}

	return 0, nil, file.SyncFS(t)
}

// Fsync implements Linux syscall fsync(2).
func Fsync(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

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

	// Check for negative values and overflow.
	if offset < 0 || offset+nbytes < 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if flags&^(linux.SYNC_FILE_RANGE_WAIT_BEFORE|linux.SYNC_FILE_RANGE_WRITE|linux.SYNC_FILE_RANGE_WAIT_AFTER) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// TODO(gvisor.dev/issue/1897): Currently, the only file syncing we support
	// is a full-file sync, i.e. fsync(2). As a result, there are severe
	// limitations on how much we support sync_file_range:
	// - In Linux, sync_file_range(2) doesn't write out the file's metadata, even
	//   if the file size is changed. We do.
	// - We always sync the entire file instead of [offset, offset+nbytes).
	// - We do not support the use of WAIT_BEFORE without WAIT_AFTER. For
	//   correctness, we would have to perform a write-out every time WAIT_BEFORE
	//   was used, but this would be much more expensive than expected if there
	//   were no write-out operations in progress.
	// - Whenever WAIT_AFTER is used, we sync the file.
	// - Ignore WRITE. If this flag is used with WAIT_AFTER, then the file will
	//   be synced anyway. If this flag is used without WAIT_AFTER, then it is
	//   safe (and less expensive) to do nothing, because the syscall will not
	//   wait for the write-out to complete--we only need to make sure that the
	//   next time WAIT_BEFORE or WAIT_AFTER are used, the write-out completes.
	// - According to fs/sync.c, WAIT_BEFORE|WAIT_AFTER "will detect any I/O
	//   errors or ENOSPC conditions and will return those to the caller, after
	//   clearing the EIO and ENOSPC flags in the address_space." We don't do
	//   this.

	if flags&linux.SYNC_FILE_RANGE_WAIT_BEFORE != 0 &&
		flags&linux.SYNC_FILE_RANGE_WAIT_AFTER == 0 {
		t.Kernel().EmitUnimplementedEvent(t)
		return 0, nil, linuxerr.ENOSYS
	}

	if flags&linux.SYNC_FILE_RANGE_WAIT_AFTER != 0 {
		if err := file.Sync(t); err != nil {
			return 0, nil, syserr.ConvertIntr(err, linuxerr.ERESTARTSYS)
		}
	}
	return 0, nil, nil
}
