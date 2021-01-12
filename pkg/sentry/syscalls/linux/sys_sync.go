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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserror"
)

// LINT.IfChange

// Sync implements linux system call sync(2).
func Sync(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	t.MountNamespace().SyncAll(t)
	// Sync is always successful.
	return 0, nil, nil
}

// Syncfs implements linux system call syncfs(2).
func Syncfs(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef(t)

	// Use "sync-the-world" for now, it's guaranteed that fd is at least
	// on the root filesystem.
	return Sync(t, args)
}

// Fsync implements linux syscall fsync(2).
func Fsync(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef(t)

	err := file.Fsync(t, 0, fs.FileMaxOffset, fs.SyncAll)
	return 0, nil, syserror.ConvertIntr(err, syserror.ERESTARTSYS)
}

// Fdatasync implements linux syscall fdatasync(2).
//
// At the moment, it just calls Fsync, which is a big hammer, but correct.
func Fdatasync(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef(t)

	err := file.Fsync(t, 0, fs.FileMaxOffset, fs.SyncData)
	return 0, nil, syserror.ConvertIntr(err, syserror.ERESTARTSYS)
}

// SyncFileRange implements linux syscall sync_file_rage(2)
func SyncFileRange(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	var err error

	fd := args[0].Int()
	offset := args[1].Int64()
	nbytes := args[2].Int64()
	uflags := args[3].Uint()

	if offset < 0 || offset+nbytes < offset {
		return 0, nil, syserror.EINVAL
	}

	if uflags&^(linux.SYNC_FILE_RANGE_WAIT_BEFORE|
		linux.SYNC_FILE_RANGE_WRITE|
		linux.SYNC_FILE_RANGE_WAIT_AFTER) != 0 {
		return 0, nil, syserror.EINVAL
	}

	if nbytes == 0 {
		nbytes = fs.FileMaxOffset
	}

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef(t)

	// SYNC_FILE_RANGE_WAIT_BEFORE waits upon write-out of all pages in the
	// specified range that have already been submitted to the device
	// driver for write-out before performing any write.
	if uflags&linux.SYNC_FILE_RANGE_WAIT_BEFORE != 0 &&
		uflags&linux.SYNC_FILE_RANGE_WAIT_AFTER == 0 {
		t.Kernel().EmitUnimplementedEvent(t)
		return 0, nil, syserror.ENOSYS
	}

	// SYNC_FILE_RANGE_WRITE initiates write-out of all dirty pages in the
	// specified range which are not presently submitted write-out.
	//
	// It looks impossible to implement this functionality without a
	// massive rework of the vfs subsystem. file.Fsync() take a file lock
	// for the entire operation, so even if it is running in a go routing,
	// it blocks other file operations instead of flushing data in the
	// background.
	//
	// It should be safe to skipped this flag while nobody uses
	// SYNC_FILE_RANGE_WAIT_BEFORE.
	_ = nbytes

	// SYNC_FILE_RANGE_WAIT_AFTER waits upon write-out of all pages in the
	// range after performing any write.
	//
	// In Linux, sync_file_range() doesn't writes out the  file's
	// meta-data, but fdatasync() does if a file size is changed.
	if uflags&linux.SYNC_FILE_RANGE_WAIT_AFTER != 0 {
		err = file.Fsync(t, offset, fs.FileMaxOffset, fs.SyncData)
	}

	return 0, nil, syserror.ConvertIntr(err, syserror.ERESTARTSYS)
}

// LINT.ThenChange(vfs2/sync.go)
