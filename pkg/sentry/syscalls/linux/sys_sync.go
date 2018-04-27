// Copyright 2018 Google Inc.
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
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Sync implements linux system call sync(2).
func Sync(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	t.MountNamespace().SyncAll(t)
	// Sync is always successful.
	return 0, nil, nil
}

// Syncfs implements linux system call syncfs(2).
func Syncfs(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())

	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// Use "sync-the-world" for now, it's guaranteed that fd is at least
	// on the root filesystem.
	return Sync(t, args)
}

// Fsync implements linux syscall fsync(2).
func Fsync(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())

	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	err := file.Fsync(t, 0, fs.FileMaxOffset, fs.SyncAll)
	return 0, nil, syserror.ConvertIntr(err, kernel.ERESTARTSYS)
}

// Fdatasync implements linux syscall fdatasync(2).
//
// At the moment, it just calls Fsync, which is a big hammer, but correct.
func Fdatasync(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())

	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	err := file.Fsync(t, 0, fs.FileMaxOffset, fs.SyncData)
	return 0, nil, syserror.ConvertIntr(err, kernel.ERESTARTSYS)
}
