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
	"gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// Flock implements linux syscall flock(2).
func Flock(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	operation := args[1].Int()

	file := t.GetFileVFS2(fd)
	if file == nil {
		// flock(2): EBADF fd is not an open file descriptor.
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	nonblocking := operation&linux.LOCK_NB != 0
	operation &^= linux.LOCK_NB

	switch operation {
	case linux.LOCK_EX:
		if err := file.LockBSD(t, int32(t.TGIDInRoot()), lock.WriteLock, !nonblocking /* block */); err != nil {
			return 0, nil, err
		}
	case linux.LOCK_SH:
		if err := file.LockBSD(t, int32(t.TGIDInRoot()), lock.ReadLock, !nonblocking /* block */); err != nil {
			return 0, nil, err
		}
	case linux.LOCK_UN:
		if err := file.UnlockBSD(t); err != nil {
			return 0, nil, err
		}
	default:
		// flock(2): EINVAL operation is invalid.
		return 0, nil, linuxerr.EINVAL
	}

	return 0, nil, nil
}
