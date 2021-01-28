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
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Ioctl implements Linux syscall ioctl(2).
func Ioctl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef(t)

	if file.StatusFlags()&linux.O_PATH != 0 {
		return 0, nil, syserror.EBADF
	}

	// Handle ioctls that apply to all FDs.
	switch args[1].Int() {
	case linux.FIONCLEX:
		t.FDTable().SetFlagsVFS2(t, fd, kernel.FDFlags{
			CloseOnExec: false,
		})
		return 0, nil, nil

	case linux.FIOCLEX:
		t.FDTable().SetFlagsVFS2(t, fd, kernel.FDFlags{
			CloseOnExec: true,
		})
		return 0, nil, nil

	case linux.FIONBIO:
		var set int32
		if _, err := primitive.CopyInt32In(t, args[2].Pointer(), &set); err != nil {
			return 0, nil, err
		}
		flags := file.StatusFlags()
		if set != 0 {
			flags |= linux.O_NONBLOCK
		} else {
			flags &^= linux.O_NONBLOCK
		}
		return 0, nil, file.SetStatusFlags(t, t.Credentials(), flags)

	case linux.FIOASYNC:
		var set int32
		if _, err := primitive.CopyInt32In(t, args[2].Pointer(), &set); err != nil {
			return 0, nil, err
		}
		flags := file.StatusFlags()
		if set != 0 {
			flags |= linux.O_ASYNC
		} else {
			flags &^= linux.O_ASYNC
		}
		file.SetStatusFlags(t, t.Credentials(), flags)
		return 0, nil, nil

	case linux.FIOGETOWN, linux.SIOCGPGRP:
		var who int32
		owner, hasOwner := getAsyncOwner(t, file)
		if hasOwner {
			if owner.Type == linux.F_OWNER_PGRP {
				who = -owner.PID
			} else {
				who = owner.PID
			}
		}
		_, err := primitive.CopyInt32Out(t, args[2].Pointer(), who)
		return 0, nil, err

	case linux.FIOSETOWN, linux.SIOCSPGRP:
		var who int32
		if _, err := primitive.CopyInt32In(t, args[2].Pointer(), &who); err != nil {
			return 0, nil, err
		}
		ownerType := int32(linux.F_OWNER_PID)
		if who < 0 {
			// Check for overflow before flipping the sign.
			if who-1 > who {
				return 0, nil, syserror.EINVAL
			}
			ownerType = linux.F_OWNER_PGRP
			who = -who
		}
		return 0, nil, setAsyncOwner(t, int(fd), file, ownerType, who)
	}

	ret, err := file.Ioctl(t, t.MemoryManager(), args)
	return ret, nil, err
}
