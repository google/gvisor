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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/eventfd"
)

// Eventfd2 implements linux syscall eventfd2(2).
func Eventfd2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	initVal := args[0].Int()
	flags := uint(args[1].Uint())
	allOps := uint(linux.EFD_SEMAPHORE | linux.EFD_NONBLOCK | linux.EFD_CLOEXEC)

	if flags & ^allOps != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	event := eventfd.New(t, uint64(initVal), flags&linux.EFD_SEMAPHORE != 0)
	event.SetFlags(fs.SettableFileFlags{
		NonBlocking: flags&linux.EFD_NONBLOCK != 0,
	})
	defer event.DecRef(t)

	fd, err := t.NewFDFrom(0, event, kernel.FDFlags{
		CloseOnExec: flags&linux.EFD_CLOEXEC != 0,
	})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(fd), nil, nil
}

// Eventfd implements linux syscall eventfd(2).
func Eventfd(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	args[1].Value = 0
	return Eventfd2(t, args)
}
