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
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/eventfd"
)

const (
	// EFD_SEMAPHORE is a flag used in syscall eventfd(2) and eventfd2(2). Please
	// see its man page for more information.
	EFD_SEMAPHORE = 1
	EFD_NONBLOCK  = 0x800
	EFD_CLOEXEC   = 0x80000
)

// Eventfd2 implements linux syscall eventfd2(2).
func Eventfd2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	initVal := args[0].Int()
	flags := uint(args[1].Uint())
	allOps := uint(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC)

	if flags & ^allOps != 0 {
		return 0, nil, syscall.EINVAL
	}

	event := eventfd.New(t, uint64(initVal), flags&EFD_SEMAPHORE != 0)
	event.SetFlags(fs.SettableFileFlags{
		NonBlocking: flags&EFD_NONBLOCK != 0,
	})
	defer event.DecRef()

	fd, err := t.FDMap().NewFDFrom(0, event, kernel.FDFlags{
		CloseOnExec: flags&EFD_CLOEXEC != 0,
	},
		t.ThreadGroup().Limits())
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
