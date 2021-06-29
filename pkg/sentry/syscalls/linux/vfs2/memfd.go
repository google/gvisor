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
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

const (
	memfdPrefix     = "memfd:"
	memfdMaxNameLen = linux.NAME_MAX - len(memfdPrefix)
	memfdAllFlags   = uint32(linux.MFD_CLOEXEC | linux.MFD_ALLOW_SEALING)
)

// MemfdCreate implements the linux syscall memfd_create(2).
func MemfdCreate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	flags := args[1].Uint()

	if flags&^memfdAllFlags != 0 {
		// Unknown bits in flags.
		return 0, nil, linuxerr.EINVAL
	}

	allowSeals := flags&linux.MFD_ALLOW_SEALING != 0
	cloExec := flags&linux.MFD_CLOEXEC != 0

	name, err := t.CopyInString(addr, memfdMaxNameLen)
	if err != nil {
		return 0, nil, err
	}

	shmMount := t.Kernel().ShmMount()
	file, err := tmpfs.NewMemfd(t, t.Credentials(), shmMount, allowSeals, memfdPrefix+name)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)

	fd, err := t.NewFDFromVFS2(0, file, kernel.FDFlags{
		CloseOnExec: cloExec,
	})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(fd), nil, nil
}
