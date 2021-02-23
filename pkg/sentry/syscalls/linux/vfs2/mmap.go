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
	"gvisor.dev/gvisor/pkg/sentry/fsbridge"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Mmap implements Linux syscall mmap(2).
func Mmap(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	prot := args[2].Int()
	flags := args[3].Int()
	fd := args[4].Int()
	fixed := flags&linux.MAP_FIXED != 0
	private := flags&linux.MAP_PRIVATE != 0
	shared := flags&linux.MAP_SHARED != 0
	anon := flags&linux.MAP_ANONYMOUS != 0
	map32bit := flags&linux.MAP_32BIT != 0

	// Require exactly one of MAP_PRIVATE and MAP_SHARED.
	if private == shared {
		return 0, nil, syserror.EINVAL
	}

	opts := memmap.MMapOpts{
		Length:   args[1].Uint64(),
		Offset:   args[5].Uint64(),
		Addr:     args[0].Pointer(),
		Fixed:    fixed,
		Unmap:    fixed,
		Map32Bit: map32bit,
		Private:  private,
		Perms: usermem.AccessType{
			Read:    linux.PROT_READ&prot != 0,
			Write:   linux.PROT_WRITE&prot != 0,
			Execute: linux.PROT_EXEC&prot != 0,
		},
		MaxPerms:  usermem.AnyAccess,
		GrowsDown: linux.MAP_GROWSDOWN&flags != 0,
		Precommit: linux.MAP_POPULATE&flags != 0,
	}
	if linux.MAP_LOCKED&flags != 0 {
		opts.MLockMode = memmap.MLockEager
	}
	defer func() {
		if opts.MappingIdentity != nil {
			opts.MappingIdentity.DecRef(t)
		}
	}()

	if !anon {
		// Convert the passed FD to a file reference.
		file := t.GetFileVFS2(fd)
		if file == nil {
			return 0, nil, syserror.EBADF
		}
		defer file.DecRef(t)

		// mmap unconditionally requires that the FD is readable.
		if !file.IsReadable() {
			return 0, nil, syserror.EACCES
		}
		// MAP_SHARED requires that the FD be writable for PROT_WRITE.
		if shared && !file.IsWritable() {
			opts.MaxPerms.Write = false
		}

		if t.Kernel().SecurityHooks != nil {
			fb := fsbridge.NewVFSFile(file)
			t.Kernel().SecurityHooks.OnFileMMap(t, fb, opts.Perms, flags)
		}

		if err := file.ConfigureMMap(t, &opts); err != nil {
			return 0, nil, err
		}
	} else if shared {
		// Back shared anonymous mappings with an anonymous tmpfs file.
		opts.Offset = 0
		file, err := tmpfs.NewZeroFile(t, t.Credentials(), t.Kernel().ShmMount(), opts.Length)
		if err != nil {
			return 0, nil, err
		}
		defer file.DecRef(t)
		if err := file.ConfigureMMap(t, &opts); err != nil {
			return 0, nil, err
		}
	}

	rv, err := t.MemoryManager().MMap(t, opts)
	return uintptr(rv), nil, err
}
