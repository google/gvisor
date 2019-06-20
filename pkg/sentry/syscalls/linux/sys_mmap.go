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
	"bytes"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Brk implements linux syscall brk(2).
func Brk(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr, _ := t.MemoryManager().Brk(t, args[0].Pointer())
	// "However, the actual Linux system call returns the new program break on
	// success. On failure, the system call returns the current break." -
	// brk(2)
	return uintptr(addr), nil, nil
}

// Mmap implements linux syscall mmap(2).
func Mmap(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	prot := args[2].Int()
	flags := args[3].Int()
	fd := kdefs.FD(args[4].Int())
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
			opts.MappingIdentity.DecRef()
		}
	}()

	if !anon {
		// Convert the passed FD to a file reference.
		file := t.FDMap().GetFile(fd)
		if file == nil {
			return 0, nil, syserror.EBADF
		}
		defer file.DecRef()

		flags := file.Flags()
		// mmap unconditionally requires that the FD is readable.
		if !flags.Read {
			return 0, nil, syserror.EACCES
		}
		// MAP_SHARED requires that the FD be writable for PROT_WRITE.
		if shared && !flags.Write {
			opts.MaxPerms.Write = false
		}

		if err := file.ConfigureMMap(t, &opts); err != nil {
			return 0, nil, err
		}
	}

	rv, err := t.MemoryManager().MMap(t, opts)
	return uintptr(rv), nil, err
}

// Munmap implements linux syscall munmap(2).
func Munmap(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, t.MemoryManager().MUnmap(t, args[0].Pointer(), args[1].Uint64())
}

// Mremap implements linux syscall mremap(2).
func Mremap(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldAddr := args[0].Pointer()
	oldSize := args[1].Uint64()
	newSize := args[2].Uint64()
	flags := args[3].Uint64()
	newAddr := args[4].Pointer()

	if flags&^(linux.MREMAP_MAYMOVE|linux.MREMAP_FIXED) != 0 {
		return 0, nil, syserror.EINVAL
	}
	mayMove := flags&linux.MREMAP_MAYMOVE != 0
	fixed := flags&linux.MREMAP_FIXED != 0
	var moveMode mm.MRemapMoveMode
	switch {
	case !mayMove && !fixed:
		moveMode = mm.MRemapNoMove
	case mayMove && !fixed:
		moveMode = mm.MRemapMayMove
	case mayMove && fixed:
		moveMode = mm.MRemapMustMove
	case !mayMove && fixed:
		// "If MREMAP_FIXED is specified, then MREMAP_MAYMOVE must also be
		// specified." - mremap(2)
		return 0, nil, syserror.EINVAL
	}

	rv, err := t.MemoryManager().MRemap(t, oldAddr, oldSize, newSize, mm.MRemapOpts{
		Move:    moveMode,
		NewAddr: newAddr,
	})
	return uintptr(rv), nil, err
}

// Mprotect implements linux syscall mprotect(2).
func Mprotect(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	length := args[1].Uint64()
	prot := args[2].Int()
	err := t.MemoryManager().MProtect(args[0].Pointer(), length, usermem.AccessType{
		Read:    linux.PROT_READ&prot != 0,
		Write:   linux.PROT_WRITE&prot != 0,
		Execute: linux.PROT_EXEC&prot != 0,
	}, linux.PROT_GROWSDOWN&prot != 0)
	return 0, nil, err
}

// Madvise implements linux syscall madvise(2).
func Madvise(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	length := uint64(args[1].SizeT())
	adv := args[2].Int()

	// "The Linux implementation requires that the address addr be
	// page-aligned, and allows length to be zero." - madvise(2)
	if addr.RoundDown() != addr {
		return 0, nil, syserror.EINVAL
	}
	if length == 0 {
		return 0, nil, nil
	}
	// Not explicitly stated: length need not be page-aligned.
	lenAddr, ok := usermem.Addr(length).RoundUp()
	if !ok {
		return 0, nil, syserror.EINVAL
	}
	length = uint64(lenAddr)

	switch adv {
	case linux.MADV_DONTNEED:
		return 0, nil, t.MemoryManager().Decommit(addr, length)
	case linux.MADV_DOFORK:
		return 0, nil, t.MemoryManager().SetDontFork(addr, length, false)
	case linux.MADV_DONTFORK:
		return 0, nil, t.MemoryManager().SetDontFork(addr, length, true)
	case linux.MADV_HUGEPAGE, linux.MADV_NOHUGEPAGE:
		fallthrough
	case linux.MADV_MERGEABLE, linux.MADV_UNMERGEABLE:
		fallthrough
	case linux.MADV_DONTDUMP, linux.MADV_DODUMP:
		// TODO(b/72045799): Core dumping isn't implemented, so these are
		// no-ops.
		fallthrough
	case linux.MADV_NORMAL, linux.MADV_RANDOM, linux.MADV_SEQUENTIAL, linux.MADV_WILLNEED:
		// Do nothing, we totally ignore the suggestions above.
		return 0, nil, nil
	case linux.MADV_REMOVE:
		// These "suggestions" have application-visible side effects, so we
		// have to indicate that we don't support them.
		return 0, nil, syserror.ENOSYS
	case linux.MADV_HWPOISON:
		// Only privileged processes are allowed to poison pages.
		return 0, nil, syserror.EPERM
	default:
		// If adv is not a valid value tell the caller.
		return 0, nil, syserror.EINVAL
	}
}

// Mincore implements the syscall mincore(2).
func Mincore(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	length := args[1].SizeT()
	vec := args[2].Pointer()

	if addr != addr.RoundDown() {
		return 0, nil, syserror.EINVAL
	}
	// "The length argument need not be a multiple of the page size, but since
	// residency information is returned for whole pages, length is effectively
	// rounded up to the next multiple of the page size." - mincore(2)
	la, ok := usermem.Addr(length).RoundUp()
	if !ok {
		return 0, nil, syserror.ENOMEM
	}
	ar, ok := addr.ToRange(uint64(la))
	if !ok {
		return 0, nil, syserror.ENOMEM
	}

	// Pretend that all mapped pages are "resident in core".
	mapped := t.MemoryManager().VirtualMemorySizeRange(ar)
	// "ENOMEM: addr to addr + length contained unmapped memory."
	if mapped != uint64(la) {
		return 0, nil, syserror.ENOMEM
	}
	resident := bytes.Repeat([]byte{1}, int(mapped/usermem.PageSize))
	_, err := t.CopyOut(vec, resident)
	return 0, nil, err
}

// Msync implements Linux syscall msync(2).
func Msync(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	length := args[1].SizeT()
	flags := args[2].Int()

	// "The flags argument should specify exactly one of MS_ASYNC and MS_SYNC,
	// and may additionally include the MS_INVALIDATE bit. ... However, Linux
	// permits a call to msync() that specifies neither of these flags, with
	// semantics that are (currently) equivalent to specifying MS_ASYNC." -
	// msync(2)
	if flags&^(linux.MS_ASYNC|linux.MS_SYNC|linux.MS_INVALIDATE) != 0 {
		return 0, nil, syserror.EINVAL
	}
	sync := flags&linux.MS_SYNC != 0
	if sync && flags&linux.MS_ASYNC != 0 {
		return 0, nil, syserror.EINVAL
	}
	err := t.MemoryManager().MSync(t, addr, uint64(length), mm.MSyncOpts{
		Sync:       sync,
		Invalidate: flags&linux.MS_INVALIDATE != 0,
	})
	// MSync calls fsync, the same interrupt conversion rules apply, see
	// mm/msync.c, fsync POSIX.1-2008.
	return 0, nil, syserror.ConvertIntr(err, kernel.ERESTARTSYS)
}

// Mlock implements linux syscall mlock(2).
func Mlock(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	length := args[1].SizeT()

	return 0, nil, t.MemoryManager().MLock(t, addr, uint64(length), memmap.MLockEager)
}

// Mlock2 implements linux syscall mlock2(2).
func Mlock2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	length := args[1].SizeT()
	flags := args[2].Int()

	if flags&^(linux.MLOCK_ONFAULT) != 0 {
		return 0, nil, syserror.EINVAL
	}

	mode := memmap.MLockEager
	if flags&linux.MLOCK_ONFAULT != 0 {
		mode = memmap.MLockLazy
	}
	return 0, nil, t.MemoryManager().MLock(t, addr, uint64(length), mode)
}

// Munlock implements linux syscall munlock(2).
func Munlock(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	length := args[1].SizeT()

	return 0, nil, t.MemoryManager().MLock(t, addr, uint64(length), memmap.MLockNone)
}

// Mlockall implements linux syscall mlockall(2).
func Mlockall(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	flags := args[0].Int()

	if flags&^(linux.MCL_CURRENT|linux.MCL_FUTURE|linux.MCL_ONFAULT) != 0 {
		return 0, nil, syserror.EINVAL
	}

	mode := memmap.MLockEager
	if flags&linux.MCL_ONFAULT != 0 {
		mode = memmap.MLockLazy
	}
	return 0, nil, t.MemoryManager().MLockAll(t, mm.MLockAllOpts{
		Current: flags&linux.MCL_CURRENT != 0,
		Future:  flags&linux.MCL_FUTURE != 0,
		Mode:    mode,
	})
}

// Munlockall implements linux syscall munlockall(2).
func Munlockall(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, t.MemoryManager().MLockAll(t, mm.MLockAllOpts{
		Current: true,
		Future:  true,
		Mode:    memmap.MLockNone,
	})
}
