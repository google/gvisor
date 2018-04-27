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
	"bytes"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/mm"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
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

	// Require exactly one of MAP_PRIVATE and MAP_SHARED.
	if private == shared {
		return 0, nil, syserror.EINVAL
	}

	opts := memmap.MMapOpts{
		Length:  args[1].Uint64(),
		Offset:  args[5].Uint64(),
		Addr:    args[0].Pointer(),
		Fixed:   fixed,
		Unmap:   fixed,
		Private: private,
		Perms: usermem.AccessType{
			Read:    linux.PROT_READ&prot != 0,
			Write:   linux.PROT_WRITE&prot != 0,
			Execute: linux.PROT_EXEC&prot != 0,
		},
		MaxPerms:  usermem.AnyAccess,
		GrowsDown: linux.MAP_GROWSDOWN&flags != 0,
		Precommit: linux.MAP_POPULATE&flags != 0,
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
	case linux.MADV_HUGEPAGE, linux.MADV_NOHUGEPAGE:
		fallthrough
	case linux.MADV_MERGEABLE, linux.MADV_UNMERGEABLE:
		fallthrough
	case linux.MADV_NORMAL, linux.MADV_RANDOM, linux.MADV_SEQUENTIAL, linux.MADV_WILLNEED:
		// Do nothing, we totally ignore the suggestions above.
		return 0, nil, nil
	case linux.MADV_REMOVE, linux.MADV_DOFORK, linux.MADV_DONTFORK:
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

func copyOutIfNotNull(t *kernel.Task, ptr usermem.Addr, val interface{}) (int, error) {
	if ptr != 0 {
		return t.CopyOut(ptr, val)
	}
	return 0, nil
}

// GetMempolicy implements the syscall get_mempolicy(2).
func GetMempolicy(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	mode := args[0].Pointer()
	nodemask := args[1].Pointer()
	maxnode := args[2].Uint()
	addr := args[3].Pointer()
	flags := args[4].Uint()

	memsAllowed := flags&linux.MPOL_F_MEMS_ALLOWED != 0
	nodeFlag := flags&linux.MPOL_F_NODE != 0
	addrFlag := flags&linux.MPOL_F_ADDR != 0

	// TODO: Once sysfs is implemented, report a single numa node in
	// /sys/devices/system/node.
	if nodemask != 0 && maxnode < 1 {
		return 0, nil, syserror.EINVAL
	}

	// 'addr' provided iff 'addrFlag' set.
	if addrFlag == (addr == 0) {
		return 0, nil, syserror.EINVAL
	}

	// Default policy for the thread.
	if flags == 0 {
		policy, nodemaskVal := t.NumaPolicy()
		if _, err := copyOutIfNotNull(t, mode, policy); err != nil {
			return 0, nil, syserror.EFAULT
		}
		if _, err := copyOutIfNotNull(t, nodemask, nodemaskVal); err != nil {
			return 0, nil, syserror.EFAULT
		}
		return 0, nil, nil
	}

	// Report all nodes available to caller.
	if memsAllowed {
		// MPOL_F_NODE and MPOL_F_ADDR not allowed with MPOL_F_MEMS_ALLOWED.
		if nodeFlag || addrFlag {
			return 0, nil, syserror.EINVAL
		}

		// Report a single numa node.
		if _, err := copyOutIfNotNull(t, nodemask, uint32(0x1)); err != nil {
			return 0, nil, syserror.EFAULT
		}
		return 0, nil, nil
	}

	if addrFlag {
		if nodeFlag {
			// Return the id for the node where 'addr' resides, via 'mode'.
			//
			// The real get_mempolicy(2) allocates the page referenced by 'addr'
			// by simulating a read, if it is unallocated before the call. It
			// then returns the node the page is allocated on through the mode
			// pointer.
			b := t.CopyScratchBuffer(1)
			_, err := t.CopyInBytes(addr, b)
			if err != nil {
				return 0, nil, syserror.EFAULT
			}
			if _, err := copyOutIfNotNull(t, mode, int32(0)); err != nil {
				return 0, nil, syserror.EFAULT
			}
		} else {
			storedPolicy, _ := t.NumaPolicy()
			// Return the policy governing the memory referenced by 'addr'.
			if _, err := copyOutIfNotNull(t, mode, int32(storedPolicy)); err != nil {
				return 0, nil, syserror.EFAULT
			}
		}
		return 0, nil, nil
	}

	storedPolicy, _ := t.NumaPolicy()
	if nodeFlag && (storedPolicy&^linux.MPOL_MODE_FLAGS == linux.MPOL_INTERLEAVE) {
		// Policy for current thread is to interleave memory between
		// nodes. Return the next node we'll allocate on. Since we only have a
		// single node, this is always node 0.
		if _, err := copyOutIfNotNull(t, mode, int32(0)); err != nil {
			return 0, nil, syserror.EFAULT
		}
		return 0, nil, nil
	}

	return 0, nil, syserror.EINVAL
}

func allowedNodesMask() uint32 {
	const maxNodes = 1
	return ^uint32((1 << maxNodes) - 1)
}

// SetMempolicy implements the syscall set_mempolicy(2).
func SetMempolicy(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	modeWithFlags := args[0].Int()
	nodemask := args[1].Pointer()
	maxnode := args[2].Uint()

	if maxnode < 1 {
		return 0, nil, syserror.EINVAL
	}

	if modeWithFlags&linux.MPOL_MODE_FLAGS == linux.MPOL_MODE_FLAGS {
		// Can't specify multiple modes simultaneously. Must also contain a
		// valid mode, which we check below.
		return 0, nil, syserror.EINVAL
	}

	mode := modeWithFlags &^ linux.MPOL_MODE_FLAGS
	if mode < 0 || mode >= linux.MPOL_MAX {
		return 0, nil, syserror.EINVAL
	}

	var nodemaskVal uint32
	if _, err := t.CopyIn(nodemask, &nodemaskVal); err != nil {
		return 0, nil, syserror.EFAULT
	}

	// When setting MPOL_INTERLEAVE, nodemask must not be empty.
	if mode == linux.MPOL_INTERLEAVE && nodemaskVal == 0 {
		return 0, nil, syserror.EINVAL
	}

	if nodemaskVal&allowedNodesMask() != 0 {
		// Invalid node specified.
		return 0, nil, syserror.EINVAL
	}

	t.SetNumaPolicy(int32(modeWithFlags), nodemaskVal)

	return 0, nil, nil
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

	if addr != addr.RoundDown() {
		return 0, nil, syserror.EINVAL
	}
	if length == 0 {
		return 0, nil, nil
	}
	la, ok := usermem.Addr(length).RoundUp()
	if !ok {
		return 0, nil, syserror.ENOMEM
	}
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

	// MS_INVALIDATE "asks to invalidate other mappings of the same file (so
	// that they can be updated with the fresh values just written)". This is a
	// no-op given that shared memory exists. However, MS_INVALIDATE can also
	// be used to detect mlocks: "EBUSY: MS_INVALIDATE was specified in flags,
	// and a memory lock exists for the specified address range." Given that
	// mlock is stubbed out, it's unsafe to pass MS_INVALIDATE silently since
	// some user program could be using it for synchronization.
	if flags&linux.MS_INVALIDATE != 0 {
		return 0, nil, syserror.EINVAL
	}
	// MS_SYNC "requests an update and waits for it to complete."
	if sync {
		err := t.MemoryManager().Sync(t, addr, uint64(la))
		// Sync calls fsync, the same interrupt conversion rules apply, see
		// mm/msync.c, fsync POSIX.1-2008.
		return 0, nil, syserror.ConvertIntr(err, kernel.ERESTARTSYS)
	}
	// MS_ASYNC "specifies that an update be scheduled, but the call returns
	// immediately". As long as dirty pages are tracked and eventually written
	// back, this is a no-op. (Correspondingly: "Since Linux 2.6.19, MS_ASYNC
	// is in fact a no-op, since the kernel properly tracks dirty pages and
	// flushes them to storage as necessary.")
	//
	// However: "ENOMEM: The indicated memory (or part of it) was not mapped."
	// This applies even for MS_ASYNC.
	ar, ok := addr.ToRange(uint64(la))
	if !ok {
		return 0, nil, syserror.ENOMEM
	}
	mapped := t.MemoryManager().VirtualMemorySizeRange(ar)
	if mapped != uint64(la) {
		return 0, nil, syserror.ENOMEM
	}
	return 0, nil, nil
}
