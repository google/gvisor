// Copyright 2021 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/iouringfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserror"

	"unsafe"
)

// Represent `struct io_uring` as defined in
// https://elixir.bootlin.com/linux/v5.10.44/source/fs/io_uring.c#L107
type IoUring struct {
	Head uint32
	_    [15]uint32 // Head and tail need to be "____cacheline_aligned_in_smp"
	Tail uint32
	_    [15]uint32 // Head and tail need to be "____cacheline_aligned_in_smp"
}

// Represent `struct io_rings` as defined in fs/io_uring.c in linux
type IoRings struct {
	Sq            IoUring
	Cq            IoUring
	SqRingMask    uint32
	CqRingMask    uint32
	SqRingEntries uint32
	CqRingEntries uint32
	SqDropped     uint32
	SqFlags       uint32
	CqFlags       uint32
	CqOverflow    uint32
	// TODO: Add cqes array?
}

// IoUringSetup implements Linux syscall io_uring_setup(2)
func IoUringSetup(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	entries := args[0].Uint()
	params := args[1].Pointer()

	paramsStruct, err := ioUringCreate(t, entries, params)
	if err != nil {
		return 0, nil, err
	}

	file_io, err_io := iouringfs.NewIouringfsFile(t, t.Kernel().IoUringMount(), paramsStruct.SqEntries, paramsStruct.CqEntries)
	if err_io != nil {
		return 0, nil, err
	}
	fd_io, err_io := t.NewFDFromVFS2(0, file_io, kernel.FDFlags{
		CloseOnExec: linux.O_CLOEXEC != 0,
	})

	return uintptr(fd_io), nil, nil
}

func ioUringCreate(t *kernel.Task, entries uint32, p hostarch.Addr) (*linux.IoUringParams, error) {
	if entries == 0 {
		return nil, syserror.EFAULT
	}

	var params linux.IoUringParams

	_, err := params.CopyIn(t, p)
	if err != nil {
		return nil, err
	}

	if entries > linux.IORING_MAX_ENTRIES {
		entries = linux.IORING_MAX_ENTRIES
	}

	params.SqEntries = entries
	params.CqEntries = 2 * params.SqEntries

	rings := IoRings{}

	params.SqOff.Head = uint32(unsafe.Offsetof(rings.Sq.Head))
	params.SqOff.Tail = uint32(unsafe.Offsetof(rings.Sq.Tail))
	params.SqOff.RingMask = uint32(unsafe.Offsetof(rings.SqRingMask))
	params.SqOff.RingEntries = uint32(unsafe.Offsetof(rings.SqRingEntries))
	params.SqOff.Flags = uint32(unsafe.Offsetof(rings.SqFlags))
	params.SqOff.Dropped = uint32(unsafe.Offsetof(rings.SqDropped))
	params.SqOff.Array = 384 // TODO: Unconstify this

	params.CqOff.Head = uint32(unsafe.Offsetof(rings.Cq) + unsafe.Offsetof(rings.Cq.Head)) // For some reason, directly using Offsetof(rigs.Cq.Head) does not work as excepted (or as in C)
	params.CqOff.Tail = uint32(unsafe.Offsetof(rings.Cq) + unsafe.Offsetof(rings.Cq.Tail)) // For some reason, directly using Offsetof(rigs.Cq.Head) does not work as excepted (or as in C)
	params.CqOff.RingMask = uint32(unsafe.Offsetof(rings.CqRingMask))
	params.CqOff.RingEntries = uint32(unsafe.Offsetof(rings.CqRingEntries))
	params.CqOff.Overflow = uint32(unsafe.Offsetof(rings.CqOverflow))
	params.CqOff.Cqes = 320 // TODO: Unconstify this
	params.CqOff.Flags = uint32(unsafe.Offsetof(rings.CqFlags))

	_, err = params.CopyOut(t, p)
	return &params, err
}

func NextPowOf2(n uint32) uint32 {
	var k uint32 = 1

	for k < n {
		k = k << 1
	}

	return k
}
