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
)

const IORING_MAX_ENTRIES uint32 = 32768

const SQ_OFF_HEAD_OFFSET uint32 = 0
const SQ_OFF_TAIL_OFFSET uint32 = 64
const CQ_OFF_HEAD_OFFSET uint32 = 128
const CQ_OFF_TAIL_OFFSET uint32 = 192
const SQ_OFF_RING_MASK_OFFSET uint32 = 256
const CQ_OFF_RING_MASK_OFFSET uint32 = 260
const SQ_OFF_RING_ENTRIES_OFFSET uint32 = 264
const CQ_OFF_RING_ENTRIES_OFFSET uint32 = 268
const SQ_OFF_DROPPED_OFFSET uint32 = 272
const SQ_OFF_FLAGS_OFFSET uint32 = 276
const CQ_OFF_FLAGS_OFFSET uint32 = 280
const CQ_OFF_OVERFLOW_OFFSET uint32 = 284
const SQ_OFF_ARRAY_OFFSET uint32 = 384
const CQ_OFF_CQES_OFFSET uint32 = 320

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

	return uintptr(fd), nil, nil
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

	if params.SqEntries > IORING_MAX_ENTRIES {
		return nil, syserror.EINVAL
	}
	params.SqEntries = nextPowOf2(entries)
	params.CqEntries = 2 * params.SqEntries

	params.SqOff.Head = SQ_OFF_HEAD_OFFSET
	params.SqOff.Tail = SQ_OFF_TAIL_OFFSET
	params.SqOff.RingMask = SQ_OFF_RING_MASK_OFFSET
	params.SqOff.RingEntries = SQ_OFF_RING_ENTRIES_OFFSET
	params.SqOff.Dropped = SQ_OFF_DROPPED_OFFSET
	params.SqOff.Flags = SQ_OFF_FLAGS_OFFSET
	params.SqOff.Array = SQ_OFF_ARRAY_OFFSET

	params.CqOff.Head = CQ_OFF_HEAD_OFFSET
	params.CqOff.Tail = CQ_OFF_TAIL_OFFSET
	params.CqOff.RingMask = CQ_OFF_RING_MASK_OFFSET
	params.CqOff.RingEntries = CQ_OFF_RING_ENTRIES_OFFSET
	params.CqOff.Flags = CQ_OFF_FLAGS_OFFSET
	params.CqOff.Overflow = CQ_OFF_OVERFLOW_OFFSET
	params.CqOff.Cqes = CQ_OFF_CQES_OFFSET

	_, err = params.CopyOut(t, p)
	return &params, err
}

func nextPowOf2(n uint32) uint32 {
	var k uint32 = 1

	for k < n {
		k = k << 1
	}

	return k
}
