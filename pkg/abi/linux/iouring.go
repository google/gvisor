// Copyright 2022 The gVisor Authors.
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

// Constants for io_uring_setup(2). See include/uapi/linux/io_uring.h.
const (
	IORING_SETUP_IOPOLL     = (1 << 0)
	IORING_SETUP_SQPOLL     = (1 << 1)
	IORING_SETUP_SQ_AFF     = (1 << 2)
	IORING_SETUP_CQSIZE     = (1 << 3)
	IORING_SETUP_CLAMP      = (1 << 4)
	IORING_SETUP_ATTACH_WQ  = (1 << 5)
	IORING_SETUP_R_DISABLED = (1 << 6)
	IORING_SETUP_SUBMIT_ALL = (1 << 7)
)

// Constants for io_uring_enter(2). See include/uapi/linux/io_uring.h.
const (
	IORING_ENTER_GETEVENTS = (1 << 0)
)

// Constants for IoUringParams.Features. See include/uapi/linux/io_uring.h.
const (
	IORING_FEAT_SINGLE_MMAP = (1 << 0)
)

// Constants for IO_URING. See include/uapi/linux/io_uring.h.
const (
	IORING_SETUP_COOP_TASKRUN = (1 << 8)
	IORING_SETUP_TASKRUN_FLAG = (1 << 9)
	IORING_SETUP_SQE128       = (1 << 10)
	IORING_SETUP_CQE32        = (1 << 11)
)

// Constants for IO_URING. See io_uring/io_uring.c.
const (
	IORING_MAX_ENTRIES    = (1 << 15) // 32768
	IORING_MAX_CQ_ENTRIES = (2 * IORING_MAX_ENTRIES)
)

// Constants for the offsets for the application to mmap the data it needs.
// See include/uapi/linux/io_uring.h.
const (
	IORING_OFF_SQ_RING = 0
	IORING_OFF_CQ_RING = 0x8000000
	IORING_OFF_SQES    = 0x10000000
)

// Constants for the IO_URING opcodes. See include/uapi/linux/io_uring.h.
const (
	IORING_OP_NOP   = 0
	IORING_OP_READV = 1
)

// IORingIndex represents SQE array indexes.
//
// +marshal
type IORingIndex uint32

// IOSqRingOffsets implements io_sqring_offsets struct.
// IOSqRingOffsets represents offsets into IORings.
// See struct io_sqring_offsets in include/uapi/linux/io_uring.h.
//
// +marshal
type IOSqRingOffsets struct {
	Head        uint32 // Offset to io_rings.sq.head
	Tail        uint32 // Offset to io_rings.sq.tail
	RingMask    uint32 // Offset to io_rings.sq_ring_mask
	RingEntries uint32 // Offset to io_rings.sq_ring_entries
	Flags       uint32 // Offset to io_rings.sq_flags
	Dropped     uint32 // Offset to io_rings.sq_dropped
	Array       uint32 // Offset to an array of SQE indices
	Resv1       uint32 // Currently reserved and expected to be zero
	Resv2       uint64 // Currently reserved and expected to be zero
}

// IOCqRingOffsets implements io_cqring_offsets struct.
// IOCqRingOffsets represents offsets into IORings.
// See struct io_cqring_offsets in include/uapi/linux/io_uring.h.
//
// +marshal
type IOCqRingOffsets struct {
	Head        uint32 // Offset to io_rings.cq.head
	Tail        uint32 // Offset to io_rings.cq.tail
	RingMask    uint32 // Offset to io_rings.cq_ring_mask
	RingEntries uint32 // Offset to io_rings.cq_ring_entries
	Overflow    uint32 // Offset to io_rings.cq_overflow
	Cqes        uint32 // Offset to io_rings.cqes
	Flags       uint32 // Offset to io_rings.cq_flags
	Resv1       uint32 // Currently reserved and expected to be zero
	Resv2       uint64 // Currently reserved and expected to be zero
}

// IOUringParams implements io_uring_params struct.
// See struct io_uring_params in include/uapi/linux/io_uring.h.
//
// +marshal
type IOUringParams struct {
	SqEntries    uint32
	CqEntries    uint32
	Flags        uint32
	SqThreadCPU  uint32
	SqThreadIdle uint32
	Features     uint32
	WqFd         uint32
	Resv         [3]uint32
	SqOff        IOSqRingOffsets
	CqOff        IOCqRingOffsets
}

// IOUringCqe implements IO completion data structure (Completion Queue Entry)
// io_uring_cqe struct. As we don't currently support IORING_SETUP_CQE32 flag
// its size is 16 bytes.
// See struct io_uring_cqe in include/uapi/linux/io_uring.h.
//
// +marshal
type IOUringCqe struct {
	UserData uint64
	Res      int32
	Flags    uint32
}

// IOUring implements io_uring struct.
// See struct io_uring in io_uring/io_uring.c.
//
// +marshal
type IOUring struct {
	// Both head and tail should be cacheline aligned. And we assume that
	// cacheline size is 64 bytes.
	Head uint32
	_    [60]byte
	Tail uint32
	_    [60]byte
}

// IORings implements io_rings struct.
// This struct describes layout of the mapped region backed by the ringBuffersFile.
// See struct io_rings in io_uring/io_uring.c.
//
// +marshal
type IORings struct {
	Sq, Cq                       IOUring
	SqRingMask, CqRingMask       uint32
	SqRingEntries, CqRingEntries uint32
	sqDropped                    uint32
	sqFlags                      int32
	cqFlags                      uint32
	CqOverflow                   uint32
	_                            [32]byte // Padding so cqes is cacheline aligned
	// Linux has an additional field struct io_uring_cqe cqes[], which represents
	// a dynamic array. We don't include it here in order to enable marshalling.
}

// IOUringSqe implements io_uring_sqe struct.
// This struct represents IO submission data structure (Submission Queue Entry). As we don't yet
// support IORING_SETUP_SQE128 flag, its size is 64 bytes with no extra padding at the end.
// See include/uapi/linux/io_uring.h.
//
// +marshal
type IOUringSqe struct {
	Opcode              uint8
	Flags               uint8
	IoPrio              uint16
	Fd                  int32
	OffOrAddrOrCmdOp    uint64
	AddrOrSpliceOff     uint64
	Len                 uint32
	specialFlags        uint32
	UserData            uint64
	BufIndexOrGroup     uint16
	personality         uint16
	spliceFDOrFileIndex int32
	addr3               uint64
	_                   uint64
}
