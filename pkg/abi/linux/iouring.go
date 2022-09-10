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

// Constants for IO_URING. See include/uapi/linux/io_uring.h.
const (
	IORING_SETUP_COOP_TASKRUN = (1 << 8)
	IORING_SETUP_TASKRUN_FLAG = (1 << 9)
	IORING_SETUP_SQE128       = (1 << 10)
	IORING_SETUP_CQE32        = (1 << 11)
)

// Constants for IO_URING. See io_uring/io_uring.c.
const (
	IORING_MAX_ENTRIES = (1 << 15) // 32768
)

// IoSqringOffsets implements io_sqring_offsets struct.
// See include/uapi/linux/io_uring.h.
//
// +marshal
type IoSqringOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Flags       uint32
	Dropped     uint32
	Array       uint32
	Resv1       uint32
	Resv2       uint64
}

// IoCqringOffsets implements io_cqring_offsets struct.
// See include/uapi/linux/io_uring.h.
//
// +marshal
type IoCqringOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Overflow    uint32
	Cqes        uint32
	Flags       uint32
	Resv1       uint32
	Resv2       uint64
}

// IoUringParams implements io_uring_params struct.
// See include/uapi/linux/io_uring.h.
//
// +marshal
type IoUringParams struct {
	SqEntries    uint32
	CqEntries    uint32
	Flags        uint32
	SqThreadCPU  uint32
	SqThreadIdle uint32
	Features     uint32
	WqFd         uint32
	Resv         [3]uint32
	SqOff        IoSqringOffsets
	CqOff        IoCqringOffsets
}
