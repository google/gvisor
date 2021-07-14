// Copyright 2021 The gVisor Authors.

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

const (
	IORING_MAX_ENTRIES    = 32768
	IORING_MAX_CQ_ENTRIES = 2 * IORING_MAX_ENTRIES

	IORING_OFF_SQ_RING = 0
	IORING_OFF_CQ_RING = 0x8000000
	IORING_OFF_SQES    = 0x10000000
)

// IoSqringOffsets represents struct io_sqring_offsets.
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

// IoCqringOffsets represents struct io_cqring_offsets.
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

// IoUringParams represents struct io_uring_params.
//
// +marshal
type IoUringParams struct {
	SqEntries    uint32
	CqEntries    uint32
	Flags        uint32
	SqThreadCPU  uint32
	SqThreadIDLE uint32
	Features     uint32
	WqFd         uint32
	Resv         [3]uint32
	SqOff        IoSqringOffsets
	CqOff        IoCqringOffsets
	//TODO: Fix missing sq_off and cq_off
}

// IoUringCqe represents struct io_uring_cqe.
//
// +marshal
type IoUringCqe struct {
	UserData uint64
	Res      int32
	Flags    uint32
}

// IoUringSqe represents struct io_uring_sqe.
// TODO: this is just a placeholder
//
// +marshal
type IoUringSqe struct {
	Resv [64]uint8
}
