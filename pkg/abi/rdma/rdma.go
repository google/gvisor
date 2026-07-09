// Copyright 2026 The gVisor Authors.
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

// Package rdma tracks the ABI of the Linux RDMA/InfiniBand userspace
// interface: include/uapi/rdma/.
package rdma

import (
	"structs"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// From include/uapi/rdma/rdma_user_ioctl_cmds.h.
const RDMA_IOCTL_MAGIC = 0x1b

// Attribute flags from include/uapi/rdma/rdma_user_ioctl_cmds.h.
const (
	UVERBS_ATTR_F_MANDATORY    = 1 << 0
	UVERBS_ATTR_F_VALID_OUTPUT = 1 << 1
)

// IBUverbsAttr is struct ib_uverbs_attr, from
// include/uapi/rdma/rdma_user_ioctl_cmds.h.
//
// +marshal slice:IBUverbsAttrSlice
type IBUverbsAttr struct {
	_        structs.HostLayout
	AttrID   uint16
	Len      uint16
	Flags    uint16
	AttrData uint16 // union: enum_data {elem_id u8, reserved u8} or reserved u16
	Data     uint64 // union: data (__aligned_u64) or data_s64 (__s64)
}

// ElemID returns the elem_id field from the enum_data variant of AttrData.
func (a *IBUverbsAttr) ElemID() uint8 {
	return uint8(a.AttrData)
}

// IBUverbsIoctlHdr is the fixed portion of struct ib_uverbs_ioctl_hdr, from
// include/uapi/rdma/rdma_user_ioctl_cmds.h.
// The flexible array member attrs[] is omitted and handled separately.
//
// +marshal
type IBUverbsIoctlHdr struct {
	_         structs.HostLayout
	Length    uint16
	ObjectID  uint16
	MethodID  uint16
	NumAttrs  uint16
	Reserved1 uint64
	DriverID  uint32
	Reserved2 uint32
}

// Struct size constants.
var (
	SizeofIBUverbsAttr     = uint32((*IBUverbsAttr)(nil).SizeBytes())
	SizeofIBUverbsIoctlHdr = uint32((*IBUverbsIoctlHdr)(nil).SizeBytes())
)

// RDMA ioctl commands from include/uapi/rdma/rdma_user_ioctl_cmds.h.
var (
	RDMA_VERBS_IOCTL = linux.IOWR(RDMA_IOCTL_MAGIC, 1, SizeofIBUverbsIoctlHdr)
)
