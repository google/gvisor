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

package rdma

import "structs"

// irdma driver-specific ABI from include/uapi/rdma/irdma-abi.h.

const IRDMA_ABI_VER = 5

// irdma_memreg_type.
const (
	IRDMA_MEMREG_TYPE_MEM = 0
	IRDMA_MEMREG_TYPE_QP  = 1
	IRDMA_MEMREG_TYPE_CQ  = 2
	IRDMA_MEMREG_TYPE_SRQ = 3
)

// irdma alloc_uctx feature flags.
const (
	IRDMA_ALLOC_UCTX_USE_RAW_ATTR      = 1 << 0
	IRDMA_ALLOC_UCTX_MIN_HW_WQ_SIZE    = 1 << 1
	IRDMA_ALLOC_UCTX_MAX_HW_SRQ_QUANTA = 1 << 2
	IRDMA_SUPPORT_WQE_FORMAT_V2         = 1 << 3
)

// IrdmaAllocUcontextReq is struct irdma_alloc_ucontext_req.
//
// +marshal
type IrdmaAllocUcontextReq struct {
	_            structs.HostLayout
	Rsvd32       uint32
	UserSpaceVer uint8
	Rsvd8        [3]uint8
	CompMask     uint64
}

// IrdmaAllocUcontextResp is struct irdma_alloc_ucontext_resp.
//
// +marshal
type IrdmaAllocUcontextResp struct {
	_              structs.HostLayout
	MaxPds         uint32
	MaxQps         uint32
	WqSize         uint32
	KernelVer      uint8
	Rsvd           [3]uint8
	FeatureFlags   uint64
	DBMmapKey      uint64
	MaxHWWqFrags   uint32
	MaxHWReadSges  uint32
	MaxHWInline    uint32
	MaxHWRqQuanta  uint32
	MaxHWWqQuanta  uint32
	MinHWCqSize    uint32
	MaxHWCqSize    uint32
	MaxHWSqChunk   uint16
	HWRev          uint8
	Rsvd2          uint8
	CompMask       uint64
	MinHWWqSize    uint16
	Rsvd3          [2]uint8
	MaxHWSrqQuanta uint32
}

// IrdmaAllocPDResp is struct irdma_alloc_pd_resp.
//
// +marshal
type IrdmaAllocPDResp struct {
	_    structs.HostLayout
	PDId uint32
	Rsvd [4]uint8
}

// IrdmaResizeCQReq is struct irdma_resize_cq_req.
//
// +marshal
type IrdmaResizeCQReq struct {
	_            structs.HostLayout
	UserCQBuffer uint64
}

// IrdmaCreateCQReq is struct irdma_create_cq_req.
//
// +marshal
type IrdmaCreateCQReq struct {
	_              structs.HostLayout
	UserCQBuf      uint64
	UserShadowArea uint64
}

// IrdmaCreateSRQReq is struct irdma_create_srq_req.
//
// +marshal
type IrdmaCreateSRQReq struct {
	_              structs.HostLayout
	UserSRQBuf     uint64
	UserShadowArea uint64
}

// IrdmaCreateSRQResp is struct irdma_create_srq_resp.
//
// +marshal
type IrdmaCreateSRQResp struct {
	_       structs.HostLayout
	SRQId   uint32
	SRQSize uint32
}

// IrdmaCreateQPReq is struct irdma_create_qp_req.
//
// +marshal
type IrdmaCreateQPReq struct {
	_            structs.HostLayout
	UserWQEBufs  uint64
	UserComplCtx uint64
}

// IrdmaMemRegReq is struct irdma_mem_reg_req.
//
// +marshal
type IrdmaMemRegReq struct {
	_       structs.HostLayout
	RegType uint16
	CqPages uint16
	RqPages uint16
	SqPages uint16
}

// IrdmaModifyQPReq is struct irdma_modify_qp_req.
//
// +marshal
type IrdmaModifyQPReq struct {
	_       structs.HostLayout
	SqFlush uint8
	RqFlush uint8
	Rsvd    [6]uint8
}

// IrdmaCreateCQResp is struct irdma_create_cq_resp.
//
// +marshal
type IrdmaCreateCQResp struct {
	_      structs.HostLayout
	CQId   uint32
	CQSize uint32
}

// IrdmaCreateQPResp is struct irdma_create_qp_resp.
//
// +marshal
type IrdmaCreateQPResp struct {
	_             structs.HostLayout
	QPId          uint32
	ActualSQSize  uint32
	ActualRQSize  uint32
	IrdmaDrvOpt   uint32
	PushIdx       uint16
	LSMM          uint8
	Rsvd          uint8
	QPCaps        uint32
}

// IrdmaModifyQPResp is struct irdma_modify_qp_resp.
//
// +marshal
type IrdmaModifyQPResp struct {
	_               structs.HostLayout
	PushWqeMmapKey  uint64
	PushDbMmapKey   uint64
	PushOffset      uint16
	PushValid       uint8
	Rsvd            [5]uint8
}

// IrdmaCreateAHResp is struct irdma_create_ah_resp.
//
// +marshal
type IrdmaCreateAHResp struct {
	_    structs.HostLayout
	AHId uint32
	Rsvd [4]uint8
}

// irdma struct size constants.
var (
	SizeofIrdmaAllocUcontextReq  = uint32((*IrdmaAllocUcontextReq)(nil).SizeBytes())
	SizeofIrdmaAllocUcontextResp = uint32((*IrdmaAllocUcontextResp)(nil).SizeBytes())
	SizeofIrdmaAllocPDResp       = uint32((*IrdmaAllocPDResp)(nil).SizeBytes())
	SizeofIrdmaResizeCQReq       = uint32((*IrdmaResizeCQReq)(nil).SizeBytes())
	SizeofIrdmaCreateCQReq       = uint32((*IrdmaCreateCQReq)(nil).SizeBytes())
	SizeofIrdmaCreateSRQReq      = uint32((*IrdmaCreateSRQReq)(nil).SizeBytes())
	SizeofIrdmaCreateSRQResp     = uint32((*IrdmaCreateSRQResp)(nil).SizeBytes())
	SizeofIrdmaCreateQPReq       = uint32((*IrdmaCreateQPReq)(nil).SizeBytes())
	SizeofIrdmaMemRegReq         = uint32((*IrdmaMemRegReq)(nil).SizeBytes())
	SizeofIrdmaModifyQPReq       = uint32((*IrdmaModifyQPReq)(nil).SizeBytes())
	SizeofIrdmaCreateCQResp      = uint32((*IrdmaCreateCQResp)(nil).SizeBytes())
	SizeofIrdmaCreateQPResp      = uint32((*IrdmaCreateQPResp)(nil).SizeBytes())
	SizeofIrdmaModifyQPResp      = uint32((*IrdmaModifyQPResp)(nil).SizeBytes())
	SizeofIrdmaCreateAHResp      = uint32((*IrdmaCreateAHResp)(nil).SizeBytes())
)
