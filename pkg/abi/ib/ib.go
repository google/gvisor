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

// Package ib contains constants and structs from the Linux InfiniBand
// userspace verbs ABI (include/uapi/rdma/).
package ib

import (
	"structs"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// IB_UVERBS_MAJOR is the fixed char-device major the Linux InfiniBand uverbs
// subsystem uses for /dev/infiniband/uverbs* (defined in
// drivers/infiniband/core/uverbs_main.c).
//
// The first 32 uverbs devices (minors 192-223) use this fixed major; a host
// with more than 32 RDMA devices would assign later ones a dynamic major.
const IB_UVERBS_MAJOR = 231

// RDMAVerbsIoctl is RDMA_VERBS_IOCTL, the single ioctl command of the modern
// uverbs interface (include/uapi/rdma/rdma_user_ioctl.h).
var RDMAVerbsIoctl = linux.IOWR(0x1b, 1, SizeofUverbsIoctlHdr)

// Struct sizes.
var (
	SizeofUverbsIoctlHdr = uint32((*UverbsIoctlHdr)(nil).SizeBytes())
	SizeofUverbsAttr     = uint32((*UverbsAttr)(nil).SizeBytes())
)

// UverbsIoctlHdr is struct ib_uverbs_ioctl_hdr, the fixed header of a
// RDMA_VERBS_IOCTL request; NumAttrs UverbsAttr follow it
// (include/uapi/rdma/rdma_user_ioctl_cmds.h).
//
// +marshal
type UverbsIoctlHdr struct {
	_         structs.HostLayout
	Length    uint16
	ObjectID  uint16
	MethodID  uint16
	NumAttrs  uint16
	Reserved1 uint64
	DriverID  uint32
	Reserved2 uint32
}

// UverbsAttr is struct ib_uverbs_attr, one attribute of a RDMA_VERBS_IOCTL
// request (include/uapi/rdma/rdma_user_ioctl_cmds.h). Data carries an inline
// value, a user pointer (Len > 8), an object handle, or an fd, depending on
// the attribute.
//
// +marshal slice:UverbsAttrSlice
type UverbsAttr struct {
	_        structs.HostLayout
	AttrID   uint16
	Len      uint16
	Flags    uint16
	AttrData uint16
	Data     uint64
}

// UVERBS ioctl object, method, and attribute IDs from
// include/uapi/rdma/ib_user_ioctl_cmds.h. Only the entries the rdma proxy
// models are listed; the enums are cherry-picked, so values are explicit.

// enum uverbs_default_objects.
const (
	UVERBS_OBJECT_DEVICE      = 0
	UVERBS_OBJECT_PD          = 1
	UVERBS_OBJECT_CQ          = 3
	UVERBS_OBJECT_QP          = 4
	UVERBS_OBJECT_MR          = 7
	UVERBS_OBJECT_ASYNC_EVENT = 16
)

// Method IDs within each object namespace.
const (
	// enum uverbs_methods_device.
	UVERBS_METHOD_INVOKE_WRITE    = 0
	UVERBS_METHOD_QUERY_PORT      = 2
	UVERBS_METHOD_GET_CONTEXT     = 3
	UVERBS_METHOD_QUERY_CONTEXT   = 4
	UVERBS_METHOD_QUERY_GID_TABLE = 5
	UVERBS_METHOD_QUERY_GID_ENTRY = 6

	// enum uverbs_methods_pd.
	UVERBS_METHOD_PD_DESTROY = 0

	// enum uverbs_methods_cq.
	UVERBS_METHOD_CQ_CREATE  = 0
	UVERBS_METHOD_CQ_DESTROY = 1

	// enum uverbs_methods_qp.
	UVERBS_METHOD_QP_CREATE  = 0
	UVERBS_METHOD_QP_DESTROY = 1

	// enum uverbs_methods_mr.
	UVERBS_METHOD_MR_DESTROY    = 1
	UVERBS_METHOD_REG_DMABUF_MR = 4
	UVERBS_METHOD_REG_MR        = 5

	// enum uverbs_method_async_event.
	UVERBS_METHOD_ASYNC_EVENT_ALLOC = 0
)

// enum uverbs_attrs_invoke_write_cmd_attr_ids.
const (
	UVERBS_ATTR_CORE_IN   = 0
	UVERBS_ATTR_CORE_OUT  = 1
	UVERBS_ATTR_WRITE_CMD = 2
)

// enum uverbs_attrs_get_context_attr_ids.
const (
	UVERBS_ATTR_GET_CONTEXT_NUM_COMP_VECTORS = 0
	UVERBS_ATTR_GET_CONTEXT_CORE_SUPPORT     = 1
	UVERBS_ATTR_GET_CONTEXT_FD_ARR           = 2
)

// enum uverbs_attrs_query_context_attr_ids.
const (
	UVERBS_ATTR_QUERY_CONTEXT_NUM_COMP_VECTORS = 0
	UVERBS_ATTR_QUERY_CONTEXT_CORE_SUPPORT     = 1
)

// enum uverbs_attrs_query_port_cmd_attr_ids.
const (
	UVERBS_ATTR_QUERY_PORT_PORT_NUM = 0
	UVERBS_ATTR_QUERY_PORT_RESP     = 1
)

// enum uverbs_attrs_query_gid_table_cmd_attr_ids.
const (
	UVERBS_ATTR_QUERY_GID_TABLE_ENTRY_SIZE       = 0
	UVERBS_ATTR_QUERY_GID_TABLE_FLAGS            = 1
	UVERBS_ATTR_QUERY_GID_TABLE_RESP_ENTRIES     = 2
	UVERBS_ATTR_QUERY_GID_TABLE_RESP_NUM_ENTRIES = 3
)

// enum uverbs_attrs_query_gid_entry_cmd_attr_ids.
const (
	UVERBS_ATTR_QUERY_GID_ENTRY_PORT       = 0
	UVERBS_ATTR_QUERY_GID_ENTRY_GID_INDEX  = 1
	UVERBS_ATTR_QUERY_GID_ENTRY_FLAGS      = 2
	UVERBS_ATTR_QUERY_GID_ENTRY_RESP_ENTRY = 3
)

// enum uverbs_attrs_destroy_pd_cmd_attr_ids.
const UVERBS_ATTR_DESTROY_PD_HANDLE = 0

// enum uverbs_attrs_reg_mr_cmd_attr_ids.
const (
	UVERBS_ATTR_REG_MR_HANDLE       = 0
	UVERBS_ATTR_REG_MR_PD_HANDLE    = 1
	UVERBS_ATTR_REG_MR_DMA_HANDLE   = 2
	UVERBS_ATTR_REG_MR_IOVA         = 3
	UVERBS_ATTR_REG_MR_ADDR         = 4
	UVERBS_ATTR_REG_MR_LENGTH       = 5
	UVERBS_ATTR_REG_MR_ACCESS_FLAGS = 6
	UVERBS_ATTR_REG_MR_FD           = 7
	UVERBS_ATTR_REG_MR_FD_OFFSET    = 8
	UVERBS_ATTR_REG_MR_RESP_LKEY    = 9
	UVERBS_ATTR_REG_MR_RESP_RKEY    = 10
)

// enum uverbs_attrs_reg_dmabuf_mr_cmd_attr_ids.
const (
	UVERBS_ATTR_REG_DMABUF_MR_HANDLE       = 0
	UVERBS_ATTR_REG_DMABUF_MR_PD_HANDLE    = 1
	UVERBS_ATTR_REG_DMABUF_MR_OFFSET       = 2
	UVERBS_ATTR_REG_DMABUF_MR_LENGTH       = 3
	UVERBS_ATTR_REG_DMABUF_MR_IOVA         = 4
	UVERBS_ATTR_REG_DMABUF_MR_FD           = 5
	UVERBS_ATTR_REG_DMABUF_MR_ACCESS_FLAGS = 6
	UVERBS_ATTR_REG_DMABUF_MR_RESP_LKEY    = 7
	UVERBS_ATTR_REG_DMABUF_MR_RESP_RKEY    = 8
)

// enum uverbs_attrs_destroy_mr_cmd_attr_ids.
const UVERBS_ATTR_DESTROY_MR_HANDLE = 0

// enum uverbs_attrs_create_cq_cmd_attr_ids.
const (
	UVERBS_ATTR_CREATE_CQ_HANDLE        = 0
	UVERBS_ATTR_CREATE_CQ_CQE           = 1
	UVERBS_ATTR_CREATE_CQ_USER_HANDLE   = 2
	UVERBS_ATTR_CREATE_CQ_COMP_CHANNEL  = 3
	UVERBS_ATTR_CREATE_CQ_COMP_VECTOR   = 4
	UVERBS_ATTR_CREATE_CQ_FLAGS         = 5
	UVERBS_ATTR_CREATE_CQ_RESP_CQE      = 6
	UVERBS_ATTR_CREATE_CQ_EVENT_FD      = 7
	UVERBS_ATTR_CREATE_CQ_BUFFER_VA     = 8
	UVERBS_ATTR_CREATE_CQ_BUFFER_LENGTH = 9
	UVERBS_ATTR_CREATE_CQ_BUFFER_FD     = 10
	UVERBS_ATTR_CREATE_CQ_BUFFER_OFFSET = 11
	UVERBS_ATTR_CREATE_CQ_BUF_UMEM      = 12
)

// enum uverbs_attrs_destroy_cq_cmd_attr_ids.
const (
	UVERBS_ATTR_DESTROY_CQ_HANDLE = 0
	UVERBS_ATTR_DESTROY_CQ_RESP   = 1
)

// enum uverbs_attrs_create_qp_cmd_attr_ids.
const (
	UVERBS_ATTR_CREATE_QP_HANDLE           = 0
	UVERBS_ATTR_CREATE_QP_XRCD_HANDLE      = 1
	UVERBS_ATTR_CREATE_QP_PD_HANDLE        = 2
	UVERBS_ATTR_CREATE_QP_SRQ_HANDLE       = 3
	UVERBS_ATTR_CREATE_QP_SEND_CQ_HANDLE   = 4
	UVERBS_ATTR_CREATE_QP_RECV_CQ_HANDLE   = 5
	UVERBS_ATTR_CREATE_QP_IND_TABLE_HANDLE = 6
	UVERBS_ATTR_CREATE_QP_USER_HANDLE      = 7
	UVERBS_ATTR_CREATE_QP_CAP              = 8
	UVERBS_ATTR_CREATE_QP_TYPE             = 9
	UVERBS_ATTR_CREATE_QP_FLAGS            = 10
	UVERBS_ATTR_CREATE_QP_SOURCE_QPN       = 11
	UVERBS_ATTR_CREATE_QP_EVENT_FD         = 12
	UVERBS_ATTR_CREATE_QP_RESP_CAP         = 13
	UVERBS_ATTR_CREATE_QP_RESP_QP_NUM      = 14
	UVERBS_ATTR_CREATE_QP_BUF_UMEM         = 15
	UVERBS_ATTR_CREATE_QP_RQ_BUF_UMEM      = 16
	UVERBS_ATTR_CREATE_QP_SQ_BUF_UMEM      = 17
)

// enum uverbs_attrs_destroy_qp_cmd_attr_ids.
const (
	UVERBS_ATTR_DESTROY_QP_HANDLE = 0
	UVERBS_ATTR_DESTROY_QP_RESP   = 1
)

// enum uverbs_attrs_async_event_create.
const UVERBS_ATTR_ASYNC_EVENT_ALLOC_FD_HANDLE = 0

// Driver-private attribute IDs (>= UVERBS_ID_DRIVER_NS) shared across
// methods. UHW_IN/UHW_OUT carry vendor driver data (e.g. mlx5's
// mlx5_ib_create_cq / mlx5_ib_create_qp with the CQ/QP DMA buffer pointers).
const (
	UVERBS_ATTR_UHW_IN  = 0x1000
	UVERBS_ATTR_UHW_OUT = 0x1001
)

// mlx5 driver-namespace object/method/attr IDs from
// include/uapi/rdma/mlx5_user_ioctl_cmds.h. The UAR (User Access Region) is
// the CQ/QP doorbell page.
const (
	MLX5_IB_OBJECT_UAR = 0x1008

	// enum mlx5_ib_uar_obj_methods.
	MLX5_IB_METHOD_UAR_OBJ_ALLOC   = 0x1000
	MLX5_IB_METHOD_UAR_OBJ_DESTROY = 0x1001

	// enum mlx5_ib_uar_obj_alloc_attrs.
	MLX5_IB_ATTR_UAR_OBJ_ALLOC_HANDLE      = 0x1000
	MLX5_IB_ATTR_UAR_OBJ_ALLOC_TYPE        = 0x1001
	MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_OFFSET = 0x1002
	MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_LENGTH = 0x1003
	MLX5_IB_ATTR_UAR_OBJ_ALLOC_PAGE_ID     = 0x1004

	// enum mlx5_ib_uar_obj_destroy_attrs.
	MLX5_IB_ATTR_UAR_OBJ_DESTROY_HANDLE = 0x1000
)

// Legacy write(2)-path command numbers (enum ib_uverbs_write_cmds,
// include/uapi/rdma/ib_user_verbs.h), as carried by the INVOKE_WRITE
// WRITE_CMD attribute.
const (
	IB_USER_VERBS_CMD_REG_MR   = 9
	IB_USER_VERBS_CMD_DEREG_MR = 13
)

// UverbsRegMR is struct ib_uverbs_reg_mr, the legacy write-path REG_MR
// command (include/uapi/rdma/ib_user_verbs.h). Variable-length driver data
// may follow.
//
// +marshal
type UverbsRegMR struct {
	_           structs.HostLayout
	Response    uint64
	Start       uint64
	Length      uint64
	HcaVA       uint64
	PDHandle    uint32
	AccessFlags uint32
}

// UverbsRegMRResp is struct ib_uverbs_reg_mr_resp, REG_MR's response
// (include/uapi/rdma/ib_user_verbs.h).
//
// +marshal
type UverbsRegMRResp struct {
	_        structs.HostLayout
	MRHandle uint32
	LKey     uint32
	RKey     uint32
}

// Mlx5CreatePrefix is the common prefix of struct mlx5_ib_create_cq and
// struct mlx5_ib_create_qp (include/uapi/rdma/mlx5-abi.h): the work-queue
// buffer and doorbell guest addresses.
//
// +marshal
type Mlx5CreatePrefix struct {
	_       structs.HostLayout
	BufAddr uint64
	DBAddr  uint64
}
