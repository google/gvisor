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

// Enums and structs from include/uapi/rdma/ib_user_ioctl_verbs.h.

// Optional MR access flag range.
const (
	IB_UVERBS_ACCESS_OPTIONAL_FIRST = 1 << 20
	IB_UVERBS_ACCESS_OPTIONAL_LAST  = 1 << 29
)

// ib_uverbs_core_support.
const (
	IB_UVERBS_CORE_SUPPORT_OPTIONAL_MR_ACCESS = 1 << 0
	IB_UVERBS_CORE_SUPPORT_ROBUST_UDATA       = 1 << 1
)

// ib_uverbs_access_flags.
const (
	IB_UVERBS_ACCESS_LOCAL_WRITE      = 1 << 0
	IB_UVERBS_ACCESS_REMOTE_WRITE     = 1 << 1
	IB_UVERBS_ACCESS_REMOTE_READ      = 1 << 2
	IB_UVERBS_ACCESS_REMOTE_ATOMIC    = 1 << 3
	IB_UVERBS_ACCESS_MW_BIND          = 1 << 4
	IB_UVERBS_ACCESS_ZERO_BASED       = 1 << 5
	IB_UVERBS_ACCESS_ON_DEMAND        = 1 << 6
	IB_UVERBS_ACCESS_HUGETLB          = 1 << 7
	IB_UVERBS_ACCESS_FLUSH_GLOBAL     = 1 << 8
	IB_UVERBS_ACCESS_FLUSH_PERSISTENT = 1 << 9
	IB_UVERBS_ACCESS_RELAXED_ORDERING = IB_UVERBS_ACCESS_OPTIONAL_FIRST
	IB_UVERBS_ACCESS_OPTIONAL_RANGE   = ((IB_UVERBS_ACCESS_OPTIONAL_LAST << 1) - 1) &^ (IB_UVERBS_ACCESS_OPTIONAL_FIRST - 1)
)

// ib_uverbs_srq_type.
const (
	IB_UVERBS_SRQT_BASIC = iota
	IB_UVERBS_SRQT_XRC
	IB_UVERBS_SRQT_TM
)

// ib_uverbs_wq_type.
const (
	IB_UVERBS_WQT_RQ = 0
)

// ib_uverbs_wq_flags.
const (
	IB_UVERBS_WQ_FLAGS_CVLAN_STRIPPING       = 1 << 0
	IB_UVERBS_WQ_FLAGS_SCATTER_FCS           = 1 << 1
	IB_UVERBS_WQ_FLAGS_DELAY_DROP            = 1 << 2
	IB_UVERBS_WQ_FLAGS_PCI_WRITE_END_PADDING = 1 << 3
)

// ib_uverbs_qp_type.
const (
	IB_UVERBS_QPT_RC         = 2
	IB_UVERBS_QPT_UC         = 3
	IB_UVERBS_QPT_UD         = 4
	IB_UVERBS_QPT_RAW_PACKET = 8
	IB_UVERBS_QPT_XRC_INI    = 9
	IB_UVERBS_QPT_XRC_TGT    = 10
	IB_UVERBS_QPT_DRIVER     = 0xff
)

// ib_uverbs_qp_create_flags.
const (
	IB_UVERBS_QP_CREATE_BLOCK_MULTICAST_LOOPBACK = 1 << 1
	IB_UVERBS_QP_CREATE_SCATTER_FCS              = 1 << 8
	IB_UVERBS_QP_CREATE_CVLAN_STRIPPING          = 1 << 9
	IB_UVERBS_QP_CREATE_PCI_WRITE_END_PADDING    = 1 << 11
	IB_UVERBS_QP_CREATE_SQ_SIG_ALL               = 1 << 12
)

// ib_uverbs_query_port_cap_flags.
const (
	IB_UVERBS_PCF_SM                              = 1 << 1
	IB_UVERBS_PCF_NOTICE_SUP                      = 1 << 2
	IB_UVERBS_PCF_TRAP_SUP                        = 1 << 3
	IB_UVERBS_PCF_OPT_IPD_SUP                     = 1 << 4
	IB_UVERBS_PCF_AUTO_MIGR_SUP                   = 1 << 5
	IB_UVERBS_PCF_SL_MAP_SUP                      = 1 << 6
	IB_UVERBS_PCF_MKEY_NVRAM                      = 1 << 7
	IB_UVERBS_PCF_PKEY_NVRAM                      = 1 << 8
	IB_UVERBS_PCF_LED_INFO_SUP                    = 1 << 9
	IB_UVERBS_PCF_SM_DISABLED                     = 1 << 10
	IB_UVERBS_PCF_SYS_IMAGE_GUID_SUP             = 1 << 11
	IB_UVERBS_PCF_PKEY_SW_EXT_PORT_TRAP_SUP      = 1 << 12
	IB_UVERBS_PCF_EXTENDED_SPEEDS_SUP             = 1 << 14
	IB_UVERBS_PCF_CM_SUP                          = 1 << 16
	IB_UVERBS_PCF_SNMP_TUNNEL_SUP                 = 1 << 17
	IB_UVERBS_PCF_REINIT_SUP                      = 1 << 18
	IB_UVERBS_PCF_DEVICE_MGMT_SUP                 = 1 << 19
	IB_UVERBS_PCF_VENDOR_CLASS_SUP                = 1 << 20
	IB_UVERBS_PCF_DR_NOTICE_SUP                   = 1 << 21
	IB_UVERBS_PCF_CAP_MASK_NOTICE_SUP             = 1 << 22
	IB_UVERBS_PCF_BOOT_MGMT_SUP                   = 1 << 23
	IB_UVERBS_PCF_LINK_LATENCY_SUP                = 1 << 24
	IB_UVERBS_PCF_CLIENT_REG_SUP                  = 1 << 25
	IB_UVERBS_PCF_IP_BASED_GIDS                   = 1 << 26
	IB_UVERBS_PCF_LINK_SPEED_WIDTH_TABLE_SUP      = 1 << 27
	IB_UVERBS_PCF_VENDOR_SPECIFIC_MADS_TABLE_SUP  = 1 << 28
	IB_UVERBS_PCF_MCAST_PKEY_TRAP_SUPPRESSION_SUP = 1 << 29
	IB_UVERBS_PCF_MCAST_FDB_TOP_SUP               = 1 << 30
	IB_UVERBS_PCF_HIERARCHY_INFO_SUP              = 1 << 31
)

// ib_uverbs_query_port_flags.
const (
	IB_UVERBS_QPF_GRH_REQUIRED = 1 << 0
)

// ib_uverbs_flow_action_esp_keymat.
const (
	IB_UVERBS_FLOW_ACTION_ESP_KEYMAT_AES_GCM = 0
)

// ib_uverbs_flow_action_esp_keymat_aes_gcm_iv_algo.
const (
	IB_UVERBS_FLOW_ACTION_IV_ALGO_SEQ = 0
)

// ib_uverbs_flow_action_esp_replay.
const (
	IB_UVERBS_FLOW_ACTION_ESP_REPLAY_NONE = 0
	IB_UVERBS_FLOW_ACTION_ESP_REPLAY_BMP  = 1
)

// ib_uverbs_flow_action_esp_flags.
const (
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_INLINE_CRYPTO = 0 << 0
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_FULL_OFFLOAD  = 1 << 0
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_TUNNEL        = 0 << 1
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_TRANSPORT     = 1 << 1
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_DECRYPT       = 0 << 2
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_ENCRYPT       = 1 << 2
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_ESN_NEW_WINDOW = 1 << 3
)

// ib_uverbs_read_counters_flags.
const (
	IB_UVERBS_READ_COUNTERS_PREFER_CACHED = 1 << 0
)

// ib_uverbs_advise_mr_advice.
const (
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH          = 0
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE    = 1
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_NO_FAULT = 2
)

// ib_uverbs_advise_mr_flag.
const (
	IB_UVERBS_ADVISE_MR_FLAG_FLUSH = 1 << 0
)

// rdma_driver_id from include/uapi/rdma/ib_user_ioctl_verbs.h.
const (
	RDMA_DRIVER_UNKNOWN    = 0
	RDMA_DRIVER_MLX5       = 1
	RDMA_DRIVER_MLX4       = 2
	RDMA_DRIVER_CXGB3      = 3
	RDMA_DRIVER_CXGB4      = 4
	RDMA_DRIVER_MTHCA      = 5
	RDMA_DRIVER_BNXT_RE    = 6
	RDMA_DRIVER_OCRDMA     = 7
	RDMA_DRIVER_NES        = 8
	RDMA_DRIVER_I40IW      = 9
	RDMA_DRIVER_IRDMA      = RDMA_DRIVER_I40IW
	RDMA_DRIVER_VMW_PVRDMA = 10
	RDMA_DRIVER_QEDR       = 11
	RDMA_DRIVER_HNS        = 12
	RDMA_DRIVER_USNIC      = 13
	RDMA_DRIVER_RXE        = 14
	RDMA_DRIVER_HFI1       = 15
	RDMA_DRIVER_QIB        = 16
	RDMA_DRIVER_EFA        = 17
	RDMA_DRIVER_SIW        = 18
	RDMA_DRIVER_ERDMA      = 19
	RDMA_DRIVER_MANA       = 20
	RDMA_DRIVER_IONIC      = 21
)

// ib_uverbs_gid_type.
const (
	IB_UVERBS_GID_TYPE_IB      = 0
	IB_UVERBS_GID_TYPE_ROCE_V1 = 1
	IB_UVERBS_GID_TYPE_ROCE_V2 = 2
)

// ib_uverbs_buffer_type.
const (
	IB_UVERBS_BUFFER_TYPE_DMABUF = 0
	IB_UVERBS_BUFFER_TYPE_VA     = 1
)

// IBUverbsQPCap is struct ib_uverbs_qp_cap, from
// include/uapi/rdma/ib_user_ioctl_verbs.h.
//
// +marshal
type IBUverbsQPCap struct {
	_             structs.HostLayout
	MaxSendWR     uint32
	MaxRecvWR     uint32
	MaxSendSge    uint32
	MaxRecvSge    uint32
	MaxInlineData uint32
}

// IBUverbsQueryPortResp is struct ib_uverbs_query_port_resp, from
// include/uapi/rdma/ib_user_verbs.h. Needed by IBUverbsQueryPortRespEx.
//
// +marshal
type IBUverbsQueryPortResp struct {
	_              structs.HostLayout
	PortCapFlags   uint32
	MaxMsgSz       uint32
	BadPkeyCntr    uint32
	QkeyViolCntr   uint32
	GidTblLen      uint32
	PkeyTblLen     uint16
	LID            uint16
	SMLID          uint16
	State          uint8
	MaxMTU         uint8
	ActiveMTU      uint8
	LMC            uint8
	MaxVLNum       uint8
	SMSL           uint8
	SubnetTimeout  uint8
	InitTypeReply  uint8
	ActiveWidth    uint8
	ActiveSpeed    uint8
	PhysState      uint8
	LinkLayer      uint8
	Flags          uint8
	Reserved       uint8
}

// IBUverbsQueryPortRespEx is struct ib_uverbs_query_port_resp_ex, from
// include/uapi/rdma/ib_user_ioctl_verbs.h.
//
// +marshal
type IBUverbsQueryPortRespEx struct {
	_              structs.HostLayout
	LegacyResp     IBUverbsQueryPortResp
	PortCapFlags2  uint16
	Reserved       [2]uint8
	ActiveSpeedEx  uint32
}

// IBUverbsGIDEntry is struct ib_uverbs_gid_entry, from
// include/uapi/rdma/ib_user_ioctl_verbs.h.
//
// +marshal
type IBUverbsGIDEntry struct {
	_             structs.HostLayout
	GID           [16]byte
	GIDIndex      uint32
	PortNum       uint32
	GIDType       uint32
	NetdevIfIndex uint32
}

// IBUverbsBufferDesc is struct ib_uverbs_buffer_desc, from
// include/uapi/rdma/ib_user_ioctl_verbs.h.
//
// +marshal
type IBUverbsBufferDesc struct {
	_             structs.HostLayout
	Type          uint32
	FD            int32
	Flags         uint32
	OptionalFlags uint32
	Addr          uint64
	Length        uint64
}

// IBUverbsFlowActionESP is struct ib_uverbs_flow_action_esp, from
// include/uapi/rdma/ib_user_ioctl_verbs.h.
//
// +marshal
type IBUverbsFlowActionESP struct {
	_             structs.HostLayout
	SPI           uint32
	Seq           uint32
	TFCPad        uint32
	Flags         uint32
	HardLimitPkts uint64
}

// IBUverbsFlowActionESPKeymatAESGCM is
// struct ib_uverbs_flow_action_esp_keymat_aes_gcm, from
// include/uapi/rdma/ib_user_ioctl_verbs.h.
//
// +marshal
type IBUverbsFlowActionESPKeymatAESGCM struct {
	_       structs.HostLayout
	IV      uint64
	IVAlgo  uint32
	Salt    uint32
	ICVLen  uint32
	KeyLen  uint32
	AESKey  [8]uint32
}

// IBUverbsFlowActionESPReplayBMP is
// struct ib_uverbs_flow_action_esp_replay_bmp, from
// include/uapi/rdma/ib_user_ioctl_verbs.h.
//
// +marshal
type IBUverbsFlowActionESPReplayBMP struct {
	_    structs.HostLayout
	Size uint32
}

// IBUverbsFlowActionESPEncap is struct ib_uverbs_flow_action_esp_encap, from
// include/uapi/rdma/ib_user_ioctl_verbs.h.
//
// +marshal
type IBUverbsFlowActionESPEncap struct {
	_       structs.HostLayout
	ValPtr  uint64
	NextPtr uint64
	Len     uint16
	Type    uint16
	Pad0    [4]byte
}

// Struct size constants.
var (
	SizeofIBUverbsQPCap                      = uint32((*IBUverbsQPCap)(nil).SizeBytes())
	SizeofIBUverbsQueryPortResp              = uint32((*IBUverbsQueryPortResp)(nil).SizeBytes())
	SizeofIBUverbsQueryPortRespEx            = uint32((*IBUverbsQueryPortRespEx)(nil).SizeBytes())
	SizeofIBUverbsGIDEntry                   = uint32((*IBUverbsGIDEntry)(nil).SizeBytes())
	SizeofIBUverbsBufferDesc                 = uint32((*IBUverbsBufferDesc)(nil).SizeBytes())
	SizeofIBUverbsFlowActionESP              = uint32((*IBUverbsFlowActionESP)(nil).SizeBytes())
	SizeofIBUverbsFlowActionESPKeymatAESGCM  = uint32((*IBUverbsFlowActionESPKeymatAESGCM)(nil).SizeBytes())
	SizeofIBUverbsFlowActionESPReplayBMP     = uint32((*IBUverbsFlowActionESPReplayBMP)(nil).SizeBytes())
	SizeofIBUverbsFlowActionESPEncap         = uint32((*IBUverbsFlowActionESPEncap)(nil).SizeBytes())
)
