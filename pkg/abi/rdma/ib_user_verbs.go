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

import (
	"structs"
)

// Enums and structs from include/uapi/rdma/ib_user_verbs.h, the legacy
// write() command ABI of /dev/infiniband/uverbsX. Flexible array members
// (driver_data[], wc[], send_wr[], recv_wr[], wq_handles[], flow_specs[])
// are omitted from the structs and must be handled separately.
//
// struct ib_uverbs_global_route (IBUverbsGlobalRoute) and struct
// ib_uverbs_ah_attr (IBUverbsAHAttr) are defined in rdma_user_cm.go;
// struct ib_uverbs_query_port_resp (IBUverbsQueryPortResp) is defined in
// ib_user_ioctl_verbs.go.

// ABI constants.
const (
	IB_USER_VERBS_ABI_VERSION  = 6
	IB_USER_VERBS_CMD_THRESHOLD = 50
)

// enum ib_uverbs_write_cmds.
const (
	IB_USER_VERBS_CMD_GET_CONTEXT = iota
	IB_USER_VERBS_CMD_QUERY_DEVICE
	IB_USER_VERBS_CMD_QUERY_PORT
	IB_USER_VERBS_CMD_ALLOC_PD
	IB_USER_VERBS_CMD_DEALLOC_PD
	IB_USER_VERBS_CMD_CREATE_AH
	IB_USER_VERBS_CMD_MODIFY_AH
	IB_USER_VERBS_CMD_QUERY_AH
	IB_USER_VERBS_CMD_DESTROY_AH
	IB_USER_VERBS_CMD_REG_MR
	IB_USER_VERBS_CMD_REG_SMR
	IB_USER_VERBS_CMD_REREG_MR
	IB_USER_VERBS_CMD_QUERY_MR
	IB_USER_VERBS_CMD_DEREG_MR
	IB_USER_VERBS_CMD_ALLOC_MW
	IB_USER_VERBS_CMD_BIND_MW
	IB_USER_VERBS_CMD_DEALLOC_MW
	IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL
	IB_USER_VERBS_CMD_CREATE_CQ
	IB_USER_VERBS_CMD_RESIZE_CQ
	IB_USER_VERBS_CMD_DESTROY_CQ
	IB_USER_VERBS_CMD_POLL_CQ
	IB_USER_VERBS_CMD_PEEK_CQ
	IB_USER_VERBS_CMD_REQ_NOTIFY_CQ
	IB_USER_VERBS_CMD_CREATE_QP
	IB_USER_VERBS_CMD_QUERY_QP
	IB_USER_VERBS_CMD_MODIFY_QP
	IB_USER_VERBS_CMD_DESTROY_QP
	IB_USER_VERBS_CMD_POST_SEND
	IB_USER_VERBS_CMD_POST_RECV
	IB_USER_VERBS_CMD_ATTACH_MCAST
	IB_USER_VERBS_CMD_DETACH_MCAST
	IB_USER_VERBS_CMD_CREATE_SRQ
	IB_USER_VERBS_CMD_MODIFY_SRQ
	IB_USER_VERBS_CMD_QUERY_SRQ
	IB_USER_VERBS_CMD_DESTROY_SRQ
	IB_USER_VERBS_CMD_POST_SRQ_RECV
	IB_USER_VERBS_CMD_OPEN_XRCD
	IB_USER_VERBS_CMD_CLOSE_XRCD
	IB_USER_VERBS_CMD_CREATE_XSRQ
	IB_USER_VERBS_CMD_OPEN_QP
)

// Extended command aliases, from the anonymous enum following
// enum ib_uverbs_write_cmds.
const (
	IB_USER_VERBS_EX_CMD_QUERY_DEVICE = IB_USER_VERBS_CMD_QUERY_DEVICE
	IB_USER_VERBS_EX_CMD_CREATE_CQ    = IB_USER_VERBS_CMD_CREATE_CQ
	IB_USER_VERBS_EX_CMD_CREATE_QP    = IB_USER_VERBS_CMD_CREATE_QP
	IB_USER_VERBS_EX_CMD_MODIFY_QP    = IB_USER_VERBS_CMD_MODIFY_QP
)

// Extended-only commands, from the same anonymous enum.
const (
	IB_USER_VERBS_EX_CMD_CREATE_FLOW = IB_USER_VERBS_CMD_THRESHOLD + iota
	IB_USER_VERBS_EX_CMD_DESTROY_FLOW
	IB_USER_VERBS_EX_CMD_CREATE_WQ
	IB_USER_VERBS_EX_CMD_MODIFY_WQ
	IB_USER_VERBS_EX_CMD_DESTROY_WQ
	IB_USER_VERBS_EX_CMD_CREATE_RWQ_IND_TBL
	IB_USER_VERBS_EX_CMD_DESTROY_RWQ_IND_TBL
	IB_USER_VERBS_EX_CMD_MODIFY_CQ
)

// enum ib_placement_type. See IBA A19.4.1.1 Placement Types.
const (
	IB_FLUSH_GLOBAL = 1 << iota
	IB_FLUSH_PERSISTENT
)

// enum ib_selectivity_level. See IBA A19.4.1.2 Selectivity Level.
const (
	IB_FLUSH_RANGE = iota
	IB_FLUSH_MR
)

// Command field masks. The command field of ib_uverbs_cmd_hdr contains the
// command number in the low byte and flags in the rest.
const (
	IB_USER_VERBS_CMD_COMMAND_MASK  = 0xff
	IB_USER_VERBS_CMD_FLAG_EXTENDED = 0x80000000
)

// IBUverbsAsyncEventDesc is struct ib_uverbs_async_event_desc.
//
// +marshal
type IBUverbsAsyncEventDesc struct {
	_         structs.HostLayout
	Element   uint64
	EventType uint32 // enum ib_event_type
	Reserved  uint32
}

// IBUverbsCompEventDesc is struct ib_uverbs_comp_event_desc.
//
// +marshal
type IBUverbsCompEventDesc struct {
	_        structs.HostLayout
	CQHandle uint64
}

// IBUverbsCQModerationCaps is struct ib_uverbs_cq_moderation_caps.
//
// +marshal
type IBUverbsCQModerationCaps struct {
	_                     structs.HostLayout
	MaxCQModerationCount  uint16
	MaxCQModerationPeriod uint16
	Reserved              uint32
}

// IBUverbsCmdHdr is struct ib_uverbs_cmd_hdr, the header preceding every
// write() command. InWords and OutWords give the length of the command
// block (including this header) and response buffer in 32-bit words.
//
// +marshal
type IBUverbsCmdHdr struct {
	_        structs.HostLayout
	Command  uint32
	InWords  uint16
	OutWords uint16
}

// IBUverbsExCmdHdr is struct ib_uverbs_ex_cmd_hdr, which follows
// IBUverbsCmdHdr for extended commands (IB_USER_VERBS_CMD_FLAG_EXTENDED).
//
// +marshal
type IBUverbsExCmdHdr struct {
	_                structs.HostLayout
	Response         uint64
	ProviderInWords  uint16
	ProviderOutWords uint16
	CmdHdrReserved   uint32
}

// IBUverbsGetContext is struct ib_uverbs_get_context.
//
// +marshal
type IBUverbsGetContext struct {
	_        structs.HostLayout
	Response uint64
}

// IBUverbsGetContextResp is struct ib_uverbs_get_context_resp.
//
// +marshal
type IBUverbsGetContextResp struct {
	_              structs.HostLayout
	AsyncFD        uint32
	NumCompVectors uint32
}

// IBUverbsQueryDevice is struct ib_uverbs_query_device.
//
// +marshal
type IBUverbsQueryDevice struct {
	_        structs.HostLayout
	Response uint64
}

// IBUverbsQueryDeviceResp is struct ib_uverbs_query_device_resp.
//
// +marshal
type IBUverbsQueryDeviceResp struct {
	_                     structs.HostLayout
	FWVer                 uint64
	NodeGUID              uint64 // big-endian
	SysImageGUID          uint64 // big-endian
	MaxMRSize             uint64
	PageSizeCap           uint64
	VendorID              uint32
	VendorPartID          uint32
	HWVer                 uint32
	MaxQP                 uint32
	MaxQPWR               uint32
	DeviceCapFlags        uint32
	MaxSGE                uint32
	MaxSGERd              uint32
	MaxCQ                 uint32
	MaxCQE                uint32
	MaxMR                 uint32
	MaxPD                 uint32
	MaxQPRdAtom           uint32
	MaxEERdAtom           uint32
	MaxResRdAtom          uint32
	MaxQPInitRdAtom       uint32
	MaxEEInitRdAtom       uint32
	AtomicCap             uint32
	MaxEE                 uint32
	MaxRDD                uint32
	MaxMW                 uint32
	MaxRawIPv6QP          uint32
	MaxRawEthyQP          uint32
	MaxMcastGrp           uint32
	MaxMcastQPAttach      uint32
	MaxTotalMcastQPAttach uint32
	MaxAH                 uint32
	MaxFMR                uint32
	MaxMapPerFMR          uint32
	MaxSRQ                uint32
	MaxSRQWR              uint32
	MaxSRQSGE             uint32
	MaxPkeys              uint16
	LocalCAAckDelay       uint8
	PhysPortCnt           uint8
	Reserved              [4]uint8
}

// IBUverbsExQueryDevice is struct ib_uverbs_ex_query_device.
//
// +marshal
type IBUverbsExQueryDevice struct {
	_        structs.HostLayout
	CompMask uint32
	Reserved uint32
}

// enum ib_uverbs_odp_general_cap_bits.
const (
	IB_UVERBS_ODP_SUPPORT = 1 << iota
	IB_UVERBS_ODP_SUPPORT_IMPLICIT
)

// enum ib_uverbs_odp_transport_cap_bits.
const (
	IB_UVERBS_ODP_SUPPORT_SEND = 1 << iota
	IB_UVERBS_ODP_SUPPORT_RECV
	IB_UVERBS_ODP_SUPPORT_WRITE
	IB_UVERBS_ODP_SUPPORT_READ
	IB_UVERBS_ODP_SUPPORT_ATOMIC
	IB_UVERBS_ODP_SUPPORT_SRQ_RECV
	IB_UVERBS_ODP_SUPPORT_FLUSH
	IB_UVERBS_ODP_SUPPORT_ATOMIC_WRITE
)

// IBUverbsODPCaps is struct ib_uverbs_odp_caps. RcOdpCaps, UcOdpCaps, and
// UdOdpCaps are the fields of the nested anonymous struct
// per_transport_caps.
//
// +marshal
type IBUverbsODPCaps struct {
	_           structs.HostLayout
	GeneralCaps uint64
	RcOdpCaps   uint32
	UcOdpCaps   uint32
	UdOdpCaps   uint32
	Reserved    uint32
}

// IBUverbsRSSCaps is struct ib_uverbs_rss_caps.
//
// +marshal
type IBUverbsRSSCaps struct {
	_                            structs.HostLayout
	SupportedQPTs                uint32
	MaxRWQIndirectionTables      uint32
	MaxRWQIndirectionTableSize   uint32
	Reserved                     uint32
}

// IBUverbsTMCaps is struct ib_uverbs_tm_caps.
//
// +marshal
type IBUverbsTMCaps struct {
	_              structs.HostLayout
	MaxRndvHdrSize uint32
	MaxNumTags     uint32
	Flags          uint32
	MaxOps         uint32
	MaxSGE         uint32
	Reserved       uint32
}

// IBUverbsExQueryDeviceResp is struct ib_uverbs_ex_query_device_resp.
//
// +marshal
type IBUverbsExQueryDeviceResp struct {
	_                structs.HostLayout
	Base             IBUverbsQueryDeviceResp
	CompMask         uint32
	ResponseLength   uint32
	ODPCaps          IBUverbsODPCaps
	TimestampMask    uint64
	HCACoreClock     uint64 // in kHz
	DeviceCapFlagsEx uint64
	RSSCaps          IBUverbsRSSCaps
	MaxWQTypeRQ      uint32
	RawPacketCaps    uint32
	TMCaps           IBUverbsTMCaps
	CQModerationCaps IBUverbsCQModerationCaps
	MaxDMSize        uint64
	XRCOdpCaps       uint32
	Reserved         uint32
}

// IBUverbsQueryPort is struct ib_uverbs_query_port.
//
// +marshal
type IBUverbsQueryPort struct {
	_        structs.HostLayout
	Response uint64
	PortNum  uint8
	Reserved [7]uint8
}

// IBUverbsAllocPD is struct ib_uverbs_alloc_pd.
//
// +marshal
type IBUverbsAllocPD struct {
	_        structs.HostLayout
	Response uint64
}

// IBUverbsAllocPDResp is struct ib_uverbs_alloc_pd_resp.
//
// +marshal
type IBUverbsAllocPDResp struct {
	_        structs.HostLayout
	PDHandle uint32
}

// IBUverbsDeallocPD is struct ib_uverbs_dealloc_pd.
//
// +marshal
type IBUverbsDeallocPD struct {
	_        structs.HostLayout
	PDHandle uint32
}

// IBUverbsOpenXRCD is struct ib_uverbs_open_xrcd.
//
// +marshal
type IBUverbsOpenXRCD struct {
	_        structs.HostLayout
	Response uint64
	FD       uint32
	OFlags   uint32
}

// IBUverbsOpenXRCDResp is struct ib_uverbs_open_xrcd_resp.
//
// +marshal
type IBUverbsOpenXRCDResp struct {
	_          structs.HostLayout
	XRCDHandle uint32
}

// IBUverbsCloseXRCD is struct ib_uverbs_close_xrcd.
//
// +marshal
type IBUverbsCloseXRCD struct {
	_          structs.HostLayout
	XRCDHandle uint32
}

// IBUverbsRegMR is struct ib_uverbs_reg_mr.
//
// +marshal
type IBUverbsRegMR struct {
	_           structs.HostLayout
	Response    uint64
	Start       uint64
	Length      uint64
	HCAVA       uint64
	PDHandle    uint32
	AccessFlags uint32
}

// IBUverbsRegMRResp is struct ib_uverbs_reg_mr_resp.
//
// +marshal
type IBUverbsRegMRResp struct {
	_        structs.HostLayout
	MRHandle uint32
	LKey     uint32
	RKey     uint32
}

// IBUverbsReregMR is struct ib_uverbs_rereg_mr.
//
// +marshal
type IBUverbsReregMR struct {
	_           structs.HostLayout
	Response    uint64
	MRHandle    uint32
	Flags       uint32
	Start       uint64
	Length      uint64
	HCAVA       uint64
	PDHandle    uint32
	AccessFlags uint32
}

// IBUverbsReregMRResp is struct ib_uverbs_rereg_mr_resp.
//
// +marshal
type IBUverbsReregMRResp struct {
	_    structs.HostLayout
	LKey uint32
	RKey uint32
}

// IBUverbsDeregMR is struct ib_uverbs_dereg_mr.
//
// +marshal
type IBUverbsDeregMR struct {
	_        structs.HostLayout
	MRHandle uint32
}

// IBUverbsAllocMW is struct ib_uverbs_alloc_mw.
//
// +marshal
type IBUverbsAllocMW struct {
	_        structs.HostLayout
	Response uint64
	PDHandle uint32
	MWType   uint8
	Reserved [3]uint8
}

// IBUverbsAllocMWResp is struct ib_uverbs_alloc_mw_resp.
//
// +marshal
type IBUverbsAllocMWResp struct {
	_        structs.HostLayout
	MWHandle uint32
	RKey     uint32
}

// IBUverbsDeallocMW is struct ib_uverbs_dealloc_mw.
//
// +marshal
type IBUverbsDeallocMW struct {
	_        structs.HostLayout
	MWHandle uint32
}

// IBUverbsCreateCompChannel is struct ib_uverbs_create_comp_channel.
//
// +marshal
type IBUverbsCreateCompChannel struct {
	_        structs.HostLayout
	Response uint64
}

// IBUverbsCreateCompChannelResp is struct
// ib_uverbs_create_comp_channel_resp.
//
// +marshal
type IBUverbsCreateCompChannelResp struct {
	_  structs.HostLayout
	FD uint32
}

// IBUverbsCreateCQ is struct ib_uverbs_create_cq.
//
// +marshal
type IBUverbsCreateCQ struct {
	_           structs.HostLayout
	Response    uint64
	UserHandle  uint64
	CQE         uint32
	CompVector  uint32
	CompChannel int32
	Reserved    uint32
}

// enum ib_uverbs_ex_create_cq_flags.
const (
	IB_UVERBS_CQ_FLAGS_TIMESTAMP_COMPLETION = 1 << iota
	IB_UVERBS_CQ_FLAGS_IGNORE_OVERRUN
)

// IBUverbsExCreateCQ is struct ib_uverbs_ex_create_cq.
//
// +marshal
type IBUverbsExCreateCQ struct {
	_           structs.HostLayout
	UserHandle  uint64
	CQE         uint32
	CompVector  uint32
	CompChannel int32
	CompMask    uint32
	Flags       uint32 // bitmask of ib_uverbs_ex_create_cq_flags
	Reserved    uint32
}

// IBUverbsCreateCQResp is struct ib_uverbs_create_cq_resp.
//
// +marshal
type IBUverbsCreateCQResp struct {
	_        structs.HostLayout
	CQHandle uint32
	CQE      uint32
}

// IBUverbsExCreateCQResp is struct ib_uverbs_ex_create_cq_resp.
//
// +marshal
type IBUverbsExCreateCQResp struct {
	_              structs.HostLayout
	Base           IBUverbsCreateCQResp
	CompMask       uint32
	ResponseLength uint32
}

// IBUverbsResizeCQ is struct ib_uverbs_resize_cq.
//
// +marshal
type IBUverbsResizeCQ struct {
	_        structs.HostLayout
	Response uint64
	CQHandle uint32
	CQE      uint32
}

// IBUverbsResizeCQResp is struct ib_uverbs_resize_cq_resp.
//
// +marshal
type IBUverbsResizeCQResp struct {
	_        structs.HostLayout
	CQE      uint32
	Reserved uint32
}

// IBUverbsPollCQ is struct ib_uverbs_poll_cq.
//
// +marshal
type IBUverbsPollCQ struct {
	_        structs.HostLayout
	Response uint64
	CQHandle uint32
	NE       uint32
}

// enum ib_uverbs_wc_opcode.
const (
	IB_UVERBS_WC_SEND = iota
	IB_UVERBS_WC_RDMA_WRITE
	IB_UVERBS_WC_RDMA_READ
	IB_UVERBS_WC_COMP_SWAP
	IB_UVERBS_WC_FETCH_ADD
	IB_UVERBS_WC_BIND_MW
	IB_UVERBS_WC_LOCAL_INV
	IB_UVERBS_WC_TSO
	IB_UVERBS_WC_FLUSH
	IB_UVERBS_WC_ATOMIC_WRITE
)

// IBUverbsWC is struct ib_uverbs_wc. Ex is a union of __be32 imm_data and
// __u32 invalidate_rkey.
//
// +marshal
type IBUverbsWC struct {
	_            structs.HostLayout
	WRID         uint64
	Status       uint32
	Opcode       uint32
	VendorErr    uint32
	ByteLen      uint32
	Ex           uint32
	QPNum        uint32
	SrcQP        uint32
	WCFlags      uint32
	PkeyIndex    uint16
	SLID         uint16
	SL           uint8
	DLIDPathBits uint8
	PortNum      uint8
	Reserved     uint8
}

// IBUverbsPollCQResp is struct ib_uverbs_poll_cq_resp. The response is
// followed by Count IBUverbsWC entries.
//
// +marshal
type IBUverbsPollCQResp struct {
	_        structs.HostLayout
	Count    uint32
	Reserved uint32
}

// IBUverbsReqNotifyCQ is struct ib_uverbs_req_notify_cq.
//
// +marshal
type IBUverbsReqNotifyCQ struct {
	_             structs.HostLayout
	CQHandle      uint32
	SolicitedOnly uint32
}

// IBUverbsDestroyCQ is struct ib_uverbs_destroy_cq.
//
// +marshal
type IBUverbsDestroyCQ struct {
	_        structs.HostLayout
	Response uint64
	CQHandle uint32
	Reserved uint32
}

// IBUverbsDestroyCQResp is struct ib_uverbs_destroy_cq_resp.
//
// +marshal
type IBUverbsDestroyCQResp struct {
	_                    structs.HostLayout
	CompEventsReported   uint32
	AsyncEventsReported  uint32
}

// IBUverbsQPAttr is struct ib_uverbs_qp_attr.
//
// +marshal
type IBUverbsQPAttr struct {
	_             structs.HostLayout
	QPAttrMask    uint32
	QPState       uint32
	CurQPState    uint32
	PathMTU       uint32
	PathMigState  uint32
	QKey          uint32
	RQPSN         uint32
	SQPSN         uint32
	DestQPNum     uint32
	QPAccessFlags uint32

	AHAttr    IBUverbsAHAttr
	AltAHAttr IBUverbsAHAttr

	// ib_qp_cap.
	MaxSendWR     uint32
	MaxRecvWR     uint32
	MaxSendSGE    uint32
	MaxRecvSGE    uint32
	MaxInlineData uint32

	PkeyIndex        uint16
	AltPkeyIndex     uint16
	EnSQDAsyncNotify uint8
	SQDraining       uint8
	MaxRdAtomic      uint8
	MaxDestRdAtomic  uint8
	MinRnrTimer      uint8
	PortNum          uint8
	Timeout          uint8
	RetryCnt         uint8
	RnrRetry         uint8
	AltPortNum       uint8
	AltTimeout       uint8
	Reserved         [5]uint8
}

// IBUverbsCreateQP is struct ib_uverbs_create_qp.
//
// +marshal
type IBUverbsCreateQP struct {
	_             structs.HostLayout
	Response      uint64
	UserHandle    uint64
	PDHandle      uint32
	SendCQHandle  uint32
	RecvCQHandle  uint32
	SRQHandle     uint32
	MaxSendWR     uint32
	MaxRecvWR     uint32
	MaxSendSGE    uint32
	MaxRecvSGE    uint32
	MaxInlineData uint32
	SQSigAll      uint8
	QPType        uint8
	IsSRQ         uint8
	Reserved      uint8
}

// enum ib_uverbs_create_qp_mask.
const (
	IB_UVERBS_CREATE_QP_MASK_IND_TABLE = 1 << iota
)

// IB_UVERBS_CREATE_QP_SUP_COMP_MASK is from the anonymous enum following
// enum ib_uverbs_create_qp_mask.
const IB_UVERBS_CREATE_QP_SUP_COMP_MASK = IB_UVERBS_CREATE_QP_MASK_IND_TABLE

// IBUverbsExCreateQP is struct ib_uverbs_ex_create_qp.
//
// +marshal
type IBUverbsExCreateQP struct {
	_               structs.HostLayout
	UserHandle      uint64
	PDHandle        uint32
	SendCQHandle    uint32
	RecvCQHandle    uint32
	SRQHandle       uint32
	MaxSendWR       uint32
	MaxRecvWR       uint32
	MaxSendSGE      uint32
	MaxRecvSGE      uint32
	MaxInlineData   uint32
	SQSigAll        uint8
	QPType          uint8
	IsSRQ           uint8
	Reserved        uint8
	CompMask        uint32
	CreateFlags     uint32
	RWQIndTblHandle uint32
	SourceQPN       uint32
}

// IBUverbsOpenQP is struct ib_uverbs_open_qp.
//
// +marshal
type IBUverbsOpenQP struct {
	_          structs.HostLayout
	Response   uint64
	UserHandle uint64
	PDHandle   uint32
	QPN        uint32
	QPType     uint8
	Reserved   [7]uint8
}

// IBUverbsCreateQPResp is struct ib_uverbs_create_qp_resp. Also used as
// the response for IB_USER_VERBS_CMD_OPEN_QP.
//
// +marshal
type IBUverbsCreateQPResp struct {
	_             structs.HostLayout
	QPHandle      uint32
	QPN           uint32
	MaxSendWR     uint32
	MaxRecvWR     uint32
	MaxSendSGE    uint32
	MaxRecvSGE    uint32
	MaxInlineData uint32
	Reserved      uint32
}

// IBUverbsExCreateQPResp is struct ib_uverbs_ex_create_qp_resp.
//
// +marshal
type IBUverbsExCreateQPResp struct {
	_              structs.HostLayout
	Base           IBUverbsCreateQPResp
	CompMask       uint32
	ResponseLength uint32
}

// IBUverbsQPDest is struct ib_uverbs_qp_dest.
//
// +marshal
type IBUverbsQPDest struct {
	_            structs.HostLayout
	DGID         [16]uint8
	FlowLabel    uint32
	DLID         uint16
	Reserved     uint16
	SGIDIndex    uint8
	HopLimit     uint8
	TrafficClass uint8
	SL           uint8
	SrcPathBits  uint8
	StaticRate   uint8
	IsGlobal     uint8
	PortNum      uint8
}

// IBUverbsQueryQP is struct ib_uverbs_query_qp.
//
// +marshal
type IBUverbsQueryQP struct {
	_        structs.HostLayout
	Response uint64
	QPHandle uint32
	AttrMask uint32
}

// IBUverbsQueryQPResp is struct ib_uverbs_query_qp_resp.
//
// +marshal
type IBUverbsQueryQPResp struct {
	_               structs.HostLayout
	Dest            IBUverbsQPDest
	AltDest         IBUverbsQPDest
	MaxSendWR       uint32
	MaxRecvWR       uint32
	MaxSendSGE      uint32
	MaxRecvSGE      uint32
	MaxInlineData   uint32
	QKey            uint32
	RQPSN           uint32
	SQPSN           uint32
	DestQPNum       uint32
	QPAccessFlags   uint32
	PkeyIndex       uint16
	AltPkeyIndex    uint16
	QPState         uint8
	CurQPState      uint8
	PathMTU         uint8
	PathMigState    uint8
	SQDraining      uint8
	MaxRdAtomic     uint8
	MaxDestRdAtomic uint8
	MinRnrTimer     uint8
	PortNum         uint8
	Timeout         uint8
	RetryCnt        uint8
	RnrRetry        uint8
	AltPortNum      uint8
	AltTimeout      uint8
	SQSigAll        uint8
	Reserved        [5]uint8
}

// IBUverbsModifyQP is struct ib_uverbs_modify_qp.
//
// +marshal
type IBUverbsModifyQP struct {
	_                structs.HostLayout
	Dest             IBUverbsQPDest
	AltDest          IBUverbsQPDest
	QPHandle         uint32
	AttrMask         uint32
	QKey             uint32
	RQPSN            uint32
	SQPSN            uint32
	DestQPNum        uint32
	QPAccessFlags    uint32
	PkeyIndex        uint16
	AltPkeyIndex     uint16
	QPState          uint8
	CurQPState       uint8
	PathMTU          uint8
	PathMigState     uint8
	EnSQDAsyncNotify uint8
	MaxRdAtomic      uint8
	MaxDestRdAtomic  uint8
	MinRnrTimer      uint8
	PortNum          uint8
	Timeout          uint8
	RetryCnt         uint8
	RnrRetry         uint8
	AltPortNum       uint8
	AltTimeout       uint8
	Reserved         [2]uint8
}

// IBUverbsExModifyQP is struct ib_uverbs_ex_modify_qp.
//
// +marshal
type IBUverbsExModifyQP struct {
	_         structs.HostLayout
	Base      IBUverbsModifyQP
	RateLimit uint32
	Reserved  uint32
}

// IBUverbsExModifyQPResp is struct ib_uverbs_ex_modify_qp_resp.
//
// +marshal
type IBUverbsExModifyQPResp struct {
	_              structs.HostLayout
	CompMask       uint32
	ResponseLength uint32
}

// IBUverbsDestroyQP is struct ib_uverbs_destroy_qp.
//
// +marshal
type IBUverbsDestroyQP struct {
	_        structs.HostLayout
	Response uint64
	QPHandle uint32
	Reserved uint32
}

// IBUverbsDestroyQPResp is struct ib_uverbs_destroy_qp_resp.
//
// +marshal
type IBUverbsDestroyQPResp struct {
	_               structs.HostLayout
	EventsReported  uint32
}

// IBUverbsSGE is struct ib_uverbs_sge.
//
// +marshal
type IBUverbsSGE struct {
	_      structs.HostLayout
	Addr   uint64
	Length uint32
	LKey   uint32
}

// enum ib_uverbs_wr_opcode.
const (
	IB_UVERBS_WR_RDMA_WRITE = iota
	IB_UVERBS_WR_RDMA_WRITE_WITH_IMM
	IB_UVERBS_WR_SEND
	IB_UVERBS_WR_SEND_WITH_IMM
	IB_UVERBS_WR_RDMA_READ
	IB_UVERBS_WR_ATOMIC_CMP_AND_SWP
	IB_UVERBS_WR_ATOMIC_FETCH_AND_ADD
	IB_UVERBS_WR_LOCAL_INV
	IB_UVERBS_WR_BIND_MW
	IB_UVERBS_WR_SEND_WITH_INV
	IB_UVERBS_WR_TSO
	IB_UVERBS_WR_RDMA_READ_WITH_INV
	IB_UVERBS_WR_MASKED_ATOMIC_CMP_AND_SWP
	IB_UVERBS_WR_MASKED_ATOMIC_FETCH_AND_ADD
	IB_UVERBS_WR_FLUSH
	IB_UVERBS_WR_ATOMIC_WRITE
)

// IBUverbsSendWR is struct ib_uverbs_send_wr. Ex is a union of __be32
// imm_data and __u32 invalidate_rkey. WR is a union of three anonymous
// structs, sized by the largest member (atomic):
//
//	rdma:   { remote_addr __u64, rkey __u32, reserved __u32 }
//	atomic: { remote_addr __u64, compare_add __u64, swap __u64,
//	          rkey __u32, reserved __u32 }
//	ud:     { ah __u32, remote_qpn __u32, remote_qkey __u32,
//	          reserved __u32 }
//
// +marshal
type IBUverbsSendWR struct {
	_         structs.HostLayout
	WRID      uint64
	NumSGE    uint32
	Opcode    uint32 // enum ib_uverbs_wr_opcode
	SendFlags uint32
	Ex        uint32
	WR        [32]byte
}

// IBUverbsPostSend is struct ib_uverbs_post_send. The command is followed
// by WRCount IBUverbsSendWR entries.
//
// +marshal
type IBUverbsPostSend struct {
	_        structs.HostLayout
	Response uint64
	QPHandle uint32
	WRCount  uint32
	SGECount uint32
	WQESize  uint32
}

// IBUverbsPostSendResp is struct ib_uverbs_post_send_resp.
//
// +marshal
type IBUverbsPostSendResp struct {
	_     structs.HostLayout
	BadWR uint32
}

// IBUverbsRecvWR is struct ib_uverbs_recv_wr.
//
// +marshal
type IBUverbsRecvWR struct {
	_        structs.HostLayout
	WRID     uint64
	NumSGE   uint32
	Reserved uint32
}

// IBUverbsPostRecv is struct ib_uverbs_post_recv. The command is followed
// by WRCount IBUverbsRecvWR entries.
//
// +marshal
type IBUverbsPostRecv struct {
	_        structs.HostLayout
	Response uint64
	QPHandle uint32
	WRCount  uint32
	SGECount uint32
	WQESize  uint32
}

// IBUverbsPostRecvResp is struct ib_uverbs_post_recv_resp.
//
// +marshal
type IBUverbsPostRecvResp struct {
	_     structs.HostLayout
	BadWR uint32
}

// IBUverbsPostSRQRecv is struct ib_uverbs_post_srq_recv. The command is
// followed by WRCount IBUverbsRecvWR entries.
//
// +marshal
type IBUverbsPostSRQRecv struct {
	_         structs.HostLayout
	Response  uint64
	SRQHandle uint32
	WRCount   uint32
	SGECount  uint32
	WQESize   uint32
}

// IBUverbsPostSRQRecvResp is struct ib_uverbs_post_srq_recv_resp.
//
// +marshal
type IBUverbsPostSRQRecvResp struct {
	_     structs.HostLayout
	BadWR uint32
}

// IBUverbsCreateAH is struct ib_uverbs_create_ah.
//
// +marshal
type IBUverbsCreateAH struct {
	_          structs.HostLayout
	Response   uint64
	UserHandle uint64
	PDHandle   uint32
	Reserved   uint32
	Attr       IBUverbsAHAttr
}

// IBUverbsCreateAHResp is struct ib_uverbs_create_ah_resp.
//
// +marshal
type IBUverbsCreateAHResp struct {
	_        structs.HostLayout
	AHHandle uint32
}

// IBUverbsDestroyAH is struct ib_uverbs_destroy_ah.
//
// +marshal
type IBUverbsDestroyAH struct {
	_        structs.HostLayout
	AHHandle uint32
}

// IBUverbsAttachMcast is struct ib_uverbs_attach_mcast.
//
// +marshal
type IBUverbsAttachMcast struct {
	_        structs.HostLayout
	GID      [16]uint8
	QPHandle uint32
	MLID     uint16
	Reserved uint16
}

// IBUverbsDetachMcast is struct ib_uverbs_detach_mcast.
//
// +marshal
type IBUverbsDetachMcast struct {
	_        structs.HostLayout
	GID      [16]uint8
	QPHandle uint32
	MLID     uint16
	Reserved uint16
}

// IBUverbsFlowSpecHdr is struct ib_uverbs_flow_spec_hdr. It is followed by
// the flow spec. In C the struct is 8-byte aligned due to the flexible
// array member __aligned_u64 flow_spec_data[0].
//
// +marshal
type IBUverbsFlowSpecHdr struct {
	_        structs.HostLayout
	Type     uint32
	Size     uint16
	Reserved uint16
}

// IBUverbsFlowEthFilter is struct ib_uverbs_flow_eth_filter.
//
// +marshal
type IBUverbsFlowEthFilter struct {
	_         structs.HostLayout
	DstMac    [6]uint8
	SrcMac    [6]uint8
	EtherType uint16 // big-endian
	VlanTag   uint16 // big-endian
}

// IBUverbsFlowSpecEth is struct ib_uverbs_flow_spec_eth. Type, Size, and
// Reserved are the members of the leading anonymous union with
// ib_uverbs_flow_spec_hdr, as in all following flow spec structs.
//
// +marshal
type IBUverbsFlowSpecEth struct {
	_        structs.HostLayout
	Type     uint32
	Size     uint16
	Reserved uint16
	Val      IBUverbsFlowEthFilter
	Mask     IBUverbsFlowEthFilter
}

// IBUverbsFlowIPv4Filter is struct ib_uverbs_flow_ipv4_filter.
//
// +marshal
type IBUverbsFlowIPv4Filter struct {
	_     structs.HostLayout
	SrcIP uint32 // big-endian
	DstIP uint32 // big-endian
	Proto uint8
	Tos   uint8
	TTL   uint8
	Flags uint8
}

// IBUverbsFlowSpecIPv4 is struct ib_uverbs_flow_spec_ipv4.
//
// +marshal
type IBUverbsFlowSpecIPv4 struct {
	_        structs.HostLayout
	Type     uint32
	Size     uint16
	Reserved uint16
	Val      IBUverbsFlowIPv4Filter
	Mask     IBUverbsFlowIPv4Filter
}

// IBUverbsFlowTCPUDPFilter is struct ib_uverbs_flow_tcp_udp_filter.
//
// +marshal
type IBUverbsFlowTCPUDPFilter struct {
	_       structs.HostLayout
	DstPort uint16 // big-endian
	SrcPort uint16 // big-endian
}

// IBUverbsFlowSpecTCPUDP is struct ib_uverbs_flow_spec_tcp_udp.
//
// +marshal
type IBUverbsFlowSpecTCPUDP struct {
	_        structs.HostLayout
	Type     uint32
	Size     uint16
	Reserved uint16
	Val      IBUverbsFlowTCPUDPFilter
	Mask     IBUverbsFlowTCPUDPFilter
}

// IBUverbsFlowIPv6Filter is struct ib_uverbs_flow_ipv6_filter.
//
// +marshal
type IBUverbsFlowIPv6Filter struct {
	_            structs.HostLayout
	SrcIP        [16]uint8
	DstIP        [16]uint8
	FlowLabel    uint32 // big-endian
	NextHdr      uint8
	TrafficClass uint8
	HopLimit     uint8
	Reserved     uint8
}

// IBUverbsFlowSpecIPv6 is struct ib_uverbs_flow_spec_ipv6.
//
// +marshal
type IBUverbsFlowSpecIPv6 struct {
	_        structs.HostLayout
	Type     uint32
	Size     uint16
	Reserved uint16
	Val      IBUverbsFlowIPv6Filter
	Mask     IBUverbsFlowIPv6Filter
}

// IBUverbsFlowSpecActionTag is struct ib_uverbs_flow_spec_action_tag.
//
// +marshal
type IBUverbsFlowSpecActionTag struct {
	_         structs.HostLayout
	Type      uint32
	Size      uint16
	Reserved  uint16
	TagID     uint32
	Reserved1 uint32
}

// IBUverbsFlowSpecActionDrop is struct ib_uverbs_flow_spec_action_drop.
//
// +marshal
type IBUverbsFlowSpecActionDrop struct {
	_        structs.HostLayout
	Type     uint32
	Size     uint16
	Reserved uint16
}

// IBUverbsFlowSpecActionHandle is struct
// ib_uverbs_flow_spec_action_handle.
//
// +marshal
type IBUverbsFlowSpecActionHandle struct {
	_         structs.HostLayout
	Type      uint32
	Size      uint16
	Reserved  uint16
	Handle    uint32
	Reserved1 uint32
}

// IBUverbsFlowSpecActionCount is struct ib_uverbs_flow_spec_action_count.
//
// +marshal
type IBUverbsFlowSpecActionCount struct {
	_         structs.HostLayout
	Type      uint32
	Size      uint16
	Reserved  uint16
	Handle    uint32
	Reserved1 uint32
}

// IBUverbsFlowTunnelFilter is struct ib_uverbs_flow_tunnel_filter.
//
// +marshal
type IBUverbsFlowTunnelFilter struct {
	_        structs.HostLayout
	TunnelID uint32 // big-endian
}

// IBUverbsFlowSpecTunnel is struct ib_uverbs_flow_spec_tunnel.
//
// +marshal
type IBUverbsFlowSpecTunnel struct {
	_        structs.HostLayout
	Type     uint32
	Size     uint16
	Reserved uint16
	Val      IBUverbsFlowTunnelFilter
	Mask     IBUverbsFlowTunnelFilter
}

// IBUverbsFlowSpecESPFilter is struct ib_uverbs_flow_spec_esp_filter.
//
// +marshal
type IBUverbsFlowSpecESPFilter struct {
	_   structs.HostLayout
	SPI uint32
	Seq uint32
}

// IBUverbsFlowSpecESP is struct ib_uverbs_flow_spec_esp.
//
// +marshal
type IBUverbsFlowSpecESP struct {
	_        structs.HostLayout
	Type     uint32
	Size     uint16
	Reserved uint16
	Val      IBUverbsFlowSpecESPFilter
	Mask     IBUverbsFlowSpecESPFilter
}

// IBUverbsFlowGREFilter is struct ib_uverbs_flow_gre_filter.
// CKsRes0Ver is bits 0-15 in offset 0 of a standard GRE header:
// bit 0 - C - checksum bit, bit 1 - reserved (0), bit 2 - key bit,
// bit 3 - sequence number bit, bits 4:12 - reserved (0),
// bits 13:15 - GRE version.
//
// +marshal
type IBUverbsFlowGREFilter struct {
	_          structs.HostLayout
	CKsRes0Ver uint16 // big-endian
	Protocol   uint16 // big-endian
	Key        uint32 // big-endian
}

// IBUverbsFlowSpecGRE is struct ib_uverbs_flow_spec_gre.
//
// +marshal
type IBUverbsFlowSpecGRE struct {
	_        structs.HostLayout
	Type     uint32
	Size     uint16
	Reserved uint16
	Val      IBUverbsFlowGREFilter
	Mask     IBUverbsFlowGREFilter
}

// IBUverbsFlowMPLSFilter is struct ib_uverbs_flow_mpls_filter.
// Label includes the entire MPLS label: bits 0:19 - label field,
// bits 20:22 - traffic class field, bit 23 - bottom of stack bit,
// bits 24:31 - ttl field.
//
// +marshal
type IBUverbsFlowMPLSFilter struct {
	_     structs.HostLayout
	Label uint32 // big-endian
}

// IBUverbsFlowSpecMPLS is struct ib_uverbs_flow_spec_mpls.
//
// +marshal
type IBUverbsFlowSpecMPLS struct {
	_        structs.HostLayout
	Type     uint32
	Size     uint16
	Reserved uint16
	Val      IBUverbsFlowMPLSFilter
	Mask     IBUverbsFlowMPLSFilter
}

// IBUverbsFlowAttr is struct ib_uverbs_flow_attr. The struct is followed
// by NumOfSpecs flow specs (struct ib_uverbs_flow_spec_xxx).
//
// +marshal
type IBUverbsFlowAttr struct {
	_          structs.HostLayout
	Type       uint32
	Size       uint16
	Priority   uint16
	NumOfSpecs uint8
	Reserved   [2]uint8
	Port       uint8
	Flags      uint32
}

// IBUverbsCreateFlow is struct ib_uverbs_create_flow.
//
// +marshal
type IBUverbsCreateFlow struct {
	_        structs.HostLayout
	CompMask uint32
	QPHandle uint32
	FlowAttr IBUverbsFlowAttr
}

// IBUverbsCreateFlowResp is struct ib_uverbs_create_flow_resp.
//
// +marshal
type IBUverbsCreateFlowResp struct {
	_          structs.HostLayout
	CompMask   uint32
	FlowHandle uint32
}

// IBUverbsDestroyFlow is struct ib_uverbs_destroy_flow.
//
// +marshal
type IBUverbsDestroyFlow struct {
	_          structs.HostLayout
	CompMask   uint32
	FlowHandle uint32
}

// IBUverbsCreateSRQ is struct ib_uverbs_create_srq.
//
// +marshal
type IBUverbsCreateSRQ struct {
	_          structs.HostLayout
	Response   uint64
	UserHandle uint64
	PDHandle   uint32
	MaxWR      uint32
	MaxSGE     uint32
	SRQLimit   uint32
}

// IBUverbsCreateXSRQ is struct ib_uverbs_create_xsrq.
//
// +marshal
type IBUverbsCreateXSRQ struct {
	_          structs.HostLayout
	Response   uint64
	UserHandle uint64
	SRQType    uint32
	PDHandle   uint32
	MaxWR      uint32
	MaxSGE     uint32
	SRQLimit   uint32
	MaxNumTags uint32
	XRCDHandle uint32
	CQHandle   uint32
}

// IBUverbsCreateSRQResp is struct ib_uverbs_create_srq_resp.
//
// +marshal
type IBUverbsCreateSRQResp struct {
	_         structs.HostLayout
	SRQHandle uint32
	MaxWR     uint32
	MaxSGE    uint32
	SRQN      uint32
}

// IBUverbsModifySRQ is struct ib_uverbs_modify_srq.
//
// +marshal
type IBUverbsModifySRQ struct {
	_         structs.HostLayout
	SRQHandle uint32
	AttrMask  uint32
	MaxWR     uint32
	SRQLimit  uint32
}

// IBUverbsQuerySRQ is struct ib_uverbs_query_srq.
//
// +marshal
type IBUverbsQuerySRQ struct {
	_         structs.HostLayout
	Response  uint64
	SRQHandle uint32
	Reserved  uint32
}

// IBUverbsQuerySRQResp is struct ib_uverbs_query_srq_resp.
//
// +marshal
type IBUverbsQuerySRQResp struct {
	_        structs.HostLayout
	MaxWR    uint32
	MaxSGE   uint32
	SRQLimit uint32
	Reserved uint32
}

// IBUverbsDestroySRQ is struct ib_uverbs_destroy_srq.
//
// +marshal
type IBUverbsDestroySRQ struct {
	_         structs.HostLayout
	Response  uint64
	SRQHandle uint32
	Reserved  uint32
}

// IBUverbsDestroySRQResp is struct ib_uverbs_destroy_srq_resp.
//
// +marshal
type IBUverbsDestroySRQResp struct {
	_              structs.HostLayout
	EventsReported uint32
}

// IBUverbsExCreateWQ is struct ib_uverbs_ex_create_wq.
//
// +marshal
type IBUverbsExCreateWQ struct {
	_           structs.HostLayout
	CompMask    uint32
	WQType      uint32
	UserHandle  uint64
	PDHandle    uint32
	CQHandle    uint32
	MaxWR       uint32
	MaxSGE      uint32
	CreateFlags uint32 // enum ib_wq_flags
	Reserved    uint32
}

// IBUverbsExCreateWQResp is struct ib_uverbs_ex_create_wq_resp.
//
// +marshal
type IBUverbsExCreateWQResp struct {
	_              structs.HostLayout
	CompMask       uint32
	ResponseLength uint32
	WQHandle       uint32
	MaxWR          uint32
	MaxSGE         uint32
	WQN            uint32
}

// IBUverbsExDestroyWQ is struct ib_uverbs_ex_destroy_wq.
//
// +marshal
type IBUverbsExDestroyWQ struct {
	_        structs.HostLayout
	CompMask uint32
	WQHandle uint32
}

// IBUverbsExDestroyWQResp is struct ib_uverbs_ex_destroy_wq_resp.
//
// +marshal
type IBUverbsExDestroyWQResp struct {
	_              structs.HostLayout
	CompMask       uint32
	ResponseLength uint32
	EventsReported uint32
	Reserved       uint32
}

// IBUverbsExModifyWQ is struct ib_uverbs_ex_modify_wq.
//
// +marshal
type IBUverbsExModifyWQ struct {
	_           structs.HostLayout
	AttrMask    uint32
	WQHandle    uint32
	WQState     uint32
	CurrWQState uint32
	Flags       uint32 // enum ib_wq_flags
	FlagsMask   uint32 // enum ib_wq_flags
}

// IB_USER_VERBS_MAX_LOG_IND_TBL_SIZE prevents memory allocation rather
// than max expected size.
const IB_USER_VERBS_MAX_LOG_IND_TBL_SIZE = 0x0d

// IBUverbsExCreateRWQIndTable is struct ib_uverbs_ex_create_rwq_ind_table.
// The command is followed by 1 << LogIndTblSize wq handles (__u32
// wq_handles[]).
//
// +marshal
type IBUverbsExCreateRWQIndTable struct {
	_             structs.HostLayout
	CompMask      uint32
	LogIndTblSize uint32
}

// IBUverbsExCreateRWQIndTableResp is struct
// ib_uverbs_ex_create_rwq_ind_table_resp.
//
// +marshal
type IBUverbsExCreateRWQIndTableResp struct {
	_              structs.HostLayout
	CompMask       uint32
	ResponseLength uint32
	IndTblHandle   uint32
	IndTblNum      uint32
}

// IBUverbsExDestroyRWQIndTable is struct
// ib_uverbs_ex_destroy_rwq_ind_table.
//
// +marshal
type IBUverbsExDestroyRWQIndTable struct {
	_            structs.HostLayout
	CompMask     uint32
	IndTblHandle uint32
}

// IBUverbsCQModeration is struct ib_uverbs_cq_moderation.
//
// +marshal
type IBUverbsCQModeration struct {
	_        structs.HostLayout
	CQCount  uint16
	CQPeriod uint16
}

// IBUverbsExModifyCQ is struct ib_uverbs_ex_modify_cq.
//
// +marshal
type IBUverbsExModifyCQ struct {
	_        structs.HostLayout
	CQHandle uint32
	AttrMask uint32
	Attr     IBUverbsCQModeration
	Reserved uint32
}

// IB_DEVICE_NAME_MAX is the maximum device name length.
const IB_DEVICE_NAME_MAX = 64

// enum ib_uverbs_device_cap_flags. Bits 9, 15, 16, 19, 22, 27, 30, 31, 32,
// 33, 35 and 37 may be set by old kernels and should not be used.
const (
	IB_UVERBS_DEVICE_RESIZE_MAX_WR         = 1 << 0
	IB_UVERBS_DEVICE_BAD_PKEY_CNTR         = 1 << 1
	IB_UVERBS_DEVICE_BAD_QKEY_CNTR         = 1 << 2
	IB_UVERBS_DEVICE_RAW_MULTI             = 1 << 3
	IB_UVERBS_DEVICE_AUTO_PATH_MIG         = 1 << 4
	IB_UVERBS_DEVICE_CHANGE_PHY_PORT       = 1 << 5
	IB_UVERBS_DEVICE_UD_AV_PORT_ENFORCE    = 1 << 6
	IB_UVERBS_DEVICE_CURR_QP_STATE_MOD     = 1 << 7
	IB_UVERBS_DEVICE_SHUTDOWN_PORT         = 1 << 8
	// IB_UVERBS_DEVICE_INIT_TYPE = 1 << 9 is not in use.
	IB_UVERBS_DEVICE_PORT_ACTIVE_EVENT     = 1 << 10
	IB_UVERBS_DEVICE_SYS_IMAGE_GUID        = 1 << 11
	IB_UVERBS_DEVICE_RC_RNR_NAK_GEN        = 1 << 12
	IB_UVERBS_DEVICE_SRQ_RESIZE            = 1 << 13
	IB_UVERBS_DEVICE_N_NOTIFY_CQ           = 1 << 14
	IB_UVERBS_DEVICE_MEM_WINDOW            = 1 << 17
	IB_UVERBS_DEVICE_UD_IP_CSUM            = 1 << 18
	IB_UVERBS_DEVICE_XRC                   = 1 << 20
	IB_UVERBS_DEVICE_MEM_MGT_EXTENSIONS    = 1 << 21
	IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2A    = 1 << 23
	IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2B    = 1 << 24
	IB_UVERBS_DEVICE_RC_IP_CSUM            = 1 << 25
	// Deprecated. Please use IB_UVERBS_RAW_PACKET_CAP_IP_CSUM.
	IB_UVERBS_DEVICE_RAW_IP_CSUM           = 1 << 26
	IB_UVERBS_DEVICE_MANAGED_FLOW_STEERING = 1 << 29
	// Deprecated. Please use IB_UVERBS_RAW_PACKET_CAP_SCATTER_FCS.
	IB_UVERBS_DEVICE_RAW_SCATTER_FCS       = 1 << 34
	IB_UVERBS_DEVICE_PCI_WRITE_END_PADDING = 1 << 36
	// Flush placement types.
	IB_UVERBS_DEVICE_FLUSH_GLOBAL     = 1 << 38
	IB_UVERBS_DEVICE_FLUSH_PERSISTENT = 1 << 39
	// Atomic write attributes.
	IB_UVERBS_DEVICE_ATOMIC_WRITE = 1 << 40
	// CoCo guest with DMA bounce buffering required.
	IB_UVERBS_DEVICE_CC_DMA_BOUNCE = 1 << 41
)

// enum ib_uverbs_raw_packet_caps.
const (
	IB_UVERBS_RAW_PACKET_CAP_CVLAN_STRIPPING = 1 << iota
	IB_UVERBS_RAW_PACKET_CAP_SCATTER_FCS
	IB_UVERBS_RAW_PACKET_CAP_IP_CSUM
	IB_UVERBS_RAW_PACKET_CAP_DELAY_DROP
)

// Struct size constants.
var (
	SizeofIBUverbsAsyncEventDesc          = uint32((*IBUverbsAsyncEventDesc)(nil).SizeBytes())
	SizeofIBUverbsCompEventDesc           = uint32((*IBUverbsCompEventDesc)(nil).SizeBytes())
	SizeofIBUverbsCQModerationCaps        = uint32((*IBUverbsCQModerationCaps)(nil).SizeBytes())
	SizeofIBUverbsCmdHdr                  = uint32((*IBUverbsCmdHdr)(nil).SizeBytes())
	SizeofIBUverbsExCmdHdr                = uint32((*IBUverbsExCmdHdr)(nil).SizeBytes())
	SizeofIBUverbsGetContext              = uint32((*IBUverbsGetContext)(nil).SizeBytes())
	SizeofIBUverbsGetContextResp          = uint32((*IBUverbsGetContextResp)(nil).SizeBytes())
	SizeofIBUverbsQueryDevice             = uint32((*IBUverbsQueryDevice)(nil).SizeBytes())
	SizeofIBUverbsQueryDeviceResp         = uint32((*IBUverbsQueryDeviceResp)(nil).SizeBytes())
	SizeofIBUverbsExQueryDevice           = uint32((*IBUverbsExQueryDevice)(nil).SizeBytes())
	SizeofIBUverbsODPCaps                 = uint32((*IBUverbsODPCaps)(nil).SizeBytes())
	SizeofIBUverbsRSSCaps                 = uint32((*IBUverbsRSSCaps)(nil).SizeBytes())
	SizeofIBUverbsTMCaps                  = uint32((*IBUverbsTMCaps)(nil).SizeBytes())
	SizeofIBUverbsExQueryDeviceResp       = uint32((*IBUverbsExQueryDeviceResp)(nil).SizeBytes())
	SizeofIBUverbsQueryPort               = uint32((*IBUverbsQueryPort)(nil).SizeBytes())
	SizeofIBUverbsAllocPD                 = uint32((*IBUverbsAllocPD)(nil).SizeBytes())
	SizeofIBUverbsAllocPDResp             = uint32((*IBUverbsAllocPDResp)(nil).SizeBytes())
	SizeofIBUverbsDeallocPD               = uint32((*IBUverbsDeallocPD)(nil).SizeBytes())
	SizeofIBUverbsOpenXRCD                = uint32((*IBUverbsOpenXRCD)(nil).SizeBytes())
	SizeofIBUverbsOpenXRCDResp            = uint32((*IBUverbsOpenXRCDResp)(nil).SizeBytes())
	SizeofIBUverbsCloseXRCD               = uint32((*IBUverbsCloseXRCD)(nil).SizeBytes())
	SizeofIBUverbsRegMR                   = uint32((*IBUverbsRegMR)(nil).SizeBytes())
	SizeofIBUverbsRegMRResp               = uint32((*IBUverbsRegMRResp)(nil).SizeBytes())
	SizeofIBUverbsReregMR                 = uint32((*IBUverbsReregMR)(nil).SizeBytes())
	SizeofIBUverbsReregMRResp             = uint32((*IBUverbsReregMRResp)(nil).SizeBytes())
	SizeofIBUverbsDeregMR                 = uint32((*IBUverbsDeregMR)(nil).SizeBytes())
	SizeofIBUverbsAllocMW                 = uint32((*IBUverbsAllocMW)(nil).SizeBytes())
	SizeofIBUverbsAllocMWResp             = uint32((*IBUverbsAllocMWResp)(nil).SizeBytes())
	SizeofIBUverbsDeallocMW               = uint32((*IBUverbsDeallocMW)(nil).SizeBytes())
	SizeofIBUverbsCreateCompChannel       = uint32((*IBUverbsCreateCompChannel)(nil).SizeBytes())
	SizeofIBUverbsCreateCompChannelResp   = uint32((*IBUverbsCreateCompChannelResp)(nil).SizeBytes())
	SizeofIBUverbsCreateCQ                = uint32((*IBUverbsCreateCQ)(nil).SizeBytes())
	SizeofIBUverbsExCreateCQ              = uint32((*IBUverbsExCreateCQ)(nil).SizeBytes())
	SizeofIBUverbsCreateCQResp            = uint32((*IBUverbsCreateCQResp)(nil).SizeBytes())
	SizeofIBUverbsExCreateCQResp          = uint32((*IBUverbsExCreateCQResp)(nil).SizeBytes())
	SizeofIBUverbsResizeCQ                = uint32((*IBUverbsResizeCQ)(nil).SizeBytes())
	SizeofIBUverbsResizeCQResp            = uint32((*IBUverbsResizeCQResp)(nil).SizeBytes())
	SizeofIBUverbsPollCQ                  = uint32((*IBUverbsPollCQ)(nil).SizeBytes())
	SizeofIBUverbsWC                      = uint32((*IBUverbsWC)(nil).SizeBytes())
	SizeofIBUverbsPollCQResp              = uint32((*IBUverbsPollCQResp)(nil).SizeBytes())
	SizeofIBUverbsReqNotifyCQ             = uint32((*IBUverbsReqNotifyCQ)(nil).SizeBytes())
	SizeofIBUverbsDestroyCQ               = uint32((*IBUverbsDestroyCQ)(nil).SizeBytes())
	SizeofIBUverbsDestroyCQResp           = uint32((*IBUverbsDestroyCQResp)(nil).SizeBytes())
	SizeofIBUverbsQPAttr                  = uint32((*IBUverbsQPAttr)(nil).SizeBytes())
	SizeofIBUverbsCreateQP                = uint32((*IBUverbsCreateQP)(nil).SizeBytes())
	SizeofIBUverbsExCreateQP              = uint32((*IBUverbsExCreateQP)(nil).SizeBytes())
	SizeofIBUverbsOpenQP                  = uint32((*IBUverbsOpenQP)(nil).SizeBytes())
	SizeofIBUverbsCreateQPResp            = uint32((*IBUverbsCreateQPResp)(nil).SizeBytes())
	SizeofIBUverbsExCreateQPResp          = uint32((*IBUverbsExCreateQPResp)(nil).SizeBytes())
	SizeofIBUverbsQPDest                  = uint32((*IBUverbsQPDest)(nil).SizeBytes())
	SizeofIBUverbsQueryQP                 = uint32((*IBUverbsQueryQP)(nil).SizeBytes())
	SizeofIBUverbsQueryQPResp             = uint32((*IBUverbsQueryQPResp)(nil).SizeBytes())
	SizeofIBUverbsModifyQP                = uint32((*IBUverbsModifyQP)(nil).SizeBytes())
	SizeofIBUverbsExModifyQP              = uint32((*IBUverbsExModifyQP)(nil).SizeBytes())
	SizeofIBUverbsExModifyQPResp          = uint32((*IBUverbsExModifyQPResp)(nil).SizeBytes())
	SizeofIBUverbsDestroyQP               = uint32((*IBUverbsDestroyQP)(nil).SizeBytes())
	SizeofIBUverbsDestroyQPResp           = uint32((*IBUverbsDestroyQPResp)(nil).SizeBytes())
	SizeofIBUverbsSGE                     = uint32((*IBUverbsSGE)(nil).SizeBytes())
	SizeofIBUverbsSendWR                  = uint32((*IBUverbsSendWR)(nil).SizeBytes())
	SizeofIBUverbsPostSend                = uint32((*IBUverbsPostSend)(nil).SizeBytes())
	SizeofIBUverbsPostSendResp            = uint32((*IBUverbsPostSendResp)(nil).SizeBytes())
	SizeofIBUverbsRecvWR                  = uint32((*IBUverbsRecvWR)(nil).SizeBytes())
	SizeofIBUverbsPostRecv                = uint32((*IBUverbsPostRecv)(nil).SizeBytes())
	SizeofIBUverbsPostRecvResp            = uint32((*IBUverbsPostRecvResp)(nil).SizeBytes())
	SizeofIBUverbsPostSRQRecv             = uint32((*IBUverbsPostSRQRecv)(nil).SizeBytes())
	SizeofIBUverbsPostSRQRecvResp         = uint32((*IBUverbsPostSRQRecvResp)(nil).SizeBytes())
	SizeofIBUverbsCreateAH                = uint32((*IBUverbsCreateAH)(nil).SizeBytes())
	SizeofIBUverbsCreateAHResp            = uint32((*IBUverbsCreateAHResp)(nil).SizeBytes())
	SizeofIBUverbsDestroyAH               = uint32((*IBUverbsDestroyAH)(nil).SizeBytes())
	SizeofIBUverbsAttachMcast             = uint32((*IBUverbsAttachMcast)(nil).SizeBytes())
	SizeofIBUverbsDetachMcast             = uint32((*IBUverbsDetachMcast)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecHdr             = uint32((*IBUverbsFlowSpecHdr)(nil).SizeBytes())
	SizeofIBUverbsFlowEthFilter           = uint32((*IBUverbsFlowEthFilter)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecEth             = uint32((*IBUverbsFlowSpecEth)(nil).SizeBytes())
	SizeofIBUverbsFlowIPv4Filter          = uint32((*IBUverbsFlowIPv4Filter)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecIPv4            = uint32((*IBUverbsFlowSpecIPv4)(nil).SizeBytes())
	SizeofIBUverbsFlowTCPUDPFilter        = uint32((*IBUverbsFlowTCPUDPFilter)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecTCPUDP          = uint32((*IBUverbsFlowSpecTCPUDP)(nil).SizeBytes())
	SizeofIBUverbsFlowIPv6Filter          = uint32((*IBUverbsFlowIPv6Filter)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecIPv6            = uint32((*IBUverbsFlowSpecIPv6)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecActionTag       = uint32((*IBUverbsFlowSpecActionTag)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecActionDrop      = uint32((*IBUverbsFlowSpecActionDrop)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecActionHandle    = uint32((*IBUverbsFlowSpecActionHandle)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecActionCount     = uint32((*IBUverbsFlowSpecActionCount)(nil).SizeBytes())
	SizeofIBUverbsFlowTunnelFilter        = uint32((*IBUverbsFlowTunnelFilter)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecTunnel          = uint32((*IBUverbsFlowSpecTunnel)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecESPFilter       = uint32((*IBUverbsFlowSpecESPFilter)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecESP             = uint32((*IBUverbsFlowSpecESP)(nil).SizeBytes())
	SizeofIBUverbsFlowGREFilter           = uint32((*IBUverbsFlowGREFilter)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecGRE             = uint32((*IBUverbsFlowSpecGRE)(nil).SizeBytes())
	SizeofIBUverbsFlowMPLSFilter          = uint32((*IBUverbsFlowMPLSFilter)(nil).SizeBytes())
	SizeofIBUverbsFlowSpecMPLS            = uint32((*IBUverbsFlowSpecMPLS)(nil).SizeBytes())
	SizeofIBUverbsFlowAttr                = uint32((*IBUverbsFlowAttr)(nil).SizeBytes())
	SizeofIBUverbsCreateFlow              = uint32((*IBUverbsCreateFlow)(nil).SizeBytes())
	SizeofIBUverbsCreateFlowResp          = uint32((*IBUverbsCreateFlowResp)(nil).SizeBytes())
	SizeofIBUverbsDestroyFlow             = uint32((*IBUverbsDestroyFlow)(nil).SizeBytes())
	SizeofIBUverbsCreateSRQ               = uint32((*IBUverbsCreateSRQ)(nil).SizeBytes())
	SizeofIBUverbsCreateXSRQ              = uint32((*IBUverbsCreateXSRQ)(nil).SizeBytes())
	SizeofIBUverbsCreateSRQResp           = uint32((*IBUverbsCreateSRQResp)(nil).SizeBytes())
	SizeofIBUverbsModifySRQ               = uint32((*IBUverbsModifySRQ)(nil).SizeBytes())
	SizeofIBUverbsQuerySRQ                = uint32((*IBUverbsQuerySRQ)(nil).SizeBytes())
	SizeofIBUverbsQuerySRQResp            = uint32((*IBUverbsQuerySRQResp)(nil).SizeBytes())
	SizeofIBUverbsDestroySRQ              = uint32((*IBUverbsDestroySRQ)(nil).SizeBytes())
	SizeofIBUverbsDestroySRQResp          = uint32((*IBUverbsDestroySRQResp)(nil).SizeBytes())
	SizeofIBUverbsExCreateWQ              = uint32((*IBUverbsExCreateWQ)(nil).SizeBytes())
	SizeofIBUverbsExCreateWQResp          = uint32((*IBUverbsExCreateWQResp)(nil).SizeBytes())
	SizeofIBUverbsExDestroyWQ             = uint32((*IBUverbsExDestroyWQ)(nil).SizeBytes())
	SizeofIBUverbsExDestroyWQResp         = uint32((*IBUverbsExDestroyWQResp)(nil).SizeBytes())
	SizeofIBUverbsExModifyWQ              = uint32((*IBUverbsExModifyWQ)(nil).SizeBytes())
	SizeofIBUverbsExCreateRWQIndTable     = uint32((*IBUverbsExCreateRWQIndTable)(nil).SizeBytes())
	SizeofIBUverbsExCreateRWQIndTableResp = uint32((*IBUverbsExCreateRWQIndTableResp)(nil).SizeBytes())
	SizeofIBUverbsExDestroyRWQIndTable    = uint32((*IBUverbsExDestroyRWQIndTable)(nil).SizeBytes())
	SizeofIBUverbsCQModeration            = uint32((*IBUverbsCQModeration)(nil).SizeBytes())
	SizeofIBUverbsExModifyCQ              = uint32((*IBUverbsExModifyCQ)(nil).SizeBytes())
)
