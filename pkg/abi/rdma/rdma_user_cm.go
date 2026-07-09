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

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// Enums and structs from include/uapi/rdma/rdma_user_cm.h, the write()
// command ABI of /dev/infiniband/rdma_cm.

// ABI constants.
const (
	RDMA_USER_CM_ABI_VERSION = 4
	RDMA_MAX_PRIVATE_DATA    = 256
)

// rdma_ucm commands, from the anonymous enum in
// include/uapi/rdma/rdma_user_cm.h.
const (
	RDMA_USER_CM_CMD_CREATE_ID = iota
	RDMA_USER_CM_CMD_DESTROY_ID
	RDMA_USER_CM_CMD_BIND_IP
	RDMA_USER_CM_CMD_RESOLVE_IP
	RDMA_USER_CM_CMD_RESOLVE_ROUTE
	RDMA_USER_CM_CMD_QUERY_ROUTE
	RDMA_USER_CM_CMD_CONNECT
	RDMA_USER_CM_CMD_LISTEN
	RDMA_USER_CM_CMD_ACCEPT
	RDMA_USER_CM_CMD_REJECT
	RDMA_USER_CM_CMD_DISCONNECT
	RDMA_USER_CM_CMD_INIT_QP_ATTR
	RDMA_USER_CM_CMD_GET_EVENT
	RDMA_USER_CM_CMD_GET_OPTION
	RDMA_USER_CM_CMD_SET_OPTION
	RDMA_USER_CM_CMD_NOTIFY
	RDMA_USER_CM_CMD_JOIN_IP_MCAST
	RDMA_USER_CM_CMD_LEAVE_MCAST
	RDMA_USER_CM_CMD_MIGRATE_ID
	RDMA_USER_CM_CMD_QUERY
	RDMA_USER_CM_CMD_BIND
	RDMA_USER_CM_CMD_RESOLVE_ADDR
	RDMA_USER_CM_CMD_JOIN_MCAST
	RDMA_USER_CM_CMD_RESOLVE_IB_SERVICE
	RDMA_USER_CM_CMD_WRITE_CM_EVENT
)

// rdma_ucm_port_space. See IBTA Annex A11, services ID bytes 4 & 5.
const (
	RDMA_PS_IPOIB = 0x0002
	RDMA_PS_IB    = 0x013F
	RDMA_PS_TCP   = 0x0106
	RDMA_PS_UDP   = 0x0111
)

// rdma_ucm query options, from the anonymous enum in
// include/uapi/rdma/rdma_user_cm.h.
const (
	RDMA_USER_CM_QUERY_ADDR = iota
	RDMA_USER_CM_QUERY_PATH
	RDMA_USER_CM_QUERY_GID
	RDMA_USER_CM_QUERY_IB_SERVICE
)

// Multicast join flags.
const (
	RDMA_MC_JOIN_FLAG_FULLMEMBER = iota
	RDMA_MC_JOIN_FLAG_SENDONLY_FULLMEMBER
	RDMA_MC_JOIN_FLAG_RESERVED
)

// Option levels.
const (
	RDMA_OPTION_ID = iota
	RDMA_OPTION_IB
)

// Option details for RDMA_OPTION_ID.
const (
	RDMA_OPTION_ID_TOS = iota
	RDMA_OPTION_ID_REUSEADDR
	RDMA_OPTION_ID_AFONLY
	RDMA_OPTION_ID_ACK_TIMEOUT
)

// Option details for RDMA_OPTION_IB.
const (
	RDMA_OPTION_IB_PATH = 1
)

// IB service flags.
const (
	RDMA_USER_CM_IB_SERVICE_FLAG_ID   = 1 << 0
	RDMA_USER_CM_IB_SERVICE_FLAG_NAME = 1 << 1
)

// RDMA_USER_CM_IB_SERVICE_NAME_SIZE is the size of
// rdma_ucm_ib_service.service_name.
const RDMA_USER_CM_IB_SERVICE_NAME_SIZE = 64

// KernelSockAddrStorage is struct __kernel_sockaddr_storage, from
// include/uapi/linux/socket.h.
//
// +marshal
type KernelSockAddrStorage struct {
	_      structs.HostLayout
	Family uint16
	Data   [126]byte
}

// IBUverbsGlobalRoute is struct ib_uverbs_global_route, from
// include/uapi/rdma/ib_user_verbs.h. Needed by IBUverbsAHAttr.
//
// +marshal
type IBUverbsGlobalRoute struct {
	_            structs.HostLayout
	DGID         [16]byte
	FlowLabel    uint32
	SGIDIndex    uint8
	HopLimit     uint8
	TrafficClass uint8
	Reserved     uint8
}

// IBUverbsAHAttr is struct ib_uverbs_ah_attr, from
// include/uapi/rdma/ib_user_verbs.h. Needed by RdmaUcmUdParam.
//
// +marshal
type IBUverbsAHAttr struct {
	_           structs.HostLayout
	GRH         IBUverbsGlobalRoute
	DLID        uint16
	SL          uint8
	SrcPathBits uint8
	StaticRate  uint8
	IsGlobal    uint8
	PortNum     uint8
	Reserved    uint8
}

// RdmaUcmCmdHdr is struct rdma_ucm_cmd_hdr.
//
// +marshal
type RdmaUcmCmdHdr struct {
	_   structs.HostLayout
	Cmd uint32
	In  uint16
	Out uint16
}

// RdmaUcmCreateID is struct rdma_ucm_create_id.
//
// +marshal
type RdmaUcmCreateID struct {
	_        structs.HostLayout
	UID      uint64
	Response uint64
	PS       uint16 // enum rdma_ucm_port_space
	QPType   uint8
	Reserved [5]uint8
}

// RdmaUcmCreateIDResp is struct rdma_ucm_create_id_resp.
//
// +marshal
type RdmaUcmCreateIDResp struct {
	_  structs.HostLayout
	ID uint32
}

// RdmaUcmDestroyID is struct rdma_ucm_destroy_id.
//
// +marshal
type RdmaUcmDestroyID struct {
	_        structs.HostLayout
	Response uint64
	ID       uint32
	Reserved uint32
}

// RdmaUcmDestroyIDResp is struct rdma_ucm_destroy_id_resp.
//
// +marshal
type RdmaUcmDestroyIDResp struct {
	_              structs.HostLayout
	EventsReported uint32
}

// RdmaUcmBindIP is struct rdma_ucm_bind_ip.
//
// +marshal
type RdmaUcmBindIP struct {
	_        structs.HostLayout
	Response uint64
	Addr     linux.SockAddrInet6
	ID       uint32
}

// RdmaUcmBind is struct rdma_ucm_bind.
//
// +marshal
type RdmaUcmBind struct {
	_        structs.HostLayout
	ID       uint32
	AddrSize uint16
	Reserved uint16
	Addr     KernelSockAddrStorage
}

// RdmaUcmResolveIP is struct rdma_ucm_resolve_ip.
//
// +marshal
type RdmaUcmResolveIP struct {
	_         structs.HostLayout
	SrcAddr   linux.SockAddrInet6
	DstAddr   linux.SockAddrInet6
	ID        uint32
	TimeoutMs uint32
}

// RdmaUcmResolveAddr is struct rdma_ucm_resolve_addr.
//
// +marshal
type RdmaUcmResolveAddr struct {
	_         structs.HostLayout
	ID        uint32
	TimeoutMs uint32
	SrcSize   uint16
	DstSize   uint16
	Reserved  uint32
	SrcAddr   KernelSockAddrStorage
	DstAddr   KernelSockAddrStorage
}

// RdmaUcmResolveRoute is struct rdma_ucm_resolve_route.
//
// +marshal
type RdmaUcmResolveRoute struct {
	_         structs.HostLayout
	ID        uint32
	TimeoutMs uint32
}

// RdmaUcmQuery is struct rdma_ucm_query.
//
// +marshal
type RdmaUcmQuery struct {
	_        structs.HostLayout
	Response uint64
	ID       uint32
	Option   uint32
}

// RdmaUcmQueryRouteResp is struct rdma_ucm_query_route_resp.
//
// +marshal
type RdmaUcmQueryRouteResp struct {
	_          structs.HostLayout
	NodeGUID   uint64
	IBRoute    [2]IBUserPathRec
	SrcAddr    linux.SockAddrInet6
	DstAddr    linux.SockAddrInet6
	NumPaths   uint32
	PortNum    uint8
	Reserved   [3]uint8
	IbdevIndex uint32
	Reserved1  uint32
}

// RdmaUcmQueryAddrResp is struct rdma_ucm_query_addr_resp.
//
// +marshal
type RdmaUcmQueryAddrResp struct {
	_          structs.HostLayout
	NodeGUID   uint64
	PortNum    uint8
	Reserved   uint8
	Pkey       uint16
	SrcSize    uint16
	DstSize    uint16
	SrcAddr    KernelSockAddrStorage
	DstAddr    KernelSockAddrStorage
	IbdevIndex uint32
	Reserved1  uint32
}

// RdmaUcmQueryPathResp is the fixed portion of struct
// rdma_ucm_query_path_resp. The flexible array member path_data[] (struct
// ib_path_rec_data) is omitted and handled separately.
//
// +marshal
type RdmaUcmQueryPathResp struct {
	_        structs.HostLayout
	NumPaths uint32
	Reserved uint32
}

// RdmaUcmQueryIBServiceResp is the fixed portion of struct
// rdma_ucm_query_ib_service_resp. The flexible array member recs[] (struct
// ib_user_service_rec) is omitted and handled separately.
//
// +marshal
type RdmaUcmQueryIBServiceResp struct {
	_              structs.HostLayout
	NumServiceRecs uint32
	Reserved       uint32
}

// RdmaUcmConnParam is struct rdma_ucm_conn_param.
//
// +marshal
type RdmaUcmConnParam struct {
	_                  structs.HostLayout
	QPNum              uint32
	QKey               uint32
	PrivateData        [RDMA_MAX_PRIVATE_DATA]uint8
	PrivateDataLen     uint8
	SRQ                uint8
	ResponderResources uint8
	InitiatorDepth     uint8
	FlowControl        uint8
	RetryCount         uint8
	RnrRetryCount      uint8
	Valid              uint8
}

// RdmaUcmUdParam is struct rdma_ucm_ud_param.
//
// +marshal
type RdmaUcmUdParam struct {
	_              structs.HostLayout
	QPNum          uint32
	QKey           uint32
	AHAttr         IBUverbsAHAttr
	PrivateData    [RDMA_MAX_PRIVATE_DATA]uint8
	PrivateDataLen uint8
	Reserved       [7]uint8
}

// RdmaUcmEce is struct rdma_ucm_ece.
//
// +marshal
type RdmaUcmEce struct {
	_        structs.HostLayout
	VendorID uint32
	AttrMod  uint32
}

// RdmaUcmConnect is struct rdma_ucm_connect.
//
// +marshal
type RdmaUcmConnect struct {
	_         structs.HostLayout
	ConnParam RdmaUcmConnParam
	ID        uint32
	Reserved  uint32
	Ece       RdmaUcmEce
}

// RdmaUcmListen is struct rdma_ucm_listen.
//
// +marshal
type RdmaUcmListen struct {
	_       structs.HostLayout
	ID      uint32
	Backlog uint32
}

// RdmaUcmAccept is struct rdma_ucm_accept.
//
// +marshal
type RdmaUcmAccept struct {
	_         structs.HostLayout
	UID       uint64
	ConnParam RdmaUcmConnParam
	ID        uint32
	Reserved  uint32
	Ece       RdmaUcmEce
}

// RdmaUcmReject is struct rdma_ucm_reject.
//
// +marshal
type RdmaUcmReject struct {
	_              structs.HostLayout
	ID             uint32
	PrivateDataLen uint8
	Reason         uint8
	Reserved       [2]uint8
	PrivateData    [RDMA_MAX_PRIVATE_DATA]uint8
}

// RdmaUcmDisconnect is struct rdma_ucm_disconnect.
//
// +marshal
type RdmaUcmDisconnect struct {
	_  structs.HostLayout
	ID uint32
}

// RdmaUcmInitQPAttr is struct rdma_ucm_init_qp_attr.
//
// +marshal
type RdmaUcmInitQPAttr struct {
	_        structs.HostLayout
	Response uint64
	ID       uint32
	QPState  uint32
}

// RdmaUcmNotify is struct rdma_ucm_notify.
//
// +marshal
type RdmaUcmNotify struct {
	_     structs.HostLayout
	ID    uint32
	Event uint32
}

// RdmaUcmJoinIPMcast is struct rdma_ucm_join_ip_mcast.
//
// +marshal
type RdmaUcmJoinIPMcast struct {
	_        structs.HostLayout
	Response uint64 // rdma_ucm_create_id_resp
	UID      uint64
	Addr     linux.SockAddrInet6
	ID       uint32
}

// RdmaUcmJoinMcast is struct rdma_ucm_join_mcast.
//
// +marshal
type RdmaUcmJoinMcast struct {
	_         structs.HostLayout
	Response  uint64 // rdma_ucm_create_id_resp
	UID       uint64
	ID        uint32
	AddrSize  uint16
	JoinFlags uint16
	Addr      KernelSockAddrStorage
}

// RdmaUcmGetEvent is struct rdma_ucm_get_event.
//
// +marshal
type RdmaUcmGetEvent struct {
	_        structs.HostLayout
	Response uint64
}

// RdmaUcmEventResp is struct rdma_ucm_event_resp.
//
// +marshal
type RdmaUcmEventResp struct {
	_      structs.HostLayout
	UID    uint64
	ID     uint32
	Event  uint32
	Status uint32
	// Param is a union of struct rdma_ucm_conn_param, struct
	// rdma_ucm_ud_param, and __u32 arg32[2]; its size is that of the
	// largest member, struct rdma_ucm_ud_param. Note that it is 4-byte
	// but not 8-byte aligned within this struct.
	Param    [304]byte
	Reserved uint32
	Ece      RdmaUcmEce
}

// RdmaUcmSetOption is struct rdma_ucm_set_option.
//
// +marshal
type RdmaUcmSetOption struct {
	_       structs.HostLayout
	Optval  uint64
	ID      uint32
	Level   uint32
	Optname uint32
	Optlen  uint32
}

// RdmaUcmMigrateID is struct rdma_ucm_migrate_id.
//
// +marshal
type RdmaUcmMigrateID struct {
	_        structs.HostLayout
	Response uint64
	ID       uint32
	FD       uint32
}

// RdmaUcmMigrateResp is struct rdma_ucm_migrate_resp.
//
// +marshal
type RdmaUcmMigrateResp struct {
	_              structs.HostLayout
	EventsReported uint32
}

// RdmaUcmIBService is struct rdma_ucm_ib_service.
//
// +marshal
type RdmaUcmIBService struct {
	_           structs.HostLayout
	ServiceID   uint64
	ServiceName [RDMA_USER_CM_IB_SERVICE_NAME_SIZE]uint8
	Flags       uint32
	Reserved    uint32
}

// RdmaUcmResolveIBService is struct rdma_ucm_resolve_ib_service.
//
// +marshal
type RdmaUcmResolveIBService struct {
	_        structs.HostLayout
	ID       uint32
	Reserved uint32
	IBS      RdmaUcmIBService
}

// RdmaUcmWriteCmEvent is struct rdma_ucm_write_cm_event.
//
// +marshal
type RdmaUcmWriteCmEvent struct {
	_        structs.HostLayout
	ID       uint32
	Reserved uint32
	Event    uint32
	Status   uint32
	// Param is a union of struct rdma_ucm_conn_param, struct
	// rdma_ucm_ud_param, and __u64 arg; its size is that of the largest
	// member, struct rdma_ucm_ud_param.
	Param [304]byte
}

// Struct size constants.
var (
	SizeofKernelSockAddrStorage     = uint32((*KernelSockAddrStorage)(nil).SizeBytes())
	SizeofIBUverbsGlobalRoute       = uint32((*IBUverbsGlobalRoute)(nil).SizeBytes())
	SizeofIBUverbsAHAttr            = uint32((*IBUverbsAHAttr)(nil).SizeBytes())
	SizeofRdmaUcmCmdHdr             = uint32((*RdmaUcmCmdHdr)(nil).SizeBytes())
	SizeofRdmaUcmCreateID           = uint32((*RdmaUcmCreateID)(nil).SizeBytes())
	SizeofRdmaUcmCreateIDResp       = uint32((*RdmaUcmCreateIDResp)(nil).SizeBytes())
	SizeofRdmaUcmDestroyID          = uint32((*RdmaUcmDestroyID)(nil).SizeBytes())
	SizeofRdmaUcmDestroyIDResp      = uint32((*RdmaUcmDestroyIDResp)(nil).SizeBytes())
	SizeofRdmaUcmBindIP             = uint32((*RdmaUcmBindIP)(nil).SizeBytes())
	SizeofRdmaUcmBind               = uint32((*RdmaUcmBind)(nil).SizeBytes())
	SizeofRdmaUcmResolveIP          = uint32((*RdmaUcmResolveIP)(nil).SizeBytes())
	SizeofRdmaUcmResolveAddr        = uint32((*RdmaUcmResolveAddr)(nil).SizeBytes())
	SizeofRdmaUcmResolveRoute       = uint32((*RdmaUcmResolveRoute)(nil).SizeBytes())
	SizeofRdmaUcmQuery              = uint32((*RdmaUcmQuery)(nil).SizeBytes())
	SizeofRdmaUcmQueryRouteResp     = uint32((*RdmaUcmQueryRouteResp)(nil).SizeBytes())
	SizeofRdmaUcmQueryAddrResp      = uint32((*RdmaUcmQueryAddrResp)(nil).SizeBytes())
	SizeofRdmaUcmQueryPathResp      = uint32((*RdmaUcmQueryPathResp)(nil).SizeBytes())
	SizeofRdmaUcmQueryIBServiceResp = uint32((*RdmaUcmQueryIBServiceResp)(nil).SizeBytes())
	SizeofRdmaUcmConnParam          = uint32((*RdmaUcmConnParam)(nil).SizeBytes())
	SizeofRdmaUcmUdParam            = uint32((*RdmaUcmUdParam)(nil).SizeBytes())
	SizeofRdmaUcmEce                = uint32((*RdmaUcmEce)(nil).SizeBytes())
	SizeofRdmaUcmConnect            = uint32((*RdmaUcmConnect)(nil).SizeBytes())
	SizeofRdmaUcmListen             = uint32((*RdmaUcmListen)(nil).SizeBytes())
	SizeofRdmaUcmAccept             = uint32((*RdmaUcmAccept)(nil).SizeBytes())
	SizeofRdmaUcmReject             = uint32((*RdmaUcmReject)(nil).SizeBytes())
	SizeofRdmaUcmDisconnect         = uint32((*RdmaUcmDisconnect)(nil).SizeBytes())
	SizeofRdmaUcmInitQPAttr         = uint32((*RdmaUcmInitQPAttr)(nil).SizeBytes())
	SizeofRdmaUcmNotify             = uint32((*RdmaUcmNotify)(nil).SizeBytes())
	SizeofRdmaUcmJoinIPMcast        = uint32((*RdmaUcmJoinIPMcast)(nil).SizeBytes())
	SizeofRdmaUcmJoinMcast          = uint32((*RdmaUcmJoinMcast)(nil).SizeBytes())
	SizeofRdmaUcmGetEvent           = uint32((*RdmaUcmGetEvent)(nil).SizeBytes())
	SizeofRdmaUcmEventResp          = uint32((*RdmaUcmEventResp)(nil).SizeBytes())
	SizeofRdmaUcmSetOption          = uint32((*RdmaUcmSetOption)(nil).SizeBytes())
	SizeofRdmaUcmMigrateID          = uint32((*RdmaUcmMigrateID)(nil).SizeBytes())
	SizeofRdmaUcmMigrateResp        = uint32((*RdmaUcmMigrateResp)(nil).SizeBytes())
	SizeofRdmaUcmIBService          = uint32((*RdmaUcmIBService)(nil).SizeBytes())
	SizeofRdmaUcmResolveIBService   = uint32((*RdmaUcmResolveIBService)(nil).SizeBytes())
	SizeofRdmaUcmWriteCmEvent       = uint32((*RdmaUcmWriteCmEvent)(nil).SizeBytes())
)
