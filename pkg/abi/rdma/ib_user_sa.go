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

// Enums and structs from include/uapi/rdma/ib_user_sa.h. Fields declared
// __be16/__be32/__be64 in the header hold network-byte-order values.

// Path record flags.
const (
	IB_PATH_GMP             = 1 << 0
	IB_PATH_PRIMARY         = 1 << 1
	IB_PATH_ALTERNATE       = 1 << 2
	IB_PATH_OUTBOUND        = 1 << 3
	IB_PATH_INBOUND         = 1 << 4
	IB_PATH_INBOUND_REVERSE = 1 << 5
	IB_PATH_BIDIRECTIONAL   = IB_PATH_OUTBOUND | IB_PATH_INBOUND_REVERSE
)

// IBPathRecData is struct ib_path_rec_data, from
// include/uapi/rdma/ib_user_sa.h.
//
// +marshal
type IBPathRecData struct {
	_        structs.HostLayout
	Flags    uint32
	Reserved uint32
	PathRec  [16]uint32
}

// IBUserPathRec is struct ib_user_path_rec, from
// include/uapi/rdma/ib_user_sa.h.
//
// +marshal
type IBUserPathRec struct {
	_                      structs.HostLayout
	DGID                   [16]byte
	SGID                   [16]byte
	DLID                   uint16
	SLID                   uint16
	RawTraffic             uint32
	FlowLabel              uint32
	Reversible             uint32
	MTU                    uint32
	Pkey                   uint16
	HopLimit               uint8
	TrafficClass           uint8
	NumbPath               uint8
	SL                     uint8
	MTUSelector            uint8
	RateSelector           uint8
	Rate                   uint8
	PacketLifeTimeSelector uint8
	PacketLifeTime         uint8
	Preference             uint8
}

// IBUserServiceRec is struct ib_user_service_rec, from
// include/uapi/rdma/ib_user_sa.h.
//
// +marshal
type IBUserServiceRec struct {
	_        structs.HostLayout
	ID       uint64
	GID      [16]byte
	Pkey     uint16
	Reserved [2]uint8
	Lease    uint32
	Key      [16]byte
	Name     [64]byte
	Data8    [16]uint8
	Data16   [8]uint16
	Data32   [4]uint32
	Data64   [2]uint64
}

// Struct size constants.
var (
	SizeofIBPathRecData    = uint32((*IBPathRecData)(nil).SizeBytes())
	SizeofIBUserPathRec    = uint32((*IBUserPathRec)(nil).SizeBytes())
	SizeofIBUserServiceRec = uint32((*IBUserServiceRec)(nil).SizeBytes())
)
