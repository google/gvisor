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

// Partial port of include/uapi/rdma/ib_user_mad.h: only the MAD agent
// registration structs referenced by the ioctls in rdma_user_ioctl.h.

// MAD registration flags.
const (
	IB_USER_MAD_USER_RMPP     = 1 << 0
	IB_USER_MAD_REG_FLAGS_CAP = IB_USER_MAD_USER_RMPP
)

// IBUserMadRegReq is struct ib_user_mad_reg_req, from
// include/uapi/rdma/ib_user_mad.h.
//
// MethodMask is declared in the header as
// packed_ulong method_mask[128 / (8 * sizeof(long))]: a 128-bit mask with
// 4-byte alignment regardless of word size, represented here as [4]uint32.
//
// +marshal
type IBUserMadRegReq struct {
	_                structs.HostLayout
	ID               uint32
	MethodMask       [4]uint32
	QPN              uint8
	MgmtClass        uint8
	MgmtClassVersion uint8
	OUI              [3]uint8
	RMPPVersion      uint8
	Pad0             [1]byte
}

// IBUserMadRegReq2 is struct ib_user_mad_reg_req2, from
// include/uapi/rdma/ib_user_mad.h.
//
// +marshal
type IBUserMadRegReq2 struct {
	_                structs.HostLayout
	ID               uint32
	QPN              uint32
	MgmtClass        uint8
	MgmtClassVersion uint8
	Res              uint16
	Flags            uint32
	MethodMask       [2]uint64
	OUI              uint32
	RMPPVersion      uint8
	Reserved         [3]uint8
}

// Struct size constants.
var (
	SizeofIBUserMadRegReq  = uint32((*IBUserMadRegReq)(nil).SizeBytes())
	SizeofIBUserMadRegReq2 = uint32((*IBUserMadRegReq2)(nil).SizeBytes())
)
