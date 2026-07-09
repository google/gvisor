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

import "gvisor.dev/gvisor/pkg/abi/linux"

// Ioctl commands from include/uapi/rdma/rdma_user_ioctl.h.

// IB_IOCTL_MAGIC is the legacy name for RDMA_IOCTL_MAGIC, kept for user
// space applications which already use it.
const IB_IOCTL_MAGIC = RDMA_IOCTL_MAGIC

// Sizes of the hfi1 (Intel Omni-Path) structs from
// include/uapi/rdma/hfi/hfi1_ioctl.h, which are not otherwise ported since
// gVisor does not support hfi1 devices. The sizes only appear in the ioctl
// command encodings below.
const (
	sizeofHfi1UserInfo = 28  // struct hfi1_user_info
	sizeofHfi1CtxtInfo = 40  // struct hfi1_ctxt_info
	sizeofHfi1BaseInfo = 120 // struct hfi1_base_info
	sizeofHfi1TidInfo  = 24  // struct hfi1_tid_info
)

// MAD specific section.
var (
	IB_USER_MAD_REGISTER_AGENT   = linux.IOWR(RDMA_IOCTL_MAGIC, 0x01, SizeofIBUserMadRegReq)
	IB_USER_MAD_UNREGISTER_AGENT = linux.IOW(RDMA_IOCTL_MAGIC, 0x02, 4) // __u32
	IB_USER_MAD_ENABLE_PKEY      = linux.IO(RDMA_IOCTL_MAGIC, 0x03)
	IB_USER_MAD_REGISTER_AGENT2  = linux.IOWR(RDMA_IOCTL_MAGIC, 0x04, SizeofIBUserMadRegReq2)
)

// HFI specific section. Scalar argument sizes assume a 64-bit host
// (unsigned long is 8 bytes), matching the architectures gVisor supports.
var (
	// HFI1_IOCTL_ASSIGN_CTXT allocates HFI and context.
	HFI1_IOCTL_ASSIGN_CTXT = linux.IOWR(RDMA_IOCTL_MAGIC, 0xE1, sizeofHfi1UserInfo)
	// HFI1_IOCTL_CTXT_INFO finds out what resources we got.
	HFI1_IOCTL_CTXT_INFO = linux.IOW(RDMA_IOCTL_MAGIC, 0xE2, sizeofHfi1CtxtInfo)
	// HFI1_IOCTL_USER_INFO sets up userspace.
	HFI1_IOCTL_USER_INFO = linux.IOW(RDMA_IOCTL_MAGIC, 0xE3, sizeofHfi1BaseInfo)
	// HFI1_IOCTL_TID_UPDATE updates expected TID entries.
	HFI1_IOCTL_TID_UPDATE = linux.IOWR(RDMA_IOCTL_MAGIC, 0xE4, sizeofHfi1TidInfo)
	// HFI1_IOCTL_TID_FREE frees expected TID entries.
	HFI1_IOCTL_TID_FREE = linux.IOWR(RDMA_IOCTL_MAGIC, 0xE5, sizeofHfi1TidInfo)
	// HFI1_IOCTL_CREDIT_UPD forces an update of PIO credit.
	HFI1_IOCTL_CREDIT_UPD = linux.IO(RDMA_IOCTL_MAGIC, 0xE6)
	// HFI1_IOCTL_RECV_CTRL controls receipt of packets.
	HFI1_IOCTL_RECV_CTRL = linux.IOW(RDMA_IOCTL_MAGIC, 0xE8, 4) // int
	// HFI1_IOCTL_POLL_TYPE sets the kind of polling we want.
	HFI1_IOCTL_POLL_TYPE = linux.IOW(RDMA_IOCTL_MAGIC, 0xE9, 4) // int
	// HFI1_IOCTL_ACK_EVENT acks & clears user status bits.
	HFI1_IOCTL_ACK_EVENT = linux.IOW(RDMA_IOCTL_MAGIC, 0xEA, 8) // unsigned long
	// HFI1_IOCTL_SET_PKEY sets context's pkey.
	HFI1_IOCTL_SET_PKEY = linux.IOW(RDMA_IOCTL_MAGIC, 0xEB, 2) // __u16
	// HFI1_IOCTL_CTXT_RESET resets context's HW send context.
	HFI1_IOCTL_CTXT_RESET = linux.IO(RDMA_IOCTL_MAGIC, 0xEC)
	// HFI1_IOCTL_TID_INVAL_READ reads TID cache invalidations.
	HFI1_IOCTL_TID_INVAL_READ = linux.IOWR(RDMA_IOCTL_MAGIC, 0xED, sizeofHfi1TidInfo)
	// HFI1_IOCTL_GET_VERS gets the version of the user cdev.
	HFI1_IOCTL_GET_VERS = linux.IOR(RDMA_IOCTL_MAGIC, 0xEE, 4) // int
)
