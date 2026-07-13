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

package linux

// Netlink RDMA client IDs, from uapi/rdma/rdma_netlink.h.
const (
	RDMA_NL_IWCM  = 2
	RDMA_NL_RSVD  = 3
	RDMA_NL_LS    = 4
	RDMA_NL_NLDEV = 5
)

// RDMANetlinkClient returns the RDMA netlink client ID encoded in the top 6
// bits of the netlink message type, from uapi/rdma/rdma_netlink.h
// (RDMA_NL_GET_CLIENT).
func (hdr *NetlinkMessageHeader) RDMANetlinkClient() uint16 {
	return (hdr.Type >> 10) & 0x3f
}

// RDMANetlinkOp returns the RDMA netlink operation encoded in the bottom 10
// bits of the netlink message type, from uapi/rdma/rdma_netlink.h
// (RDMA_NL_GET_OP).
func (hdr *NetlinkMessageHeader) RDMANetlinkOp() uint16 {
	return hdr.Type & 0x3ff
}

// RDMANetlinkTypeFor returns the netlink message type for an RDMA_NL_NLDEV
// operation, from uapi/rdma/rdma_netlink.h (RDMA_NL_GET_TYPE).
func RDMANetlinkTypeFor(op uint16) uint16 {
	return (RDMA_NL_NLDEV << 10) | (op & 0x3ff)
}

// NLDEV commands, from uapi/rdma/rdma_netlink.h (enum rdma_nldev_command).
const (
	RDMA_NLDEV_CMD_UNSPEC      = 0
	RDMA_NLDEV_CMD_GET         = 1
	RDMA_NLDEV_CMD_SET         = 2
	RDMA_NLDEV_CMD_NEWLINK     = 3
	RDMA_NLDEV_CMD_DELLINK     = 4
	RDMA_NLDEV_CMD_PORT_GET    = 5
	RDMA_NLDEV_CMD_SYS_GET     = 6
	RDMA_NLDEV_CMD_SYS_SET     = 7
	RDMA_NLDEV_CMD_GET_CHARDEV = 15
)

// NLDEV attributes, from uapi/rdma/rdma_netlink.h (enum rdma_nldev_attr).
// Only the attributes used by rdma-core device discovery are defined; the
// enum is dense in Linux, so values here are explicit.
const (
	RDMA_NLDEV_ATTR_UNSPEC           = 0
	RDMA_NLDEV_ATTR_PAD              = 0  // Alias of UNSPEC, used for 64-bit alignment padding.
	RDMA_NLDEV_ATTR_DEV_INDEX        = 1  // u32
	RDMA_NLDEV_ATTR_DEV_NAME         = 2  // string
	RDMA_NLDEV_ATTR_PORT_INDEX       = 3  // u32; the device port count in RDMA_NLDEV_CMD_GET responses.
	RDMA_NLDEV_ATTR_NODE_GUID        = 6  // u64, raw big-endian GUID bytes
	RDMA_NLDEV_ATTR_DEV_NODE_TYPE    = 14 // u8
	RDMA_NLDEV_SYS_ATTR_NETNS_MODE   = 66 // u8
	RDMA_NLDEV_ATTR_CHARDEV_TYPE     = 69 // string
	RDMA_NLDEV_ATTR_CHARDEV_NAME     = 70 // string
	RDMA_NLDEV_ATTR_CHARDEV_ABI      = 71 // u64
	RDMA_NLDEV_ATTR_CHARDEV          = 72 // u64, huge_encode_dev() encoded dev_t
	RDMA_NLDEV_ATTR_UVERBS_DRIVER_ID = 73 // u32
	RDMA_NLDEV_SYS_ATTR_COPY_ON_FORK = 93 // u8
)

// RDMA driver IDs, from uapi/rdma/ib_user_ioctl_verbs.h
// (enum rdma_driver_id). Reported to userspace in
// RDMA_NLDEV_ATTR_UVERBS_DRIVER_ID so that libibverbs can select a provider
// library without PCI ID matching.
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
	RDMA_DRIVER_IRDMA      = 9
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
)

// HugeEncodeDev encodes a device major/minor pair in Linux's
// huge_encode_dev() format, used by RDMA_NLDEV_ATTR_CHARDEV. From
// include/linux/kdev_t.h:new_encode_dev.
func HugeEncodeDev(major, minor uint32) uint64 {
	return uint64(minor&0xff) | (uint64(major) << 8) | (uint64(minor&^0xff) << 12)
}
