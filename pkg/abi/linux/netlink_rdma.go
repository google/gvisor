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

// NETLINK_RDMA message clients and commands, from
// include/uapi/rdma/rdma_netlink.h.
const (
	RDMA_NL_NLDEV = 5

	RDMA_NLDEV_CMD_SYS_GET = 6
)

// RDMA_NLDEV_SYS_ATTR_* netlink attributes.
const (
	RDMA_NLDEV_SYS_ATTR_NETNS_MODE   = 66
	RDMA_NLDEV_SYS_ATTR_COPY_ON_FORK = 93
)

// RDMANLMsgType composes an NETLINK_RDMA message type from a client and op,
// matching RDMA_NL_GET_TYPE in include/uapi/rdma/rdma_netlink.h.
func RDMANLMsgType(client, op uint16) uint16 {
	return (client << 10) | op
}
