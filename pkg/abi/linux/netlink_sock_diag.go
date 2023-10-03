// Copyright 2023 The gVisor Authors.
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

// Netlink message types for NETLINK_SOCK_DIAG sockets, from uapi/linux/sock_diag.h.
const (
	SOCK_DIAG_BY_FAMILY = 20
	SOCK_DESTROY        = 21
)

// InetDiagSockid is struct inet_diag_sockid from uapi/linux/inet_diag.h.
//
// +marshal
type InetDiagSockid struct {
	SrcPort uint16
	DstPort uint16
	SrcAddr [4]uint32
	DstAddr [4]uint32
	Iface   uint32
	Cookie  [2]uint32
}

// InetDiagReqV2 is struct inet_diag_req_v2 from uapi/linux/inet_diag.h.
//
// +marshal
type InetDiagReqV2 struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	Pad      uint8
	States   uint32
	ID       InetDiagSockid
}

// InetDiagMsg is struct inet_diag_msg from uapi/linux/inet_diag.h.
//
// +marshal
type InetDiagMsg struct {
	Family  uint8
	State   uint8
	Timer   uint8
	Retrans uint8
	ID      InetDiagSockid
	Expires uint32
	RQueue  uint32
	WQueue  uint32
	UID     uint32
	Inode   uint32
}
