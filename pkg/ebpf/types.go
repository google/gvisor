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

package ebpf

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
)

type CgroupBpfAttachType uint

// Subset of attachment types that are valid for cgroup eBPF programs.
const (
	CGROUP_INET_INGRESS CgroupBpfAttachType = iota
	CGROUP_INET_EGRESS
	CGROUP_INET_SOCK_CREATE
	CGROUP_SOCK_OPS
	CGROUP_DEVICE
	CGROUP_INET4_BIND
	CGROUP_INET6_BIND
	CGROUP_INET4_CONNECT
	CGROUP_INET6_CONNECT
	CGROUP_UNIX_CONNECT
	CGROUP_INET4_POST_BIND
	CGROUP_INET6_POST_BIND
	CGROUP_UDP4_SENDMSG
	CGROUP_UDP6_SENDMSG
	CGROUP_UNIX_SENDMSG
	CGROUP_SYSCTL
	CGROUP_UDP4_RECVMSG
	CGROUP_UDP6_RECVMSG
	CGROUP_UNIX_RECVMSG
	CGROUP_GETSOCKOPT
	CGROUP_SETSOCKOPT
	CGROUP_INET4_GETPEERNAME
	CGROUP_INET6_GETPEERNAME
	CGROUP_UNIX_GETPEERNAME
	CGROUP_INET4_GETSOCKNAME
	CGROUP_INET6_GETSOCKNAME
	CGROUP_UNIX_GETSOCKNAME
	CGROUP_INET_SOCK_RELEASE
	MAX_CGROUP_BPF_ATTACH_TYPE
)

type BpfAttachType interface {
	isBpfAttachType()
}

func (c CgroupBpfAttachType) isBpfAttachType() {}

// TODO: finish this scaffolding

func ParseAttachmentType(b linux.BpfAttachType) BpfAttachType {
	switch b {
	case linux.BPF_CGROUP_DEVICE:
		return CGROUP_DEVICE
	}

	return nil
}
