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

// CgroupAttachType is an attachment type that is valid for a cgroup eBPF program.
type CgroupAttachType uint

// Subset of attachment types that are valid for cgroup eBPF programs.
const (
	CGROUP_INET_INGRESS CgroupAttachType = iota
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
	MAX_CGROUP_BPF_ATTACH_TYPE uint = iota
)

// AttachType is an interface implemented by each subsystem's subset of valid
// attachment types.
type AttachType interface {
	// MatchingProgType returns the program type that expects to be attached
	// at this attachment type.
	//
	// Analogous to kernel/bpf/syscall.c:attach_type_to_prog_type() in Linux.
	MatchingProgType() linux.BPFProgramType
}

// MatchingProgType implements AttachType.MatchingProgType.
func (c CgroupAttachType) MatchingProgType() linux.BPFProgramType {
	switch c {
	case CGROUP_INET_INGRESS, CGROUP_INET_EGRESS:
		return linux.BPF_PROG_TYPE_CGROUP_SKB
	case CGROUP_INET_SOCK_CREATE, CGROUP_INET_SOCK_RELEASE, CGROUP_INET4_POST_BIND, CGROUP_INET6_POST_BIND:
		return linux.BPF_PROG_TYPE_CGROUP_SOCK
	case CGROUP_INET4_BIND, CGROUP_INET6_BIND, CGROUP_INET4_CONNECT, CGROUP_INET6_CONNECT, CGROUP_UNIX_CONNECT, CGROUP_INET4_GETPEERNAME, CGROUP_INET6_GETPEERNAME, CGROUP_UNIX_GETPEERNAME, CGROUP_INET4_GETSOCKNAME, CGROUP_INET6_GETSOCKNAME, CGROUP_UNIX_GETSOCKNAME, CGROUP_UDP4_SENDMSG, CGROUP_UDP6_SENDMSG, CGROUP_UNIX_SENDMSG, CGROUP_UDP4_RECVMSG, CGROUP_UDP6_RECVMSG, CGROUP_UNIX_RECVMSG:
		return linux.BPF_PROG_TYPE_CGROUP_SOCK_ADDR
	case CGROUP_SOCK_OPS:
		return linux.BPF_PROG_TYPE_SOCK_OPS
	case CGROUP_DEVICE:
		return linux.BPF_PROG_TYPE_CGROUP_DEVICE
	case CGROUP_SYSCTL:
		return linux.BPF_PROG_TYPE_CGROUP_SYSCTL
	case CGROUP_GETSOCKOPT, CGROUP_SETSOCKOPT:
		return linux.BPF_PROG_TYPE_CGROUP_SOCKOPT
	default:
		return linux.BPF_PROG_TYPE_UNSPEC
	}
}

// ParseAttachmentType takes a raw linux.BPFAttachType provided by userspace and converts
// it an appropriately-typed BPFAttachType object depending on which subsystem it is to be
// attached to.
//
// ParseAttachmentType returns nil if the attachment type is unknown or unsupported.
func ParseAttachmentType(b linux.BPFAttachType) AttachType {
	switch b {
	case linux.BPF_CGROUP_INET_INGRESS:
		return CGROUP_INET_INGRESS
	case linux.BPF_CGROUP_INET_EGRESS:
		return CGROUP_INET_EGRESS
	case linux.BPF_CGROUP_INET_SOCK_CREATE:
		return CGROUP_INET_SOCK_CREATE
	case linux.BPF_CGROUP_SOCK_OPS:
		return CGROUP_SOCK_OPS
	case linux.BPF_CGROUP_DEVICE:
		return CGROUP_DEVICE
	case linux.BPF_CGROUP_INET4_BIND:
		return CGROUP_INET4_BIND
	case linux.BPF_CGROUP_INET6_BIND:
		return CGROUP_INET6_BIND
	case linux.BPF_CGROUP_INET4_CONNECT:
		return CGROUP_INET4_CONNECT
	case linux.BPF_CGROUP_INET6_CONNECT:
		return CGROUP_INET6_CONNECT
	case linux.BPF_CGROUP_UNIX_CONNECT:
		return CGROUP_UNIX_CONNECT
	case linux.BPF_CGROUP_INET4_POST_BIND:
		return CGROUP_INET4_POST_BIND
	case linux.BPF_CGROUP_INET6_POST_BIND:
		return CGROUP_INET6_POST_BIND
	case linux.BPF_CGROUP_UDP4_SENDMSG:
		return CGROUP_UDP4_SENDMSG
	case linux.BPF_CGROUP_UDP6_SENDMSG:
		return CGROUP_UDP6_SENDMSG
	case linux.BPF_CGROUP_UNIX_SENDMSG:
		return CGROUP_UNIX_SENDMSG
	case linux.BPF_CGROUP_SYSCTL:
		return CGROUP_SYSCTL
	case linux.BPF_CGROUP_UDP4_RECVMSG:
		return CGROUP_UDP4_RECVMSG
	case linux.BPF_CGROUP_UDP6_RECVMSG:
		return CGROUP_UDP6_RECVMSG
	case linux.BPF_CGROUP_UNIX_RECVMSG:
		return CGROUP_UNIX_RECVMSG
	case linux.BPF_CGROUP_GETSOCKOPT:
		return CGROUP_GETSOCKOPT
	case linux.BPF_CGROUP_SETSOCKOPT:
		return CGROUP_SETSOCKOPT
	case linux.BPF_CGROUP_INET4_GETPEERNAME:
		return CGROUP_INET4_GETPEERNAME
	case linux.BPF_CGROUP_INET6_GETPEERNAME:
		return CGROUP_INET6_GETPEERNAME
	case linux.BPF_CGROUP_UNIX_GETPEERNAME:
		return CGROUP_UNIX_GETPEERNAME
	case linux.BPF_CGROUP_INET4_GETSOCKNAME:
		return CGROUP_INET4_GETSOCKNAME
	case linux.BPF_CGROUP_INET6_GETSOCKNAME:
		return CGROUP_INET6_GETSOCKNAME
	case linux.BPF_CGROUP_UNIX_GETSOCKNAME:
		return CGROUP_UNIX_GETSOCKNAME
	case linux.BPF_CGROUP_INET_SOCK_RELEASE:
		return CGROUP_INET_SOCK_RELEASE
	}

	return nil
}
