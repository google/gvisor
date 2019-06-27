// Copyright 2019 The gVisor Authors.
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

package strace

import (
	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// CapabilityBitset is the set of capabilities in a bitset.
var CapabilityBitset = abi.FlagSet{
	{
		Flag: 1 << uint32(linux.CAP_CHOWN),
		Name: "CAP_CHOWN",
	},
	{
		Flag: 1 << uint32(linux.CAP_DAC_OVERRIDE),
		Name: "CAP_DAC_OVERRIDE",
	},
	{
		Flag: 1 << uint32(linux.CAP_DAC_READ_SEARCH),
		Name: "CAP_DAC_READ_SEARCH",
	},
	{
		Flag: 1 << uint32(linux.CAP_FOWNER),
		Name: "CAP_FOWNER",
	},
	{
		Flag: 1 << uint32(linux.CAP_FSETID),
		Name: "CAP_FSETID",
	},
	{
		Flag: 1 << uint32(linux.CAP_KILL),
		Name: "CAP_KILL",
	},
	{
		Flag: 1 << uint32(linux.CAP_SETGID),
		Name: "CAP_SETGID",
	},
	{
		Flag: 1 << uint32(linux.CAP_SETUID),
		Name: "CAP_SETUID",
	},
	{
		Flag: 1 << uint32(linux.CAP_SETPCAP),
		Name: "CAP_SETPCAP",
	},
	{
		Flag: 1 << uint32(linux.CAP_LINUX_IMMUTABLE),
		Name: "CAP_LINUX_IMMUTABLE",
	},
	{
		Flag: 1 << uint32(linux.CAP_NET_BIND_SERVICE),
		Name: "CAP_NET_BIND_SERVICE",
	},
	{
		Flag: 1 << uint32(linux.CAP_NET_BROADCAST),
		Name: "CAP_NET_BROADCAST",
	},
	{
		Flag: 1 << uint32(linux.CAP_NET_ADMIN),
		Name: "CAP_NET_ADMIN",
	},
	{
		Flag: 1 << uint32(linux.CAP_NET_RAW),
		Name: "CAP_NET_RAW",
	},
	{
		Flag: 1 << uint32(linux.CAP_IPC_LOCK),
		Name: "CAP_IPC_LOCK",
	},
	{
		Flag: 1 << uint32(linux.CAP_IPC_OWNER),
		Name: "CAP_IPC_OWNER",
	},
	{
		Flag: 1 << uint32(linux.CAP_SYS_MODULE),
		Name: "CAP_SYS_MODULE",
	},
	{
		Flag: 1 << uint32(linux.CAP_SYS_RAWIO),
		Name: "CAP_SYS_RAWIO",
	},
	{
		Flag: 1 << uint32(linux.CAP_SYS_CHROOT),
		Name: "CAP_SYS_CHROOT",
	},
	{
		Flag: 1 << uint32(linux.CAP_SYS_PTRACE),
		Name: "CAP_SYS_PTRACE",
	},
	{
		Flag: 1 << uint32(linux.CAP_SYS_PACCT),
		Name: "CAP_SYS_PACCT",
	},
	{
		Flag: 1 << uint32(linux.CAP_SYS_ADMIN),
		Name: "CAP_SYS_ADMIN",
	},
	{
		Flag: 1 << uint32(linux.CAP_SYS_BOOT),
		Name: "CAP_SYS_BOOT",
	},
	{
		Flag: 1 << uint32(linux.CAP_SYS_NICE),
		Name: "CAP_SYS_NICE",
	},
	{
		Flag: 1 << uint32(linux.CAP_SYS_RESOURCE),
		Name: "CAP_SYS_RESOURCE",
	},
	{
		Flag: 1 << uint32(linux.CAP_SYS_TIME),
		Name: "CAP_SYS_TIME",
	},
	{
		Flag: 1 << uint32(linux.CAP_SYS_TTY_CONFIG),
		Name: "CAP_SYS_TTY_CONFIG",
	},
	{
		Flag: 1 << uint32(linux.CAP_MKNOD),
		Name: "CAP_MKNOD",
	},
	{
		Flag: 1 << uint32(linux.CAP_LEASE),
		Name: "CAP_LEASE",
	},
	{
		Flag: 1 << uint32(linux.CAP_AUDIT_WRITE),
		Name: "CAP_AUDIT_WRITE",
	},
	{
		Flag: 1 << uint32(linux.CAP_AUDIT_CONTROL),
		Name: "CAP_AUDIT_CONTROL",
	},
	{
		Flag: 1 << uint32(linux.CAP_SETFCAP),
		Name: "CAP_SETFCAP",
	},
	{
		Flag: 1 << uint32(linux.CAP_MAC_OVERRIDE),
		Name: "CAP_MAC_OVERRIDE",
	},
	{
		Flag: 1 << uint32(linux.CAP_MAC_ADMIN),
		Name: "CAP_MAC_ADMIN",
	},
	{
		Flag: 1 << uint32(linux.CAP_SYSLOG),
		Name: "CAP_SYSLOG",
	},
	{
		Flag: 1 << uint32(linux.CAP_WAKE_ALARM),
		Name: "CAP_WAKE_ALARM",
	},
	{
		Flag: 1 << uint32(linux.CAP_BLOCK_SUSPEND),
		Name: "CAP_BLOCK_SUSPEND",
	},
	{
		Flag: 1 << uint32(linux.CAP_AUDIT_READ),
		Name: "CAP_AUDIT_READ",
	},
}
