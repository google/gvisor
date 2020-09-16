// Copyright 2018 The gVisor Authors.
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

// A Capability represents the ability to perform a privileged operation.
type Capability int

// Capabilities defined by Linux. Taken from the kernel's
// include/uapi/linux/capability.h. See capabilities(7) or that file for more
// detailed capability descriptions.
const (
	CAP_CHOWN            = Capability(0)
	CAP_DAC_OVERRIDE     = Capability(1)
	CAP_DAC_READ_SEARCH  = Capability(2)
	CAP_FOWNER           = Capability(3)
	CAP_FSETID           = Capability(4)
	CAP_KILL             = Capability(5)
	CAP_SETGID           = Capability(6)
	CAP_SETUID           = Capability(7)
	CAP_SETPCAP          = Capability(8)
	CAP_LINUX_IMMUTABLE  = Capability(9)
	CAP_NET_BIND_SERVICE = Capability(10)
	CAP_NET_BROADCAST    = Capability(11)
	CAP_NET_ADMIN        = Capability(12)
	CAP_NET_RAW          = Capability(13)
	CAP_IPC_LOCK         = Capability(14)
	CAP_IPC_OWNER        = Capability(15)
	CAP_SYS_MODULE       = Capability(16)
	CAP_SYS_RAWIO        = Capability(17)
	CAP_SYS_CHROOT       = Capability(18)
	CAP_SYS_PTRACE       = Capability(19)
	CAP_SYS_PACCT        = Capability(20)
	CAP_SYS_ADMIN        = Capability(21)
	CAP_SYS_BOOT         = Capability(22)
	CAP_SYS_NICE         = Capability(23)
	CAP_SYS_RESOURCE     = Capability(24)
	CAP_SYS_TIME         = Capability(25)
	CAP_SYS_TTY_CONFIG   = Capability(26)
	CAP_MKNOD            = Capability(27)
	CAP_LEASE            = Capability(28)
	CAP_AUDIT_WRITE      = Capability(29)
	CAP_AUDIT_CONTROL    = Capability(30)
	CAP_SETFCAP          = Capability(31)
	CAP_MAC_OVERRIDE     = Capability(32)
	CAP_MAC_ADMIN        = Capability(33)
	CAP_SYSLOG           = Capability(34)
	CAP_WAKE_ALARM       = Capability(35)
	CAP_BLOCK_SUSPEND    = Capability(36)
	CAP_AUDIT_READ       = Capability(37)

	// CAP_LAST_CAP is the highest-numbered capability.
	// Seach for "CAP_LAST_CAP" to find other places that need to change.
	CAP_LAST_CAP = CAP_AUDIT_READ
)

// Ok returns true if cp is a supported capability.
func (cp Capability) Ok() bool {
	return cp >= 0 && cp <= CAP_LAST_CAP
}

// String returns the capability name.
func (cp Capability) String() string {
	switch cp {
	case CAP_CHOWN:
		return "CAP_CHOWN"
	case CAP_DAC_OVERRIDE:
		return "CAP_DAC_OVERRIDE"
	case CAP_DAC_READ_SEARCH:
		return "CAP_DAC_READ_SEARCH"
	case CAP_FOWNER:
		return "CAP_FOWNER"
	case CAP_FSETID:
		return "CAP_FSETID"
	case CAP_KILL:
		return "CAP_KILL"
	case CAP_SETGID:
		return "CAP_SETGID"
	case CAP_SETUID:
		return "CAP_SETUID"
	case CAP_SETPCAP:
		return "CAP_SETPCAP"
	case CAP_LINUX_IMMUTABLE:
		return "CAP_LINUX_IMMUTABLE"
	case CAP_NET_BIND_SERVICE:
		return "CAP_NET_BIND_SERVICE"
	case CAP_NET_BROADCAST:
		return "CAP_NET_BROADCAST"
	case CAP_NET_ADMIN:
		return "CAP_NET_ADMIN"
	case CAP_NET_RAW:
		return "CAP_NET_RAW"
	case CAP_IPC_LOCK:
		return "CAP_IPC_LOCK"
	case CAP_IPC_OWNER:
		return "CAP_IPC_OWNER"
	case CAP_SYS_MODULE:
		return "CAP_SYS_MODULE"
	case CAP_SYS_RAWIO:
		return "CAP_SYS_RAWIO"
	case CAP_SYS_CHROOT:
		return "CAP_SYS_CHROOT"
	case CAP_SYS_PTRACE:
		return "CAP_SYS_PTRACE"
	case CAP_SYS_PACCT:
		return "CAP_SYS_PACCT"
	case CAP_SYS_ADMIN:
		return "CAP_SYS_ADMIN"
	case CAP_SYS_BOOT:
		return "CAP_SYS_BOOT"
	case CAP_SYS_NICE:
		return "CAP_SYS_NICE"
	case CAP_SYS_RESOURCE:
		return "CAP_SYS_RESOURCE"
	case CAP_SYS_TIME:
		return "CAP_SYS_TIME"
	case CAP_SYS_TTY_CONFIG:
		return "CAP_SYS_TTY_CONFIG"
	case CAP_MKNOD:
		return "CAP_MKNOD"
	case CAP_LEASE:
		return "CAP_LEASE"
	case CAP_AUDIT_WRITE:
		return "CAP_AUDIT_WRITE"
	case CAP_AUDIT_CONTROL:
		return "CAP_AUDIT_CONTROL"
	case CAP_SETFCAP:
		return "CAP_SETFCAP"
	case CAP_MAC_OVERRIDE:
		return "CAP_MAC_OVERRIDE"
	case CAP_MAC_ADMIN:
		return "CAP_MAC_ADMIN"
	case CAP_SYSLOG:
		return "CAP_SYSLOG"
	case CAP_WAKE_ALARM:
		return "CAP_WAKE_ALARM"
	case CAP_BLOCK_SUSPEND:
		return "CAP_BLOCK_SUSPEND"
	case CAP_AUDIT_READ:
		return "CAP_AUDIT_READ"
	default:
		return "UNKNOWN"
	}
}

// Version numbers used by the capget/capset syscalls, defined in Linux's
// include/uapi/linux/capability.h.
const (
	// LINUX_CAPABILITY_VERSION_1 causes the data pointer to be
	// interpreted as a pointer to a single cap_user_data_t. Since capability
	// sets are 64 bits and the "capability sets" in cap_user_data_t are 32
	// bits only, this causes the upper 32 bits to be implicitly 0.
	LINUX_CAPABILITY_VERSION_1 = 0x19980330

	// LINUX_CAPABILITY_VERSION_2 and LINUX_CAPABILITY_VERSION_3 cause the
	// data pointer to be interpreted as a pointer to an array of 2
	// cap_user_data_t, using the second to store the 32 MSB of each capability
	// set. Versions 2 and 3 are identical, but Linux printk's a warning on use
	// of version 2 due to a userspace API defect.
	LINUX_CAPABILITY_VERSION_2 = 0x20071026
	LINUX_CAPABILITY_VERSION_3 = 0x20080522

	// HighestCapabilityVersion is the highest supported
	// LINUX_CAPABILITY_VERSION_* version.
	HighestCapabilityVersion = LINUX_CAPABILITY_VERSION_3
)

// CapUserHeader is equivalent to Linux's cap_user_header_t.
//
// +marshal
type CapUserHeader struct {
	Version uint32
	Pid     int32
}

// CapUserData is equivalent to Linux's cap_user_data_t.
//
// +marshal slice:CapUserDataSlice
type CapUserData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}
