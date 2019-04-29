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

	// MaxCapability is the highest-numbered capability.
	MaxCapability = CAP_AUDIT_READ
)

// Ok returns true if cp is a supported capability.
func (cp Capability) Ok() bool {
	return cp >= 0 && cp <= MaxCapability
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
type CapUserHeader struct {
	Version uint32
	Pid     int32
}

// CapUserData is equivalent to Linux's cap_user_data_t.
type CapUserData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}
