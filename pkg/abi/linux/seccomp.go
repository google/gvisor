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

import "fmt"

// Seccomp constants taken from <linux/seccomp.h>.
const (
	SECCOMP_MODE_NONE   = 0
	SECCOMP_MODE_FILTER = 2

	SECCOMP_RET_ACTION_FULL = 0xffff0000
	SECCOMP_RET_ACTION      = 0x7fff0000
	SECCOMP_RET_DATA        = 0x0000ffff

	SECCOMP_SET_MODE_FILTER  = 1
	SECCOMP_GET_ACTION_AVAIL = 2
	SECCOMP_GET_NOTIF_SIZES  = 3

	SECCOMP_FILTER_FLAG_TSYNC        = 1
	SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3

	SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1

	SECCOMP_IOCTL_NOTIF_RECV      = 0xc0502100
	SECCOMP_IOCTL_NOTIF_SEND      = 0xc0182101
	SECCOMP_IOCTL_NOTIF_SET_FLAGS = 0x40082104

	SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP = 1
)

// BPFAction is an action for a BPF filter.
type BPFAction uint32

// BPFAction definitions.
const (
	SECCOMP_RET_KILL_PROCESS BPFAction = 0x80000000
	SECCOMP_RET_KILL_THREAD  BPFAction = 0x00000000
	SECCOMP_RET_TRAP         BPFAction = 0x00030000
	SECCOMP_RET_ERRNO        BPFAction = 0x00050000
	SECCOMP_RET_TRACE        BPFAction = 0x7ff00000
	SECCOMP_RET_USER_NOTIF   BPFAction = 0x7fc00000
	SECCOMP_RET_ALLOW        BPFAction = 0x7fff0000
)

func (a BPFAction) String() string {
	switch a & SECCOMP_RET_ACTION_FULL {
	case SECCOMP_RET_KILL_PROCESS:
		return "kill process"
	case SECCOMP_RET_KILL_THREAD:
		return "kill thread"
	case SECCOMP_RET_TRAP:
		data := a.Data()
		if data == 0 {
			return "trap"
		}
		return fmt.Sprintf("trap (data=%#x)", data)
	case SECCOMP_RET_ERRNO:
		return fmt.Sprintf("return errno=%#x", a.Data())
	case SECCOMP_RET_TRACE:
		data := a.Data()
		if data == 0 {
			return "trace"
		}
		return fmt.Sprintf("trace (data=%#x)", data)
	case SECCOMP_RET_ALLOW:
		return "allow"
	case SECCOMP_RET_USER_NOTIF:
		return "unotify"
	}
	return fmt.Sprintf("invalid action: %#x", a)
}

// Data returns the SECCOMP_RET_DATA portion of the action.
func (a BPFAction) Data() uint16 {
	return uint16(a & SECCOMP_RET_DATA)
}

// WithReturnCode sets the lower 16 bits of the SECCOMP_RET_ERRNO or
// SECCOMP_RET_TRACE actions to the provided return code, overwriting the previous
// action, and returns a new BPFAction. If not SECCOMP_RET_ERRNO or
// SECCOMP_RET_TRACE then this panics.
func (a BPFAction) WithReturnCode(code uint16) BPFAction {
	// mask out the previous return value
	baseAction := a & SECCOMP_RET_ACTION_FULL
	if baseAction == SECCOMP_RET_ERRNO || baseAction == SECCOMP_RET_TRACE {
		return BPFAction(uint32(baseAction) | uint32(code))
	}
	panic("WithReturnCode only valid for SECCOMP_RET_ERRNO and SECCOMP_RET_TRACE")
}

// SockFprog is sock_fprog taken from <linux/filter.h>.
type SockFprog struct {
	Len    uint16
	pad    [6]byte
	Filter *BPFInstruction
}

// SeccompData is equivalent to struct seccomp_data, which contains the data
// passed to seccomp-bpf filters.
//
// +marshal
type SeccompData struct {
	// Nr is the system call number.
	Nr int32

	// Arch is an AUDIT_ARCH_* value indicating the system call convention.
	Arch uint32

	// InstructionPointer is the value of the instruction pointer at the time
	// of the system call.
	InstructionPointer uint64

	// Args contains the first 6 system call arguments.
	Args [6]uint64
}

// SeccompNotifResp is equivalent to struct seccomp_notif_resp.
//
// +marshal
type SeccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// SeccompNotifSizes is equivalent to struct seccomp_notif_sizes.
//
// +marshal
type SeccompNotifSizes struct {
	Notif      uint16
	Notif_resp uint16
	Data       uint16
}

// SeccompNotif is equivalent to struct seccomp_notif.
//
// +marshal
type SeccompNotif struct {
	ID    uint64
	Pid   int32
	Flags uint32
	Data  SeccompData
}

// String returns a human-friendly representation of this `SeccompData`.
func (sd SeccompData) String() string {
	return fmt.Sprintf(
		"sysno=%d arch=%#x rip=%#x args=[%#x %#x %#x %#x %#x %#x]",
		sd.Nr,
		sd.Arch,
		sd.InstructionPointer,
		sd.Args[0],
		sd.Args[1],
		sd.Args[2],
		sd.Args[3],
		sd.Args[4],
		sd.Args[5],
	)
}
