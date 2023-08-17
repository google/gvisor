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

// Clone constants per clone(2).
const (
	CSIGNAL = 0xff

	CLONE_VM             = 0x100
	CLONE_FS             = 0x200
	CLONE_FILES          = 0x400
	CLONE_SIGHAND        = 0x800
	CLONE_PIDFD          = 0x1000
	CLONE_PTRACE         = 0x2000
	CLONE_VFORK          = 0x4000
	CLONE_PARENT         = 0x8000
	CLONE_THREAD         = 0x10000
	CLONE_NEWNS          = 0x20000
	CLONE_SYSVSEM        = 0x40000
	CLONE_SETTLS         = 0x80000
	CLONE_PARENT_SETTID  = 0x100000
	CLONE_CHILD_CLEARTID = 0x200000
	CLONE_DETACHED       = 0x400000
	CLONE_UNTRACED       = 0x800000
	CLONE_CHILD_SETTID   = 0x1000000
	CLONE_NEWCGROUP      = 0x2000000
	CLONE_NEWUTS         = 0x4000000
	CLONE_NEWIPC         = 0x8000000
	CLONE_NEWUSER        = 0x10000000
	CLONE_NEWPID         = 0x20000000
	CLONE_NEWNET         = 0x40000000
	CLONE_IO             = 0x80000000

	// Only passable via clone3(2).
	CLONE_CLEAR_SIGHAND = 0x100000000
	CLONE_INTO_CGROUP   = 0x200000000
)

// CloneArgs is struct clone_args, from include/uapi/linux/sched.h.
type CloneArgs struct {
	Flags      uint64
	Pidfd      uint64
	ChildTID   uint64
	ParentTID  uint64
	ExitSignal uint64
	Stack      uint64
	StackSize  uint64
	TLS        uint64
	SetTID     uint64
	SetTIDSize uint64
	Cgroup     uint64
}
