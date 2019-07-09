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
	CLONE_VM             = 0x100
	CLONE_FS             = 0x200
	CLONE_FILES          = 0x400
	CLONE_SIGHAND        = 0x800
	CLONE_PARENT         = 0x8000
	CLONE_PTRACE         = 0x2000
	CLONE_VFORK          = 0x4000
	CLONE_THREAD         = 0x10000
	CLONE_NEWNS          = 0x20000
	CLONE_SYSVSEM        = 0x40000
	CLONE_SETTLS         = 0x80000
	CLONE_PARENT_SETTID  = 0x100000
	CLONE_CHILD_CLEARTID = 0x200000
	CLONE_DETACHED       = 0x400000
	CLONE_UNTRACED       = 0x800000
	CLONE_CHILD_SETTID   = 0x1000000
	CLONE_NEWUTS         = 0x4000000
	CLONE_NEWIPC         = 0x8000000
	CLONE_NEWUSER        = 0x10000000
	CLONE_NEWPID         = 0x20000000
	CLONE_NEWNET         = 0x40000000
	CLONE_IO             = 0x80000000
)
